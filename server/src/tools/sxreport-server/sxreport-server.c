/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *  Special exception for linking this software with OpenSSL:
 *
 *  In addition, as a special exception, Skylable Ltd. gives permission to
 *  link the code of this program with the OpenSSL library and distribute
 *  linked combinations including the two. You must obey the GNU General
 *  Public License in all respects for all of the code used other than
 *  OpenSSL. You may extend this exception to your version of the program,
 *  but you are not obligated to do so. If you do not wish to do so, delete
 *  this exception statement from your version.
 */

#include "default.h"
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/resource.h>
#include <dirent.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "config.h"
#include "cmd_main.h"
#include "sx.h"
#include "sqlite3.h"
#include "hashfs.h"
#include "init.h"
#include "../../fcgi/cfgfile.h"
#include "../../../libsxclient/src/sxreport.h"
#include "../../../libsxclient/src/sxlog.h"
#include "../../../libsxclient/src/misc.h"
#include "../../../libsxclient/src/vcrypto.h"

static struct gengetopt_args_info fcgi_args;
static int fcgi_args_parsed;
static FILE *logfile;

#undef INFO
#define INFO(...) sxi_log_msg(&logger, NULL, SX_LOG_INFO,  __VA_ARGS__)

static void dump(const char *name, FILE *in)
{
    char line[1024];
    INFO("\n--- %s ---", name);
    while (fgets(line, sizeof(line), in)) {
        unsigned n = strlen(line);
        if (n > 0)
            line[n-1] = '\0';
        INFO("\t%s", line);
    }
    INFO("---=---");
}

static int run_command(const char *cmd)
{
    fflush(stderr);
    FILE *cmdout = popen(cmd, "r");
    if (!cmdout)
        return -1;/* silently ignore missing executables on other platforms */
    dump(cmd, cmdout);
    return pclose(cmdout);
}

static void print_fs(const char *dir)
{
    /* There is no portable way to easily determine FS type or list mountpoints.
     * statfs only gives an FS type that can't tell difference between ext3 and
     * ext4.
     * getmntent is Linux specific (FreeBSD has mountinfo).
     * So try to use 'df -T' which deals with all the non-portable way to get
     * that info.
     * Failing that print only space usage */
    char cmd[4096];
    snprintf(cmd,sizeof(cmd),"df -T '%s' 2>/dev/null", dir);
    if (run_command(cmd) != 0) {
        struct statvfs vfs;
        if (statvfs(dir, &vfs) == 0) {
            long long avail = vfs.f_bavail * vfs.f_frsize;
            long long total = vfs.f_blocks * vfs.f_frsize;
            INFO("\tSpace free: %lld / %lld, %lld%% used",
                   avail, total, 100 * (total - avail) / total);
        }
    }
#ifdef __linux__
    FILE *p = popen("lsblk -Dtfl","r");
    if (p) {
        char line[1024], header[1024], best[1024];
        best[0] = '\0';
        if (fgets(header, sizeof(header), p)) {
            while (fgets(line, sizeof(line), p)) {
                int n = strlen(line);
                if (!n)
                    continue;
                line[n-1] = '\0';
                const char *mountpoint = strrchr(line,' ');
                if (mountpoint) {
                    mountpoint++;
                    if (*mountpoint && strlen(mountpoint) > 1 &&
                        !strncmp(mountpoint,dir,strlen(mountpoint)) &&
                        strlen(mountpoint) > strlen(best)) {
                        sxi_strlcpy(best, line, sizeof(best));
                    }
                }
            }
            if (*best) {
                INFO("%s%s", header, best);
            }
        }
        pclose(p);
    }
#endif
}

static void print_hashfs(sxc_client_t *sx, const char *path)
{
    sxi_report_section(sx, "Detailed storage statistics");
    struct stat buf;
    if (stat(path, &buf) == -1) {
        WARN("Storage stat failed for '%s': %s", path, strerror(errno));
        return;
    }
    INFO("Storage directory '%s': %o %d:%d", path, buf.st_mode, buf.st_uid, buf.st_gid);
    long long size = buf.st_size;
    DIR *d  = opendir(path);
    if(d) {
        struct dirent *dentry;
        while ((dentry = readdir(d))) {
            char name[4096];
            if (!strcmp(dentry->d_name,".") || !strcmp(dentry->d_name,".."))
                continue;
            snprintf(name,sizeof(name),"%s/%s", path, dentry->d_name);
            if (stat(name, &buf) == -1)
                continue;
            INFO("\t%-20s: %o %d:%d %20lld",
                   dentry->d_name, buf.st_mode, buf.st_uid, buf.st_gid, (long long)buf.st_size);
            size += buf.st_size;
        }
        closedir(d);
    }

    sx_hashfs_t *h = sx_hashfs_open(path, sx);
    if(!h) {
        WARN("Storage cannot be opened!");
	return;
    }
    const sx_node_t *self= sx_hashfs_self(h);
    if (self)
        INFO("Current node space usage: %lld (%.2f%%)", size,
               100.0 * size / sx_node_capacity(self));
    else
        INFO("This is a bare node");

    INFO("HashFS Version: %s", sx_hashfs_version(h)->string);

    sx_hashfs_stats(h);
    sx_hashfs_analyze(h, 1);
    sx_hashfs_close(h);
}

static void print_sqlite3_build_info(void)
{
    struct sxi_fmt fmt;
    unsigned i;

    INFO("SQLite3: %s", sqlite3_sourceid());
    sxi_fmt_start(&fmt);
    sxi_fmt_msg(&fmt, "\t compile options:");
    for (i=0;;i++) {
        const char *opt = sqlite3_compileoption_get(i);
        if (!opt)
            break;
        sxi_fmt_msg(&fmt, " %s", opt);
    }
    INFO("%s", fmt.buf);
}

static void print_mem(void)
{
    INFO("Memory and swap statistics:");
    if (run_command("free 2>/dev/null"))
        INFO("\tN/A");
}

static void print_net(void)
{
    INFO("Network device information:\n");
#ifdef __linux__
    DIR *d = opendir("/sys/class/net");
    if (d) {
        struct dirent *dentry;
        while ((dentry = readdir(d))) {
            char name[128];
            if (*dentry->d_name == '.')
                continue;
            snprintf(name, sizeof(name), "/sys/class/net/%s/speed", dentry->d_name);
            FILE *f = fopen(name, "r");
            if (f) {
                int speed;
                if (fscanf(f,"%d",&speed) == 1)
                    INFO("\t%s Speed: %d Mbps", dentry->d_name, speed);
                fclose(f);
            }
        }
        closedir(d);
    }
#endif
    if (run_command("/sbin/ifconfig 2>/dev/null"))
        INFO("\tN/A");
}

static void dump_file(const char *file, const char *name)
{
    FILE *f = fopen(file, "r");
    if (!f)
        return;
    dump(name, f);
    fclose(f);
}

static void print_cpuinfo()
{
#ifdef __linux__
    dump_file("/proc/cpuinfo", "/proc/cpuinfo");
#endif
}

static void print_ssl_cert_info(sxc_client_t *sx, const char *file)
{
    INFO("SSL server certificate:");
    sxi_vcrypt_print_cert_info(sx, file, 0);
}

static void print_ssl_key_info(const char *file)
{
    if (!access(file, F_OK))
        WARN("SSL certificate key not readable");
    /* TODO: check that the private key belongs to the x509 cert */
}

static int parse_key_value(char *line, const char **key, const char **value)
{
    char *q;
    for (q = line;*q == ' ' || *q == '\t';q++) {}
    if (*q == '#')
        return -1;
    *key = q;
    while (*q != ' ' && *q != '\t' && *q) q++;
    if (!*q)
        return -1;
    *q = '\0';
    q++;
    while (*q == ' ' || *q == '\t') q++;
    *value = q;
    while (*q != ';' &&  *q) q++;
    *q = '\0';
    return 0;
}

static void print_sxhttpd_conf(sxc_client_t *sx, const char *dir, const char *file)
{
    char path[1024];
    char line[1024];

    snprintf(path, sizeof(path), "%s/%s", dir, file);
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    dump_file(path, path);
    while (fgets(line, sizeof(line), f)) {
        const char *key, *value;
        if (parse_key_value(line, &key, &value) == -1)
            continue;
        if (!strcmp(key, "ssl_certificate"))
            print_ssl_cert_info(sx, value);
        if (!strcmp(key, "ssl_certificate_key"))
            print_ssl_key_info(value);
        if (!strcmp(key, "ssl_ciphers"))
            sxi_vcrypt_print_cipherlist(sx, value);
    }
    fclose(f);
}

static void print_info(sxc_client_t *sx, const char *sysconfdir)
{
    char file[1024];

    sxi_report_section(sx, "Build configuration");
    sxi_report_library_versions(sx, src_version());
    sxi_report_library_int(sx, "sqlite", SQLITE_VERSION_NUMBER, sqlite3_libversion_number(),
                      1000000, 1000, 1);
    sxi_report_build_info(sx);
    sxi_report_build_flags(sx);
    print_sqlite3_build_info();

    sxi_report_system_info(sx);
#ifdef __linux__
    INFO("OS distribution: ");
    if (run_command("/usr/bin/lsb_release -ds 2>/dev/null") != 0)
        printf("N/A\n");
    INFO("--- Loaded modules: ---");
    if (run_command("lsmod") != 0)
        INFO("N/A");
#endif
    print_cpuinfo();

    sxi_report_section(sx, "Runtime configuration");
    INFO("SX.fcgi configuration file: %s/sxserver/sxfcgi.conf", sysconfdir);
    INFO("SX.fcgi configuration parsed OK: %s",
           fcgi_args_parsed ? "yes" : "no");

    if (fcgi_args.data_dir_given) {
        struct stat log, data;
        INFO("Data directory: %s/data", fcgi_args.data_dir_arg);
        INFO("Logfile: %s", fcgi_args.logfile_arg);
        if (stat(fcgi_args.data_dir_arg, &data) == 0) {
            if (stat(fcgi_args.logfile_arg, &log) == 0 &&
                log.st_dev == data.st_dev)
                /* filling data partition will make us impossible to log or
                 * viceversa */
                WARN("WARNING: log and data directories are on the same partition!");
            INFO("\tData I/O blocksize: %ld", (long)data.st_blksize);
        }
    }
    snprintf(file,sizeof(file),"%s/sxserver/sxfcgi.conf", sysconfdir);
    dump_file(file, file);

    print_sxhttpd_conf(sx, sysconfdir, "/sxserver/sxhttpd.conf");

    sxi_report_limits(sx);
    print_net();

    sxi_report_section(sx, "Runtime status");
    if (fcgi_args.data_dir_given) {
        print_fs(fcgi_args.data_dir_arg);
        print_fs(fcgi_args.logfile_arg);
    }
    print_mem();
}

static void print_storage(sxc_client_t *sx)
{
    sxi_report_section(sx, "Storage status");
    if (fcgi_args.data_dir_given)
        print_hashfs(sx, fcgi_args.data_dir_arg);
}

static void print_logs(const char *sysconfdir)
{
    char path[1024];
    char line[1024];
    if (fcgi_args.logfile_arg)
        dump_file(fcgi_args.logfile_arg, fcgi_args.logfile_arg);
    snprintf(path, sizeof(path), "%s/sxserver/sxhttpd.conf", sysconfdir);
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    while (fgets(line, sizeof(line), f)) {
        const char *key, *value;
        if (parse_key_value(line, &key, &value) == -1)
            continue;
        if (!strcmp(key,"error_log"))
            dump_file(value, value);
    }
    fclose(f);
}

static void print_cluster(sxc_client_t *sx)
{
    sxi_report_section(sx, "Cluster status");
    if (!fcgi_args.data_dir_given)
        return;
    const char *path = fcgi_args.data_dir_arg;
    const sx_nodelist_t *nodes;
    sx_hashfs_t *h = sx_hashfs_open(path, sx);
    if(!h) {
        WARN("Storage cannot be opened!");
	return;
    }
    INFO("Cluster UUID: %s", sx_hashfs_uuid(h)->string);

    const sx_node_t *self= sx_hashfs_self(h);

    nodes = sx_hashfs_all_nodes(h, NL_NEXT);
    if(nodes && sx_nodelist_count(nodes)) {
	unsigned int i, nnodes = sx_nodelist_count(nodes);
	INFO("List of nodes:");
	for(i=0; i<nnodes; i++) {
	    const sx_node_t *n = sx_nodelist_get(nodes, i);
	    if(!n) {
		WARN("Error while retrieving the node list");
		break;
	    }
	    INFO("\t %c %s %s (%s) %lld", (n == self) ? '*' : '-', sx_node_uuid(n)->string, sx_node_addr(n), sx_node_internal_addr(n), (long long int)sx_node_capacity(n));
	}
    } else
	INFO("No node was set yet");
}

extern int anonymize_filter(sxc_client_t *sx, const char *path, FILE *in, FILE *out);

int main(int argc, char **argv) {
    struct main_args_info args;
    struct cmdline_parser_params *params = NULL;
    char name[1024];
    long t = time(NULL);
    sxc_logger_t flogger;
    sxc_client_t *sx;

    if (main_cmdline_parser(argc, argv, &args))
        return 1;
    if (args.version_given) {
        printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, src_version());
        main_cmdline_parser_free(&args);
        return 0;
    }

    params = cmdline_parser_params_create();
    if (!params) {
        fprintf(stderr,"ERROR: Cannot allocate config parser\n");
        main_cmdline_parser_free(&args);
        return 1;
    }

    if(args.get_mem_given) {
	int64_t mem = 0;
	int ret = 1;
	sxc_client_t *sx = sx_init(NULL, NULL, NULL, 0, argc, argv);
	if(sx) {
	    ret = sxi_report_mem(sx, &mem, NULL, NULL, NULL) ? 1 : 0;
	    sx_done(&sx);
	} 
	printf("%llu\n", (unsigned long long) mem);
	return ret;
    }

    if(geteuid())
	fprintf(stderr, "WARNING: In most cases this program should be run by root to access all necessary files\n");

    if (args.output_given)
        snprintf(name, sizeof(name), "%s", args.output_arg);
    else
	snprintf(name, sizeof(name), "sxreport-server-%ld.log", t);

    if(!access(name, F_OK)) {
        fprintf(stderr,"ERROR: File %s exists\n", name);
        main_cmdline_parser_free(&args);
        return 1;
    }

    umask(077);
    logfile = fopen(name, "w+");
    if (!logfile) {
        fprintf(stderr,"ERROR: Cannot open logfile '%s': %s\n",
                name, strerror(errno));
        return 1;
    }

    sx = sx_init(sxc_file_logger(&flogger, argv[0], name, 0), NULL, NULL, 0, argc, argv);
    if(!sx)
	return 1;
    sxc_set_verbose(sx, 1);
    params->initialize = 1;
    cmdline_parser_init(&fcgi_args);/* without this it'll crash */
    const char *sysconfdir = args.sysconfdir_given ? args.sysconfdir_arg : INFO_SYSCONFDIR;
    char file[1024];
    snprintf(file,sizeof(file),"%s/sxserver/sxfcgi.conf", sysconfdir);
    if (!cmdline_parser_config_file(file, &fcgi_args,params))
        fcgi_args_parsed = 1;

    if (!args.all_given && !args.append_given && !args.info_given &&
        !args.logs_given && !args.cluster_given && !args.storage_given)
        args.all_given = 1;

    if (args.all_given)
        args.info_given = args.logs_given = args.cluster_given = args.storage_given = 1;

    if (args.info_given) {
        print_info(sx, sysconfdir);
    }
    if (args.storage_given) {
        print_storage(sx);
    }
    if (args.cluster_given) {
        print_cluster(sx);
    }

    if (args.logs_given) {
        print_logs(sysconfdir);
    }

    unsigned i;
    for (i=0;i<args.append_given;i++) {
        if (!strcmp(args.append_arg[i], "-"))
            dump("stdin", stdin);
        else
            dump_file(args.append_arg[i], args.append_arg[i]);
    }

    if (!args.no_anonymize_flag) {
        FILE *out, *logfile_in;
	char oname[1024];

        logfile_in = fopen(name, "r");
	if(!logfile_in) {
            WARN("Cannot open input file '%s': %s", name, strerror(errno));
	    sx_done(&sx);
            return 1;
        }
	sxi_strlcpy(oname, name, sizeof(oname));
	snprintf(name, sizeof(name), "sxreport-server-%ld-anon.log", t);
        out = fopen(name, "w");
        if (!out) {
	    fclose(logfile_in);
            WARN("Cannot open anonymized output file '%s': %s",
                 name, strerror(errno));
	    sx_done(&sx);
            return 1;
        }
        if(fclose(logfile)) {
	    fclose(logfile_in);
	    fclose(out);
            WARN("Cannot close output file '%s': %s",
                 oname, strerror(errno));
	    sx_done(&sx);
            return 1;
        }
        logfile = out;
        anonymize_filter(sx, fcgi_args.data_dir_arg, logfile_in, out);
        if(fclose(out)) {
	    fclose(logfile_in);
            WARN("Cannot close output file '%s': %s",
                 name, strerror(errno));
	    sx_done(&sx);
            return 1;
        }
        fclose(logfile_in);
	unlink(oname);
	if(args.output_given && !rename(name, oname))
	    sxi_strlcpy(name, oname, sizeof(name));
    }
    if (fcgi_args_parsed)
        cmdline_parser_free(&fcgi_args);
    free(params);
    printf("%s stored in %s\n", args.no_anonymize_given ? "Report" : "Anonymized report", name);
    printf("You can attach it to a bugreport at %s\n", PACKAGE_BUGREPORT);
    main_cmdline_parser_free(&args);
    sx_done(&sx);
    return 0;
}
