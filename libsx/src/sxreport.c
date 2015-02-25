/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "default.h"
#include "sxreport.h"
#include "sxlog.h"
#include "libsx-int.h"
#include "ltdl.h"
#include <string.h>
#include <yajl/yajl_version.h>
#include <curl/curl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include "vcrypto.h"

#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif

#if defined(HAVE_SYS_SYSCTL_H) || defined(__APPLE__)
#include <sys/sysctl.h>
#endif

static void print_confstr(sxc_client_t *sx, const char *msg, int name)
{
    size_t n = confstr(name, NULL, 0);
    char *info = malloc(n);
    if (!info)
        return;
    confstr(name, info, n);
    sxi_info(sx, "%s: %s", msg, info);
    free(info);
}

static void check_library(sxc_client_t *sx, const char *name, const char *compile_ver, const char *runtime_ver, int warn)
{
    struct sxi_fmt fmt;
    sxi_fmt_start(&fmt);
    sxi_fmt_msg(&fmt, "%s: %s", name, runtime_ver);
    if (strcmp(compile_ver, runtime_ver)) {
        sxi_fmt_msg(&fmt, " (%s build time)", compile_ver);
        if (warn)
            sxi_fmt_msg(&fmt, " WARNING: version mismatch!");
    }
    sxi_info(sx, "%s", fmt.buf);
}

static void print_ver(struct sxi_fmt *fmt, long ver, long major_div, long minor_div, long patch_div)
{
    long major = ver / major_div;
    long minor = (ver - major * major_div) / minor_div;
    long patch = (ver - (major * major_div + minor * minor_div)) / patch_div;
    sxi_fmt_msg(fmt, "%ld.%ld.%ld", major, minor, patch);
}

void sxi_report_library_int(sxc_client_t *sx, const char *name, long compile_ver, long runtime_ver,
                            long major_div, long minor_div, long patch_div)
{
    struct sxi_fmt fmt;
    sxi_fmt_start(&fmt);
    sxi_fmt_msg(&fmt, "%s: ", name);
    print_ver(&fmt, runtime_ver, major_div, minor_div, patch_div);
    if (compile_ver != runtime_ver) {
        sxi_fmt_msg(&fmt, " (");
        print_ver(&fmt, compile_ver, major_div, minor_div, patch_div);
        sxi_fmt_msg(&fmt, " build time)");
        if ((compile_ver / major_div) != (runtime_ver / major_div)) {
            sxi_fmt_msg(&fmt, " WARNING: major version mismatch!");
        }
        if (runtime_ver < compile_ver) {
            /* runtime version should either be the same, or upgraded */
            sxi_fmt_msg(&fmt, " WARNING: runtime version is OLDER than at build time!");
        }
    }
    sxi_info(sx, "%s", fmt.buf);
}

void sxi_report_section(sxc_client_t *sx, const char *section)
{
    char line[1024];
    struct sxi_fmt fmt;
    unsigned n = strlen(section);
    if (n >= sizeof(line))
        n = sizeof(line) - 1;

    sxi_fmt_start(&fmt);
    sxi_fmt_msg(&fmt, "%s\n", section);
    memset(line, '-', n);
    line[n] = '\0';
    sxi_info(sx, "\n%s%s", fmt.buf, line);
}

void sxi_report_library_versions(sxc_client_t *sx, const char *srcver)
{
    sxi_report_section(sx, "Library versions");
    check_library(sx, "libsx", srcver, sxc_get_version(), 1);
    sxi_report_library_int(sx, "yajl", YAJL_VERSION, yajl_version(), 10000, 100, 1);

    curl_version_info_data *data = curl_version_info(CURLVERSION_NOW);
    sxi_report_library_int(sx, "curl", LIBCURL_VERSION_NUM, data->version_num, 65536, 256, 1);
    sxi_info(sx, "\t%s", curl_version());
    if (!data->ssl_version ||
        (strncmp("OpenSSL", data->ssl_version, strlen("OpenSSL"))
        && strncmp("NSS", data->ssl_version, strlen("NSS"))))
        sxi_info(sx, "\tWARNING: curl was NOT linked with OpenSSL or NSS");
    sxi_report_crypto(sx);
#ifdef _CS_GNU_LIBC_VERSION
    print_confstr(sx, "libc", _CS_GNU_LIBC_VERSION);
#endif
#ifdef _CS_GNU_LIBPTHREAD_VERSION
    print_confstr(sx, "libpthread", _CS_GNU_LIBPTHREAD_VERSION);
#endif
}

void sxi_report_build_info(sxc_client_t *sx)
{
    struct sxi_fmt fmt;

    sxi_report_section(sx, "Build information");
    sxi_fmt_start(&fmt);
    sxi_info(sx, "Package version: %s", PACKAGE_VERSION);

    sxi_fmt_msg(&fmt, "Compiler: ");
#ifdef __GNUC__
    sxi_fmt_msg(&fmt, "(GCC compatible)");
#endif
#ifdef __VERSION__
    sxi_fmt_msg(&fmt, " version: %s", __VERSION__);
#endif
    sxi_info(sx, "%s", fmt.buf);

#ifdef _POSIX_C_SOURCE
    sxi_info(sx, "POSIX version: %ld", (long)(_POSIX_C_SOURCE));
#endif
#ifdef PATH_MAX
    sxi_info(sx, "PATH_MAX: %d", PATH_MAX);
#endif
#ifdef NAME_MAX
    sxi_info(sx, "NAME_MAX: %d", NAME_MAX);
#endif
    sxi_info(sx, "Pointer size: %ld", sizeof(void*)*8);
    sxi_info(sx, "File offset: %ld", sizeof(off_t)*8);

    sxi_fmt_start(&fmt);
    sxi_fmt_msg(&fmt, "Byte order: ");
#ifdef WORDS_BIGENDIAN
    sxi_fmt_msg(&fmt, "big endian");
#else
    sxi_fmt_msg(&fmt, "little endian");
#endif
    sxi_info(sx, "%s", fmt.buf);

    sxi_info(sx, "libltdl: prefix: %s, archive: .%s, dynamic: %s, env: %s",
             LT_LIBPREFIX, LT_LIBEXT, LT_MODULE_EXT, LT_MODULE_PATH_VAR);
}

static void print_runtime_endian(sxc_client_t *sx)
{
    uint8_t buf8[4] = {1, 2, 3, 4};
    uint32_t buf32;
    memcpy(&buf32, &buf8, sizeof(buf32));
    sxi_info(sx, "CPU runtime endianness: 0x%08x", buf32);
}

static void print_cpufreq_info(sxc_client_t *sx)
{
#ifdef __linux__
    char path[1024];
    char line[1024];
    struct sxi_fmt fmt;
    struct dirent *dentry;
    const char *dir = "/sys/devices/system/cpu";
    DIR *d = opendir(dir);
    if (!d)
        return;
    sxi_fmt_start(&fmt);
    while ((dentry = readdir(d))) {
        FILE *f;
        int cpb;
        int n;
        if (sscanf(dentry->d_name, "cpu%d", &n) != 1)
            continue;
        snprintf(path, sizeof(path), "%s/%s/cpufreq/scaling_governor", dir, dentry->d_name);
        f = fopen(path, "r");
        if (!f)
            continue;
        if (fgets(line, sizeof(line), f)) {
            unsigned n = strlen(line);
            if (n > 0)
                line[n - 1] = '\0';
            if (!strstr(fmt.buf, line))
                sxi_fmt_msg(&fmt, "%s ", line);
        }
        fclose(f);
        snprintf(path, sizeof(path), "%s/%s/cpufreq/cpb", dir, dentry->d_name);
        f = fopen(path, "r");
        if (!f)
            continue;
        if (fscanf(f, "%d", &cpb) == 1) {
            snprintf(line, sizeof(line), "cpb(%s)", cpb ? "on" : "off");
            if (!strstr(fmt.buf, line))
                sxi_fmt_msg(&fmt, "%s ", line);
        }
        fclose(f);
    }
    closedir(d);
    if (*fmt.buf)
        sxi_info(sx, "CPU freq scaling: %s", fmt.buf);
#endif
}

void sxi_report_system_info(sxc_client_t *sx)
{
    const char *path;
    struct utsname uts;
    time_t t = time(NULL);
    struct tm *tm;
    char buf[256];

    if (uname(&uts) == -1)
        return;
    sxi_report_section(sx, "System information");

    tm = gmtime(&t);
    if (tm && strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", tm) > 0)
        sxi_info(sx, "Current UTC time: %s", buf);
    tm = localtime(&t);
    if (tm && strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", tm) > 0)
        sxi_info(sx, "Current local time: %s", buf);

    sxi_info(sx, "CPU architecture: %s", uts.machine);
    print_runtime_endian(sx);
#if defined(_SC_NPROCESSORS_CONF) && defined(_SC_NPROCESSORS_ONLN)
    sxi_info(sx, "CPU cores: %ld/%ld", sysconf(_SC_NPROCESSORS_ONLN), sysconf(_SC_NPROCESSORS_CONF));
#endif
    print_cpufreq_info(sx);
    sxi_info(sx, "OS: %s %s %s", uts.sysname, uts.release, uts.version);
#ifdef _SC_IPV6
    sxi_info(sx, "IPv6: %ld", sysconf(_SC_IPV6));
#endif
    path = lt_dlgetsearchpath();
    sxi_info(sx, "ltdl search path: %s", path ? path : "");
}

static void print_limit(struct sxi_fmt *fmt, rlim_t lim, const char *type)
{
    sxi_fmt_msg(fmt, " %s: ", type);
    if (lim != RLIM_INFINITY)
        sxi_fmt_msg(fmt, "%lld", (long long)lim);
    else
        sxi_fmt_msg(fmt, "unlimited");
}

static void print_rlimit(sxc_client_t *sx, int limit, const char *name)
{
    struct rlimit rlim;
    struct sxi_fmt fmt;
    sxi_fmt_start(&fmt);
    sxi_fmt_msg(&fmt, "\t%-11s: ", name);
    if (getrlimit(limit,&rlim) == -1) {
        sxi_info(sx, "%sN/A", fmt.buf);
        return;
    }
    print_limit(&fmt, rlim.rlim_cur,"soft");
    print_limit(&fmt, rlim.rlim_max,"hard");
    sxi_info(sx, "%s", fmt.buf);
}

void sxi_report_limits(sxc_client_t *sx)
{
    struct passwd *p = getpwuid(geteuid());
    struct group *g = getgrgid(getegid());
    sxi_report_section(sx, "Resource limits");
    sxi_info(sx,"For current user: %s(%d):%s(%d)",
             p && p->pw_name ? p->pw_name : "", geteuid(),
             g && g->gr_name ? g->gr_name : "", getegid());
    print_rlimit(sx, RLIMIT_CORE, "core");
    print_rlimit(sx, RLIMIT_CPU, "cpu");
    print_rlimit(sx, RLIMIT_DATA,"data");
    print_rlimit(sx, RLIMIT_FSIZE,"filesize");
    print_rlimit(sx, RLIMIT_NOFILE,"open files");
    print_rlimit(sx, RLIMIT_STACK,"stack");
#ifdef RLIMIT_AS
    print_rlimit(sx, RLIMIT_AS,"memory");
#endif
}

int sxi_list(sxc_client_t *sx, const char *dir, const char *entry, int depth)
{
    int ret = -1;
    struct stat buf;
    unsigned n = strlen(dir) + strlen(entry) + 2;
    char *path = malloc(n);
    if (!path)
        return -1;
    do {
        snprintf(path, n, "%s/%s", dir, entry);
        if (lstat(path, &buf) == -1)
            break;
        if (S_ISDIR(buf.st_mode)) {
            DIR *dir = opendir(path);
            if (!dir)
                break;
            struct dirent *dentry;
            while ((dentry = readdir(dir))) {
                if (!strcmp(dentry->d_name,".") || !strcmp(dentry->d_name,".."))
                    continue;
                sxi_list(sx, path, dentry->d_name, depth+1);
            }
            closedir(dir);
            break;
        }
        sxi_info(sx,"\tdepth: %d, mode:0%o owner:%d:%d size:%20lld",
                 depth, buf.st_mode, buf.st_uid, buf.st_gid,
                 (long long)buf.st_size);
        ret = 0;
    } while(0);
    free(path);
    return ret;
}

int sxi_report_os(sxc_client_t *sx, char *name, size_t name_len, char *arch, size_t arch_len, char *release, size_t rel_len, char *version, size_t ver_len) {
    struct utsname uts;

    if(!sx)
        return 1;

    if (uname(&uts) == -1) {
        sxi_seterr(sx, SXE_ECFG, "Failed to get system information");
        return 1;
    }

    if(name)
        snprintf(name, name_len, "%s", uts.sysname);
    if(arch)
        snprintf(arch, arch_len, "%s", uts.machine);
    if(arch)
        snprintf(release, rel_len, "%s", uts.release);
    if(arch)
        snprintf(version, ver_len, "%s", uts.version);
    return 0;
}

int sxi_report_fs(sxc_client_t *sx, const char *path, int64_t *block_size, int64_t *total_blocks, int64_t *available_blocks) {
#ifndef HAVE_SYS_STATVFS_H
    if(!sx)
        return 1;

    sxi_seterr(sx, SXE_ECFG, "Filesystem information not available for this system");
    return 1;
#else
    struct statvfs fs_stat;

    if(!sx)
        return 1;

    if(!path) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return 1;
    }

    if(statvfs(path, &fs_stat)) {
        sxi_seterr(sx, SXE_ECFG, "Failed to get filesystem information");
        return 1;
    }

    *block_size = fs_stat.f_frsize;
    *total_blocks = fs_stat.f_blocks;
    *available_blocks = fs_stat.f_bavail;
    return 0;
#endif
}

int sxi_report_cpu(sxc_client_t *sx, int *ncpus, char *endianness, size_t endianness_len) {
    int cores;
    int num = 1;
#if defined(CTL_HW) && defined(HW_NCPU)
    int mib[2] = { CTL_HW, HW_NCPU };
    size_t len = sizeof(cores);
#endif

    if(!sx)
        return 1;

#if defined(_SC_NPROCESSORS_CONF)
    cores = sysconf(_SC_NPROCESSORS_CONF);
    if(cores < 0) {
        sxi_seterr(sx, SXE_ECFG, "Failed to get number of processors");
        return 1;
    }
#elif defined(CTL_HW) && defined(HW_NCPU)
    if(sysctl(mib, 2, &cores, &len, NULL, 0) < 0) {
        sxi_seterr(sx, SXE_ECFG, "Failed to get number of cores");
        return 1;
    }
#endif

    if(ncpus)
        *ncpus = cores;
    if(endianness)
        snprintf(endianness, endianness_len, "%s", *((uint8_t*)&num) == 1 ? "little-endian" : "big-endian");
    return 0;
}

int sxi_report_mem(sxc_client_t *sx, int64_t *total_mem) {
    int64_t total = 0, page_size = 0;
#if defined(CTL_HW) && defined(HW_MEMSIZE)
    int mib[2] = { CTL_HW, HW_MEMSIZE };
    size_t len = sizeof(total);
#endif

    if(!sx)
        return 1;

#if defined(_SC_PAGESIZE) && defined(_SC_PHYS_PAGES)
    page_size = sysconf(_SC_PAGESIZE);
    if(page_size < 0) {
        sxi_seterr(sx, SXE_ECFG, "Failed to get system memory page size");
        return 1;
    }

    total = sysconf(_SC_PHYS_PAGES);
    if(total < 0) {
        sxi_seterr(sx, SXE_ECFG, "Failed to get system memory total pages number");
        return 1;
    } 
    total *= page_size;
#elif defined(CTL_HW) && defined(HW_MEMSIZE)
    if(sysctl(mib, 2, &total, &len, NULL, 0) < 0) {
        sxi_seterr(sx, SXE_ECFG, "Failed to get page size");
        return 1;
    }
#endif

    if(total_mem)
        *total_mem = total;
    return 0;
}
