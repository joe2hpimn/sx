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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fastcgi.h>
#include <fcgiapp.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "fcgi-server.h"
#include "fcgi-utils.h"
#include "jobmgr.h"
#include "blockmgr.h"
#include "cfgfile.h"
#include "cmdline.h"
#include "init.h"
#include "gc.h"
#include "utils.h"

FCGX_Stream *fcgi_in, *fcgi_out, *fcgi_err;
FCGX_ParamArray envp;
sx_hashfs_t *hashfs;
int job_trigger, block_trigger, gc_trigger, gc_expire_trigger;
static pid_t ownpid;

#define MAX_CHILDREN 256
#define JOBMGR MAX_CHILDREN
#define BLKMGR MAX_CHILDREN+1
#define GCMGR MAX_CHILDREN+2

static int terminate = 0;
static pid_t pids[MAX_CHILDREN+3];

static void killall(int signum) {
    int i;
    for(i=0; i < sizeof(pids) / sizeof(*pids); i++)
	if(pids[i] > 0)
	    kill(pids[i], signum);
}
static void sighandler(int signum) {
    /* Dispatch signal to children in case user kills the main
       process instead of the whole process group */
    killall(signum);
    if (signum == SIGHUP || signum == SIGUSR1) {
        log_reopen();
        return;
    }
    terminate = 1;
}

static void child_sighandler(int signum)
{
    if (signum == SIGHUP || signum == SIGUSR1) {
        log_reopen();
        return;
    }
    FCGX_ShutdownPending();
    terminate = 1;
}

static int in_request;
static void fcgilog_log(void *ctx, const char *argv0, int prio, const char *msg)
{
    char buf[65536];
    if (!in_request) {
        server_logger.log(NULL, argv0, prio, msg);
        return;
        /* do not crash if fcgi is inside accept or already finished */
    }
    const char *meth = FCGX_GetParam("REQUEST_METHOD", envp);
    const char *uri = FCGX_GetParam("REQUEST_URI", envp);
    const char *remote_addr = FCGX_GetParam("REMOTE_ADDR",envp);
    const char *remote_port = FCGX_GetParam("REMOTE_PORT", envp);
    const char *server_addr = FCGX_GetParam("SERVER_ADDR",envp);
    const char *server_port = FCGX_GetParam("SERVER_PORT", envp);
    if (!meth) meth = "N/A";
    if (!uri) uri = "";
    if (!remote_addr) remote_addr = "N/A";
    if (!remote_port) remote_port = "";
    if (!server_addr) server_addr = "";
    if (!server_port) server_port = "";
    snprintf(buf, sizeof(buf), "%s:%s -> %s:%s %s %s| %s",
             remote_addr, remote_port,
             server_addr, server_port,
             meth, uri, msg);
    server_logger.log(NULL, argv0, prio, buf);
}

static sxc_logger_t fcgilog = {
    NULL, NULL, fcgilog_log
};

void OS_LibShutdown(void);
#include <sys/resource.h>
static int accept_loop(sxc_client_t *sx, const char *self, const char *dir) {
    struct sigaction act;
    int i, rc = EXIT_SUCCESS;
    FCGX_Request req;

    /* must use sigaction, because signal would set ERESTARTSYS
     * and we'd never break out of the accept loop */
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = child_sighandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGUSR2, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    signal(SIGPIPE, SIG_IGN);

    act.sa_flags = SA_RESTART;
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);

    hashfs = sx_hashfs_open(dir, sx);
    if(!hashfs) {
	CRIT("Failed to initialize the hash server interface");
        rc = EXIT_FAILURE;
	goto accept_loop_end;
    }
    sx_hashfs_set_triggers(hashfs, job_trigger, block_trigger, gc_trigger, gc_expire_trigger);

    ownpid = getpid();
    FCGX_Init();
    FCGX_InitRequest(&req, FCGI_LISTENSOCK_FILENO, FCGI_FAIL_ACCEPT_ON_INTR);
    for(i=0; !terminate && i < worker_max_requests; i++) {
	if(FCGX_Accept_r(&req) < 0) {
            if (errno != EINTR)
                break;
            continue;
        }
        fcgi_in = req.in;
        fcgi_out = req.out;
        fcgi_err = req.err;
        envp = req.envp;
        if (!fcgi_out || !fcgi_in || !fcgi_err || !envp) {
            CRIT("NULL fcgi streams/env");
            continue;
        }
        in_request = 1;
	send_server_info();
	handle_request();
        sx_hashfs_checkpoint_passive(hashfs);
        in_request = 0;
    }
    FCGX_Finish_r(&req);
    sx_hashfs_close(hashfs);

    if(i!=worker_max_requests)
	INFO("Accept loop exiting upon request");
    else
        INFO("Accept loop exiting after %u requests", worker_max_requests);

 accept_loop_end:
    OS_LibShutdown();
    close(job_trigger);
    close(block_trigger);
    close(gc_trigger);
    close(gc_expire_trigger);
    return rc;
}

void print_help(const char *prog)
{
    int i =0;
    const char *config_options[] = {
  "      socket=SOCKET        Set socket for connection with httpd",
  "      socket-mode=MODE     Set socket mode to MODE (octal number; unix\n                               sockets only)",
  "      data-dir=PATH        Path to data directory",
  "      logfile=FILE         Write all log information to FILE",
  "      pidfile=FILE         Write process ID to FILE",
  "      children=N           Start N children processes  (default=`32')",
  "      foreground           Do not daemonize  (default=off)",
  "      debug                Enable debug messages  (default=off)",
  "      run-as=user[:group]  Run as specified user[:group]",
  "      ssl_ca=STRING        Path to SSL CA certificate",
    0
    };

    printf("%s %s\n\n", CMDLINE_PARSER_PACKAGE, src_version());
    printf("SX FastCGI Server\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("  -h, --help		Print help and exit\n");
    printf("  -V, --version		Print version and exit\n");
    printf("  -D, --debug		Enable debug messages  (default=off)\n");
    printf("      --foreground      Do not daemonize  (default=off)\n");
    printf("\n");

    printf("This program reads all settings from the config file %s\n", DEFAULT_FCGI_CFGFILE);
    printf("Available config file options:\n\n");
    while(config_options[i])
	printf("%s\n", config_options[i++]);
    printf("\n");
}

int main(int argc, char **argv) {
    int i, s, pidfd =-1, sockmode = -1, trig[2], inner_job_trigger, inner_block_trigger, inner_gc_trigger, inner_gc_expire_trigger, alive;
    int debug, foreground, have_nodeid = 0;
    sx_uuid_t cluster_uuid, node_uuid;
    char *pidfile = NULL;
    sx_hashfs_t *test_hashfs;
    char buf[8192];
    mode_t mask;
    struct gengetopt_args_info args;
    struct cmdline_args_info cmdargs;
    struct cmdline_parser_params *params;
    struct rlimit rlim;
    time_t wait_start;
    pid_t dead;
    sxc_client_t *sx = NULL;

    if(cmdline_args(argc, argv, &cmdargs))
	return EXIT_FAILURE;

    if(cmdargs.version_given) {
	printf("%s %s\n", CMDLINE_PARSER_PACKAGE, src_version());
	cmdline_args_free(&cmdargs);
	return EXIT_SUCCESS;
    }

    if(cmdargs.help_given) {
	print_help(argv[0]);
	cmdline_args_free(&cmdargs);
	return EXIT_SUCCESS;
    }

    params = cmdline_parser_params_create();
    if(!params) {
	cmdline_args_free(&cmdargs);
	return EXIT_FAILURE;
    }
    params->initialize = 1;

    if(cmdline_parser_config_file(cmdargs.config_file_given ? cmdargs.config_file_arg : DEFAULT_FCGI_CFGFILE, &args, params)) {
	free(params);
	cmdline_args_free(&cmdargs);
	return EXIT_FAILURE;
    }
    free(params);

    debug = (cmdargs.debug_flag || args.debug_flag) ? 1 : 0;
    foreground = (cmdargs.foreground_flag || args.foreground_flag) ? 1 : 0;

    sx = sx_init(NULL, NULL, NULL, foreground, argc, argv);
    if (!sx) {
	cmdline_args_free(&cmdargs);
        return EXIT_FAILURE;
    }

    if(!cmdargs.config_file_given)
	INFO("Using default config file %s", DEFAULT_FCGI_CFGFILE);
    cmdline_args_free(&cmdargs);

    if(!getrlimit(RLIMIT_NOFILE, &rlim) && (rlim.rlim_cur < MAX_FDS || rlim.rlim_max < MAX_FDS)) {
	unsigned int l_soft = rlim.rlim_cur, l_hard = rlim.rlim_max;
	rlim.rlim_cur = rlim.rlim_max = MAX_FDS;
	if(setrlimit(RLIMIT_NOFILE, &rlim))
	    WARN("Can't increase the limit for maximum number of open files (current: %u/%u)", l_soft, l_hard);
    }

    if(args.run_as_given) {
        if (runas(args.run_as_arg) == -1) {
            cmdline_parser_free(&args);
            return EXIT_FAILURE;
        }
    }
    /* must init with logfile after we switched uid, otherwise children wouldn't be able
     * to open the logfile */
    sx_done(&sx);
    sx = sx_init(NULL, NULL, args.logfile_arg, foreground, argc, argv);
    if (!sx) {
        cmdline_parser_free(&args);
        sx_done(&sx);
	return EXIT_FAILURE;
    }

    memset(pids, 0, sizeof(pids));

    if(debug)
	log_setminlevel(sx,SX_LOG_DEBUG);

    if(!FCGX_IsCGI()) {
	CRIT("This program cannot be run as a fastcgi application; please refer to the documentation or --help for invocation instuctions.");
        cmdline_parser_free(&args);
        sx_done(&sx);
	return EXIT_FAILURE;
    }

    if(debug)
	log_setminlevel(sx,SX_LOG_DEBUG);

    /* the interactions between these values are complex,
     * no validation: responsibility of the admin when tweaking hidden vars */
    gc_interval = args.gc_interval_arg;
    gc_max_batch = args.gc_max_batch_arg;
    blockmgr_delay = args.blockmgr_delay_arg;
    db_min_passive_wal_pages = args.db_min_passive_wal_pages_arg;
    db_max_passive_wal_pages = args.db_max_passive_wal_pages_arg;
    db_max_restart_wal_pages = args.db_max_wal_restart_pages_arg;
    db_idle_restart = args.db_idle_restart_arg;
    db_busy_timeout = args.db_busy_timeout_arg;
    worker_max_wait = args.worker_max_wait_arg;
    worker_max_requests = args.worker_max_requests_arg;

    if(args.children_arg <= 0 || args.children_arg > MAX_CHILDREN) {
	CRIT("Invalid number of children");
        cmdline_parser_free(&args);
        sx_done(&sx);
	return EXIT_FAILURE;
    }

    if(args.pidfile_given)
	pidfile = args.pidfile_arg;

    if(args.socket_mode_given) {
	sockmode = args.socket_mode_arg;
	if(sockmode<=0) {
	    CRIT("Invalid socket mode");
            cmdline_parser_free(&args);
            sx_done(&sx);
            return EXIT_FAILURE;
	}
    }

    /* Create trigger pipe */
    if(pipe(trig)) {
	PCRIT("Cannot create communication pipe");
        cmdline_parser_free(&args);
        sx_done(&sx);
	return EXIT_FAILURE;
    }
    job_trigger = trig[1];
    inner_job_trigger = trig[0];

    if(pipe(trig)) {
	PCRIT("Cannot create communication pipe");
        cmdline_parser_free(&args);
        sx_done(&sx);
	return EXIT_FAILURE;
    }
    block_trigger = trig[1];
    inner_block_trigger = trig[0];

    if(pipe(trig)) {
	PCRIT("Cannot create communication pipe");
        cmdline_parser_free(&args);
        sx_done(&sx);
	return EXIT_FAILURE;
    }
    gc_trigger = trig[1];
    inner_gc_trigger = trig[0];
    if(pipe(trig)) {
	PCRIT("Cannot create communication pipe");
        cmdline_parser_free(&args);
        sx_done(&sx);
	return EXIT_FAILURE;
    }
    gc_expire_trigger = trig[1];
    inner_gc_expire_trigger = trig[0];
    /* Create the pidfile before detaching from terminal */
#define MAX_PID_ATTEMPTS 10
    if(pidfile) {
	if(*pidfile == '/')
	    pidfile = strdup(pidfile);
	else {
	    const char *pfile = pidfile;
	    if(!getcwd(buf, sizeof(buf))) {
		PCRIT("Cannot get the current work directory");
                cmdline_parser_free(&args);
                sx_done(&sx);
		return EXIT_FAILURE;
	    }
	    pidfile = malloc(strlen(buf) + 1 + strlen(pfile) + 1);
	    if(pidfile)
		sprintf(pidfile, "%s/%s", buf, pfile);
	}
	if(!pidfile) {
	    PCRIT("Failed to allocate pidfile");
            cmdline_parser_free(&args);
            sx_done(&sx);
	    return EXIT_FAILURE;
	}
	for(i=0;i<MAX_PID_ATTEMPTS;i++) {
	    char *eopid;
	    int pidsz;

	    pidfd = open(pidfile, O_CREAT | O_WRONLY | O_EXCL, 0644);
	    if(pidfd >= 0)
		break;
	    if(errno != EEXIST) {
		PCRIT("Failed to create pidfile %s", pidfile);
                cmdline_parser_free(&args);
                free(pidfile);
                sx_done(&sx);
		return EXIT_FAILURE;
	    }

	    pidfd = open(pidfile, O_RDONLY);
	    if(pidfd < 0) {
		if(errno == ENOENT)
		    continue;
		PCRIT("Failed to open existing pidfile %s", pidfile);
                cmdline_parser_free(&args);
                free(pidfile);
                sx_done(&sx);
		return EXIT_FAILURE;
	    }

	    pidsz = read(pidfd, buf, sizeof(buf)-1);
	    close(pidfd);
	    if(pidsz < 0) {
		PCRIT("Failed to read pid from existing pidfile %s", pidfile);
                cmdline_parser_free(&args);
                free(pidfile);
                sx_done(&sx);
		return EXIT_FAILURE;
	    }

	    if(pidsz) {
		/* Filled-in pidfile */
		buf[pidsz] = 0;
		pidsz = strtol(buf, &eopid, 10);
		if(*eopid != '\0' && *eopid != '\n') {
		    CRIT("Failed to read pid from existing pidfile %s", pidfile);
                    cmdline_parser_free(&args);
                    free(pidfile);
                    sx_done(&sx);
		    return EXIT_FAILURE;
		}

		if(kill(pidsz, 0) == -1) {
		    if(errno == ESRCH) {
			if(unlink(pidfile)) {
			    PCRIT("Failed to remove stale pidfile %s", pidfile);
                            cmdline_parser_free(&args);
                            free(pidfile);
                            sx_done(&sx);
			    return EXIT_FAILURE;
			}
			INFO("Removed stale pidfile %s", pidfile);
			continue;
		    }
		    if(errno != EPERM) {
			PCRIT("Cannot determine if pid %d is alive", pidsz);
                        cmdline_parser_free(&args);
                        free(pidfile);
                        sx_done(&sx);
			return EXIT_FAILURE;
		    }
		}

		CRIT("Pid %d is still alive", pidsz);
                cmdline_parser_free(&args);
                free(pidfile);
                sx_done(&sx);
		return EXIT_FAILURE;
	    }

	    /* Empty pidfile */
	    if(unlink(pidfile)) {
		PCRIT("Failed to remove empty pidfile %s", pidfile);
                cmdline_parser_free(&args);
                free(pidfile);
                sx_done(&sx);
		return EXIT_FAILURE;
	    }
	    INFO("Removed empty pidfile %s", pidfile);
	}

	if(i==MAX_PID_ATTEMPTS) {
	    CRIT("Cannot create pidfile after "STRIFY(MAX_PID_ATTEMPTS)" tries");
            cmdline_parser_free(&args);
            free(pidfile);
            sx_done(&sx);
	    return EXIT_FAILURE;
	}
    }
    /* Create the fcgi socket and set permissions */
    if(sockmode >= 0)
	mask = umask(0);

    INFO("Opening socket '%s'. If you see nothing past this line, it means that the socket could not be opened. Please double check it.", args.socket_arg);
    s = FCGX_OpenSocket(args.socket_arg, 1024);
    if(s<0) {
	CRIT("Failed to open socket '%s'", args.socket_arg);
        cmdline_parser_free(&args);
        sx_done(&sx);
	return EXIT_FAILURE;
    }
    INFO("Socket '%s' opened successfully", args.socket_arg);

    if(sockmode >= 0) {
	struct sockaddr_un sa;
	int salen = sizeof(sa);
	umask(mask);
	if(getsockname(s, (struct sockaddr *)&sa, &salen)) {
	    PCRIT("failed to determine socket domain");
            cmdline_parser_free(&args);
            sx_done(&sx);
	    return EXIT_FAILURE;
	}
	if(sa.sun_family == AF_UNIX) {
	    if(salen > sizeof(sa)) {
		CRIT("Cannot locate socket: path too long");
                cmdline_parser_free(&args);
                sx_done(&sx);
		return EXIT_FAILURE;
	    }
	    if(chmod(sa.sun_path, sockmode)) {
		PCRIT("Cannot set permissions on socket %s", sa.sun_path);
                cmdline_parser_free(&args);
                sx_done(&sx);
		return EXIT_FAILURE;
	    }
	} else
	    WARN("Ignoring socket permissions on non-unix socket");
    }

    if(s != FCGI_LISTENSOCK_FILENO) {
	if(dup2(s, FCGI_LISTENSOCK_FILENO)<0) {
	    PCRIT("Failed to rename socket descriptor %d to %d", s, FCGI_LISTENSOCK_FILENO);
            cmdline_parser_free(&args);
            sx_done(&sx);
	    return EXIT_FAILURE;
	}
	close(s);
    }

    /* Just attempt to open the hashfs so we can alert about basic mistakes
     * earlier and while we are still attached to the terminal */
    test_hashfs = sx_hashfs_open(args.data_dir_arg, sx);
    if(test_hashfs) {
	const sx_uuid_t *id = sx_hashfs_uuid(test_hashfs);
	memcpy(&cluster_uuid, id, sizeof(*id));
	have_nodeid = sx_hashfs_self_uuid(test_hashfs, &node_uuid) == OK;
	sx_hashfs_close(test_hashfs);
    } else {
	CRIT("Failed to initialize the storage interface");
	fprintf(stderr, "Failed to initialize the storage interface - check the logfile %s\n", args.logfile_arg);
        cmdline_parser_free(&args);
        sx_done(&sx);
	return EXIT_FAILURE;
    }

    /* Detach from terminal if required to do so */
    if(!foreground) {
	int fd;
	if(chdir("/")) {
	    PCRIT("Failed to change to root directory");
            cmdline_parser_free(&args);
            free(pidfile);
            sx_done(&sx);
	    return EXIT_FAILURE;
	}
#if STDIN_FILENO != FCGI_LISTENSOCK_FILENO
	if((fd = open("/dev/null", O_RDONLY))<0 || dup2(fd, STDIN_FILENO)<0) {
	    PCRIT("Failed to redirect standard input to null");
            cmdline_parser_free(&args);
            free(pidfile);
            sx_done(&sx);
	    return EXIT_FAILURE;
	}
        close(fd);
#endif
#if STDOUT_FILENO != FCGI_LISTENSOCK_FILENO
	if((fd = open("/dev/null", O_WRONLY))<0 || dup2(fd, STDOUT_FILENO)<0) {
	    PCRIT("Failed to redirect standard output to null");
            cmdline_parser_free(&args);
            free(pidfile);
            sx_done(&sx);
	    return EXIT_FAILURE;
	}
        close(fd);
#endif
#if STDERR_FILENO != FCGI_LISTENSOCK_FILENO
	if((fd = open("/dev/null", O_WRONLY))<0 || dup2(fd, STDERR_FILENO)<0) {
	    PCRIT("Failed to redirect standard error to null");
            cmdline_parser_free(&args);
            free(pidfile);
            sx_done(&sx);
	    return EXIT_FAILURE;
	}
        close(fd);
#endif
	switch(fork()) {
	case 0:
	    break;
	case -1:
	    PCRIT("Cannot fork into background");
            cmdline_parser_free(&args);
            free(pidfile);
            sx_done(&sx);
	    return EXIT_FAILURE;
	default:
	    INFO("Successfully daemonized");
            cmdline_parser_free(&args);
            free(pidfile);
            OS_LibShutdown();
            sx_done(&sx);
	    return EXIT_SUCCESS;
	}

	setsid();
    }

    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sighandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGUSR2, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    signal(SIGPIPE, SIG_IGN);

    act.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGHUP, &act, NULL);

    /* Write pid to pidfile */
    if(pidfile) {
	snprintf(buf, sizeof(buf), "%d", getpid());
	i = strlen(buf);
	if(write(pidfd, buf, i) != i) {
	    PCRIT("Failed to write pid to pidfile %s", pidfile);
            cmdline_parser_free(&args);
            free(pidfile);
            sx_done(&sx);
	    return EXIT_FAILURE;
	}
	close(pidfd);
    }

    /* Spawn the job manager */
    pids[JOBMGR] = fork();
    if(pids[JOBMGR] < 0) {
	PCRIT("Cannot spawn the job manager");
        cmdline_parser_free(&args);
        free(pidfile);
        sx_done(&sx);
	return EXIT_FAILURE;
    } else if(!pids[JOBMGR]) {
        int ret;
        sx_done(&sx);
        sx = sx_init(NULL, "job manager", args.logfile_arg, foreground, argc, argv);
        if (sx) {
            if(debug)
                log_setminlevel(sx,SX_LOG_DEBUG);
            ret = jobmgr(sx, argv[0], args.data_dir_arg, inner_job_trigger);
        } else {
            ret = 1;
        }
        cmdline_parser_free(&args);
        free(pidfile);
        sx_done(&sx);
        OS_LibShutdown();
        return ret;
    }
    close(inner_job_trigger);

    /* Spawn the block manager */
    pids[BLKMGR] = fork();
    if(pids[BLKMGR] < 0) {
	PCRIT("Cannot spawn the block manager");
        cmdline_parser_free(&args);
        free(pidfile);
	kill(pids[JOBMGR], SIGTERM);
        sx_done(&sx);
	return EXIT_FAILURE;
    } else if(!pids[BLKMGR]) {
        int ret;
        sx_done(&sx);
        sx = sx_init(NULL, "block manager", args.logfile_arg, foreground, argc, argv);
        if (sx) {
            if(debug)
                log_setminlevel(sx,SX_LOG_DEBUG);
            ret = blockmgr(sx, argv[0], args.data_dir_arg, inner_block_trigger);
        } else {
            ret = 1;
        }
        cmdline_parser_free(&args);
        free(pidfile);
	close(job_trigger);
	close(block_trigger);
        close(gc_trigger);
        close(gc_expire_trigger);
        OS_LibShutdown();
        sx_done(&sx);
        return ret;
    }
    close(inner_block_trigger);

    /* Spawn the garbage collector */
    pids[GCMGR] = fork();
    if(pids[GCMGR] < 0) {
	PCRIT("Cannot spawn the garbage collector");
        cmdline_parser_free(&args);
        free(pidfile);
	kill(pids[JOBMGR], SIGTERM);
	kill(pids[BLKMGR], SIGTERM);
        sx_done(&sx);
	return EXIT_FAILURE;
    } else if(!pids[GCMGR]) {
        int ret;
        sx_done(&sx);
        sx = sx_init(NULL, "garbage collector", args.logfile_arg, foreground, argc, argv);
        if (sx) {
            if(debug)
                log_setminlevel(sx,SX_LOG_DEBUG);
            ret = gc(sx, argv[0], args.data_dir_arg, inner_gc_trigger, inner_gc_expire_trigger);
        } else {
            ret = 1;
        }
        cmdline_parser_free(&args);
        free(pidfile);
	close(job_trigger);
	close(block_trigger);
        close(gc_trigger);
        close(gc_expire_trigger);
        OS_LibShutdown();
        sx_done(&sx);
        return ret;
    }
    close(inner_block_trigger);

    if(have_nodeid)
	INFO("Node %s in cluster %s starting up", node_uuid.string, cluster_uuid.string);
    else
	INFO("Bare node in cluster %s starting up", cluster_uuid.string);

    /* Spawn workers and monitor them */
    while(!terminate) {
	int status;

	/* Prefork/respawn all the (missing) children */
	for(i=0; !terminate && i<args.children_arg; i++) {
	    if(pids[i]<=0) {
		pids[i] = fork();
		switch(pids[i]) {
		case -1:
		    PCRIT("Failed to fork");
		    terminate = -1;
		    break;
		case 0:
                    sx_done(&sx);
                    sx = sx_init(&fcgilog, "fastcgi worker", args.logfile_arg, foreground, argc, argv);
                    if (sx) {
                        if(debug)
                            log_setminlevel(sx,SX_LOG_DEBUG);
                        status = accept_loop(sx, argv[0], args.data_dir_arg);
                    } else {
                        status = 1;
                    }
		    cmdline_parser_free(&args);
		    free(pidfile);
		    OS_LibShutdown();
                    sx_done(&sx);
		    return status;
		}
		DEBUG("Spawned new worker: pid %d", pids[i]);
	    }
	}

	if(terminate)
	    break;

	DEBUG("All %d children active, waiting...", args.children_arg);
        do {
            dead = wait(&status);
        } while(dead == -1 && errno == EINTR);

	if(dead<0) { /* wait failed */
	    PCRIT("Failed to wait for children");
	    terminate = -1;
	    break;
	}

	if(dead == pids[JOBMGR] || dead == pids[BLKMGR] || dead == pids[GCMGR]) {
	    /* Critical child died */
	    if(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
                if (!terminate)
                    WARN("Critical child exited (PID %d)", dead);
		terminate = 1;
            }
	    else {
		const char *deadproc;
		if(dead == pids[JOBMGR])
		    deadproc = "Job manager";
		else if(dead == pids[BLKMGR])
		    deadproc = "Block manager";
		else
		    deadproc = "Garbage collector";
		if(WIFSIGNALED(status))
		    CRIT("%s was killed with %d",  deadproc, WTERMSIG(status));
		else
		    CRIT("%s terminated abnormally : %d", deadproc, WEXITSTATUS(status));
		terminate = -1;
	    }
	} else if(WIFEXITED(status) && WEXITSTATUS(status)) {
	    /* Worker died abnormally - FIXME is this even possible? or harmful? */
	    CRIT("Worker process %d terminated abnormally : %d", dead, WEXITSTATUS(status));
	    terminate = -1;
	} else if(WIFSIGNALED(status)) {
	    /* Worker was killed */
	    WARN("Worker process %d killed with %d", dead, WTERMSIG(status));
	} else {
	    /* Worker reached natural end of life */
	    DEBUG("Worker process %d exited", dead);
	}

	for(i=0; i<sizeof(pids) / sizeof(*pids); i++) {
	    if(pids[i]==dead) {
		pids[i] = 0;
		break;
	    }
	}
    }

    killall(SIGTERM); /* ask all children to quit */
    INFO("Waiting up to %d seconds for all children to quit...", worker_max_wait);
    alive = 1;
    wait_start = time(NULL);
    while(alive) {
	if(wait_start + worker_max_wait <= time(NULL))
	    break;

	dead = waitpid(-1, NULL, WNOHANG);
	if(dead < 0) {
	    if(errno == EINTR)
		continue;
	    break;
	}

	if(dead == 0) {
	    sleep(1);
	    continue;
	}

	alive = 0;
	for(i=0; i<sizeof(pids) / sizeof(*pids); i++) {
	    if(pids[i]==dead)
		pids[i] = 0;
	    else if(pids[i] > 0)
		alive++;
	}
	DEBUG("Waiting for %d children", alive);
    }

    if(alive) {
	CRIT("Forcibly terminating the remaining children");
	killall(SIGKILL); /* forcibly kill all children */
    } else
	INFO("All children have exited");

    if(pidfile) {
	unlink(pidfile);
	free(pidfile);
    }

    OS_LibShutdown();
    close(job_trigger);
    close(block_trigger);
    close(gc_trigger);
    close(gc_expire_trigger);
    cmdline_parser_free(&args);
    sx_done(&sx);

    return terminate == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
}
