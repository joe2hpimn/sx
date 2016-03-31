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
#include "hbeat.h"
#include "utils.h"

FCGX_Stream *fcgi_in, *fcgi_out, *fcgi_err;
FCGX_ParamArray envp;
sx_hashfs_t *hashfs;

static pid_t ownpid;

#define MAX_CHILDREN 256
#define JOBMGR MAX_CHILDREN
#define BLKMGR MAX_CHILDREN+1
#define GCMGR MAX_CHILDREN+2
#define HBEATMGR MAX_CHILDREN+3

static const char *mgr_names[] = {
    "job manager",
    "block manager",
    "garbage collector",
    "heartbeat manager",
};

static int terminate = 0;
static pid_t pids[MAX_CHILDREN+4];

enum trig_t {
    TRIG_JOB = 0,
    TRIG_BLOCK,
    TRIG_GC,
    TRIG_EGC,
    TRIG_HBEAT,

    TRIG_MAX
};
static int pipes[TRIG_MAX * 2];

static void trig_init() {
    unsigned int i;
    for(i=0; i<TRIG_MAX * 2; i++)
	pipes[i] = -1;
}


static void trig_destroy_common(int sel) {
    unsigned int i;
    for(i=0; i<TRIG_MAX; i++) {
	if(pipes[i*2+sel] < 0)
	    continue;
	close(pipes[i*2+sel]);
	pipes[i*2+sel] = -1;
    }
}

static void trig_destroy_workers(void) {
    trig_destroy_common(1);
}
static void trig_destroy_managers(void) {
    trig_destroy_common(0);
}
static void trig_destroy_all(void) {
    trig_destroy_workers();
    trig_destroy_managers();
}

static int trig_create(void) {
    unsigned int i;
    for(i=0; i<TRIG_MAX; i++) {
	int *trig = &pipes[i * 2];
	if(pipe(trig)) {
	    PCRIT("Cannot create communication pipe");
	    trig_destroy_all();
	    return -1;
	}
    }

    return 0;
}

static int trig_worker(enum trig_t which) {
    return pipes[which * 2 + 1];
}
static int trig_manager(enum trig_t which) {
    return pipes[which * 2];
}

static int get_procnum(pid_t pid) {
    unsigned int i;
    for(i=0; i < sizeof(pids) / sizeof(*pids); i++)
	if(pids[i] == pid)
	    return i;
    return -1;
}
static int is_manager(int procnum) {
    return (procnum >= MAX_CHILDREN && procnum < sizeof(pids) / sizeof(*pids));
}
static const char *process_name(int procnum) {
    if(procnum < MAX_CHILDREN || procnum >= sizeof(pids) / sizeof(*pids))
	return "worker";
    return mgr_names[procnum - MAX_CHILDREN];
}

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
    NULL, NULL, fcgilog_log, NULL
};

void OS_LibShutdown(void);
#include <sys/resource.h>
static int accept_loop(sxc_client_t *sx, const char *dir, int socket, worker_type_t wtype) {
    struct sigaction act;
    int i, rc = EXIT_SUCCESS;
    FCGX_Request req;

    if(socket != FCGI_LISTENSOCK_FILENO) {
	if(dup2(socket, FCGI_LISTENSOCK_FILENO)<0) {
	    PCRIT("Failed to rename socket descriptor %d to %d", socket, FCGI_LISTENSOCK_FILENO);
	    return EXIT_FAILURE;
	}
	close(socket);
    }

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
    sx_hashfs_set_triggers(hashfs, trig_worker(TRIG_JOB), trig_worker(TRIG_BLOCK), trig_worker(TRIG_GC), trig_worker(TRIG_EGC), trig_worker(TRIG_HBEAT));

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
	handle_request(wtype);
        in_request = 0;
    }
    FCGX_Finish_r(&req);
    sx_hashfs_close(hashfs);

    if(i!=worker_max_requests)
	INFO("Accept loop exiting upon request");
    else
        INFO("Accept loop exiting after %u requests", worker_max_requests);

 accept_loop_end:
    return rc;
}

void print_help(const char *prog)
{
    int i =0;
    const char *config_options[] = {
  "      socket=SOCKET          Set socket for connection with httpd",
  "      children=N             Start N children processes (default=`24')",
  "      reserved-socket=SOCKET Set httpd socket reserved for internode\n                             communication (default=none)",
  "      reserved-children=N    Start N children processes reserved for\n                             internode communication (only applicable\n                             if reserved-socket is set; default=`8')",
  "      socket-mode=MODE       Set mode of httpd socket(s) to MODE (octal\n                             number; applies to unix sockets only)",
  "      data-dir=PATH          Path to data directory",
  "      logfile=FILE           Write all log information to FILE",
  "      pidfile=FILE           Write process ID to FILE",
  "      foreground             Do not daemonize  (default=off)",
  "      debug                  Enable debug messages  (default=off)",
  "      run-as=user[:group]    Run as specified user[:group]",
  "      ssl_ca=PATH            Path to SSL CA certificate",
    0
    };

    printf("%s %s\n\n", CMDLINE_PARSER_PACKAGE, src_version());
    printf("SX FastCGI Server\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("  -h, --help                 Print help and exit\n");
    printf("  -V, --version              Print version and exit\n");
    printf("\n");

    printf("This program reads all settings from the config file %s\n", DEFAULT_FCGI_CFGFILE);
    printf("Available config file options:\n\n");
    while(config_options[i])
	printf("%s\n", config_options[i++]);
    printf("\n");
}



#define MAX_PID_ATTEMPTS 10
char *make_pidfile(const char *pidfile_arg, int *pidfd) {
    char buf[8192];
    char *pidfile = NULL;
    unsigned int i;

    *pidfd = -1;

    /* Make absolute */
    if(*pidfile_arg == '/')
	pidfile = strdup(pidfile_arg);
    else {
	if(!getcwd(buf, sizeof(buf))) {
	    PCRIT("Cannot get the current work directory");
	    goto pidfile_err;
	}
	pidfile = malloc(strlen(buf) + 1 + strlen(pidfile_arg) + 1);
	if(pidfile)
	    sprintf(pidfile, "%s/%s", buf, pidfile_arg);
    }
    if(!pidfile) {
	PCRIT("Failed to allocate pidfile");
	goto pidfile_err;
    }

    /* Try to read pid from pidfile */
    for(i=0;i<MAX_PID_ATTEMPTS;i++) {
	char *eopid;
	int pidsz, readfd;

	*pidfd = open(pidfile, O_CREAT | O_WRONLY | O_EXCL, 0644);
	if(*pidfd >= 0)
	    break; /* New pidfile created */
	if(errno != EEXIST) {
	    PCRIT("Failed to create pidfile %s", pidfile);
	    goto pidfile_err;
	}

	/* Pidfile exists */
	readfd = open(pidfile, O_RDONLY);
	if(readfd < 0) {
	    if(errno == ENOENT)
		continue;
	    PCRIT("Failed to open existing pidfile %s", pidfile);
	    goto pidfile_err;
	}

	/* Get pid */
	pidsz = read(readfd, buf, sizeof(buf)-1);
	close(readfd);
	if(pidsz < 0) {
	    PCRIT("Failed to read pid from existing pidfile %s", pidfile);
	    goto pidfile_err;
	}
	
	if(pidsz) {
	    /* Check if still alive */
	    buf[pidsz] = 0;
	    pidsz = strtol(buf, &eopid, 10);
	    if(*eopid != '\0' && *eopid != '\n') {
		CRIT("Failed to read pid from existing pidfile %s", pidfile);
		goto pidfile_err;
	    }

	    if(kill(pidsz, 0) == -1) {
		if(errno == ESRCH) {
		    /* Process is dead: unlink and try again */
		    if(unlink(pidfile)) {
			PCRIT("Failed to remove stale pidfile %s", pidfile);
			goto pidfile_err;
		    }
		    INFO("Removed stale pidfile %s", pidfile);
		    continue;
		}
		if(errno != EPERM) {
		    PCRIT("Cannot determine if pid %d is alive", pidsz);
		    goto pidfile_err;
		}
	    }

	    CRIT("Pid %d is still alive", pidsz);
	    goto pidfile_err;
	}

	/* Pidfile is empty: unlink and try again */
	if(unlink(pidfile)) {
	    PCRIT("Failed to remove empty pidfile %s", pidfile);
	    goto pidfile_err;
	}
	INFO("Removed empty pidfile %s", pidfile);
    }

    if(i==MAX_PID_ATTEMPTS)
	CRIT("Cannot create pidfile after "STRIFY(MAX_PID_ATTEMPTS)" tries");

 pidfile_err:
    if(*pidfd < 0) {
	free(pidfile);
	pidfile = NULL;
    }
    
    return pidfile;
}


static int sxreinit(sxc_client_t **sx, const char *procdesc, sxc_logger_t *logr, const char *logfile, int foreground, int debug, int argc, char **argv) {
    if(*sx)
	sx_done(sx);

    *sx = sx_init(logr, procdesc, logfile, foreground, argc, argv);
    if(!*sx)
	return -1;

    if(debug)
	log_setminlevel(*sx,SX_LOG_DEBUG);

    if(sxi_set_query_prefix(*sx, ".s2s/")) {
	WARN("Failed to set SX query prefix");
    }

    return 0;
}

static int open_socket(const char *path, int mode) {
    mode_t mask;
    int s;

    if(mode >= 0)
	mask = umask(0);

    INFO("Opening socket '%s'. If you see nothing past this line, it means that the socket could not be opened. Please double check it.", path);
    s = FCGX_OpenSocket(path, 1024);
    if(s<0) {
	CRIT("Failed to open socket '%s'", path);
	return -1;
    }
    INFO("Socket '%s' opened successfully", path);

    if(mode >= 0) {
	struct sockaddr_un sa;
	int salen = sizeof(sa);
	umask(mask);
	if(getsockname(s, (struct sockaddr *)&sa, &salen)) {
	    PCRIT("failed to determine socket domain");
	    return -1;
	}
	if(sa.sun_family == AF_UNIX) {
	    if(salen > sizeof(sa)) {
		CRIT("Cannot locate socket: path too long");
		return -1;
	    }
	    if(chmod(sa.sun_path, mode)) {
		PCRIT("Cannot set permissions on socket %s", sa.sun_path);
		return -1;
	    }
	} else
	    WARN("Ignoring socket permissions on non-unix socket");
    }
    return s;
}

#define NOPIDFILE() do { free(pidfile); pidfile = NULL; } while(0)

#define SPAWNMGR(pid, child)						\
    do {								\
	const char *name = process_name(pid);				\
	pids[pid] = fork();						\
	if(pids[pid] <= 0) {						\
	    if(pids[pid] == 0) {					\
		trig_destroy_workers();					\
		NOPIDFILE();						\
		if(!sxreinit(&sx, name, NULL, args.logfile_arg, foreground, debug, argc, argv)) \
		    ret = child;					\
		else							\
		    ret = EXIT_FAILURE;					\
	    } else							\
		PCRIT("Cannot spawn the %s process", name);		\
	    killall(SIGTERM);						\
	    goto getout;						\
	}								\
    } while(0)


int main(int argc, char **argv) {
    int i, s, rs = -1, pidfd =-1, sockmode = -1, alive, all_children;
    int debug, foreground, have_nodeid = 0;
    sx_uuid_t cluster_uuid, node_uuid;
    char *pidfile = NULL;
    sx_hashfs_t *test_hashfs;
    char buf[8192];
    struct gengetopt_args_info args;
    struct cmdline_args_info cmdargs;
    struct cmdline_parser_params *params;
    struct rlimit rlim;
    time_t wait_start;
    pid_t dead;
    sxc_client_t *sx = NULL;
    int ret = EXIT_FAILURE;

    memset(pids, 0, sizeof(pids));
    trig_init();

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

    if(sxreinit(&sx, NULL, NULL, NULL, foreground, debug, argc, argv)) {
	cmdline_args_free(&cmdargs);
        goto getout;
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

    if(args.run_as_given && runas(args.run_as_arg) == -1)
        goto getout;

    /* must init with logfile after we switched uid, otherwise children wouldn't be able
     * to open the logfile */
    if(sxreinit(&sx, NULL, NULL, args.logfile_arg, foreground, debug, argc, argv))
	goto getout;

    if(!FCGX_IsCGI()) {
	CRIT("This program cannot be run as a fastcgi application; please refer to the documentation or --help for invocation instuctions.");
        goto getout;
    }

    /* the interactions between these values are complex,
     * no validation: responsibility of the admin when tweaking hidden vars */
    gc_interval = args.gc_interval_arg;
    gc_max_batch_time = args.gc_max_batch_time_arg;
    gc_yield_time = args.gc_yield_time_arg;
    gc_slow_check = !args.gc_no_slow_check_flag;
    blockmgr_delay = args.blockmgr_delay_arg;
    db_min_passive_wal_pages = args.db_min_passive_wal_pages_arg;
    db_max_passive_wal_pages = args.db_max_passive_wal_pages_arg;
    db_max_restart_wal_pages = args.db_max_wal_restart_pages_arg;
    db_max_mmapsize = args.db_max_mmapsize_arg;
    db_custom_vfs = !args.db_no_custom_vfs_flag;
    db_idle_restart = args.db_idle_restart_arg;
    db_busy_timeout = args.db_busy_timeout_arg;
    worker_max_wait = args.worker_max_wait_arg;
    worker_max_requests = args.worker_max_requests_arg;
    verbose_rebalance = args.verbose_rebalance_flag;
    verbose_gc = args.verbose_gc_flag;

    if(args.max_pending_user_jobs_arg <= 0) {
	CRIT("Invalid job limit value");
        goto getout;
    }
    max_pending_user_jobs = args.max_pending_user_jobs_arg;

    if(args.children_arg <= 0 || args.children_arg > MAX_CHILDREN) {
	CRIT("Invalid number of children");
        goto getout;
    }
    all_children = args.children_arg;
    if(args.reserved_socket_given) {
	all_children += args.reserved_children_arg;
	if(args.reserved_children_arg <= 0 || all_children > MAX_CHILDREN) {
	    CRIT("Invalid number of children");
	    goto getout;
	}
    }

    /* Create triggers */
    if(trig_create())
	goto getout;

    /* Create the pidfile before detaching from terminal */
    if(args.pidfile_given) {
	pidfile = make_pidfile(args.pidfile_arg, &pidfd);
	if(!pidfile)
	    goto getout;
    }

    /* Create the fcgi socket and set permissions */
    if(args.socket_mode_given) {
	sockmode = args.socket_mode_arg;
	if(sockmode<=0) {
	    CRIT("Invalid socket mode");
	    goto getout;
	}
    }

    s = open_socket(args.socket_arg, sockmode);
    if(s < 0)
	goto getout;
    if(args.reserved_socket_given) {
	if(!strcmp(args.socket_arg, args.reserved_socket_arg)) {
	    /* Catch some silly mistake */
	    CRIT("Path to socket and reserved-socket must be different. Please check your configuration.");
	    goto getout;
	}
	rs = open_socket(args.reserved_socket_arg, sockmode);
	if(rs < 0)
	    goto getout;
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
        const char *msg = msg_get_reason();
        if (msg && *msg) {
            fprintf(stderr, "%s\n", msg);
            if (strstr(msg, "Version mismatch")) {
                fprintf(stderr,"\nYou should upgrade the node by running:\n\tsxsetup --upgrade\n\n");
            }
        } else {
            fprintf(stderr, "Failed to initialize the storage interface - check the logfile %s\n", args.logfile_arg);
        }
	goto getout;
    }

    /* Detach from terminal if required to do so */
    if(!foreground) {
	int fd;
	if(chdir("/")) {
	    PCRIT("Failed to change to root directory");
	    goto getout;
	}
	if(s != STDIN_FILENO && rs != STDIN_FILENO) {
	    if((fd = open("/dev/null", O_RDONLY))<0 || dup2(fd, STDIN_FILENO)<0) {
		PCRIT("Failed to redirect standard input to null");
		goto getout;
	    }
	    close(fd);
	}
	if(s != STDOUT_FILENO && rs != STDOUT_FILENO) {
	    if((fd = open("/dev/null", O_WRONLY))<0 || dup2(fd, STDOUT_FILENO)<0) {
		PCRIT("Failed to redirect standard output to null");
		goto getout;
	    }
	    close(fd);
	}
	if(s != STDERR_FILENO && rs != STDERR_FILENO) {
	    if((fd = open("/dev/null", O_WRONLY))<0 || dup2(fd, STDERR_FILENO)<0) {
		PCRIT("Failed to redirect standard error to null");
		goto getout;
	    }
	    close(fd);
	}
	switch(fork()) {
	case 0:
	    break;
	case -1:
	    PCRIT("Cannot fork into background");
	    goto getout;
	default:
	    INFO("Successfully daemonized");
	    NOPIDFILE();
	    ret = EXIT_SUCCESS;
	    goto getout;
	}

	setsid();
    }

    /* Install signal handlers */
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
	    goto getout;
	}
	close(pidfd);
	pidfd = -1;
    }

    /* Spawn the job manager */
    SPAWNMGR(JOBMGR, jobmgr(sx, args.data_dir_arg, trig_manager(TRIG_JOB)));

    /* Spawn the block manager */
    SPAWNMGR(BLKMGR, blockmgr(sx, args.data_dir_arg, trig_manager(TRIG_BLOCK)));

    /* Spawn the garbage collector */
    SPAWNMGR(GCMGR, gc(sx, args.data_dir_arg, trig_manager(TRIG_GC), trig_manager(TRIG_EGC)));

    /* Spawn the heartbeat manager */
    SPAWNMGR(HBEATMGR, hbeatmgr(sx, args.data_dir_arg, trig_manager(TRIG_HBEAT)));

    trig_destroy_managers();

    if(have_nodeid)
	INFO("Node %s in cluster %s starting up", node_uuid.string, cluster_uuid.string);
    else
	INFO("Bare node in cluster %s starting up", cluster_uuid.string);

    /* Spawn workers and monitor them */
    while(!terminate) {
	const char *deadname;
	int status, procnum;

	/* Prefork/respawn all the (missing) children */
	for(i=0; !terminate && i<all_children; i++) {
	    if(pids[i]<=0) {
		pids[i] = fork();
		switch(pids[i]) {
		case -1:
		    PCRIT("Failed to fork");
		    terminate = -1;
		    break;
		case 0:
		    NOPIDFILE();
		    if(!sxreinit(&sx, "fastcgi worker", &fcgilog, args.logfile_arg, foreground, debug, argc, argv))
                        ret = (i >= args.children_arg) ?
			    accept_loop(sx, args.data_dir_arg, rs, WORKER_S2S) :
			    accept_loop(sx, args.data_dir_arg, s, WORKER_GENERIC);
		    else
                        ret = EXIT_FAILURE;
		    goto getout;
		}
		DEBUG("Spawned new worker: pid %d", pids[i]);
	    }
	}

	if(terminate)
	    break;

	DEBUG("All %d children active, waiting...", all_children);
        do {
            dead = wait(&status);
        } while(dead == -1 && errno == EINTR);

	if(dead<0) { /* wait failed */
	    PCRIT("Failed to wait for children");
	    terminate = -1;
	    break;
	}

        /* TODO: SIGBUS handling if mmap I/O is enabled */

	procnum = get_procnum(dead);
	deadname = process_name(procnum);
	if(is_manager(procnum)) {
	    /* Critical child died */
	    if(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
                if (!terminate)
                    WARN("Process %s exited (PID %d)", deadname, dead);
            } else {
		if(WIFSIGNALED(status))
		    CRIT("Process %s was killed with %d",  deadname, WTERMSIG(status));
		else
		    CRIT("Process %s terminated abnormally : %d", deadname, WEXITSTATUS(status));
	    }
	    terminate = 1;
	} else if(WIFEXITED(status) && WEXITSTATUS(status)) {
	    /* Worker died abnormally */
	    WARN("Worker process %d terminated abnormally : %d", dead, WEXITSTATUS(status));
	} else if(WIFSIGNALED(status)) {
	    /* Worker was killed */
	    WARN("Worker process %d killed with %d", dead, WTERMSIG(status));
	} else {
	    /* Worker reached natural end of life */
	    DEBUG("Worker process %d exited", dead);
	}

	if(procnum >= 0 && procnum < sizeof(pids) / sizeof(*pids))
	    pids[procnum] = 0;
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

    ret = terminate == 1 ? EXIT_SUCCESS : EXIT_FAILURE;

 getout:
    if(pidfd >= 0)
	close(pidfd);
    if(pidfile) { /* Only set in the parent */
	unlink(pidfile);
	free(pidfile);
    }
    sx_done(&sx);
    trig_destroy_all();
    cmdline_parser_free(&args);
    OS_LibShutdown();

    return ret;
}
