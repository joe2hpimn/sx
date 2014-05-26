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
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>

#include "sx.h"
#include "cmdline.h"
#include "version.h"
#include "libsx/src/misc.h"

struct gengetopt_args_info args;

static int is_sx(const char *p) {
    return strncmp(p, "sx://", 5) == 0 || strncmp(p, SXC_ALIAS_PREFIX, strlen(SXC_ALIAS_PREFIX)) == 0;
}

static sxc_client_t *sx = NULL;

static void sighandler(int signal)
{
    struct termios tcur;
    if(sx)
	sxc_shutdown(sx, signal);

    /* work around for ctrl+c during getpassword() in the aes filter */
    tcgetattr(0, &tcur);
    tcur.c_lflag |= ECHO;
    tcsetattr(0, TCSANOW, &tcur);

    fprintf(stderr, "Process interrupted\n");
    exit(1);
}

#define PREFIX "["
#define POSTFIX "]" 
#define BRACKETS (sizeof(PREFIX) + sizeof(POSTFIX) - 2)
#define STANDARD_WINDOW_WIDTH   80 /* Standard window size */
#define MINIMAL_WINDOW_WIDTH    (43 + BRACKETS) /* percent -> 5 chars + space, speed up 16 to chars + space, B/s -> 3 chars + ETA -> 5 chars + eta time -> up to 12 chars + 2 chars for [] */

static int get_window_width(void) {
    static int window_width = 0;

    /* If window width was set do nothing */
    if(window_width) {
        return window_width;
    } else {
        #ifdef TIOCGWINSZ
            struct winsize window_size;
            if(!ioctl(fileno(stdout), TIOCGWINSZ, &window_size)) {
                window_width = window_size.ws_col >= MINIMAL_WINDOW_WIDTH ? window_size.ws_col : MINIMAL_WINDOW_WIDTH;
            } else {
                window_width = STANDARD_WINDOW_WIDTH;
            }
        #else
            window_width = STANDARD_WINDOW_WIDTH;
        #endif
    }

    return window_width;
}

#define BAR_WIDTH (get_window_width() - MINIMAL_WINDOW_WIDTH)

static char *process_time(double seconds) {
    char *str = NULL;
    int d = 0;
    int h = 0;
    int m = 0;
    int s = (int)seconds;
    str = calloc(13, sizeof(char));
    if(!str)
        return NULL;

    m = s / 60;
    s %= 60;

    if(m) {
        h = m / 60;
        m %= 60;
    }
    if(h) {
        d = h / 24;
        h %= 24;
    }

    if(seconds < 1.0) {
        snprintf(str, 5, "<1s");
    } else if(!m) {
        snprintf(str, 4, "%ds", s);
    } else if(!h) {
        snprintf(str, 7, "%dm%ds", m, s);
    } else if(!d) {
        snprintf(str, 10, "%dh%dm%ds", h, m, s);
    } else if(d >= 100) { 
        /* Number of days is so high that we could exceed maximum time string */
        snprintf(str, 6, "100d+");
    } else {
        snprintf(str, 13, "%dd%dh%dm%ds", d, h, m, s);
    }

    return str;
}

/* Process given number to produce short bytes representation */
static char *process_number(int64_t number) {
    char *str = NULL;
    int len = 8; /* 6 digits + comma + NUL byte */
    int i = -1;
    char units[] = { 'K', 'M', 'G', 'T', 'P' };
    double tmpnumber = number;
    while(tmpnumber >= 1024.0) {
        tmpnumber /= 1024.0;
        i++;
    }

    if(i >= (int)(sizeof(units) / sizeof(char))) 
        return NULL;

    /* Add space for unit */
    if(i >= 0) {
        len++;
    }

    str = calloc(len, sizeof(char));
    if(!str)
        return NULL;

    if(i >= 0)
        snprintf(str, len, "%.0lf%c", tmpnumber, units[i]);
    else
        snprintf(str, len, "%.0lf", tmpnumber);

    return str;
}

static struct bar_internal_t {
    char *bar;
    int index;
} *bar_internal = NULL;

static int bar_new() {
    if(BAR_WIDTH == 0) {
        return 1;
    }

    if(!bar_internal) {
        bar_internal = calloc(1, sizeof(struct bar_internal_t));
        if(!bar_internal) {
            fprintf(stderr, "Could not allocate memory for progress bar\n");
            return 1;
        }
    }

    bar_internal->bar = calloc(BAR_WIDTH + 1, sizeof(char));
    if(!bar_internal->bar) {
        free(bar_internal);
        bar_internal = NULL;
        fprintf(stderr, "Could not allocate memory for progress bar\n");
        return 1;
    }
    
    return 0;
}

static void bar_free() {
    if(bar_internal) {
        free(bar_internal->bar);
    }
    free(bar_internal);
}

static void bar_progress(const sxc_xfer_stat_t *xfer_stat) {
    double m = 1.0f / (double)BAR_WIDTH;
    double c = 0;
    int percent = 0;
    double speed = 0;
    double eta = 0;
    int i = 0;
    float x = 0;
    int written = 0;
    static int64_t last_skipped = 0;
    int skipped_changed = 0; /* it is set to 1 when some blocks where skipped */
    char *processed_speed = NULL;
    char *processed_eta = NULL;

    if(!bar_internal) {
        return;
    }

    if(!xfer_stat){
        /* Could not get stats, do not print error, since this function can be called frequently during transfer */
        return;
    }

    if(xfer_stat->status != SXC_XFER_STATUS_PART_FINISHED && xfer_stat->status != SXC_XFER_STATUS_WAITING) {
        int64_t skipped = xfer_stat->current_xfer.file_size - xfer_stat->current_xfer.to_send;
        c = xfer_stat->current_xfer.file_size > 0 ? (double)(skipped + xfer_stat->current_xfer.sent) / (double)xfer_stat->current_xfer.file_size : 1.0;
        if(skipped != last_skipped) {
            last_skipped = skipped;
            skipped_changed = 1;
        } else {
            skipped_changed = 0;
        }
    } else {
        /* Skip rest of the file since this is part finished or waiting status */
        c = 1.0;
        last_skipped = 0;
        skipped_changed = 0;
    }
    
    percent = c <= 1.0 ? 100 * c : 100;
    speed = xfer_stat->current_xfer.total_time > 0 ? xfer_stat->current_xfer.sent / xfer_stat->current_xfer.total_time : 0;
    eta = speed > 0 ? xfer_stat->current_xfer.to_send / speed - xfer_stat->current_xfer.total_time : 0;
    x = bar_internal->index * m;
    for(i = bar_internal->index; i < BAR_WIDTH; i++) {
        if(x < c) {
            if(skipped_changed) {
                bar_internal->bar[i] = '+';
            } else {
                bar_internal->bar[i] = '=';
            }
        } else {
            break;
        }
        x += m;
        bar_internal->index++;
    }

    if(i < BAR_WIDTH) {
        bar_internal->bar[i] = '>';
        i++;
    }

    for(; i < BAR_WIDTH; i++) {
        bar_internal->bar[i] = ' ';
    }

    printf("\r");

    processed_speed = process_number(speed);
    processed_eta = process_time(eta);
    if(processed_speed && processed_eta)
        written = printf("%4d%% %s%s%s %7s%s ETA %s", percent, PREFIX, bar_internal->bar, POSTFIX, processed_speed, "B/s", processed_eta);
    else
        written = printf("%4d%% %s%s%s %13.2lf%s", percent, PREFIX, bar_internal->bar, POSTFIX, speed, "B/s");
    free(processed_speed);
    free(processed_eta);

    /* If bar has changed its length, then cleanup end of bar with spaces */
    for(i = written; i < get_window_width(); i++) {
        printf(" ");
    }

    if(xfer_stat->status == SXC_XFER_STATUS_PART_FINISHED || xfer_stat->status == SXC_XFER_STATUS_WAITING) {
        printf("\n");
        bar_internal->index = 0;
        memset(bar_internal->bar, 0, BAR_WIDTH + 1);
    }

    fflush(stdout);
}

#define DOTS_BYTES              1024
#define DOTS_PER_CLUSTER        10 
#define DOTS_CLUSTERS           5

static void dots_progress(const sxc_xfer_stat_t *xfer_stat) {
    static int dots_written = 0;
    static int64_t xfer_written = 0;
    static int64_t last_skipped = 0;
    static int j = 0;
    double c = 0;
    int percent = 0;
    double speed = 0;
    char *processed_speed = NULL;
    int64_t skipped = 0;
    int64_t skipped_changed = 0;
    double eta = 0;
    char *processed_eta = NULL;

    if(!xfer_stat){
        /* Could not get stats, do not print error, since this function can be called frequently during transfer */
        return;
    }

    skipped = xfer_stat->current_xfer.file_size - xfer_stat->current_xfer.to_send;

    if(skipped > last_skipped) {
        last_skipped = skipped;
        skipped_changed = 1;
    } else {
        skipped_changed = 0;
    }

    while(xfer_stat->current_xfer.sent + skipped > xfer_written) {
        /* If new line was added, dots_written should be 0 */
        if(dots_written == 0) {
            printf("%14ldK ", xfer_written / DOTS_BYTES);
        }

        /* Add number of bytes corresponding to one dot */
        xfer_written += DOTS_BYTES;

        j++; 
        dots_written++;
        if(skipped_changed)
            printf("+");
        else
            printf(".");
        if((j + 1) % (DOTS_PER_CLUSTER + 1) == 0) {
            printf(" ");
            j++;
        }
        
        /* If all dots fot this line was printed, write out stats and break line */
        if(dots_written == DOTS_PER_CLUSTER * DOTS_CLUSTERS) {
            c = xfer_stat->current_xfer.file_size > 0 ? (double)xfer_written / (double)xfer_stat->current_xfer.file_size : 1.0;     
            speed = xfer_stat->current_xfer.total_time > 0 ? (double)xfer_stat->current_xfer.sent / xfer_stat->current_xfer.total_time : 0;
            percent = c <= 1.0 ? 100 * c : 100;
            eta = speed > 0 ? xfer_stat->current_xfer.to_send / speed - xfer_stat->current_xfer.total_time : 0;

            dots_written = 0;
            j = 0;
            processed_speed = process_number(speed);
            if(xfer_stat->current_xfer.sent > 0)
                processed_eta = process_time(eta);
            else 
                processed_eta = strdup("n/a");

            if(processed_speed && processed_eta) {
                printf("%4d%% %8s%s ETA %s\n", percent, processed_speed, "B/s", processed_eta);
            } else {
                printf("%4d%% %lf%s\n", percent, speed, "B/s");
            }
            free(processed_speed);
            free(processed_eta);
        }
    }

    if(xfer_stat->status == SXC_XFER_STATUS_WAITING || xfer_stat->status == SXC_XFER_STATUS_PART_FINISHED) {
        speed = xfer_stat->current_xfer.total_time > 0 ? (double)xfer_stat->current_xfer.sent / xfer_stat->current_xfer.total_time : 0;
        eta = speed > 0 ? xfer_stat->current_xfer.to_send / speed - xfer_stat->current_xfer.total_time : 0.0;

        for(; j < DOTS_CLUSTERS * (DOTS_PER_CLUSTER + 1); j++) {
            printf("%c", ' ');
        }

        processed_speed = process_number(speed);
        if(xfer_stat->current_xfer.sent > 0)
            processed_eta = process_time(eta);
        else 
            processed_eta = strdup("n/a");
    
        if(processed_speed && processed_eta) {
            printf("%4d%% %8s%s ETA %s\n", 100, processed_speed, "B/s", processed_eta);
        } else {
            printf("%4d%% %lf%s\n", 100, speed, "B/s");
        }
        free(processed_speed);
        free(processed_eta);

        dots_written = 0;
        xfer_written = 0;
        last_skipped = 0;
        j = 0;
    }

    fflush(stdout);
}

/* If possible, get type of callback (progress bar or dots) */
static sxc_xfer_callback get_callback_type(void) {
    static sxc_xfer_callback progress_callback_type = NULL;
    if(progress_callback_type) return progress_callback_type;

    #ifdef HAVE_ISATTY
        if(isatty(fileno(stdout))) {
            progress_callback_type = bar_progress;
            if(bar_new()) {
                progress_callback_type = dots_progress;
            }
        } else {
            progress_callback_type = dots_progress;
        }
    #else
        progress_callback_type = dots_progress;
    #endif
    return progress_callback_type;
}

static void progress_callback(const sxc_xfer_stat_t *xfer_stat) {
    if(!xfer_stat) {
        /* Do not report an error becuse this callback can be called frequently during transfer */
        return;
    }

    /* Called to let callbacks finishing lines */
    if(xfer_stat->status == SXC_XFER_STATUS_PART_FINISHED || xfer_stat->status == SXC_XFER_STATUS_WAITING)
        get_callback_type()(xfer_stat);

    switch(xfer_stat->status) {
        case SXC_XFER_STATUS_PART_STARTED : {
            char *processed_size = process_number(xfer_stat->current_xfer.file_size);
            if(processed_size) {
                printf("%s %s (size: %sB)\n", xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_DOWNLOAD ? "Downloading" : "Uploading", 
                    xfer_stat->current_xfer.file_name, processed_size);
            } else {
                printf("%s %s (size: %ldB)\n", xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_DOWNLOAD ? "Downloading" : "Uploading", 
                    xfer_stat->current_xfer.file_name, xfer_stat->current_xfer.file_size);
            }
            free(processed_size);
        } break;

        case SXC_XFER_STATUS_FINISHED:
        case SXC_XFER_STATUS_FINISHED_ERROR: {
            /* Do notnig */
        } break;

        case SXC_XFER_STATUS_PART_FINISHED:
        case SXC_XFER_STATUS_WAITING: {
            if(xfer_stat->current_xfer.to_send > 0) {
                char *processed_number = process_number(xfer_stat->current_xfer.sent);
                char *processed_speed = process_number(xfer_stat->current_xfer.sent / xfer_stat->current_xfer.total_time);
                char *processed_time = process_time(xfer_stat->current_xfer.total_time);
                const char *transferred_str = get_callback_type() == bar_progress ? "Transferred" : " transferred";
                const char *file_name = get_callback_type() == bar_progress ? "" : xfer_stat->current_xfer.file_name;

                if(processed_number && processed_speed && processed_time) {
                    printf("%s%s %sB in %s (@%sB/s)\n\n", file_name, transferred_str, processed_number, processed_time, processed_speed);
                } else {
                    printf("%s%s %ldB in %.0lf (@%0.2lfB/s)\n\n", file_name, transferred_str, xfer_stat->current_xfer.sent, 
                        xfer_stat->current_xfer.total_time, xfer_stat->current_xfer.sent / xfer_stat->current_xfer.total_time);
                }
                free(processed_number);
                free(processed_speed);
                free(processed_time);
            } else {
                printf("\n");
            }
        } break;

        case SXC_XFER_STATUS_RUNNING: {
            get_callback_type()(xfer_stat);
        } break;

        case SXC_XFER_STATUS_STARTED: {
            /* Do nothing, transfer starts */
        } break;
    }
}

static sxc_file_t *sxfile_from_arg(sxc_cluster_t **cluster, const char *arg) {
    sxc_file_t *file;

    if(is_sx(arg)) {
	sxc_uri_t *uri = sxc_parse_uri(sx, arg);

	if(!uri) {
	    fprintf(stderr, "Bad uri %s: %s\n", arg, sxc_geterrmsg(sx));
	    return NULL;
	}
	if(!uri->volume) {
	    fprintf(stderr, "Bad path %s\n", arg);
	    sxc_free_uri(uri);
	    return NULL;
	}

	*cluster = sxc_cluster_load_and_update(sx, args.config_dir_arg, uri->host, uri->profile);
	if(!*cluster) {
	    fprintf(stderr, "Failed to load config for %s: %s\n", uri->host, sxc_geterrmsg(sx));
	    sxc_free_uri(uri);
	    return NULL;
	}

	file = sxc_file_remote(*cluster, uri->volume, uri->path);
	sxc_free_uri(uri);
	if(!file) {
	    sxc_cluster_free(*cluster);
            *cluster = NULL;
        }
    } else
	file = sxc_file_local(sx, arg);

    if(!file) {
	fprintf(stderr, "Failed to create file object: %s\n", sxc_geterrmsg(sx));
	return NULL;
    }

    return file;
}

/* Return > 0 if given bandwidth limit argument could be properly parsed */
static int process_bandwidth_arg(const char *str) {
    int len = 0;
    int64_t value = 0;
    int i = 0, j = 0;
    char units[] = { 'K', 'k', 'M', 'm', 'G', 'g'};
    int units_size = sizeof(units) / sizeof(char);
    if(!str|| !(len = strlen(str)))
        return -1;

    /* Check if unit is given */
    for(i = 0; i < units_size; i++) {
        if(str[len - 1] == units[i]) {
            /* Unit found, break the loop if len is greater that 0 */
            len--;
            if(!len)
                return -1;
            else
                break;
        }
    }

    /* Check if number consist of digits only */
    for(j = len - 1; j >= 0; j--) {
        if(!isdigit(str[j])) {
            return -1;
        }
    }

    /* Get value and check if it is positive */
    value = atoll(str);
    if(value < 0) 
        return -1;

    if(i < units_size) {
        for(j = 0; j <= i / 2; j++) {
            value *= 1024;
        }
    } else {
        value *= 1024;
    }

    return value;
}

int main(int argc, char **argv) {
    int ret = 1, i;
    sxc_file_t *src_file = NULL, *dst_file = NULL;
    const char *fname;
    char *filter_dir;
    sxc_logger_t log;
    sxc_cluster_t *cluster1 = NULL, *cluster2 = NULL;
    int64_t limit = 0;

    if(cmdline_parser(argc, argv, &args))
	exit(1);

    if(args.version_given) {
	printf("%s %s\n", CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	cmdline_parser_free(&args);
	exit(0);
    }

    if(args.inputs_num < 2) {
	fprintf(stderr, "Wrong number of arguments (see --help)\n");
	cmdline_parser_free(&args);
	exit(1);
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxi_yesno))) {
	cmdline_parser_free(&args);
	return 1;
    }

    if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
        fprintf(stderr, "Could not set configuration directory %s: %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
        ret = 1;
        goto main_err;
    }

    sxc_set_debug(sx, args.debug_flag);
    sxc_set_verbose(sx, args.verbose_flag);

    if(args.bwlimit_given) {
        limit = process_bandwidth_arg(args.bwlimit_arg);
        if(limit < 0) {
            fprintf(stderr, "Could not parse bandwidth limit argument (see --help)\n");
            cmdline_parser_free(&args);
            sxc_shutdown(sx, 0);
            return 1;
        }
    }

    if(args.filter_dir_given) {
	filter_dir = strdup(args.filter_dir_arg);
    } else {
	const char *pt = getenv("SX_FILTER_DIR");
	if(pt)
	    filter_dir = strdup(pt);
	else
	    filter_dir = strdup(SX_FILTER_DIR);
    }
    if(!filter_dir) {
	fprintf(stderr, "Failed to set filter dir\n");
	cmdline_parser_free(&args);
        sxc_shutdown(sx, 0);
	return 1;
    }
    sxc_filter_loadall(sx, filter_dir);
    free(filter_dir);

    fname = args.inputs[args.inputs_num-1];
    if(!strcmp(fname, "-"))
	fname = "/dev/stdout";
    if(!(dst_file = sxfile_from_arg(&cluster1, fname)))
	goto main_err;

    if(limit && cluster1 && sxc_cluster_set_bandwidth_limit(sx, cluster1, limit)) {
        fprintf(stderr, "Failed to set bandwidth limit to %s\n", args.bwlimit_arg);
        goto main_err;
    }

    if((!args.no_progress_flag || args.verbose_flag) && cluster1 && sxc_cluster_set_progress_cb(sx, cluster1, progress_callback)) {
        fprintf(stderr, "Could not set progress callback\n");
        goto main_err;
    }
        
    if (args.inputs_num > 2 &&
        sxc_file_require_dir(dst_file)) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        goto main_err;
    }

    for(i = 0;i < args.inputs_num-1; i++) {
        fname = args.inputs[i];
        if(!strcmp(fname, "-"))
            fname = "/dev/stdin";
        if(!(src_file = sxfile_from_arg(&cluster2, fname)))
            goto main_err;

        if(limit && cluster2 && sxc_cluster_set_bandwidth_limit(sx, cluster2, limit)) {
            fprintf(stderr, "Failed to set bandwidth limit to %s\n", args.bwlimit_arg);
            goto main_err;
        }

        if((!args.no_progress_flag || args.verbose_flag) && cluster2 && sxc_cluster_set_progress_cb(sx, cluster2, progress_callback)) {
            fprintf(stderr, "Could not set progress callback\n");
            goto main_err;
        }
        
        /* TODO: more than one input requires directory as target,
         * and do the filename appending if target *is* a directory */
        if(sxc_copy(src_file, dst_file, args.recursive_flag)) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            goto main_err;
        }
        sxc_file_free(src_file);
        src_file = NULL;
    }
    
    ret = 0;

 main_err:
    bar_free();

    sxc_file_free(src_file);
    sxc_file_free(dst_file);

    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    sxc_cluster_free(cluster1);
    sxc_cluster_free(cluster2);
    sxc_shutdown(sx, 0);
    cmdline_parser_free(&args);

    return ret;
}
