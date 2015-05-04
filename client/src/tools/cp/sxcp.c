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
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

#include "sx.h"
#include "cmdline.h"
#include "version.h"
#include "libsx/src/misc.h"
#include "bcrumbs.h"

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

static unsigned int get_window_width(void) {
    static unsigned int window_width = 0;

    /* If window width was set do nothing */
    if(window_width)
        return window_width;
    else {
        #ifdef TIOCGWINSZ
            struct winsize window_size;
            if(!ioctl(fileno(stdout), TIOCGWINSZ, &window_size))
                window_width = window_size.ws_col >= MINIMAL_WINDOW_WIDTH ? window_size.ws_col : MINIMAL_WINDOW_WIDTH;
            else
                window_width = STANDARD_WINDOW_WIDTH;
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

    if(d >= 100)
        /* Number of days is so high that we could exceed maximum time string */
        snprintf(str, 6, "100d+");
    else if(d)
        snprintf(str, 13, "%dd%dh%dm%ds", d, h, m, s);
    else if(h)
        snprintf(str, 10, "%dh%dm%ds", h, m, s);
    else if(m)
        snprintf(str, 7, "%dm%ds", m, s);
    else if(seconds >= 1.0)
        snprintf(str, 4, "%ds", s);
    else
        snprintf(str, 5, "<1s");

    return str;
}

static void print_number(char *str, int maxlen, double number, char *unit) {
    if(number - (unsigned long long)number < 0.01)
        snprintf(str, maxlen, "%.0lf%c", number, unit ? *unit : '\0');
    else if(number * 10.0 - (unsigned long long)(number * 10.0) < 0.1)
        snprintf(str, maxlen, "%.1lf%c", number, unit ? *unit : '\0');
    else
        snprintf(str, maxlen, "%.2lf%c", number, unit ? *unit : '\0');
}

/* Process given number to produce short bytes representation */
static char *process_number(int64_t number) {
    char *str = NULL;
    int len = 9; /* 6 digits + comma + unit + NUL byte */
    int i = -1;
    char units[] = { 'K', 'M', 'G', 'T', 'P' };
    double tmpnumber = number;
    while(tmpnumber >= 1024.0) {
        tmpnumber /= 1024.0;
        i++;
    }

    if(i >= (int)(sizeof(units) / sizeof(char))) 
        return NULL;

    str = calloc(len, sizeof(char));
    if(!str)
        return NULL;

    print_number(str, len, tmpnumber, i >= 0 ? &units[i] : NULL);

    return str;
}

static struct bar_internal_t {
    char *bar;
    unsigned int index;
} *bar_internal = NULL;

static int bar_new() {
    if(BAR_WIDTH == 0)
        return 1;

    if(!bar_internal) {
        bar_internal = calloc(1, sizeof(struct bar_internal_t));
        if(!bar_internal) {
            fprintf(stderr, "ERROR: Could not allocate memory for progress bar\n");
            return 1;
        }
    }

    bar_internal->bar = calloc(BAR_WIDTH + 1, sizeof(char));
    if(!bar_internal->bar) {
        free(bar_internal);
        bar_internal = NULL;
        fprintf(stderr, "ERROR: Could not allocate memory for progress bar\n");
        return 1;
    }
    
    return 0;
}

static void bar_free() {
    if(bar_internal)
        free(bar_internal->bar);
    free(bar_internal);
}

static int bar_progress(const sxc_xfer_stat_t *xfer_stat) {
    double m = 1.0f / (double)BAR_WIDTH;
    double c = 0;
    int percent = 0;
    unsigned int i = 0;
    float x = 0;
    int64_t skipped = 0;
    double sc = 0;
    static int64_t last_skipped = 0;

    if(!bar_internal || !xfer_stat)
        return SXE_ABORT;

    if(xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_BOTH)
        skipped = 2 * xfer_stat->current_xfer.file_size - xfer_stat->current_xfer.to_send;
    else
        skipped = xfer_stat->current_xfer.file_size - xfer_stat->current_xfer.to_send;

    if(skipped < 0)
        skipped = 0;

    if(xfer_stat->status != SXC_XFER_STATUS_PART_FINISHED && xfer_stat->status != SXC_XFER_STATUS_WAITING) {
        if(xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_BOTH) {
            sc = xfer_stat->current_xfer.file_size > 0 ? (double)(skipped - last_skipped) / (double)(xfer_stat->current_xfer.file_size * 2) : 0;
            c = xfer_stat->current_xfer.file_size > 0 ? (double)(skipped + xfer_stat->current_xfer.sent) / (double)(xfer_stat->current_xfer.file_size * 2): 1.0;
        } else {
            sc = xfer_stat->current_xfer.file_size > 0 ? (double)(skipped - last_skipped) / (double)xfer_stat->current_xfer.file_size : 0;
            c = xfer_stat->current_xfer.file_size > 0 ? (double)(skipped + xfer_stat->current_xfer.sent) / (double)xfer_stat->current_xfer.file_size : 1.0;
        }
        if(skipped != last_skipped)
            last_skipped = skipped;
    } else {
        /* Skip rest of the file since this is part finished or waiting status */
        c = 1.0;
        last_skipped = 0;
    }
    
    percent = c <= 1.0 ? 100 * c : 100;
    x = bar_internal->index * m;
    for(i = bar_internal->index; i < BAR_WIDTH; i++) {
        if(x < c) {
            if(sc > 0) {
                bar_internal->bar[i] = '+';
                sc -= m;
            } else
                bar_internal->bar[i] = '=';
        } else
            break;
        x += m;
        bar_internal->index++;
    }

    if(i < BAR_WIDTH) {
        bar_internal->bar[i] = '>';
        i++;
    }

    for(; i < BAR_WIDTH; i++)
        bar_internal->bar[i] = ' ';

    fprintf(stderr, "\r");

    if(xfer_stat->status != SXC_XFER_STATUS_PART_FINISHED && xfer_stat->status != SXC_XFER_STATUS_WAITING &&
       xfer_stat->status != SXC_XFER_STATUS_PART_STARTED) {
        char *processed_speed = process_number(xfer_stat->current_xfer.real_speed);
        char *processed_eta = xfer_stat->current_xfer.eta >= 1.0 ? process_time(xfer_stat->current_xfer.eta) : NULL;
        int written = 0;
        if(processed_speed && processed_eta)
            written = fprintf(stderr, "%4d%% %s%s%s %7s%s ETA %s", percent, PREFIX, bar_internal->bar, POSTFIX, processed_speed, "B/s", processed_eta);
        else if(processed_speed)
            written = fprintf(stderr, "%4d%% %s%s%s %7s%s", percent, PREFIX, bar_internal->bar, POSTFIX, processed_speed, "B/s");
        else
            written = fprintf(stderr, "%4d%% %s%s%s %13.2lf%s", percent, PREFIX, bar_internal->bar, POSTFIX, xfer_stat->current_xfer.real_speed, "B/s");
        free(processed_speed);
        free(processed_eta);

        /* If bar has changed its length, then cleanup end of bar with spaces */
        for(i = written; i < get_window_width(); i++)
            fprintf(stderr, " ");

    } else {
        bar_internal->index = 0;
        memset(bar_internal->bar, 0, BAR_WIDTH + 1);

        /* Clear previous bar */
        for(i = 0; i < get_window_width(); i++)
            fprintf(stderr, " ");

        fprintf(stderr, "\r");
    }

    return SXE_NOERROR;
}

/* hold progress callback type */
static sxc_xfer_callback progress_callback_type = NULL;

typedef enum { DOTS_SMALL, DOTS_LARGE, DOTS_SCALE } dots_type_t;

#define DOTS_BYTES_DEFAULT              1024
#define DOTS_PER_CLUSTER_DEFAULT        10
#define DOTS_CLUSTERS_DEFAULT           5

typedef struct {
    unsigned int bytes;
    unsigned int per_cluster;
    unsigned int clusters;
    dots_type_t type;
} dots_sizes_t;
static dots_sizes_t dots_sizes = { DOTS_BYTES_DEFAULT, DOTS_PER_CLUSTER_DEFAULT, DOTS_CLUSTERS_DEFAULT, DOTS_SMALL};

/* Forward declaration, used by function below */
static int dots_progress(const sxc_xfer_stat_t *xfer_stat);

/* Set dots output type */
static int set_dots_type(const char *type) {
    if(!type)
        return 1;

    /* User demanded to change dots output type, set progress callback to dots */
    progress_callback_type = dots_progress;

    if(!strcmp(type, "long")) {
        /* Follow wget, 8KB blocks, 3 clusters with 16 dots each */
        dots_sizes.bytes = 8192;
        dots_sizes.per_cluster = 16;
        dots_sizes.clusters = 3;
        dots_sizes.type = DOTS_LARGE;
    } else if (!strcmp(type, "scale")) {
        /* Scale dots depending on blocksize */
        dots_sizes.bytes = 0; /* Will be used later */
        dots_sizes.per_cluster = 10;
        dots_sizes.clusters = 5;
        dots_sizes.type = DOTS_SCALE;
    } else if(!strcmp(type, "short")) {
        dots_sizes.bytes = DOTS_BYTES_DEFAULT;
        dots_sizes.per_cluster = DOTS_PER_CLUSTER_DEFAULT;
        dots_sizes.clusters = DOTS_CLUSTERS_DEFAULT;
        dots_sizes.type = DOTS_SMALL;
    } else
        return 1;

    return 0;
}

static int dots_progress(const sxc_xfer_stat_t *xfer_stat) {
    static unsigned int dots_written = 0;
    static int64_t xfer_written = 0;
    static int64_t last_skipped = 0;
    static unsigned int j = 0;
    double c = 0;
    int percent = 0;
    char *processed_speed = NULL;
    int64_t skipped = 0;
    char *processed_eta = NULL;

    if(!xfer_stat)
        /* Could not get stats, do not print error, since this function can be called frequently during transfer */
        return SXE_ABORT;

    if(dots_sizes.type == DOTS_SCALE)
        dots_sizes.bytes = xfer_stat->current_xfer.blocksize;

    if(xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_BOTH)
        skipped = 2 * xfer_stat->current_xfer.file_size - xfer_stat->current_xfer.to_send;
    else
        skipped = xfer_stat->current_xfer.file_size - xfer_stat->current_xfer.to_send;

    if(skipped < 0)
        skipped = 0;

    while(xfer_stat->current_xfer.sent + skipped > xfer_written) {
        /* If new line was added, dots_written should be 0 */
        if(dots_written == 0) /* Divide by 1KB to have output in kilobytes */
            fprintf(stderr, "%14lluK ", (unsigned long long) xfer_written / 1024);

        /* Add number of bytes corresponding to one dot */
        xfer_written += dots_sizes.bytes;

        j++; 
        dots_written++;
        if(skipped > last_skipped) {
            last_skipped += dots_sizes.bytes;
            fprintf(stderr, "+");
        } else
            fprintf(stderr, ".");
        if((j + 1) % (dots_sizes.per_cluster + 1) == 0) {
            fprintf(stderr, " ");
            j++;
        }
        
        /* If all dots fot this line was printed, write out stats and break line */
        if(dots_written == dots_sizes.per_cluster * dots_sizes.clusters) {
            if(xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_BOTH)
                c = xfer_stat->current_xfer.file_size > 0 ? (double)xfer_written / (double)(xfer_stat->current_xfer.file_size * 2) : 1.0;
            else
                c = xfer_stat->current_xfer.file_size > 0 ? (double)xfer_written / (double)xfer_stat->current_xfer.file_size : 1.0;

            percent = c <= 1.0 ? 100 * c : 100;

            dots_written = 0;
            j = 0;
            processed_speed = process_number(xfer_stat->current_xfer.real_speed);
            if(xfer_stat->current_xfer.sent > 0)
                processed_eta = process_time(xfer_stat->current_xfer.eta);
            else 
                processed_eta = strdup("n/a");

            if(processed_speed && processed_eta)
                fprintf(stderr, "%4d%% %8s%s ETA %s\n", percent, processed_speed, "B/s", processed_eta);
            else
                fprintf(stderr, "%4d%% %lf%s\n", percent, xfer_stat->current_xfer.real_speed, "B/s");

            free(processed_speed);
            free(processed_eta);
        }
    }

    if(xfer_stat->status == SXC_XFER_STATUS_WAITING || xfer_stat->status == SXC_XFER_STATUS_PART_FINISHED) {
        /* Handle newline when all dots for last line were written */
        if(dots_written) {
            for(; j < dots_sizes.clusters * (dots_sizes.per_cluster + 1); j++)
                fprintf(stderr, "%c", ' ');

            processed_speed = process_number(xfer_stat->current_xfer.real_speed);
            if(xfer_stat->current_xfer.sent > 0)
                processed_eta = process_time(xfer_stat->current_xfer.eta);
            else 
                processed_eta = strdup("n/a");
    
            if(processed_speed && processed_eta)
                fprintf(stderr, "%4d%% %8s%s ETA %s\n", 100, processed_speed, "B/s", processed_eta);
            else
                fprintf(stderr, "%4d%% %lf%s\n", 100, xfer_stat->current_xfer.real_speed, "B/s");

            free(processed_speed);
            free(processed_eta);
            dots_written = 0;
        }

        xfer_written = 0;
        last_skipped = 0;
        j = 0;
    }

    return SXE_NOERROR;
}

/* If possible, get type of callback (progress bar or dots) */
static sxc_xfer_callback get_callback_type(void) {
    if(progress_callback_type) return progress_callback_type;

    #ifdef HAVE_ISATTY
        if(isatty(fileno(stderr))) {
            progress_callback_type = bar_progress;
            if(bar_new()) {
                progress_callback_type = dots_progress;
            }
        } else
            progress_callback_type = dots_progress;
    #else
        progress_callback_type = dots_progress;
    #endif
    return progress_callback_type;
}

static int progress_callback(const sxc_xfer_stat_t *xfer_stat) {
    if(!xfer_stat)
        return SXE_ABORT;

    /* Called to let callbacks finishing lines */
    if(xfer_stat->status == SXC_XFER_STATUS_PART_FINISHED || xfer_stat->status == SXC_XFER_STATUS_WAITING)
        get_callback_type()(xfer_stat);

    switch(xfer_stat->status) {
        case SXC_XFER_STATUS_PART_STARTED : {
            char *processed_size = process_number(xfer_stat->current_xfer.file_size);
            char *file_name_esc = strdup(xfer_stat->current_xfer.file_name);
            if(file_name_esc)
                sxc_escstr(file_name_esc);

            if(processed_size && file_name_esc) {
                const char *op;
                if(xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_DOWNLOAD)
                    op = "Downloading";
                else if(xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_UPLOAD)
                    op = "Uploading";
                else
                    op = "Transferring";

                printf("%s %s (size: %sB)\n", op, file_name_esc, processed_size);
                fflush(stdout);
            }

            free(processed_size);
            free(file_name_esc);

            return get_callback_type()(xfer_stat);
        } break;

        case SXC_XFER_STATUS_FINISHED:
        case SXC_XFER_STATUS_FINISHED_ERROR: {
            /* Do notnig */
        } break;

        case SXC_XFER_STATUS_PART_FINISHED:
        case SXC_XFER_STATUS_WAITING: {
            if(xfer_stat->current_xfer.to_send > 0) {
                char *processed_number = process_number(xfer_stat->current_xfer.sent);
                char *processed_speed = process_number(xfer_stat->current_xfer.real_speed);
                char *processed_time = process_time(xfer_stat->current_xfer.total_time);
                const char *transferred_str = get_callback_type() == bar_progress ? "Transferred" : " transferred";
                const char *file_name = get_callback_type() == bar_progress ? "" : xfer_stat->current_xfer.file_name;
                char *file_name_esc = strdup(file_name);

                if(file_name_esc)
                    sxc_escstr(file_name_esc);

                if(processed_number && processed_speed && processed_time && file_name_esc) {
                    printf("%s%s %sB in %s (@%sB/s)\n", file_name_esc, transferred_str, processed_number, processed_time, processed_speed);
                    fflush(stdout);
                }

                free(file_name_esc);
                free(processed_number);
                free(processed_speed);
                free(processed_time);
            }
        } break;

        case SXC_XFER_STATUS_RUNNING: {
            return get_callback_type()(xfer_stat);
        } break;

        case SXC_XFER_STATUS_STARTED: {
            /* Do nothing, transfer starts */
        } break;
    }

    return SXE_NOERROR;
}

static sxc_file_t *sxfile_from_arg(sxc_cluster_t **cluster, const char *arg, int require_remote_path) {
    sxc_file_t *file;

    if(is_sx(arg)) {
	sxc_uri_t *uri = sxc_parse_uri(sx, arg);

	if(!uri) {
	    fprintf(stderr, "ERROR: Bad uri %s: %s\n", arg, sxc_geterrmsg(sx));
	    return NULL;
	}
	if(!uri->volume || (require_remote_path && !uri->path)) {
	    if(!uri->volume)
		fprintf(stderr, "ERROR: Bad path %s: Missing volume name\n", arg);
	    else
		fprintf(stderr, "ERROR: Bad path %s: Missing file path\n", arg);
	    sxc_free_uri(uri);
	    return NULL;
	}
        if(!*cluster || strcmp(sxc_cluster_get_sslname(*cluster), uri->host)) {
	    sxc_cluster_free(*cluster);
	    *cluster = sxc_cluster_load_and_update(sx, uri->host, uri->profile);
	}
	if(!*cluster) {
	    fprintf(stderr, "ERROR: Failed to load config for %s: %s\n", uri->host, sxc_geterrmsg(sx));
	    if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_CFG_ERR))
		fprintf(stderr, SXBC_TOOLS_CFG_MSG, uri->host, uri->host);
            else if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_CONN_ERR))
                fprintf(stderr, SXBC_TOOLS_CONN_MSG);
	    sxc_free_uri(uri);
	    return NULL;
	}

	file = sxc_file_remote(*cluster, uri->volume, uri->path, NULL);
	sxc_free_uri(uri);
	if(!file) {
	    sxc_cluster_free(*cluster);
            *cluster = NULL;
        }
    } else
	file = sxc_file_local(sx, arg);

    if(!file) {
	fprintf(stderr, "ERROR: Failed to create file object: %s\n", sxc_geterrmsg(sx));
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
        if(!isdigit(str[j]))
            return -1;
    }

    /* Get value and check if it is positive */
    value = atoll(str);
    if(value < 0) 
        return -1;

    if(i < units_size) {
        for(j = 0; j <= i / 2; j++)
            value *= 1024;
    } else
        value *= 1024;

    return value;
}

int main(int argc, char **argv) {
    int ret = 1, skipped = 0;
    unsigned int i;
    sxc_file_t *src_file = NULL, *dst_file = NULL;
    const char *fname;
    char *filter_dir;
    sxc_logger_t log;
    sxc_cluster_t *cluster1 = NULL, *cluster2 = NULL;
    int64_t limit = 0;
    sxc_exclude_t *exclude = NULL;

    if(cmdline_parser(argc, argv, &args))
	exit(1);

    if(args.version_given) {
	printf("%s %s\n", CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	cmdline_parser_free(&args);
	exit(0);
    }

    if(args.inputs_num < 2) {
	cmdline_parser_print_help();
	printf("\n");
	fprintf(stderr, "ERROR: Wrong number of arguments\n");
	cmdline_parser_free(&args);
	exit(1);
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxc_input_fn, NULL))) {
	cmdline_parser_free(&args);
	return 1;
    }

    if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
        fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
        goto main_err;
    }

    sxc_set_debug(sx, args.debug_flag);
    sxc_set_verbose(sx, args.verbose_flag);

    if(args.bwlimit_given) {
        limit = process_bandwidth_arg(args.bwlimit_arg);
        if(limit < 0) {
	    cmdline_parser_print_help();
	    printf("\n");
            fprintf(stderr, "ERROR: Could not parse bandwidth limit argument\n");
            cmdline_parser_free(&args);
            sxc_shutdown(sx, 0);
            return 1;
        }
    }

    if(args.filter_dir_given) {
	filter_dir = strdup(args.filter_dir_arg);
    } else {
	const char *pt = sxi_getenv("SX_FILTER_DIR");
	if(pt)
	    filter_dir = strdup(pt);
	else
	    filter_dir = strdup(SX_FILTER_DIR);
    }
    if(!filter_dir) {
	fprintf(stderr, "ERROR: Failed to set filter dir\n");
	cmdline_parser_free(&args);
        sxc_shutdown(sx, 0);
	return 1;
    }
    sxc_filter_loadall(sx, filter_dir);
    free(filter_dir);

    if(args.dot_size_given) {
        if(set_dots_type(args.dot_size_arg)) {
            fprintf(stderr, "ERROR: Failed to set dots size: invalid argument: %s\n", args.dot_size_arg);
            goto main_err;
        }
    }

    fname = args.inputs[args.inputs_num-1];
    if(!strcmp(fname, "-")) {
	fname = "/dev/stdout";
	args.no_progress_flag = 1;
    }
    if(!(dst_file = sxfile_from_arg(&cluster1, fname, 0)))
	goto main_err;

    if(cluster1 && (args.total_conns_limit_given || args.host_conns_limit_given)) {
        if(args.total_conns_limit_arg < 0 || args.host_conns_limit_arg < 0) {
            fprintf(stderr, "ERROR: Connections limit must be positive number\n");
            goto main_err;
        }
        if(sxc_cluster_set_conns_limit(cluster1, args.total_conns_limit_arg, args.host_conns_limit_arg)) {
            fprintf(stderr, "ERROR: Failed to set connections limits: %s\n", sxc_geterrmsg(sx));
            goto main_err;
        }
    }

    if(limit && cluster1 && sxc_cluster_set_bandwidth_limit(sx, cluster1, limit)) {
        fprintf(stderr, "ERROR: Failed to set bandwidth limit to %s\n", args.bwlimit_arg);
        goto main_err;
    }

    if((!args.no_progress_flag || args.verbose_flag) && cluster1 && sxc_cluster_set_progress_cb(sx, cluster1, progress_callback, NULL)) {
        fprintf(stderr, "ERROR: Could not set progress callback\n");
        goto main_err;
    }
        
    if (args.inputs_num > 2 &&
        sxc_file_require_dir(dst_file)) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        goto main_err;
    }

    if(args.exclude_given && args.include_given) {
        fprintf(stderr, "ERROR: Cannot use --exclude and --include at the same time\n");
        goto main_err;
    }

    if(args.exclude_given) {
        if(!(exclude = sxc_exclude_init(sx, (const char**)args.exclude_arg, args.exclude_given, SXC_EXCLUDE))) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            goto main_err;
        }
    } else if(args.include_given) {
        if(!(exclude = sxc_exclude_init(sx, (const char**)args.include_arg, args.include_given, SXC_INCLUDE))) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            goto main_err;
        }
    }

    if(args.node_preference_given) {
        char *enumb;
        float preference = strtof(args.node_preference_arg, &enumb);
        if(*enumb || preference < 0.0 || preference > 1.0) {
            fprintf(stderr, "ERROR: Invalid argument: must be from 0.0 to 1.0\n");
            goto main_err;
        }

        if(sxc_set_node_preference(sx, preference)) {
            fprintf(stderr, "ERROR: Failed to set node preference\n");
            goto main_err;
        }
    }

    for(i = 0;i < args.inputs_num-1; i++) {
        fname = args.inputs[i];
        if(!strcmp(fname, "-")) {
            fname = "/dev/stdin";
	} else if(!is_sx(fname)) {
	    struct stat sb;
	    if(access(fname, R_OK)) {
		fprintf(stderr, "ERROR: Cannot access %s: %s\n", fname, strerror(errno));
		if(args.ignore_errors_flag) {
		    skipped++;
		    continue;
		}
		goto main_err;
	    }
	    if(stat(fname, &sb)) {
		fprintf(stderr, "ERROR: Cannot stat %s: %s\n", fname, strerror(errno));
		if(args.ignore_errors_flag) {
		    skipped++;
		    continue;
		}
		goto main_err;
	    }
	    if(S_ISDIR(sb.st_mode) && !args.recursive_flag) {
		fprintf(stderr, "WARNING: Cannot copy directory %s: use -r to copy recursively\n", fname);
		if(args.ignore_errors_flag) {
		    skipped++;
		    continue;
		}
		goto main_err;
	    }
	}

        if(!(src_file = sxfile_from_arg(&cluster2, fname, !args.recursive_flag))) {
	    if(args.ignore_errors_flag) {
		skipped++;
		continue;
	    }
	    goto main_err;
	}

        if(cluster2 && (args.total_conns_limit_given || args.host_conns_limit_given)) {
            if(args.total_conns_limit_arg < 0 || args.host_conns_limit_arg < 0) {
                fprintf(stderr, "ERROR: Connections limit must be positive number\n");
                goto main_err;
            }
            if(sxc_cluster_set_conns_limit(cluster2, args.total_conns_limit_arg, args.host_conns_limit_arg)) {
                fprintf(stderr, "ERROR: Failed to set connections limits: %s\n", sxc_geterrmsg(sx));
                goto main_err;
            }
        }

        if(limit && cluster2 && sxc_cluster_set_bandwidth_limit(sx, cluster2, limit)) {
            fprintf(stderr, "ERROR: Failed to set bandwidth limit to %s\n", args.bwlimit_arg);
            goto main_err;
        }

        if((!args.no_progress_flag || args.verbose_flag) && cluster2 && sxc_cluster_set_progress_cb(sx, cluster2, progress_callback, NULL)) {
            fprintf(stderr, "ERROR: Could not set progress callback\n");
            goto main_err;
        }
        
        /* TODO: more than one input requires directory as target,
         * and do the filename appending if target *is* a directory */
        if(sxc_copy(src_file, dst_file, args.recursive_flag, args.one_file_system_flag, args.ignore_errors_flag, exclude, 0)) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
	    if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_NOTFOUND_ERR) && is_sx(fname) && fname[strlen(fname) - 1] == '/')
		fprintf(stderr, SXBC_TOOLS_NOTFOUND_MSG, fname);
	    if((cluster1 || cluster2) && strstr(sxc_geterrmsg(sx), SXBC_TOOLS_VOL_ERR))
		fprintf(stderr, SXBC_TOOLS_VOL_MSG, "", "", cluster1 ? sxc_cluster_get_sslname(cluster1) : sxc_cluster_get_sslname(cluster2));
	    if(args.ignore_errors_flag) {
		skipped++;
		continue;
	    }
            goto main_err;
        }
        sxc_file_free(src_file);
        src_file = NULL;
    }

    /* If --node-preference is given, save cluster configuration in order to store nodes speeds */
    if(args.node_preference_given) {
        if(cluster1 && sxc_cluster_save(cluster1, sxc_get_confdir(sx))) {
            fprintf(stderr, "ERROR: Failed to save cluster configuration: %s\n", sxc_geterrmsg(sx));
            goto main_err;
        }
        if(cluster2 && sxc_cluster_save(cluster2, sxc_get_confdir(sx))) {
            fprintf(stderr, "ERROR: Failed to save cluster configuration: %s\n", sxc_geterrmsg(sx));
            goto main_err;
        }
    }

    ret = skipped ? 1 : 0;
    if(skipped > 1 && !args.recursive_flag)
	fprintf(stderr, "ERROR: Failed to process %d files\n", skipped);

 main_err:
    bar_free();
    sxc_exclude_delete(exclude);
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
