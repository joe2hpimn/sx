/*
 *  Copyright (C) 2015 Skylable Ltd. <info-copyright@skylable.com>
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

#ifndef PARAMS_H
#define PARAMS_H

#define _BSD_SOURCE
#include "default.h"
#include <stdio.h>
#include <pthread.h>
#define FUSE_USE_VERSION 26 /* This has to be defined before fuse.h */
#include <fuse.h>
#include <sx.h>
#include "cmdline.h"
#include "libsxclient/src/fileops.h"
#include "libsxclient/src/misc.h"
#include "server/src/common/sxlimits.h"

#define SXFS_SXNEWDIR ".sxnewdir"
#define SXFS_UPLOAD_DIR "upload"
#define SXFS_LOSTDIR_SUFIX "-lost"
#define SXFS_ALLOC_ENTRIES 100
#define SXFS_THREADS_LIMIT 64
#define SXFS_FILE_OPENED 0x1
#define SXFS_FILE_REMOVED 0x2
#define SXFS_FILE_ATTR (S_IFREG|S_IRUSR|S_IWUSR)
#define SXFS_DIR_ATTR (S_IFDIR|S_IRUSR|S_IWUSR|S_IXUSR)
#define SXFS_DIR_SIZE SX_BS_SMALL

#define SXFS_BS_MEDIUM_AMOUNT 128   /* 16 kB * 128 = 2MB */
#define SXFS_BS_LARGE_AMOUNT 4      /*  1 MB *  4  = 4MB */

#define SXFS_THREAD_WAIT 200000L /* microseconds to wait for other threads (200000 -> 0.2s) */
#define SXFS_THREAD_SLEEP 5000000L /* microseconds deletion and upload threads wait for next turn */
#define SXFS_LS_RELOAD 3.0 /* seconds sxfs assumes data it already has is up to date */
#define SXFS_LAST_ACTION_WAIT 1.0 /* seconds must have been passed since last file action */

#define SXFS_LOG_TYPE_NORMAL 0x1
#define SXFS_LOG_TYPE_DEBUG 0x2
#define SXFS_LOG_TYPE_VERBOSE 0x3
#define SXFS_LOG_TYPE_ERROR 0x4
#define SXFS_DATA ((sxfs_state_t*) fuse_get_context()->private_data)
#define SXFS_LOG(...) sxfs_log(sxfs, __func__, SXFS_LOG_TYPE_NORMAL, __VA_ARGS__)
#define SXFS_DEBUG(...) sxfs_log(sxfs, __func__, SXFS_LOG_TYPE_DEBUG, __VA_ARGS__)
#define SXFS_VERBOSE(...) sxfs_log(sxfs, __func__, SXFS_LOG_TYPE_VERBOSE, __VA_ARGS__)
#define SXFS_ERROR(...) sxfs_log(sxfs, __func__, SXFS_LOG_TYPE_ERROR, __VA_ARGS__)

struct _sxfs_lsfile_t {
    int remote, opened;
    time_t remote_mtime;
    char *name;
    struct stat st;
};
typedef struct _sxfs_lsfile_t sxfs_lsfile_t;

struct _sxfs_lsdir_t {
    int init, remote, sxnewdir; /* init - directory loaded correctly
                         * sxnewdir - directory has '.sxnewdir' file */
    size_t ndirs, maxdirs, nfiles, maxfiles;
    char *name, *etag;
    struct stat st;
    struct timeval tv; /* timecheck for cache reloading */
    struct _sxfs_lsdir_t *parent, **dirs; /* typedef is after this struct definition */
    sxfs_lsfile_t **files;
};
typedef struct _sxfs_lsdir_t sxfs_lsdir_t;

struct _sxfs_file_t {
    int flush, write_fd;
    unsigned long int num_open, threads_num;
    char *write_path, *remote_path;
    sxi_sxfs_data_t *fdata;
    sxfs_lsfile_t *ls_file;
    pthread_mutex_t mutex;
};
typedef struct _sxfs_file_t sxfs_file_t;

struct _sxfs_cache_t;
typedef struct _sxfs_cache_t sxfs_cache_t;

struct _sxfs_state {
    int pipefd[2], need_file, attribs, recovery_failed, *threads, *fh_table;
    size_t fh_limit, threads_num, threads_max;
    char *pname, *tempdir, *lostdir, *empty_file_path;
    pthread_key_t sxkey, tid_key;
    /* mutex priority: ls > delete > upload */
    pthread_mutex_t sx_data_mutex, ls_mutex, delete_mutex, delete_thread_mutex, upload_mutex, upload_thread_mutex, files_mutex, limits_mutex;
    pthread_cond_t delete_cond, upload_cond;
    sxc_uri_t *uri;
    sxi_ht *files;
    sxfs_lsdir_t *root;
    sxfs_cache_t *cache;
    FILE *logfile;
    struct gengetopt_args_info *args;
    pthread_t upload_thread, delete_thread;
};
typedef struct _sxfs_state sxfs_state_t;

struct _sxfs_sx_data {
    sxc_logger_t log;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    pthread_mutex_t *sx_data_mutex;
};
typedef struct _sxfs_sx_data sxfs_sx_data_t;

#endif

