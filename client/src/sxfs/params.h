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
#include <openssl/md5.h>
#include <pthread.h>
#define FUSE_USE_VERSION 26 /* This has to be defined before fuse.h */
#include <fuse.h>
#include <sx.h>
#include "cmdline.h"
#include "libsxclient/src/fileops.h"
#include "server/src/common/sxlimits.h"

#define SXFS_THREADS_LIMIT 64

struct _sxfs_lsfile_t {
    int remote, opened;
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
    int flush, write_fd, nblocks;
    unsigned long int blocksize, num_open;
    char *blocks, **blocks_path, *etag, *write_path;
    sxi_sxfs_data_t *fdata;
    sxfs_lsfile_t *ls_file;
    pthread_mutex_t block_mutex;
};
typedef struct _sxfs_file_t sxfs_file_t;

struct _sxfs_state {
    int read_only, recovery_failed, threads_num, *fh_table;
    size_t fh_limit;
    char *pname, *tempdir, *lostdir, *empty_file_path, *read_block_template;
    pthread_key_t pkey;
    /* mutex priority: ls > delete > upload */
    pthread_mutex_t sx_data_mutex, ls_mutex, delete_mutex, upload_mutex, files_mutex, limits_mutex;
    sxc_uri_t *uri;
    sxc_meta_t *files;
    sxfs_lsdir_t *root;
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

#define ALLOC_AMOUNT 100
#define THREAD_WAIT_USEC 200000L /* microseconds to wait for other threads (200000 -> 0.2s) */
#define LS_RELOAD_TIME 3000000L /* microseconds sxfs assumes data it already has is up to date */
#define JOB_SLEEP_USEC 5000000L /* microseconds deletion and upload threads wait for next turn */
#define LAST_ACTION_WAIT_USEC 1000000L /* microseconds must have been passed since last file action */
#define SXFS_DATA ((sxfs_state_t*) fuse_get_context()->private_data)
#define SXFS_LOG(...) sxfs_log(SXFS_DATA, __FUNCTION__, 0, __VA_ARGS__)
#define SXFS_DEBUG(...) sxfs_log(SXFS_DATA, __FUNCTION__, 1, __VA_ARGS__)

#endif

