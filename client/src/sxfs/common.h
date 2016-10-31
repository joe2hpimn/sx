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

#ifndef COMMON_H
#define COMMON_H

#include "params.h"
#include <default.h>
#include <ftw.h>
#include "libsxclient/src/vcrypto.h"

struct _sxfs_queue_entry_t;
struct _sxfs_queue_data_t;
typedef struct _sxfs_queue_entry_t sxfs_queue_entry_t;
typedef struct _sxfs_queue_data_t sxfs_queue_data_t;

void sxfs_log (sxfs_state_t *sxfs, const char *fn, int debug, const char *format_string, ...) FMT_PRINTF(4, 5);
int sxfs_diglen (long int n);
int sxfs_sx_err (sxc_client_t *sx);
int sxfs_resize (void *ptr, size_t *size, size_t elsize);
char *sxfs_hash (sxfs_state_t *sxfs, const char *name);
int sxfs_thread_create (sxfs_state_t *sxfs, pthread_t *thread, void *(start_routine)(void*), void *arg);
int sxfs_build_path (const char *path);
int sxfs_move_file (sxfs_state_t *sxfs, const char *source, const char *dest);
int sxfs_clear_path (const char *path);

int sxfs_get_file (sxfs_state_t *sxfs, sxfs_file_t *sxfs_file);
void sxfs_file_free (sxfs_state_t* sxfs, sxfs_file_t *sxfs_file);

void sxfs_sx_data_destroy (void *ptr);
int sxfs_get_sx_data (sxfs_state_t *sxfs, sxc_client_t **sx, sxc_cluster_t **cluster);
void sxfs_thread_id_destroy (void *ptr);
int sxfs_get_thread_id (sxfs_state_t *sxfs);

void sxfs_lsfile_free (sxfs_lsfile_t *file);
int sxfs_lsdir_add_file (sxfs_lsdir_t *dir, const char *path, struct stat *st);
int sxfs_lsdir_add_dir (sxfs_lsdir_t *dir, const char *path);
void sxfs_lsdir_free (sxfs_lsdir_t *dir);

int sxfs_str_cmp (const void *ptr, size_t index, const char *file_name);
int sxfs_lsfile_cmp (const void *files, size_t index, const char *file_name);
int sxfs_lsdir_cmp (const void *dirs, size_t index, const char *dir_name);
ssize_t sxfs_find_entry (const void *table, size_t size, const char *name, int (*compare)(const void*, size_t, const char*));

int sxfs_ls_update (const char *absolute_path, sxfs_lsdir_t **dir);
int sxfs_ls_stat (const char *path, struct stat *st); /* returned values: <0 - error /  0 - not found / 1 - file / 2 - directory */
int sxfs_upload_force (const char *local_file_path, const char *remote_file_path, sxfs_lsfile_t *lsfile);

int sxfs_delete_check_path (const char *path);
int sxfs_delete_rename_prepare (const char *path, const char *newpath);
void sxfs_delete_rename (const char *path, const char *newpath);
void sxfs_delete_rename_abort (const char *path);
int sxfs_delete (const char *path, int is_remote, int upload_checked);
int sxfs_delete_start (void);
void sxfs_delete_stop (void);

int sxfs_upload_get_file (const char *path, sxfs_file_t *sxfs_file);
void sxfs_upload_del_path (const char *path);
int sxfs_upload_remote_check (sxfs_state_t *sxfs, const char *path);
int sxfs_upload_truncate (const char *path, off_t length);
int sxfs_upload_rename_prepare (const char *path, const char *newpath);
void sxfs_upload_rename (const char *path, const char *newpath);
void sxfs_upload_rename_abort (const char *path);
int sxfs_upload (const char *src, const char *dest, sxfs_lsfile_t *lsfile, int force);
int sxfs_upload_start (void);
void sxfs_upload_stop (void);

#endif

