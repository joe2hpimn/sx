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

#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include "params.h"
#include "common.h"
#include "cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#ifdef HAVE_SETGROUPS
#include <sys/param.h>
#endif
#include <inttypes.h>
#include "libsxclient/src/clustcfg.h"
#include "libsxclient/include/version.h"

#define SXFS_SX_DATA_MUTEX (1<<0)
#define SXFS_LS_MUTEX (1<<1)
#define SXFS_UPLOAD_MUTEX (1<<2)
#define SXFS_DELETE_MUTEX (1<<3)
#define SXFS_FILES_MUTEX (1<<4)
#define SXFS_LIMITS_MUTEX (1<<5)
#define SXFS_UPLOAD_THREAD_MUTEX (1<<6)
#define SXFS_DELETE_THREAD_MUTEX (1<<7)
#define SXFS_SX_DATA_KEY (1<<8)
#define SXFS_THREAD_ID_KEY (1<<9)
#define SXFS_RENAME_FILE 0x1
#define SXFS_RENAME_DIR 0x2
#define SXFS_CHMOD 0x1
#define SXFS_CHOWN 0x2
#define SXFS_UTIMENS 0x4

#define FH_CHECK(fh)                                \
    if(fh >= sxfs->fh_limit) {                      \
        SXFS_ERROR("File handle out of scope");     \
        return -EBADF;                              \
    }                                               \
    pthread_mutex_lock(&sxfs->limits_mutex);        \
    sxfs_file = sxfs->fh_table[fh];                 \
    pthread_mutex_unlock(&sxfs->limits_mutex);      \
    if(!sxfs_file) {                                \
        SXFS_ERROR("File not opened: %s", path);    \
        return -EFAULT;                             \
    }                                               \
    if(sxfs_file->is_dir) {                         \
        SXFS_ERROR("Got directory descriptor");     \
        return -EISDIR;                             \
    }

static int check_path_len (sxfs_state_t *sxfs, const char *path, int is_dir) {
    if(strlen(path) + (is_dir ? 1 + lenof(SXFS_SXNEWDIR) : 0) > SXLIMIT_MAX_FILENAME_LEN)
        return -ENAMETOOLONG;
    return 0;
} /* check_path_len */

static int sxfs_getattr (const char *path, struct stat *st) {
    int ret;
    char *path2 = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path || !st) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s'", path);
    if((ret = check_path_len(sxfs, path, 0))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    if(strlen(path) > 1 && path[strlen(path)-1] == '/') {
        path2 = strdup(path);
        if(!path2) {
            SXFS_ERROR("Out of memory: %s", path);
            return -ENOMEM;
        }
        path2[strlen(path2)-1] = '\0';
    }
    if((ret = sxfs_ls_stat(path2 ? path2 : path, st)) < 0) {
        if(ret == -ENOENT)
            SXFS_DEBUG("%s: %s", path2 ? path2 : path, strerror(ENOENT));
        else
            SXFS_ERROR("Cannot check file status: %s", path2 ? path2 : path);
        free(path2);
        return ret;
    }
    st->st_atime = st->st_mtime;
    free(path2);
    return 0;
} /* sxfs_getattr */

static int sxfs_readlink (const char *path, char *buf, size_t bufsize) {
    return -ENOTSUP;
} /* sxfs_readlink*/

static int sxfs_mknod (const char *path, mode_t mode, dev_t dev) {
    int ret;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', mode: %c%c%c%c%c%c%c%c%c%c (%o)", path, S_ISDIR(mode) ? 'd' : '-',
                        mode & S_IRUSR ? 'r' : '-', mode & S_IWUSR ? 'w' : '-', mode & S_IXUSR ? 'x' : '-',
                        mode & S_IRGRP ? 'r' : '-', mode & S_IWGRP ? 'w' : '-', mode & S_IXGRP ? 'x' : '-',
                        mode & S_IROTH ? 'r' : '-', mode & S_IWOTH ? 'w' : '-', mode & S_IXOTH ? 'x' : '-', (unsigned int)mode);
    if((ret = check_path_len(sxfs, path, 0))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    if(mode && !S_ISREG(mode)) {
        SXFS_ERROR("Not supported type of file: %s", S_ISCHR(mode) ? "character special file" : S_ISBLK(mode) ? "block special file" :
                                                   S_ISFIFO(mode) ? "FIFO (named pipe)" : S_ISSOCK(mode) ? "UNIX domain socket" : "unknown type");
        return -ENOTSUP;
    }
    SXFS_ERROR("To create regular file FUSE should use create()");
    return -ENOSYS; /* Function not implemented */
} /* sxfs_mknod */

static int sxfs_mkdir (const char *path, mode_t mode) {
    int ret;
    size_t i;
    char *dir_name, *remote_file_path;
    sxfs_lsdir_t *dir;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', mode: %c%c%c%c%c%c%c%c%c%c (%o)", path, S_ISDIR(mode) ? 'd' : '-',
                        mode & S_IRUSR ? 'r' : '-', mode & S_IWUSR ? 'w' : '-', mode & S_IXUSR ? 'x' : '-',
                        mode & S_IRGRP ? 'r' : '-', mode & S_IWGRP ? 'w' : '-', mode & S_IXGRP ? 'x' : '-',
                        mode & S_IROTH ? 'r' : '-', mode & S_IWOTH ? 'w' : '-', mode & S_IXOTH ? 'x' : '-', (unsigned int)mode);
    if((ret = check_path_len(sxfs, path, 1))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    dir_name = strrchr(path, '/');
    if(!dir_name) {
        SXFS_ERROR("'/' not found in '%s'", path);
        return -EINVAL;
    }
    dir_name++;
    remote_file_path = (char*)malloc(strlen(path) + 1 + lenof(SXFS_SXNEWDIR) + 1);
    if(!remote_file_path) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    sprintf(remote_file_path, "%s/%s", path, SXFS_SXNEWDIR);
    pthread_mutex_lock(&sxfs->ls_mutex);
    if((ret = sxfs_ls_update(path, &dir))) {
        SXFS_ERROR("Cannot load file tree: %s", path);
        goto sxfs_mkdir_err;
    }
    if(sxfs_find_entry((const void**)dir->files, dir->nfiles, dir_name, sxfs_lsfile_cmp) >= 0) {
        SXFS_ERROR("File already exists: %s", path);
        ret = -EEXIST;
        goto sxfs_mkdir_err;
    }
    if(sxfs_find_entry((const void**)dir->dirs, dir->ndirs, dir_name, sxfs_lsdir_cmp) >= 0) {
        SXFS_ERROR("Directory already exists: %s", path);
        ret = -EEXIST;
        goto sxfs_mkdir_err;
    }
    if((ret = sxfs_lsdir_add_dir(dir, path))) {
        SXFS_ERROR("Cannot add new directory to cache: %s", path);
        goto sxfs_mkdir_err;
    }
    if(sxfs->attribs) {
        dir->dirs[dir->ndirs-1]->st.st_mode = S_IFDIR | mode;
        dir->dirs[dir->ndirs-1]->st.st_uid = fuse_get_context()->uid;
        dir->dirs[dir->ndirs-1]->st.st_gid = fuse_get_context()->gid;
    }
    if((ret = sxfs_upload(NULL, remote_file_path, NULL, 0))) {
        SXFS_ERROR("Cannot upload empty file: %s", remote_file_path);
        sxfs_lsdir_free(dir->dirs[dir->ndirs-1]);
        dir->dirs[dir->ndirs-1] = NULL;
        dir->ndirs--;
        goto sxfs_mkdir_err;
    }
    if(sxfs->args->use_queues_flag) {
        dir->dirs[dir->ndirs-1]->sxnewdir = 1;
    } else {
        dir->dirs[dir->ndirs-1]->remote = 1;
        dir->dirs[dir->ndirs-1]->sxnewdir = 2;
    }
    for(i=dir->ndirs-1; i>0 && strcmp(dir->dirs[i-1]->name, dir->dirs[i]->name) > 0; i--) {
        sxfs_lsdir_t *tmp = dir->dirs[i-1];
        dir->dirs[i-1] = dir->dirs[i];
        dir->dirs[i] = tmp;
    }

    ret = 0;
sxfs_mkdir_err:
    pthread_mutex_unlock(&sxfs->ls_mutex);
    free(remote_file_path);
    return ret;
} /* sxfs_mkdir */

static int sxfs_unlink (const char *path) {
    int ret, index;
    size_t i;
    time_t mctime;
    char *file_name;
    sxfs_lsdir_t *dir;
    sxfs_file_t *sxfs_file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s'", path);
    if((ret = check_path_len(sxfs, path, 0))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    if((mctime = time(NULL)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
        return ret;
    }
    file_name = strrchr(path, '/');
    if(!file_name) {
        SXFS_ERROR("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name++;
    pthread_mutex_lock(&sxfs->ls_mutex);
    if((ret = sxfs_ls_update(path, &dir))) {
        SXFS_ERROR("Cannot load file tree: %s", path);
        goto sxfs_unlink_err;
    }
    index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
    if(index < 0) {
        SXFS_ERROR("File not found: %s", path);
        ret = -ENOENT;
        goto sxfs_unlink_err;
    }

    /* check whether this is the last entry in directory */
    if(dir->nfiles == 1 && !dir->ndirs && !dir->sxnewdir && strcmp(dir->name, "/")) {
        char *ptr, *newdir_file = (char*)malloc(strlen(path) + 1 + lenof(SXFS_SXNEWDIR) + 1);
        if(!newdir_file) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            goto sxfs_unlink_err;
        }
        sprintf(newdir_file, "%s", path);
        ptr = strrchr(newdir_file, '/');
        if(!ptr) {
            SXFS_ERROR("'/' not found in '%s'", newdir_file);
            free(newdir_file);
            ret = -EINVAL;
            goto sxfs_unlink_err;
        }
        ptr++;
        *ptr = '\0';
        strcat(newdir_file, SXFS_SXNEWDIR);
        if((ret = sxfs_upload(NULL, newdir_file, NULL, 0))) {
            SXFS_ERROR("Cannot upload empty file: %s", newdir_file);
            free(newdir_file);
            goto sxfs_unlink_err;
        }
        if(sxfs->args->use_queues_flag) {
            dir->sxnewdir = 1;
        } else {
            dir->remote = 1;
            dir->sxnewdir = 2;
        }
        free(newdir_file);
    }
    if((ret = sxfs_delete(path, dir->files[index]->remote, 0))) {
        SXFS_ERROR("Cannot remove file: %s", path);
        goto sxfs_unlink_err;
    }

    /* remove file from file tree */
    sxfs_lsfile_free(dir->files[index]);
    for(i=index+1; i<dir->nfiles; i++)
        dir->files[i-1] = dir->files[i];
    dir->files[dir->nfiles-1] = NULL;
    dir->nfiles--;
    dir->st.st_mtime = dir->st.st_ctime = mctime;

    /* mark the file to not try to upload it anymore */
    pthread_mutex_lock(&sxfs->files_mutex);
    if(!sxi_ht_get(sxfs->files, path, strlen(path), (void**)&sxfs_file)) {
        pthread_mutex_lock(&sxfs_file->mutex);
        sxfs_file->flush = -1;
        pthread_mutex_unlock(&sxfs_file->mutex);
    }
    pthread_mutex_unlock(&sxfs->files_mutex);

    ret = 0;
sxfs_unlink_err:
    pthread_mutex_unlock(&sxfs->ls_mutex);
    return ret;
} /* sxfs_unlink */

static int sxfs_rmdir (const char *path) {
    int ret, index;
    size_t i;
    time_t mctime;
    char *dir_name, *dirpath;
    sxfs_lsdir_t *dir;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s'", path);
    if((ret = check_path_len(sxfs, path, 1))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    if((mctime = time(NULL)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
        return ret;
    }
    dir_name = strrchr(path, '/');
    if(!dir_name) {
        SXFS_ERROR("'/' not found in '%s'", path);
        return -EINVAL;
    }
    dir_name++;
    dirpath = (char*)malloc(strlen(path) + 2);
    if(!dirpath) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    sprintf(dirpath, "%s/", path);
    pthread_mutex_lock(&sxfs->ls_mutex);
    if((ret = sxfs_ls_update(dirpath, &dir))) { /* loading content of deleting directory */
        SXFS_ERROR("Cannot load file tree: %s", dirpath);
        goto sxfs_rmdir_err;
    }
    if(dir->ndirs || dir->nfiles) {
        SXFS_ERROR("Directory not empty: %s", path);
        SXFS_DEBUG("> %s '.sxnewdir' file", dir->sxnewdir ? (dir->sxnewdir == 1 ? "Local" : "Remote") : "No");
        for(i=0; i<dir->nfiles; i++)
            SXFS_DEBUG("> %s", dir->files[i]->name);
        for(i=0; i<dir->ndirs; i++)
            SXFS_DEBUG("> %s/", dir->dirs[i]->name);
        ret = -ENOTEMPTY;
        goto sxfs_rmdir_err;
    }
    dir = dir->parent; /* go back to get deleting directory in dir->dirs[] */
    index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, dir_name, sxfs_lsdir_cmp);
    if(index < 0) { /* should never be true */
        SXFS_ERROR("Directory not found: %s", path);
        ret = -ENOENT;
        goto sxfs_rmdir_err;
    }

    /* check whether this is the last entry in directory */
    if(!dir->nfiles && dir->ndirs == 1 && !dir->sxnewdir && strcmp(dir->name, "/")) {
        char *ptr, *newdir_file = (char*)malloc(strlen(path) + 1 + lenof(SXFS_SXNEWDIR) + 1);
        if(!newdir_file) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            goto sxfs_rmdir_err;
        }
        sprintf(newdir_file, "%s", path);
        ptr = strrchr(newdir_file, '/');
        if(!ptr) {
            SXFS_ERROR("'/' not found in '%s'", newdir_file);
            free(newdir_file);
            ret = -EINVAL;
            goto sxfs_rmdir_err;
        }
        ptr++;
        *ptr = '\0';
        strcat(newdir_file, SXFS_SXNEWDIR);
        if((ret = sxfs_upload(NULL, newdir_file, NULL, 0))) {
            SXFS_ERROR("Cannot upload empty file: %s", newdir_file);
            free(newdir_file);
            goto sxfs_rmdir_err;
        }
        if(sxfs->args->use_queues_flag) {
            dir->sxnewdir = 1;
        } else {
            dir->remote = 1;
            dir->sxnewdir = 2;
        }
        free(newdir_file);
    }

    if((ret = sxfs_delete(dirpath, dir->dirs[index]->sxnewdir == 2 || dir->dirs[index]->remote, 0))) {
        SXFS_ERROR("Cannot remove directory: %s", dirpath);
        goto sxfs_rmdir_err;
    }

    /* remove directory from file tree */
    sxfs_lsdir_free(dir->dirs[index]);
    for(i=index+1; i<dir->ndirs; i++)
        dir->dirs[i-1] = dir->dirs[i];
    dir->dirs[dir->ndirs-1] = NULL;
    dir->ndirs--;
    dir->st.st_mtime = dir->st.st_ctime = mctime;

    ret = 0;
sxfs_rmdir_err:
    pthread_mutex_unlock(&sxfs->ls_mutex);
    free(dirpath);
    return ret;
} /* sxfs_rmdir */

static int sxfs_symlink (const char *path, const char *newpath) {
    return -ENOTSUP;
} /* sxfs_symlink*/

static int sxfs_rename (const char *path, const char *newpath) {
    int ret, operation_type, locked = 0, delete_queue_renamed = 0, upload_queue_renamed = 0, tmp_created = 0, sxnewdir = 0, is_remote = 0;
    ssize_t index_from, index_to;
    size_t i;
    char *file_name_from, *file_name_to, *src_path = NULL, *dst_path = NULL, *dst_path2 = NULL, *new_remote_path = NULL;
    time_t ctime;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *src = NULL, *dest = NULL;
    sxfs_lsdir_t *dir_from, *dir_to;
    sxfs_file_t *sxfs_file = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path || !newpath) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(*path != '/' || *newpath != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s' -> '%s'", path, newpath);
    if((ret = check_path_len(sxfs, path, 0))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    if((ret = check_path_len(sxfs, newpath, 0))) {
        SXFS_DEBUG("'%s' path is too long", newpath);
        return ret;
    }
    if(!strcmp(path, newpath))
        return -EINVAL;
    if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
        SXFS_ERROR("Cannot get SX data");
        return ret;
    }
    if((ctime = time(NULL)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
        return ret;
    }
    file_name_from = strrchr(path, '/');
    if(!file_name_from) {
        SXFS_ERROR("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name_from++;
    file_name_to = strrchr(newpath, '/');
    if(!file_name_to) {
        SXFS_ERROR("'/' not found in '%s'", newpath);
        return -EINVAL;
    }
    new_remote_path = strdup(newpath);
    if(!new_remote_path) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    file_name_to = strdup(file_name_to + 1);
    if(!file_name_to) {
        SXFS_ERROR("Out of memory: %s", strrchr(newpath, '/') + 1);
        ret = -ENOMEM;
        goto sxfs_rename_err;
    }
    src_path = (char*)malloc(strlen(path) + 1 + lenof(SXFS_SXNEWDIR) + 1);
    if(!src_path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_rename_err;
    }
    dst_path = (char*)malloc(strlen(newpath) + 1 + lenof(SXFS_SXNEWDIR) + 1);
    if(!dst_path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_rename_err;
    }
    dst_path2 = (char*)malloc(strlen(newpath) + lenof("_XXXXXX/") + 1);
    if(!dst_path2) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_rename_err;
    }
    pthread_mutex_lock(&sxfs->ls_mutex);
    locked |= SXFS_LS_MUTEX;
    if((ret = sxfs_ls_update(path, &dir_from))) {
        SXFS_ERROR("Cannot load file tree: %s", path);
        goto sxfs_rename_err;
    }
    if((ret = sxfs_ls_update(newpath, &dir_to))) {
        SXFS_ERROR("Cannot load file tree: %s", newpath);
        goto sxfs_rename_err;
    }
    index_from = sxfs_find_entry((const void**)dir_from->files, dir_from->nfiles, file_name_from, sxfs_lsfile_cmp);
    if(index_from >= 0) {
        operation_type = SXFS_RENAME_FILE;
        if(dir_from->nfiles == 1 && !dir_from->ndirs && dir_from != dir_to)
            sxnewdir = 1;
    } else {
        index_from = sxfs_find_entry((const void**)dir_from->dirs, dir_from->ndirs, file_name_from, sxfs_lsdir_cmp);
        if(index_from >= 0) {
            operation_type = SXFS_RENAME_DIR;
            if(dir_from->ndirs == 1 && !dir_from->nfiles && dir_from != dir_to)
                sxnewdir = 1;
        }
        else {
            ret = -ENOENT;
            goto sxfs_rename_err;
        }
    }
    index_to = sxfs_find_entry((const void**)dir_to->files, dir_to->nfiles, file_name_to, sxfs_lsfile_cmp);
    if(index_to >= 0) {
        if(operation_type == SXFS_RENAME_DIR) {
            SXFS_ERROR("New name is a file but old is a directory: '%s' and '%s'", path, newpath);
            ret = -ENOTDIR;
            goto sxfs_rename_err;
        }
    } else {
        index_to = sxfs_find_entry((const void**)dir_to->dirs, dir_to->ndirs, file_name_to, sxfs_lsdir_cmp);
        if(index_to >= 0) {
            if(operation_type == SXFS_RENAME_FILE) {
                SXFS_ERROR("New name is a directory but old is a file: '%s' and '%s'", path, newpath);
                ret = -EISDIR;
                goto sxfs_rename_err;
            }
        } else {
            if(operation_type == SXFS_RENAME_FILE) {
                if(dir_from != dir_to && dir_to->nfiles == dir_to->maxfiles && sxfs_resize((void**)&dir_to->files, &dir_to->maxfiles, sizeof(sxfs_lsfile_t*))) {
                    SXFS_ERROR("OOM growing file list: %s", strerror(errno));
                    ret = -ENOMEM;
                    goto sxfs_rename_err;
                }
            } else {
                if(dir_from != dir_to && dir_to->ndirs == dir_to->maxdirs && sxfs_resize((void**)&dir_to->dirs, &dir_to->maxdirs, sizeof(sxfs_lsdir_t*))) {
                    SXFS_ERROR("OOM growing directories list: %s", strerror(errno));
                    ret = -ENOMEM;
                    goto sxfs_rename_err;
                }
            }
        }
    }
    sprintf(src_path, "%s%s", path, operation_type == SXFS_RENAME_DIR ? "/" : "");
    sprintf(dst_path, "%s%s", newpath, operation_type == SXFS_RENAME_DIR ? "/" : "");
    if(sxfs->args->use_queues_flag && (ret = sxfs_delete_check_path(dst_path))) {
        SXFS_ERROR("Cannot check deletion queue: %s", dst_path);
        goto sxfs_rename_err;
    }
    if(operation_type == SXFS_RENAME_DIR && index_to >= 0) {
        sxfs_lsdir_t *dir;
        sprintf(dst_path, "%s/", newpath);
        if((ret = sxfs_ls_update(dst_path, &dir))) { /* load content of destination directory */
            SXFS_ERROR("Cannot load file tree: %s", dst_path);
            goto sxfs_rename_err;
        }
        if(dir->nfiles || dir->ndirs) {
            SXFS_ERROR("Destination directory not empty: %s", newpath);
            SXFS_DEBUG("> %s '.sxnewdir' file", dir->sxnewdir ? (dir->sxnewdir == 1 ? "Local" : "Remote") : "No");
            for(i=0; i<dir->nfiles; i++)
                SXFS_DEBUG("> %s", dir->files[i]->name);
            for(i=0; i<dir->ndirs; i++)
                SXFS_DEBUG("> %s/", dir->dirs[i]->name);
            ret = -ENOTEMPTY;
            goto sxfs_rename_err;
        }
    }
    if(!dir_from->sxnewdir && sxnewdir) {
        char *newdir_file = (char*)malloc(strlen(path) + 1 + lenof(SXFS_SXNEWDIR) + 1);
        if(!newdir_file) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            goto sxfs_rename_err;
        }
        sprintf(newdir_file, "%s/%s", path, SXFS_SXNEWDIR);
        if((ret = sxfs_upload(NULL, newdir_file, NULL, 0))) {
            SXFS_ERROR("Cannot upload empty file: %s", newdir_file);
            free(newdir_file);
            goto sxfs_rename_err;
        }
        if(sxfs->args->use_queues_flag) {
            dir_from->sxnewdir = 1;
        } else {
            dir_from->remote = 1;
            dir_from->sxnewdir = 2;
        }
        free(newdir_file);
    }
    if(index_to >= 0) {
        int fd;
        ssize_t index;
        char *tmp_name = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof("sxfs_namegen_XXXXXX") + 1), *name;

        if(!tmp_name) {
            SXFS_ERROR("Out of memory");
            goto sxfs_rename_err;
        }
        do {
            sprintf(tmp_name, "%s/sxfs_namegen_XXXXXX", sxfs->tempdir);
            fd = mkstemp(tmp_name);
            if(fd < 0) {
                ret = -errno;
                SXFS_ERROR("Cannot create unique temporary file: %s", strerror(errno));
                free(tmp_name);
                goto sxfs_rename_err;
            }
            close(fd);
            unlink(tmp_name);
            sprintf(dst_path2, "%s%s", newpath, tmp_name + strlen(tmp_name) - 7);
            name = strrchr(dst_path2, '/') + 1;
            index = sxfs_find_entry((const void**)dir_to->files, dir_to->nfiles, name, sxfs_lsfile_cmp);
            if(index < 0)
                index = sxfs_find_entry((const void**)dir_to->dirs, dir_to->ndirs, name, sxfs_lsdir_cmp);
        } while(index >= 0);
        free(tmp_name);
        if(operation_type == SXFS_RENAME_DIR)
            strcat(dst_path2, "/");
    }
    pthread_mutex_lock(&sxfs->files_mutex);
    locked |= SXFS_FILES_MUTEX;
    if(!sxi_ht_get(sxfs->files, path, strlen(path), (void**)&sxfs_file)) {
        if(sxi_ht_add(sxfs->files, newpath, strlen(newpath), sxfs_file)) {
            SXFS_ERROR("Cannot add new file to the hashtable: %s", newpath);
            ret = -ENOMEM;
            goto sxfs_rename_err;
        }
    } else { /* no need to hold this lock when there is no operation on sxfs->files
             ** and without the lock sxfs can be slightly faster */
        pthread_mutex_unlock(&sxfs->files_mutex);
        locked &= ~SXFS_FILES_MUTEX;
    }
    if(sxfs->args->use_queues_flag) {
        if(operation_type == SXFS_RENAME_DIR && (ret = sxfs_delete_rename_prepare(src_path, dst_path))) { /* there can be something deleted inside directory being renamed */
            if(ret < 0) {
                SXFS_ERROR("Cannot initialize deletion queue renaming");    
                goto sxfs_rename_err;
            }
            delete_queue_renamed = 1;
        }
        if(index_to >= 0 && (ret = sxfs_upload_rename_prepare(dst_path, dst_path2))) {
            if(ret < 0) {
                SXFS_ERROR("Cannot initialize temporary upload queue renaming");
                goto sxfs_rename_err;
            }
            tmp_created = 1;
        }
        if((ret = sxfs_upload_rename_prepare(src_path, dst_path))) {
            if(ret < 0) {
                SXFS_ERROR("Cannot initialize upload queue renaming");
                goto sxfs_rename_err;
            }
            upload_queue_renamed = 1;
        }
    }
    /* move remote file */
    if((operation_type == SXFS_RENAME_FILE && dir_from->files[index_from]->remote) || (operation_type == SXFS_RENAME_DIR && dir_from->dirs[index_from]->remote))
        is_remote = 1;
    if(!is_remote && sxfs_upload_remote_check(sxfs, src_path)) {
        is_remote = 1;
        if(operation_type == SXFS_RENAME_FILE)
            dir_from->files[index_from]->remote = 1;
        else
            dir_from->dirs[index_from]->remote = 1;
    }
    if(is_remote) {
        int r;

        src = sxc_file_remote(cluster, sxfs->uri->volume, src_path+1, NULL);
        if(!src) {
            SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_rename_err;
        }
        dest = sxc_file_remote(cluster, sxfs->uri->volume, dst_path+1, NULL);
        if(!dest) {
            SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_rename_err;
        }

        if((r = sxc_mass_rename(cluster, src, dest, 1))) {
            if(r == -2) {
                /* Mass operation requested on a volume with filename processing filter, falling back to sxc_copy + sxc_rm method */
                sxc_clearerr(sx);

                if(sxc_copy_single(src, dest, 1, 0, 0, NULL, 0)) {
                    SXFS_ERROR("Cannot copy '%s' file: %s", path, sxc_geterrmsg(sx));
                    ret = -sxfs_sx_err(sx);
                    goto sxfs_rename_err;
                }

                if((ret = sxfs_delete(src_path, 1, 1))) {
                    SXFS_ERROR("Failed to remove source file");
                    goto sxfs_rename_err;
                }
            } else { /* Rename operation failed */
                SXFS_ERROR("%s", sxc_geterrmsg(sx));
                ret = -sxfs_sx_err(sx);
                goto sxfs_rename_err;
            }
        }
    }

    /* update remote path in file structure */
    if(sxfs_file) {
        free(sxfs_file->remote_path);
        sxfs_file->remote_path = new_remote_path;
        new_remote_path = NULL;
    }

    /* rename queues entries */
    sxfs_delete_rename(src_path, dst_path);
    if(index_to >= 0)
        sxfs_upload_rename(dst_path, dst_path2);
    sxfs_upload_rename(src_path, dst_path);

    /* file tree update */
    if(operation_type == SXFS_RENAME_FILE) { /* renaming file */
        sxfs_lsfile_t *file = dir_from->files[index_from];
        free(file->name);
        file->name = file_name_to;
        file_name_to = NULL;
        for(i=index_from+1; i<dir_from->nfiles; i++)
            dir_from->files[i-1] = dir_from->files[i];
        dir_from->files[dir_from->nfiles-1] = NULL;
        dir_from->nfiles--;
        if(index_to >= 0) {
            if(dir_from == dir_to && index_from < index_to)
                index_to--;
            sxfs_lsfile_free(dir_to->files[index_to]);
            dir_to->files[index_to] = file;
        } else {
            for(i=dir_to->nfiles; i>0 && strcmp(dir_to->files[i-1]->name, file->name) > 0; i--)
                dir_to->files[i] = dir_to->files[i-1];
            dir_to->files[i] = file;
            dir_to->nfiles++;
        }
        file->st.st_ctime = ctime;
    } else { /* renaming directory */
        sxfs_lsdir_t *dir = dir_from->dirs[index_from];
        free(dir->name);
        dir->name = file_name_to;
        file_name_to = NULL;
        for(i=index_from+1; i<dir_from->ndirs; i++)
            dir_from->dirs[i-1] = dir_from->dirs[i];
        dir_from->dirs[dir_from->ndirs-1] = NULL;
        dir_from->ndirs--;
        dir->parent = dir_to;
        if(index_to >= 0) {
            if(dir_from == dir_to && index_from < index_to)
                index_to--;
            sxfs_lsdir_free(dir_to->dirs[index_to]);
            dir_to->dirs[index_to] = dir;
        } else {
            for(i=dir_to->ndirs; i>0 && strcmp(dir_to->dirs[i-1]->name, dir->name) > 0; i--)
                dir_to->dirs[i] = dir_to->dirs[i-1];
            dir_to->dirs[i] = dir;
            dir_to->ndirs++;
        }
        dir->st.st_ctime = ctime;
    }

    ret = 0;
sxfs_rename_err:
    if(ret) {
        if(delete_queue_renamed)
            sxfs_delete_rename_abort(src_path);
        if(upload_queue_renamed)
            sxfs_upload_rename_abort(src_path);
        if(tmp_created)
            sxfs_upload_rename_abort(dst_path);
    } else if(tmp_created) {
        sxfs_delete(dst_path2, 0, 0);
    }
    if(locked & SXFS_FILES_MUTEX) {
        sxi_ht_del(sxfs->files, ret ? newpath : path, strlen(ret ? newpath : path));
        pthread_mutex_unlock(&sxfs->files_mutex);
    }
    if(locked & SXFS_LS_MUTEX)
        pthread_mutex_unlock(&sxfs->ls_mutex);
    free(new_remote_path);
    free(file_name_to);
    free(src_path);
    free(dst_path);
    free(dst_path2);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* sxfs_rename */

static int sxfs_link (const char *path, const char *newpath) {
    return -ENOTSUP;
} /* sxfs_link*/

static int sxfs_update_filemeta (const char *path, int function, mode_t mode, uid_t uid, gid_t gid, time_t mtime) {
    int ret, files_locked = 0;
    ssize_t index;
    time_t ctime;
    char *path2 = NULL, *file_name;
    sxfs_lsdir_t *dir;
    sxfs_state_t *sxfs = SXFS_DATA;

    switch(function) {
        case SXFS_CHMOD: {
            sxfs_log(sxfs, "sxfs_chmod", SXFS_LOG_TYPE_DEBUG, "'%s', mode: %c%c%c%c%c%c%c%c%c%c (%o)", path, S_ISDIR(mode) ? 'd' : '-',
                mode & S_IRUSR ? 'r' : '-', mode & S_IWUSR ? 'w' : '-', mode & S_IXUSR ? 'x' : '-',
                mode & S_IRGRP ? 'r' : '-', mode & S_IWGRP ? 'w' : '-', mode & S_IXGRP ? 'x' : '-',
                mode & S_IROTH ? 'r' : '-', mode & S_IWOTH ? 'w' : '-', mode & S_IXOTH ? 'x' : '-', (unsigned int)mode); /* there will be S_IRUSR and S_IWUSR added */
            break;
        }
        case SXFS_CHOWN: {
            sxfs_log(sxfs, "sxfs_chown", SXFS_LOG_TYPE_DEBUG, "'%s', uid: %d, gid: %d", path, (int)uid, (int)gid);
            break;
        }
        case SXFS_UTIMENS: {
            struct tm *tm = localtime(&mtime);
            if(tm)
                sxfs_log(sxfs, "sxfs_utimens", SXFS_LOG_TYPE_DEBUG, "'%s', mtime: %02d-%02d-%04d %02d:%02d:%02d (%ld)", path, tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec, (long int)mtime);
            else
                sxfs_log(sxfs, "sxfs_utimens", 1, "'%s, mtime: %ld'", path, (long int)mtime);
            break;
        }
        default: break;
    }
    if(!path) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    if((ret = check_path_len(sxfs, path, 0))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    if((ctime = time(NULL)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
        return ret;
    }
    if(!strcmp(path, "/")) {
        pthread_mutex_lock(&sxfs->ls_mutex);
        switch(function) {
            case SXFS_CHMOD:
                if(sxfs->attribs)
                    sxfs->root->st.st_mode = mode;
                break;
            case SXFS_CHOWN:
                if(sxfs->attribs) {
                    if((int)uid >= 0)
                        sxfs->root->st.st_uid = uid;
                    if((int)gid >= 0)
                        sxfs->root->st.st_gid = gid;
                }
                break;
            case SXFS_UTIMENS:
                sxfs->root->st.st_mtime = mtime;
                break;
            default: break;
        }
        sxfs->root->st.st_ctime = ctime;
        pthread_mutex_unlock(&sxfs->ls_mutex);
        return 0;
    }
    if(strlen(path) > 1 && path[strlen(path)-1] == '/') {
        path2 = strdup(path);
        if(!path2) {
            SXFS_ERROR("Out of memory: %s", path);
            return -ENOMEM;
        }
        path2[strlen(path2)-1] = '\0';
    }
    file_name = strrchr(path2 ? path2 : path, '/');
    if(!file_name) {
        SXFS_ERROR("'/' not found in '%s'", path2 ? path2 : path);
        free(path2);
        return -EINVAL;
    }
    file_name++;
    pthread_mutex_lock(&sxfs->ls_mutex);
    if((ret = sxfs_ls_update(path2 ? path2 : path, &dir))) {
        SXFS_ERROR("Cannot load file tree: %s", path2 ? path2 : path);
        goto sxfs_update_filemeta_err;
    }
    index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp);
    if(index >= 0) {
        switch(function) {
            case SXFS_CHMOD:
                if(sxfs->attribs)
                    dir->dirs[index]->st.st_mode = mode;
                break;
            case SXFS_CHOWN:
                if(sxfs->attribs) {
                    if((int)uid >= 0)
                        dir->dirs[index]->st.st_uid = uid;
                    if((int)gid >= 0)
                        dir->dirs[index]->st.st_gid = gid;
                }
                break;
            case SXFS_UTIMENS:
                if(sxfs->attribs)
                    dir->dirs[index]->st.st_mtime = mtime;
                break;
            default: break;
        }
        dir->dirs[index]->st.st_ctime = ctime;
    } else {
        index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
        if(index >= 0) {
            if(sxfs->attribs) {
                sxfs_file_t *sxfs_file = NULL;

                pthread_mutex_lock(&sxfs->files_mutex);
                files_locked = 1;
                if(dir->files[index]->opened && sxi_ht_get(sxfs->files, path, strlen(path), (void**)&sxfs_file)) {
                    SXFS_ERROR("File not opened: %s", path);
                    ret = -EFAULT;
                    goto sxfs_update_filemeta_err;
                }
                if(function == SXFS_CHMOD)
                    mode |= S_IRUSR | S_IWUSR; /* sxfs has to have the ability to upload and perform I/O operations on the file */
                if(!sxfs_file || !sxfs_file->write_path) {
                    if(dir->files[index]->remote) {
                        int fail = 1, meta_fail = 0;
                        uint32_t val32;
                        uint64_t val64;
                        sxc_file_t *file;
                        sxc_meta_t *newmeta;
                        sxc_client_t *sx;
                        sxc_cluster_t *cluster;

                        if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
                            SXFS_ERROR("Cannot get SX data");
                            goto sxfs_update_filemeta_err;
                        }
                        file = sxc_file_remote(cluster, sxfs->uri->volume, path+1, NULL);
                        if(!file) {
                            SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
                            ret = -sxfs_sx_err(sx);
                            goto sxfs_update_filemeta_err;
                        }
                        do {
                            newmeta = sxc_meta_new(sx);
                            if(!newmeta) {
                                SXFS_ERROR("Cannot create new meta: %s", sxc_geterrmsg(sx));
                                ret = -sxfs_sx_err(sx);
                                break;
                            }
                            switch(function) {
                                case SXFS_CHMOD: {
                                    val32 = sxi_swapu32(mode);
                                    if(sxc_meta_setval(newmeta, "attribsMode", &val32, sizeof(val32))) {
                                        SXFS_ERROR("Out of memory");
                                        ret = -ENOMEM;
                                        meta_fail = 1;
                                    }
                                    break;
                                }
                                case SXFS_CHOWN: {
                                    if((int)uid >= 0) {
                                        val32 = sxi_swapu32(uid);
                                        if(sxc_meta_setval(newmeta, "attribsUID", &val32, sizeof(val32))) {
                                            SXFS_ERROR("Out of memory");
                                            ret = -ENOMEM;
                                            meta_fail = 1;
                                        }
                                    }
                                    if((int)gid >= 0) {
                                        val32 = sxi_swapu32(gid);
                                        if(sxc_meta_setval(newmeta, "attribsGID", &val32, sizeof(val32))) {
                                            SXFS_ERROR("Out of memory");
                                            ret = -ENOMEM;
                                            meta_fail = 1;
                                        }
                                    }
                                    break;
                                }
                                case SXFS_UTIMENS: {
                                    val64 = sxi_swapu64(mtime);
                                    if(sxc_meta_setval(newmeta, "attribsMtime", &val64, sizeof(val64))) {
                                        SXFS_ERROR("Out of memory");
                                        ret = -ENOMEM;
                                        meta_fail = 1;
                                    }
                                    if(sxc_meta_setval(newmeta, "attribsAtime", &val64, sizeof(val64))) {
                                        SXFS_ERROR("Out of memory");
                                        ret = -ENOMEM;
                                        meta_fail = 1;
                                    }
                                    break;
                                }
                                default: break;
                            }
                            if(meta_fail)
                                break;
                            if(sxc_update_filemeta(file, newmeta)) {
                                SXFS_ERROR("Cannot update filemeta: %s", sxc_geterrmsg(sx));
                                ret = -sxfs_sx_err(sx);
                                break;
                            }
                            fail = 0;
                        } while(0);
                        sxc_file_free(file);
                        sxc_meta_free(newmeta);
                        if(fail)
                            goto sxfs_update_filemeta_err;
                    }
                } else if(!sxfs_file->flush) {
                    sxfs_file->flush = 1;
                }
                switch(function) {
                    case SXFS_CHMOD:
                        if(sxfs->attribs)
                            dir->files[index]->st.st_mode = mode;
                        break;
                    case SXFS_CHOWN:
                        if(sxfs->attribs) {
                            if((int)uid >= 0)
                                dir->files[index]->st.st_uid = uid;
                            if((int)gid >= 0)
                                dir->files[index]->st.st_gid = gid;
                        }
                        break;
                    case SXFS_UTIMENS:
                        dir->files[index]->st.st_mtime = mtime;
                        break;
                    default: break;
                }
            }
            dir->files[index]->st.st_ctime = ctime;
        } else {
            SXFS_ERROR("%s: %s", strerror(ENOENT), path2 ? path2 : path);
            ret = -ENOENT;
            goto sxfs_update_filemeta_err;
        }
    }

    ret = 0;
sxfs_update_filemeta_err:
    pthread_mutex_unlock(&sxfs->ls_mutex);
    if(files_locked)
        pthread_mutex_unlock(&sxfs->files_mutex);
    free(path2);
    return ret;
} /* sxfs_update_filemeta */

static int sxfs_chmod (const char *path, mode_t mode) {
    return sxfs_update_filemeta(path, SXFS_CHMOD, mode, 0, 0, 0);
} /* sxfs_chmod */

static int sxfs_chown (const char *path, uid_t uid, gid_t gid) {
    return sxfs_update_filemeta(path, SXFS_CHOWN, 0, uid, gid, 0);
} /* sxfs_chown */

static int sxfs_truncate (const char *path, off_t length) {
    int ret, fd = -1, locked = 0;
    ssize_t index;
    char *file_name, *local_file_path = NULL;
    time_t mctime;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxfs_lsdir_t *dir;
    sxfs_file_t *sxfs_file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    if(length < 0) {
        SXFS_ERROR("Negative size");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s' (length: %lld)", path, (long long int)length);
    if((ret = check_path_len(sxfs, path, 0))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    if((mctime = time(NULL)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
        return ret;
    }
    file_name = strrchr(path, '/');
    if(!file_name) {
        SXFS_ERROR("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name++;
    pthread_mutex_lock(&sxfs->ls_mutex);
    if((ret = sxfs_ls_update(path, &dir))) {
        SXFS_ERROR("Cannot load file tree: %s", path);
        goto sxfs_truncate_err;
    }
    index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp);
    if(index >= 0) {
        SXFS_ERROR("Named file is a directory: %s", path);
        ret = -EISDIR;
        goto sxfs_truncate_err;
    }
    index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
    if(index < 0) {
        SXFS_ERROR("%s: %s", strerror(ENOENT), path);
        ret = -ENOENT;
        goto sxfs_truncate_err;
    }
    if(dir->files[index]->st.st_size != length) {
        pthread_mutex_lock(&sxfs->files_mutex);
        locked |= SXFS_FILES_MUTEX;
        if(!sxi_ht_get(sxfs->files, path, strlen(path), (void**)&sxfs_file)) {
            if(sxfs_file->write_fd >= 0) {
                SXFS_DEBUG("'%s': Using file descriptor: %d", path, sxfs_file->write_fd);
                if(ftruncate(sxfs_file->write_fd, length)) {
                    if(errno == ENOSPC)
                        ret = -ENOBUFS;
                    else
                        ret = -errno;
                    SXFS_ERROR("Cannot set '%s' size to %lld: %s", sxfs_file->write_path, (long long int)length, strerror(errno));
                    goto sxfs_truncate_err;
                }
                if(!sxfs_file->flush)
                    sxfs_file->flush = 1;
            }
        } else {
            sxfs_file = NULL;
        }
        ret = 0;
        if((!sxfs_file || sxfs_file->write_fd < 0) && (!sxfs->args->use_queues_flag || (ret = sxfs_upload_truncate(path, length)))) {
            if(ret && ret != -ENOENT) {
                if(ret == -ENOSPC)
                    ret = -ENOBUFS;
                goto sxfs_truncate_err;
            }
            local_file_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + strlen("file_XXXXXX") + 1);
            if(!local_file_path) {
                SXFS_ERROR("Out of memory");
                ret = -ENOMEM;
                goto sxfs_truncate_err;
            }
            sprintf(local_file_path, "%s/file_XXXXXX", sxfs->tempdir);
            fd = mkstemp(local_file_path);
            if(fd < 0) {
                ret = -errno;
                SXFS_ERROR("Cannot create unique temporary file: %s", strerror(errno));
                goto sxfs_truncate_err;
            }
            if(length) {
                ssize_t retval;
                off_t to_read, offset = 0;
                char buff[SX_BS_LARGE + 1];
                sxfs_file_t *tmp_sxfs_file = NULL, *sxfs_file_ptr;

                if(!sxfs_file) {
                    if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
                        SXFS_ERROR("Cannot get SX data");
                        goto sxfs_truncate_err;
                    }
                    tmp_sxfs_file = (sxfs_file_t*)calloc(1, sizeof(sxfs_file_t));
                    if(!tmp_sxfs_file) {
                        SXFS_ERROR("Out of memory");
                        ret = -ENOMEM;
                        goto sxfs_truncate_err;
                    }
                    tmp_sxfs_file->write_fd = -1;
                    tmp_sxfs_file->ls_file = dir->files[index];
                    tmp_sxfs_file->remote_path = strdup(path);
                    if(!tmp_sxfs_file->remote_path) {
                        SXFS_ERROR("Out of memory");
                        ret = -ENOMEM;
                        free(tmp_sxfs_file);
                        goto sxfs_truncate_err;
                    }
                    if((ret = pthread_mutex_init(&tmp_sxfs_file->mutex, NULL))) {
                        SXFS_ERROR("Cannot create files data mutex: %s", strerror(ret));
                        ret = -ret;
                        free(tmp_sxfs_file->remote_path);
                        free(tmp_sxfs_file);
                        goto sxfs_truncate_err;
                    }
                    sxc_file_t *file_remote = sxc_file_remote(cluster, sxfs->uri->volume, path+1, NULL);
                    if(!file_remote) {
                        SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
                        ret = -sxfs_sx_err(sx);
                        sxfs_file_free(sxfs, tmp_sxfs_file);
                        goto sxfs_truncate_err;
                    }
                    tmp_sxfs_file->fdata = sxi_sxfs_download_init(file_remote);
                    if(!tmp_sxfs_file->fdata) {
                        SXFS_ERROR("Cannot initialize file downloading: %s", sxc_geterrmsg(sx));
                        ret = -sxfs_sx_err(sx);
                        sxfs_file_free(sxfs, tmp_sxfs_file);
                        sxc_file_free(file_remote);
                        goto sxfs_truncate_err;
                    }
                    sxc_file_free(file_remote);
                    sxfs_file_ptr = tmp_sxfs_file;
                } else {
                    sxfs_file_ptr = sxfs_file;
                }
                to_read = MIN(sxfs_file_ptr->fdata->filesize, length);
                while(to_read) {
                    if((retval = sxfs_cache_read(sxfs, sxfs_file_ptr, buff, MIN(to_read, sxfs_file_ptr->fdata->blocksize), offset)) < 0) {
                        SXFS_ERROR("Cannot read the cache: %s", strerror(-retval));
                        ret = retval;
                        sxfs_file_free(sxfs, tmp_sxfs_file);
                        goto sxfs_truncate_err;
                    }
                    if(!retval) /* EOF */
                        break;
                    if(write(fd, buff, retval) < 0) {
                        ret = -errno;
                        SXFS_ERROR("Cannot write to '%s' file: %s", local_file_path, strerror(errno));
                        sxfs_file_free(sxfs, tmp_sxfs_file);
                        goto sxfs_truncate_err;
                    }
                    to_read -= retval;
                    offset += retval;
                }
                sxfs_file_free(sxfs, tmp_sxfs_file);
                if(ftruncate(fd, length)) {
                    if(errno == ENOSPC)
                        ret = -ENOBUFS;
                    else
                        ret = -errno;
                    SXFS_ERROR("Cannot set '%s' size to %lld: %s", local_file_path, (long long int)length, strerror(errno));
                    goto sxfs_truncate_err;
                }
            }
            if(sxfs_file) {
                sxfs_file->write_fd = fd;
                sxfs_file->write_path = local_file_path;
                fd = -1;
                local_file_path = NULL;
                SXFS_DEBUG("'%s': New file descriptor: %d", path, sxfs_file->write_fd);
                if(!sxfs_file->flush)
                    sxfs_file->flush = 1;
            } else {
                time_t mtime = dir->files[index]->st.st_mtime, ctime = dir->files[index]->st.st_ctime;
                off_t size = dir->files[index]->st.st_size;

                if(sxfs->attribs) { /* set file attributes BEFORE file upload (in case of no queues) */
                    dir->files[index]->st.st_size = length;
                    dir->files[index]->st.st_blocks = (length + 511) / 512;
                    dir->files[index]->st.st_mtime = dir->files[index]->st.st_ctime = mctime;
                }

                if((ret = sxfs_upload(local_file_path, path, dir->files[index], 0))) {
                    SXFS_ERROR("Cannot upload file: %s", path);
                    dir->files[index]->st.st_size = size;
                    dir->files[index]->st.st_blocks = (size + 511) / 512;
                    dir->files[index]->st.st_mtime = mtime;
                    dir->files[index]->st.st_ctime = ctime;
                    goto sxfs_truncate_err;
                }
                free(local_file_path);
                local_file_path = NULL;
            }
        }
        dir->files[index]->st.st_size = length;
        dir->files[index]->st.st_blocks = (length + 511) / 512;
        dir->files[index]->st.st_mtime = dir->files[index]->st.st_ctime = mctime;
    }

    ret = 0;
sxfs_truncate_err:
    pthread_mutex_unlock(&sxfs->ls_mutex);
    if(locked & SXFS_FILES_MUTEX)
        pthread_mutex_unlock(&sxfs->files_mutex);
    if(fd >= 0 && close(fd))
        SXFS_ERROR("Cannot close '%s' file: %s", local_file_path, strerror(errno));
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        SXFS_ERROR("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    return ret;
} /* sxfs_truncate */

static int sxfs_open (const char *path, struct fuse_file_info *file_info) {
    int ret, fd = -1, locked = 0, file_moved = 0, file_created = 0, file_stored = 0;
    size_t i;
    ssize_t index;
    time_t mctime;
    char *local_file_path = NULL, *file_name;
    sxfs_lsdir_t *dir;
    sxfs_file_t *sxfs_file = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path || !file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s' (%s%s %s)", path, file_info->flags & (O_RDONLY | O_RDWR) ? "r" : "-", file_info->flags & (O_WRONLY | O_RDWR) ? "w" : "-", file_info->flags & O_TRUNC ? "t" : "-");
    if((ret = check_path_len(sxfs, path, 0))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    file_info->fh = 0;
    file_name = strrchr(path, '/');
    if(!file_name) {
        SXFS_ERROR("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name++;
    if((mctime = time(NULL)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
        return ret;
    }
    pthread_mutex_lock(&sxfs->ls_mutex);
    if((ret = sxfs_ls_update(path, &dir))) { /* no creation flag is passed by FUSE */
        SXFS_ERROR("Cannot load file tree: %s", path);
        goto sxfs_open_err;
    }
    index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
    if(index < 0) {
        SXFS_ERROR("%s", strerror(ENOENT));
        ret = -ENOENT;
        goto sxfs_open_err;
    }
    local_file_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof("file_XXXXXX") + 1);
    if(!local_file_path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_open_err;
    }
    sprintf(local_file_path, "%s/file_XXXXXX", sxfs->tempdir);
    fd = mkstemp(local_file_path);
    if(fd < 0) { 
        ret = -errno;
        SXFS_ERROR("Cannot create unique temporary file: %s", strerror(errno));
        goto sxfs_open_err;
    }
    pthread_mutex_lock(&sxfs->files_mutex);
    locked |= SXFS_FILES_MUTEX;
    if(sxi_ht_get(sxfs->files, path, strlen(path), (void**)&sxfs_file)) {
        /* file not yet opened */
        sxfs_file = (sxfs_file_t*)calloc(1, sizeof(sxfs_file_t));
        if(!sxfs_file) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            goto sxfs_open_err;
        }
        sxfs_file->write_fd = -1;
        sxfs_file->ls_file = dir->files[index];
        if((ret = pthread_mutex_init(&sxfs_file->mutex, NULL))) {
            SXFS_ERROR("Cannot create files data mutex: %s", strerror(ret));
            ret = -ret;
            free(sxfs_file);
            goto sxfs_open_err;
        }
        if(sxi_ht_add(sxfs->files, path, strlen(path), sxfs_file)) {
            SXFS_ERROR("Cannot add new file to the hashtable: %s", path);
            free(sxfs_file);
            ret = -ENOMEM;
            goto sxfs_open_err;
        }
        file_created = 1;
        sxfs_file->remote_path = strdup(path);
        if(!sxfs_file->remote_path) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            goto sxfs_open_err;
        }
        if(sxfs->args->use_queues_flag) {
            if(file_info->flags & O_TRUNC) {
                sxfs_upload_del_path(path);
            } else if((ret = sxfs_upload_get_file(path, sxfs_file))) { /* try to use file from upload queue */
                if(ret != -ENOENT) {
                    SXFS_ERROR("Cannot get '%s' file from upload queue", path);
                    goto sxfs_open_err;
                }
            } else {
                SXFS_VERBOSE("Using file from upload queue");
                file_moved = 2;
                SXFS_DEBUG("'%s': New file descriptor: %d", path, sxfs_file->write_fd);
            }
        }
    } else {
        SXFS_DEBUG("'%s' file already opened %lu times", path, sxfs_file->num_open);
        if(file_info->flags & O_TRUNC && sxfs_file->write_fd >= 0 && ftruncate(sxfs_file->write_fd, 0)) {
            if(errno == ENOSPC)
                ret = -ENOBUFS;
            else
                ret = -errno;
            SXFS_ERROR("Cannot truncate '%s' file: %s", sxfs_file->write_path, strerror(errno));
            goto sxfs_open_err;
        }
    }
    pthread_mutex_lock(&sxfs->limits_mutex);
    for(i=0; i<sxfs->fh_limit; i++) {
        if(!sxfs->fh_table[i]) {
            file_info->fh = (uint64_t)i;
            sxfs->fh_table[i] = sxfs_file;
            break;
        }
    }
    pthread_mutex_unlock(&sxfs->limits_mutex);
    if(i == sxfs->fh_limit) {
        SXFS_ERROR("%s", strerror(ENFILE));
        ret = -ENFILE;
        goto sxfs_open_err;
    }
    file_stored = 1;
    if(file_info->flags & O_TRUNC) {
        if(sxfs_file->write_fd < 0) {
            sxfs_file->write_path = local_file_path;
            sxfs_file->write_fd = fd;
            local_file_path = NULL;
            fd = -1;
            SXFS_DEBUG("New file descriptor: %d", sxfs_file->write_fd);
        }
        if(sxfs_file->ls_file->st.st_size) {
            sxfs_file->ls_file->st.st_size = 0;
            sxfs_file->ls_file->st.st_mtime = sxfs_file->ls_file->st.st_ctime = mctime;
            if(!sxfs_file->flush)
                sxfs_file->flush = 1;
        }
    } else if(sxfs_file->write_fd < 0 && !sxfs_file->fdata) {
        sxc_client_t *sx;
        sxc_cluster_t *cluster;
        sxc_file_t *file_remote;

        if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
            SXFS_ERROR("Cannot get SX data");
            goto sxfs_open_err;
        }
        file_remote = sxc_file_remote(cluster, sxfs->uri->volume, path+1, NULL);
        if(!file_remote) {
            SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_open_err;
        }
        sxfs_file->fdata = sxi_sxfs_download_init(file_remote);
        if(!sxfs_file->fdata) {
            SXFS_ERROR("Cannot initialize file downloading: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            sxc_file_free(file_remote);
            goto sxfs_open_err;
        }
        sxc_file_free(file_remote);
    }
    sxfs_file->num_open++;
    sxfs_file->ls_file->opened |= SXFS_FILE_OPENED;
    pthread_mutex_lock(&sxfs->limits_mutex);
    sxfs->fh_table[file_info->fh] = sxfs_file;
    pthread_mutex_unlock(&sxfs->limits_mutex);
    SXFS_DEBUG("New file handle: %llu", (unsigned long long int)file_info->fh);
    if(sxfs_file->fdata)
        SXFS_VERBOSE("Blocksize: %u, hashes: %u", sxfs_file->fdata->blocksize, sxfs_file->fdata->nhashes);

    ret = 0;
sxfs_open_err:
    if(fd >= 0 && close(fd))
        SXFS_ERROR("Cannot close '%s' file: %s", local_file_path ? local_file_path : sxfs_file->write_path, strerror(errno));
    if(ret) {
        if(file_stored) {
            pthread_mutex_lock(&sxfs->limits_mutex);
            sxfs->fh_table[file_info->fh] = NULL;
            pthread_mutex_unlock(&sxfs->limits_mutex);
        }
        file_info->fh = 0;
        if(file_created) {
            sxi_ht_del(sxfs->files, path, strlen(path));
            sxfs_file_free(sxfs, sxfs_file);
        }
    } else if(file_moved) {
        sxfs_upload_del_path(path);
    }
    pthread_mutex_unlock(&sxfs->ls_mutex);
    if(locked & SXFS_FILES_MUTEX)
        pthread_mutex_unlock(&sxfs->files_mutex);
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        SXFS_ERROR("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    return ret;
} /* sxfs_open */

static int sxfs_read (const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *file_info) {
    int ret;
    ssize_t retval;
    size_t read = 0;
    sxfs_file_t *sxfs_file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!buf || !file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(path && *path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(path && *path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_VERBOSE("'%s' (fd: %llu, size: %llu; offset: %lld)", path, (unsigned long long int)file_info->fh, (unsigned long long int)size, (long long int)offset);
    if(offset < 0) {
        SXFS_ERROR("Negative offset");
        return -EINVAL;
    }
    FH_CHECK(file_info->fh);
    while(size) {
        retval = sxfs_cache_read(sxfs, sxfs_file, buf+read, size, offset);
        if(retval < 0) {
            ret = retval;
            SXFS_ERROR("Cannot read data from cache");
            goto sxfs_read_err;
        }
        if(!retval) /* EOF */
            break;
        read += retval;
        size -= retval;
        offset += retval;
    }
    SXFS_VERBOSE("Read %lld bytes", (long long int)read);

    ret = read;
sxfs_read_err:
    return ret;
} /* sxfs_read */

static int sxfs_write (const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *file_info) {
    int ret;
    struct stat st;
    sxfs_file_t *sxfs_file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!buf || !file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(path && *path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(path && *path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_VERBOSE("'%s' (fd: %llu, size: %llu; offset: %lld)", path, (unsigned long long int)file_info->fh, (unsigned long long int)size, (long long int)offset);
    if(offset < 0) {
        SXFS_ERROR("Negative offset");
        return -EINVAL;
    }
    FH_CHECK(file_info->fh);
    if(sxfs_file->write_fd >= 0) {
        SXFS_VERBOSE("Using file descriptor: %d", sxfs_file->write_fd);
    } else if((ret = sxfs_get_file(sxfs, sxfs_file))) {
        SXFS_ERROR("Cannot download '%s' file", sxfs_file->remote_path);
        return ret;
    }
    ret = pwrite(sxfs_file->write_fd, buf, size, offset);
    if(ret < 0) {
        if(errno == ENOSPC)
            ret = -ENOBUFS;
        else
            ret = -errno;
        SXFS_ERROR("Cannot write data to '%s' file: %s", sxfs_file->write_path, strerror(errno));
    } else {
        SXFS_VERBOSE("Wrote %d bytes", ret); /* FUSE defines write() to return int */
        pthread_mutex_lock(&sxfs_file->mutex);
        if(!sxfs_file->flush)
            sxfs_file->flush = 1;
        pthread_mutex_unlock(&sxfs_file->mutex);
        pthread_mutex_lock(&sxfs->ls_mutex);
        if(fstat(sxfs_file->write_fd, &st)) {
            pthread_mutex_unlock(&sxfs->ls_mutex);
            ret = -errno;
            SXFS_ERROR("Cannot stat %s file: %s", sxfs_file->write_path, strerror(errno));
            return ret;
        }
        sxfs_file->ls_file->st.st_mtime = st.st_mtime;
        sxfs_file->ls_file->st.st_ctime = st.st_ctime;
        sxfs_file->ls_file->st.st_size = st.st_size;
        sxfs_file->ls_file->st.st_blocks = (st.st_size + 511) / 512;
        pthread_mutex_unlock(&sxfs->ls_mutex);
    }
    return ret;
} /* sxfs_write */

static int sxfs_statfs (const char *path, struct statvfs *st) {
    int ret, tmp;
    int64_t volsize, used_volsize;
    char *volname = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_cluster_lv_t *vlist;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!st) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    /* value of path is not important */
    SXFS_DEBUG("'%s'", path);
/* f_bsize      filesystem block size
 * f_frsize     fragment size           (ignored by fuse)
 * f_blocks     size of fs in f_frsize units
 * f_bfree      # free blocks
 * f_bavail     # free blocks for unprivileged users
 * f_files      # inodes
 * f_ffree      # free inodes
 * f_favail     # free inodes for unprivileged users (ignored by fuse)
 * f_fsid       filesystem ID           (ignored by fuse)
 * f_flag       mount flags             (ignored by fuse)
 * f_namemax    maximum filename length */
    memset(st, 0, sizeof(struct statvfs));
    if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
        SXFS_ERROR("Cannot get SX data");
        return ret;
    }
    vlist = sxc_cluster_listvolumes(cluster, 1);
    if(!vlist) {
        SXFS_ERROR("%s", sxc_geterrmsg(sx));
        return -sxfs_sx_err(sx);
    }
    while(1) {
        tmp = sxc_cluster_listvolumes_next(vlist, &volname, NULL, &used_volsize, NULL, NULL, &volsize, NULL, NULL, NULL, NULL, NULL);
        if(tmp) {
            if(tmp < 0) {
                SXFS_ERROR("Failed to retrieve volume data");
                ret = -sxfs_sx_err(sx);
                goto sxfs_statfs_err;
            }
            if(!strcmp(sxfs->uri->volume, volname))
                break;
            free(volname);
            volname = NULL;
        } else
            break;
    }
    if(!volname) {
        SXFS_ERROR("'%s' volume not found", sxfs->uri->volume);
        ret = -ENOENT;
        goto sxfs_statfs_err;
    }
    st->f_bsize = st->f_frsize = SX_BS_SMALL;
    st->f_blocks = (fsblkcnt_t)((volsize + SX_BS_SMALL - 1) / SX_BS_SMALL); /* f_frsize * f_blocks should be equal volsize (value rounded up) */
    st->f_bfree = st->f_bavail = used_volsize > volsize ? 0 : (fsblkcnt_t)((volsize - used_volsize + SX_BS_SMALL - 1) / SX_BS_SMALL);
    st->f_files = (fsblkcnt_t)(volsize / SX_BS_SMALL);
    st->f_ffree = st->f_favail = used_volsize > volsize ? 0 : (fsblkcnt_t)((volsize - used_volsize) / SX_BS_SMALL);
    st->f_namemax = SXLIMIT_MAX_FILENAME_LEN;

    ret = 0;
sxfs_statfs_err:
    free(volname);
    sxc_cluster_listvolumes_free(vlist);
    return ret;
} /* sxfs_statfs */

static int sxfs_flush (const char *path, struct fuse_file_info *file_info) {
    int ret, fd = -1;
    ssize_t rd;
    off_t offset = 0;
    char *file_path = NULL, buff[65536];
    sxfs_file_t *sxfs_file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(path && *path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(path && *path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s' (fd: %llu)", path, (unsigned long long int)file_info->fh);
    FH_CHECK(file_info->fh);
    pthread_mutex_lock(&sxfs_file->mutex);
    if(sxfs_file->flush > 0) {
        SXFS_DEBUG("Using file descriptor: %d", sxfs_file->write_fd);
        file_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof("flush_XXXXXX") + 1);
        if(!file_path) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            goto sxfs_flush_err;
        }
        sprintf(file_path, "%s/flush_XXXXXX", sxfs->tempdir);
        fd = mkstemp(file_path);
        if(fd < 0) {
            ret = -errno;
            SXFS_ERROR("Cannot create unique temporary file: %s", strerror(errno));
            goto sxfs_flush_err;
        }
        while((rd = pread(sxfs_file->write_fd, buff, sizeof(buff), offset)) > 0) {
            if(write(fd, buff, rd) < 0) {
                ret = -errno;
                SXFS_ERROR("Cannot write to '%s' file: %s", file_path, strerror(errno));
                goto sxfs_flush_err;
            }
            offset += rd;
        }
        if(rd < 0) {
            ret = -errno;
            SXFS_ERROR("Cannot read from '%s' file: %s", sxfs_file->write_path, strerror(errno));
            goto sxfs_flush_err;
        }
        if((ret = sxfs_upload(file_path, sxfs_file->remote_path, sxfs_file->ls_file, 1))) {
            SXFS_ERROR("Cannot upload file: %s", sxfs_file->remote_path);
            goto sxfs_flush_err;
        }
        free(file_path);
        file_path = NULL;
        sxfs_file->flush = 0;
    }

    ret = 0;
sxfs_flush_err:
    pthread_mutex_unlock(&sxfs_file->mutex);
    if(fd >= 0 && close(fd))
        SXFS_ERROR("Cannot close '%s' file: %s", file_path, strerror(errno));
    if(file_path && unlink(file_path) && errno != ENOENT)
        SXFS_ERROR("Cannot remove '%s' file: %s", file_path, strerror(errno));
    free(file_path);
    return ret;
} /* sxfs_flush */

/* return value of release() is ignored by FUSE */
static int sxfs_release (const char *path, struct fuse_file_info *file_info) {
    sxfs_file_t *sxfs_file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(path && *path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(path && *path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s' (fd: %llu)", path, (unsigned long long int)file_info->fh);
    /* do not use FH_CHECK() to be able to try with sxi_ht_get() */
    if(file_info->fh >= sxfs->fh_limit) {
        SXFS_ERROR("File handle out of scope");
        return -EBADF;
    }
    pthread_mutex_lock(&sxfs->limits_mutex);
    sxfs_file = sxfs->fh_table[file_info->fh];
    if(!sxfs_file)
        SXFS_ERROR("File handle not used or already released");
    else
        sxfs->fh_table[file_info->fh] = NULL;
    pthread_mutex_unlock(&sxfs->limits_mutex);
    pthread_mutex_lock(&sxfs->files_mutex);
    if(!sxfs_file && (!path || sxi_ht_get(sxfs->files, path, strlen(path), (void**)&sxfs_file))) { /* try to cleanup data in case of fh_table inconsistency */
        SXFS_ERROR("File not opened: %s", path);
        goto sxfs_release_err;
    }
    if(sxfs_file->write_fd >= 0)
        SXFS_DEBUG("Using file descriptor: %d", sxfs_file->write_fd);
    sxfs_file->num_open--;
    SXFS_DEBUG("Opened %lu more times", sxfs_file->num_open);
    if(!sxfs_file->num_open) {
        SXFS_DEBUG("Closing the file");
        if(sxfs_file->flush > 0) {
            if(sxfs_upload(sxfs_file->write_path, sxfs_file->remote_path, sxfs_file->ls_file, 1)) {
                SXFS_ERROR("Cannot upload file: %s", sxfs_file->remote_path);
                goto sxfs_release_err;
            }
            free(sxfs_file->write_path);
            close(sxfs_file->write_fd);
            sxfs_file->write_path = NULL;
            sxfs_file->write_fd = -1;
        }
        sxi_ht_del(sxfs->files, sxfs_file->remote_path, strlen(sxfs_file->remote_path));
        sxfs_file_free(sxfs, sxfs_file);
    }

sxfs_release_err:
    pthread_mutex_unlock(&sxfs->files_mutex);
    return 0; /* return value of release() is ignored by FUSE */
} /* sxfs_release */

static int sxfs_fsync (const char *path, int datasync, struct fuse_file_info *file_info) {
    int ret;
    sxfs_file_t *sxfs_file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(path && *path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(path && *path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', datasync: %d (fd: %llu)", path, datasync, (unsigned long long int)file_info->fh);
    FH_CHECK(file_info->fh);
    pthread_mutex_lock(&sxfs_file->mutex);
    if(sxfs_file->flush > 0) {
        if((ret = sxfs_upload_force(sxfs_file->write_path, sxfs_file->remote_path, sxfs_file->ls_file))) {
            pthread_mutex_unlock(&sxfs_file->mutex);
            SXFS_ERROR("Cannot upload the file");
            return ret;
        }
        sxfs_file->flush = 0;
    }
    pthread_mutex_unlock(&sxfs_file->mutex);
    return 0;
} /* sxfs_fsync */

#ifdef __APPLE__
static int sxfs_setxattr (const char *path, const char *name, const char *value, size_t size, int flags, uint32_t position) {
#else
static int sxfs_setxattr (const char *path, const char *name, const char *value, size_t size, int flags) {
#endif
    return -ENOTSUP;
} /* sxfs_setxattr */

#ifdef __APPLE__
static int sxfs_getxattr (const char *path, const char *name, char *value, size_t size, uint32_t position) {
#else
static int sxfs_getxattr (const char *path, const char *name, char *value, size_t size) {
#endif
    return -ENOTSUP;
} /* sxfs_getxattr */

static int sxfs_listxattr (const char *path, char *list, size_t size) {
    return -ENOTSUP;
} /* sxfs_listxattr */

static int sxfs_removexattr (const char *path, const char *name) {
    return -ENOTSUP;
} /* sxfs_removexattr */

static int sxfs_opendir (const char *path, struct fuse_file_info *file_info) {
    int ret;
    size_t i, pathlen;
    sxfs_file_t *sxfs_file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path || !file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    pathlen = strlen(path);
    SXFS_DEBUG("'%s'", path);
    file_info->fh = 0;
    if((ret = check_path_len(sxfs, path, 0))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    sxfs_file = (sxfs_file_t*)calloc(1, sizeof(sxfs_file_t));
    if(!sxfs_file) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    sxfs_file->is_dir = 1;
    sxfs_file->remote_path = (char*)malloc(pathlen + 1 + 1);
    if(!sxfs_file->remote_path) {
        SXFS_ERROR("Out of memory");
        free(sxfs_file);
        return -ENOMEM;
    }
    sprintf(sxfs_file->remote_path, "%s%s", path, path[pathlen-1] != '/' ? "/" : "");
    pthread_mutex_lock(&sxfs->limits_mutex);
    for(i=0; i<sxfs->fh_limit; i++) {
        if(!sxfs->fh_table[i]) {
            file_info->fh = (uint64_t)i;
            sxfs->fh_table[i] = sxfs_file;
            break;
        }
    }
    pthread_mutex_unlock(&sxfs->limits_mutex);
    if(i == sxfs->fh_limit) {
        SXFS_ERROR("%s", strerror(ENFILE));
        free(sxfs_file->remote_path);
        free(sxfs_file);
        return -ENFILE;
    }
    return 0;
} /* sxfs_opendir */

static int sxfs_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *file_info) {
    int ret;
    size_t i;
    sxfs_file_t *sxfs_file;
    sxfs_lsdir_t *dir;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!buf || !filler | !file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(path && *path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(path && *path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    /* sxfs does not use offset here */
    SXFS_DEBUG("'%s', offset: %lld", path, (long long int)offset);
    if(file_info->fh >= sxfs->fh_limit) {
        SXFS_ERROR("File handle out of scope");
        return -EBADF;
    }
    pthread_mutex_lock(&sxfs->limits_mutex);
    sxfs_file = sxfs->fh_table[file_info->fh];
    pthread_mutex_unlock(&sxfs->limits_mutex);
    if(!sxfs_file) {
        SXFS_ERROR("Directory not opened: %s", path);
        return -EFAULT;
    }
    if(!sxfs_file->is_dir) {
        SXFS_ERROR("Got file descriptor instead of directory");
        return -ENOTDIR;
    }
    pthread_mutex_lock(&sxfs->ls_mutex);
    if((ret = sxfs_ls_update(sxfs_file->remote_path, &dir))) {
        SXFS_ERROR("Cannot load file tree: %s", sxfs_file->remote_path);
        goto sxfs_readdir_err;
    }
    if(filler(buf, ".", NULL, 0)) {
        SXFS_ERROR("filler failed on current directory");
        ret = -ENOBUFS;
        goto sxfs_readdir_err;
    }
    if(filler(buf, "..", NULL, 0)) {
        SXFS_ERROR("filler failed on parent directory");
        ret = -ENOBUFS;
        goto sxfs_readdir_err;
    }
    for(i=0; i<dir->ndirs; i++)
        if(filler(buf, dir->dirs[i]->name, NULL, 0)) {
            SXFS_ERROR("filler failed on '%s': buffer is full", dir->dirs[i]->name);
            ret = -ENOBUFS;
            goto sxfs_readdir_err;
        }
    for(i=0; i<dir->nfiles; i++)
        if(filler(buf, dir->files[i]->name, NULL, 0)) {
            SXFS_ERROR("filler failed on '%s': buffer is full", dir->files[i]->name);
            ret = -ENOBUFS;
            goto sxfs_readdir_err;
        }

    ret = 0;
sxfs_readdir_err:
    pthread_mutex_unlock(&sxfs->ls_mutex);
    return ret;
} /* sxfs_readdir */

static int sxfs_releasedir (const char *path, struct fuse_file_info *file_info) {
    sxfs_file_t *sxfs_file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(path && *path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(path && *path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s'", path);
    if(file_info->fh >= sxfs->fh_limit) {
        SXFS_ERROR("File handle out of scope");
        return -EBADF;
    }
    pthread_mutex_lock(&sxfs->limits_mutex);
    sxfs_file = sxfs->fh_table[file_info->fh];
    pthread_mutex_unlock(&sxfs->limits_mutex);
    if(!sxfs_file) {
        SXFS_ERROR("Directory not opened: %s", path);
        return -EFAULT;
    }
    if(!sxfs_file->is_dir) {
        SXFS_ERROR("Got file descriptor instead of directory");
        return -ENOTDIR;
    }
    pthread_mutex_lock(&sxfs->limits_mutex);
    sxfs->fh_table[file_info->fh] = NULL;
    pthread_mutex_unlock(&sxfs->limits_mutex);
    free(sxfs_file->remote_path);
    free(sxfs_file);
    return 0;
} /* sxfs_releasedir */

static void* sxfs_init (struct fuse_conn_info *conn) {
    sxfs_state_t *sxfs = SXFS_DATA;

    if(sxfs->pipefd[1] >= 0) {
        int status = 0, fd;
        char eot = 4;

        fd = open("/dev/null", O_RDWR);
        if(fd < 0) {
            fprintf(stderr, "ERROR: Cannot open '/dev/null': %s\n", strerror(errno));
        } else {
            if(dup2(fd, 2) == -1) {
                fprintf(stderr, "ERROR: Cannot close stderr: %s\n", strerror(errno));
            } else {
                write(sxfs->pipefd[1], &eot, 1); /* End of transmission */
                write(sxfs->pipefd[1], &status, sizeof(int));
                close(sxfs->pipefd[1]);
                sxfs->pipefd[1] = -1;
            }
            close(fd);
        }
        if(sxfs->pipefd[1] >= 0)
            fprintf(stderr, "ERROR: Cannot correctly start the daemon. Please restart sxfs\n");
    }
    if(sxfs->args->use_queues_flag) {
        SXFS_DEBUG("Starting additional threads");
        sxfs_delete_start();
        sxfs_upload_start();
    }
    return sxfs;
} /* sxfs_init */

static void sxfs_destroy (void *ptr) {
    sxfs_state_t *sxfs = (sxfs_state_t*)ptr;

    if(sxfs->args->use_queues_flag) {
        SXFS_DEBUG("Stopping additional threads");
        sxfs_delete_stop();
        sxfs_upload_stop();
    }
} /* sxfs_destroy */

static int sxfs_access (const char *path, int mode) {
    int tmp;
    char *path2 = NULL;
    struct stat st;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', mode: %c%c%c%c (%o)", path, mode & F_OK ? 'F' : '-', mode & R_OK ? 'R' : '-', mode & W_OK ? 'W' : '-', mode & X_OK ? 'X' : '-', mode);
    if((tmp = check_path_len(sxfs, path, 0))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return tmp;
    }
    if(strlen(path) > 1 && path[strlen(path)-1] == '/') {
        path2 = strdup(path);
        if(!path2) {
            SXFS_ERROR("Cannot duplicate the path: %s", strerror(errno));
            return -ENOMEM;
        }
        path2[strlen(path2)-1] = '\0';
    }
    if((tmp = sxfs_ls_stat(path2 ? path2 : path, &st)) < 0) {
        SXFS_ERROR("Cannot check file status: %s", path2 ? path2 : path);
        free(path2);
        return tmp;
    } 
    free(path2);
    if(mode == F_OK || ((st.st_mode & mode) == (mode_t)mode))
        return 0;
    else
        return -EACCES;
} /* sxfs_access */

static int sxfs_create (const char *path, mode_t mode, struct fuse_file_info *file_info) {
    int ret, fd = -1, files_locked = 0;
    size_t i;
    char *file_name, *local_file_path;
    sxfs_file_t *sxfs_file = NULL;
    sxfs_lsdir_t *dir = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path || !file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    mode |= S_IRUSR | S_IWUSR; /* sxfs has to have the ability to upload and perform I/O operations on the file */
    SXFS_DEBUG("'%s', mode: %c%c%c%c%c%c%c%c%c%c (%o)", path, S_ISDIR(mode) ? 'd' : '-',
                        mode & S_IRUSR ? 'r' : '-', mode & S_IWUSR ? 'w' : '-', mode & S_IXUSR ? 'x' : '-',
                        mode & S_IRGRP ? 'r' : '-', mode & S_IWGRP ? 'w' : '-', mode & S_IXGRP ? 'x' : '-',
                        mode & S_IROTH ? 'r' : '-', mode & S_IWOTH ? 'w' : '-', mode & S_IXOTH ? 'x' : '-', (unsigned int)mode);
    file_info->fh = 0;
    if((ret = check_path_len(sxfs, path, 0))) {
        SXFS_DEBUG("'%s' path is too long", path);
        return ret;
    }
    if(mode && !S_ISREG(mode)) {
        SXFS_ERROR("Not supported type of file: %s", S_ISCHR(mode) ? "character special file" : S_ISBLK(mode) ? "block special file" :
                                                   S_ISFIFO(mode) ? "FIFO (named pipe)" : S_ISSOCK(mode) ? "UNIX domain socket" : "unknown type");
        return -ENOTSUP;
    }
    file_name = strrchr(path, '/');
    if(!file_name) {
        SXFS_ERROR("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name++;
    local_file_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof("file_XXXXXX") + 1);
    if(!local_file_path) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    sprintf(local_file_path, "%s/file_XXXXXX", sxfs->tempdir);
    fd = mkstemp(local_file_path);
    if(fd < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot create unique temporary file: %s", strerror(errno));
        free(local_file_path);
        return ret;
    }
    pthread_mutex_lock(&sxfs->ls_mutex);
    if(sxfs->args->use_queues_flag && (ret = sxfs_delete_check_path(path))) {
        SXFS_ERROR("Cannot check deletion queue: %s", path);
        goto sxfs_create_err;
    }
    if((ret = sxfs_ls_update(path, &dir))) {
        SXFS_ERROR("Cannot load file tree: %s", path);
        goto sxfs_create_err;
    }
    if(sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp) >= 0) {
        SXFS_ERROR("File already exists: %s", path);
        ret = -EEXIST;
        goto sxfs_create_err;
    }
    if(sxfs_find_entry((const void**)dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp) >= 0) {
        SXFS_ERROR("Directory already exists: %s", path);
        ret = -EEXIST;
        goto sxfs_create_err;
    }
    if((ret = sxfs_lsdir_add_file(dir, path, NULL))) {
        SXFS_ERROR("Cannot add new file to cache: %s", path);
        goto sxfs_create_err;
    }
    sxfs_file = (sxfs_file_t*)calloc(1, sizeof(sxfs_file_t));
    if(!sxfs_file) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_create_err;
    }
    sxfs_file->write_fd = -1;
    sxfs_file->ls_file = dir->files[dir->nfiles-1];
    if((ret = pthread_mutex_init(&sxfs_file->mutex, NULL))) {
        SXFS_ERROR("Cannot create files data mutex: %s", strerror(ret));
        ret = -ret;
        free(sxfs_file);
        sxfs_file = NULL;
        goto sxfs_create_err;
    }
    sxfs_file->remote_path = strdup(path);
    if(!sxfs_file->remote_path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_create_err;
    }
    if(sxfs->attribs) {
        sxfs_file->ls_file->st.st_mode = mode;
        dir->files[dir->nfiles-1]->st.st_uid = fuse_get_context()->uid;
        dir->files[dir->nfiles-1]->st.st_gid = fuse_get_context()->gid;
    }
    pthread_mutex_lock(&sxfs->files_mutex);
    files_locked = 1;
    if(sxi_ht_add(sxfs->files, path, strlen(path), sxfs_file)) {
        SXFS_ERROR("Cannot add new file to the hashtable: %s", path);
        ret = -ENOMEM;
        goto sxfs_create_err;
    }
    sxfs_file->write_fd = fd;
    sxfs_file->write_path = local_file_path;
    fd = -1;
    local_file_path = NULL;
    pthread_mutex_lock(&sxfs->limits_mutex);
    for(i=0; i<sxfs->fh_limit; i++) {
        if(!sxfs->fh_table[i]) {
            file_info->fh = (uint64_t)i;
            sxfs->fh_table[i] = sxfs_file;
            break;
        }
    }
    if(i == sxfs->fh_limit) {
        SXFS_ERROR("%s", strerror(ENFILE));
        ret = -ENFILE;
        pthread_mutex_unlock(&sxfs->limits_mutex);
        goto sxfs_create_err;
    }
    sxfs_file->flush = 1;
    sxfs_file->num_open++;
    sxfs_file->ls_file->opened |= SXFS_FILE_OPENED;
    pthread_mutex_unlock(&sxfs->limits_mutex);
    for(i=dir->nfiles-1; i>0 && strcmp(dir->files[i-1]->name, dir->files[i]->name) > 0; i--) {
        sxfs_lsfile_t *tmp_file = dir->files[i-1];
        dir->files[i-1] = dir->files[i];
        dir->files[i] = tmp_file;
    }
    SXFS_DEBUG("'%s': New file handle: %llu", path, (unsigned long long int)file_info->fh);

    ret = 0;
sxfs_create_err:
    if(fd >= 0) {
        if(close(fd))
            SXFS_ERROR("Cannot close '%s' file: %s", local_file_path, strerror(errno));
        if(unlink(local_file_path))
            SXFS_ERROR("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
    }
    free(local_file_path);
    if(ret) {
        if(dir && dir->nfiles && !strcmp(dir->files[dir->nfiles-1]->name, file_name)) {
            sxfs_lsfile_free(dir->files[dir->nfiles-1]);
            dir->files[dir->nfiles-1] = NULL;
            dir->nfiles--;
        }
        sxfs_file_free(sxfs, sxfs_file);
        sxi_ht_del(sxfs->files, path, strlen(path));
    }
    pthread_mutex_unlock(&sxfs->ls_mutex);
    if(files_locked)
        pthread_mutex_unlock(&sxfs->files_mutex);
    return ret;
} /* sxfs_create */

static int sxfs_fgetattr (const char *path, struct stat *st, struct fuse_file_info *file_info) {
    sxfs_file_t *sxfs_file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!st || !file_info) {
        SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    if(path && *path == '\0') {
        SXFS_ERROR("Empty path");
        return -ENOENT;
    }
    if(path && *path != '/') {
        SXFS_ERROR("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s' (fd: %llu)", path, (unsigned long long int)file_info->fh);
    FH_CHECK(file_info->fh);
    pthread_mutex_lock(&sxfs->ls_mutex);
    memcpy(st, &sxfs_file->ls_file->st, sizeof(struct stat));
    pthread_mutex_unlock(&sxfs->ls_mutex);
    st->st_atime = st->st_mtime;
    return 0;
} /* sxfs_fgetattr */

static int sxfs_utimens (const char *path, const struct timespec tv[2]) {
    return sxfs_update_filemeta(path, SXFS_UTIMENS, 0, 0, 0, tv[1].tv_sec);
} /* sxfs_utimens */

struct fuse_operations sxfs_oper = {
    .getattr = sxfs_getattr,
    .readlink = sxfs_readlink,
    .getdir = NULL, /* deprecated, use readdir() */
    .mknod = sxfs_mknod,
    .mkdir = sxfs_mkdir,
    .unlink = sxfs_unlink,
    .rmdir = sxfs_rmdir,
    .symlink = sxfs_symlink,
    .rename = sxfs_rename,
    .link = sxfs_link,
    .chmod = sxfs_chmod,
    .chown = sxfs_chown,
    .truncate = sxfs_truncate,
    .utime = NULL, /* deprecated, use utimens() */
    .open = sxfs_open,
    .read = sxfs_read,
    .write = sxfs_write,
    .statfs = sxfs_statfs,
    .flush = sxfs_flush,
    .release = sxfs_release,
    .fsync = sxfs_fsync,
    .setxattr = sxfs_setxattr,
    .getxattr = sxfs_getxattr,
    .listxattr = sxfs_listxattr,
    .removexattr = sxfs_removexattr,
    .opendir = sxfs_opendir,
    .readdir = sxfs_readdir,
    .releasedir = sxfs_releasedir,
    .fsyncdir = NULL,
    .init = sxfs_init,
    .destroy = sxfs_destroy,
    .access = sxfs_access,
    .create = sxfs_create,
    .ftruncate = NULL,
    .fgetattr = sxfs_fgetattr,
    .lock = NULL,
    .utimens = sxfs_utimens,
#ifndef __APPLE__
#if FUSE_VERSION >= 29
    .flag_nopath = 0,
#endif
#if FUSE_VERSION == 28 || FUSE_VERSION == 29
    .flag_nullpath_ok = 1,
#endif
#endif
};

static int sxfs_input_fn (sxc_client_t *sx, sxc_input_t type, const char *prompt, const char *def, char *in, unsigned int insize, void *ctx) {
    sxfs_state_t *sxfs = (sxfs_state_t*)ctx;

    if(!sx || !prompt || !in | !insize) {
        if(sx)
            sxi_seterr(sx, SXE_EARG, "NULL argument");
        return -1;
    }
    switch(type) {
        case SXC_INPUT_YN:
        case SXC_INPUT_PLAIN:
        case SXC_INPUT_SENSITIVE:
            sxi_seterr(sx, SXE_EARG, "Password callback in sxfs");
            if(sxfs)
                fprintf(sxfs->logfile, "ERROR: The access to the encrypted volume is not initialized yet. Please copy a file with sxcp to configure it.\n");
            return -1;
        default:
            sxi_seterr(sx, SXE_EARG, "Unknown input type");
            return -1;
    }
} /* sxfs_input_fn */

static int runas (const char *usergroup) {
    int ret = -1;
    uid_t uid;
    gid_t gid;
    char *user, *group, *end;
    struct group *gr = NULL;
    struct passwd *pw = NULL;

    user = strdup(usergroup);
    if(!user) {
        fprintf(stderr, "ERROR: Out of memory: %s\n", usergroup);
        return -1;
    }
    group = strchr(user, ':');
    if(group)
        *group++ = '\0';
    if(!*user && (!group || !*group)) {
	fprintf(stderr, "ERROR: Cannot parse '%s'\n", usergroup);
	goto runas_err;
    }
    uid = strtol(user, &end, 10);
    errno = 0;
    if(end == user + strlen(user))
        pw = getpwuid(uid);
    else
        pw = getpwnam(user);
    if(!pw) {
        if(errno)
           fprintf(stderr, "ERROR: Cannot get password file entry: %s\n", strerror(errno));
        else
           fprintf(stderr, "ERROR: Cannot find password file entry: %s\n", user);
        endpwent();
	goto runas_err;
    }
    uid = pw->pw_uid;
    if(!group || !*group) {
        gid = pw->pw_gid;
    } else {
        gid = strtol(group, &end, 10);
        errno = 0;
        if(end == group + strlen(group))
            gr = getgrgid(gid);
        else
            gr = getgrnam(group);
        if(!gr) {
            if(errno)
               fprintf(stderr, "ERROR: Cannot get group file entry: %s\n", strerror(errno));
            else
               fprintf(stderr, "ERROR: Cannot find group file entry: %s\n", user);
            endgrent();
            goto runas_err;
        }
        gid = gr->gr_gid;
    }
    if(getuid() == uid && geteuid() == uid &&
       getgid() == gid && getegid() == gid) {
        ret = 0; /* don't do anything if correct user is already set */
	goto runas_err;
    }
#ifdef HAVE_SETGROUPS
    if(setgroups(1, &gid) == -1) {
        fprintf(stderr, "ERROR: Setgroups failed: %s\n", strerror(errno));
        goto runas_err;
    }
#endif
    if(setgid(gid) == -1) {
        fprintf(stderr, "ERROR: Cannot set GID: %s\n", strerror(errno));
	goto runas_err;
    }
    if(setuid(uid) == -1) {
        fprintf(stderr, "ERROR: Cannot set UID: %s\n", strerror(errno));
	goto runas_err;
    }
    if(setenv("HOME", pw->pw_dir, 1)) {
        fprintf(stderr, "ERROR: Cannot set HOME variable: %s\n", strerror(errno));
        goto runas_err;
    }

    ret = 0;
runas_err:
    free(user);
    if(pw)
        endpwent();
    if(gr)
        endgrent();
    return ret;
} /* runas */

static void print_and_log (FILE *logfile, const char* format_string, ...) {
    char buffer[4096];
    va_list vl;

    va_start(vl, format_string);
    vsnprintf(buffer, sizeof(buffer), format_string, vl);
    va_end(vl);
    fprintf(stderr, "%s", buffer); /* when running as a daemon, stderr is in fact the write end of the pipe */
    if(logfile)
        fprintf(logfile, "%s", buffer);
} /* print_and_log */

static int check_password (sxc_client_t *sx, sxc_cluster_t *cluster, sxfs_state_t *sxfs) {
    int ret = -1, fd;
    unsigned int nfiles;
    char *path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof(".sxfs_tmp_XXXXXX") + 1), *file_name;
    sxc_file_t *src = NULL, *dest = NULL;
    sxc_cluster_lf_t *flist;
    sxc_file_list_t *rmlist = NULL;

    if(!path) {
        fprintf(stderr, "ERROR: Out of memory\n");
        return ret;
    }
    while(1) {
        sprintf(path, "%s/.sxfs_tmp_XXXXXX", sxfs->tempdir);
        fd = mkstemp(path);
        if(fd < 0) {
            fprintf(stderr, "ERROR: Cannot create temporary file: %s\n", strerror(errno));
            free(path);
            return ret;
        }
        if(close(fd)) {
            fprintf(stderr, "ERROR: Cannot close '%s' file: %s\n", path, strerror(errno));
            goto check_password_err;
        }
        file_name = strrchr(path, '/');
        if(!file_name) {
            fprintf(stderr, "ERROR: '/' not found in '%s'\n", path);
            goto check_password_err;
        }
        flist = sxc_cluster_listfiles(cluster, sxfs->uri->volume, file_name+1, 0, &nfiles, 0);
        if(!flist) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            goto check_password_err;
        }
        sxc_cluster_listfiles_free(flist);
        if(!nfiles)
            break;
        if(unlink(path)) {
            fprintf(stderr, "ERROR: Cannot remove '%s' file: %s\n", path, strerror(errno));
            free(path);
            return ret;
        }
    }
    src = sxc_file_local(sx, path);
    if(!src) {
        fprintf(stderr, "ERROR: Cannot create local file object: %s\n", sxc_geterrmsg(sx));
        goto check_password_err;
    }
    dest = sxc_file_remote(cluster, sxfs->uri->volume, file_name+1, NULL);
    if(!dest) {
        fprintf(stderr, "ERROR: Cannot create file object: %s\n", sxc_geterrmsg(sx));
        goto check_password_err;
    }
    rmlist = sxc_file_list_new(sx, 0, 0);
    if(!rmlist) {
        fprintf(stderr, "ERROR: Cannot create new file list: %s\n", sxc_geterrmsg(sx));
        goto check_password_err;
    }
    if(sxc_copy_single(src, dest, 0, 0, 0, NULL, 0)) {
        fprintf(stderr, "ERROR: Cannot upload '%s' file: %s\n", path, sxc_geterrmsg(sx));
        goto check_password_err;
    }
    if(sxc_file_list_add(rmlist, dest, 0)) {
        fprintf(stderr, "ERROR: Cannot add file: %s\n", sxc_geterrmsg(sx));
        goto check_password_err;
    }
    dest = NULL; /* sxc_file_list_free frees all files inside it */
    if(sxc_rm(rmlist, 0)) {
        fprintf(stderr, "ERROR: Cannot remove file: %s\n", sxc_geterrmsg(sx));
        goto check_password_err;
    }

    ret = 0;
check_password_err:
    sxc_file_free(src);
    sxc_file_free(dest);
    sxc_file_list_free(rmlist);
    if(unlink(path))
        fprintf(stderr, "ERROR: Cannot remove '%s' file: %s\n", path, strerror(errno));
    free(path);
    return ret;
} /* check_password */

static int sxfs_daemonize (sxfs_state_t *sxfs) {
    int fd = -1, ret = -1, err;
    ssize_t n;
    char c;

    if(!sxfs->args->foreground_flag) {
        if(!sxfs->logfile)
            fprintf(stderr, "*** It is recommended to always use --logfile when not running in the foreground ***\n");
        fd = open("/dev/null", O_RDWR);
        if(fd < 0) {
            fprintf(stderr, "ERROR: Cannot open '/dev/null': %s\n", strerror(errno));
            goto sxfs_daemonize_err;
        }
        if(pipe(sxfs->pipefd) < 0) {
            fprintf(stderr, "ERROR: Cannot create new pipe: %s\n", strerror(errno));
            goto sxfs_daemonize_err;
        }
        switch(fork()) {
            case -1:
                fprintf(stderr, "ERROR: Cannot fork: %s\n", strerror(errno));
                goto sxfs_daemonize_err;
            case 0:
                if(close(sxfs->pipefd[0]))
                    fprintf(stderr, "ERROR: Cannot close read end of the pipe: %s\n", strerror(errno));
                sxfs->pipefd[0] = -1;
                break;
            default:
                if(close(sxfs->pipefd[1]))
                    fprintf(stderr, "ERROR: Cannot close write end of the pipe: %s\n", strerror(errno));
                while(1) { /* read from the pipe until EOT */
                    if((n = read(sxfs->pipefd[0], &c, 1)) < 1) {
                        fprintf(stderr, "ERROR: Cannot read from the pipe: %s\n", n < 0 ? strerror(errno) : "pipe closed");
                        close(sxfs->pipefd[0]);
                        _exit(1);
                    }
                    if(c == 4) /* End of transmission */
                        break;
                    fprintf(stderr, "%c", c);
                }
                if((n = read(sxfs->pipefd[0], &err, sizeof(err))) < 0) {
                    fprintf(stderr, "ERROR: Cannot read from the pipe: %s\n", strerror(errno));
                    close(sxfs->pipefd[0]);
                    _exit(1);
                }
                if(close(sxfs->pipefd[0]))
                    fprintf(stderr, "ERROR: Cannot close read end of the pipe: %s\n", strerror(errno));
                _exit(err);
        }
        if(setsid() == -1) {
            fprintf(stderr, "ERROR: Cannot create new session: %s\n", strerror(errno));
            goto sxfs_daemonize_err;
        }
        if(chdir("/")) {
            fprintf(stderr, "ERROR: Cannot change working directory: %s\n", strerror(errno));
            goto sxfs_daemonize_err;
        }
        if(dup2(fd, 0) == -1) {
            fprintf(stderr, "ERROR: Cannot close stdin: %s\n", strerror(errno));
            goto sxfs_daemonize_err;
        }
        if(dup2(fd, 1) == -1) {
            fprintf(stderr, "ERROR: Cannot close stdout: %s\n", strerror(errno));
            goto sxfs_daemonize_err;
        }
        if(dup2(sxfs->pipefd[1], 2) == -1) {
            fprintf(stderr, "ERROR: Cannot close stderr: %s\n", strerror(errno));
            goto sxfs_daemonize_err;
        }
    } else {
        if(chdir("/")) {
            fprintf(stderr, "ERROR: Cannot change working directory: %s\n", strerror(errno));
            return ret;
        }
    }

    ret = 0;
sxfs_daemonize_err:
    if(fd >= 0 && close(fd))
        fprintf(stderr, "ERROR: Cannot close '/dev/null' device: %s\n", strerror(errno));
    return ret;
} /* sxfs_daemonize */

int main (int argc, char **argv) {
    int i, ret = 1, err, read_only = 0, acl, runas_found = 0, pthread_flag = 0, tempdir_created = 0, cache_created = 0, tmp;
    unsigned int j;
    ssize_t cache_size = 0;
    char *volume_name = NULL, *username = NULL, *profile = NULL, *filter_dir = NULL, *cache_size_str = NULL, *cache_dir = NULL;
    const char *filter_dir_env = sxi_getenv("SX_FILTER_DIR");
    struct timeval tv;
    struct tm *tm;
    sxc_logger_t log;
    sxc_client_t *sx = NULL;
    sxc_cluster_t *cluster = NULL;
    sxc_meta_t *volmeta = NULL;
    sxc_cluster_la_t *ulist = NULL;
    sxi_hostlist_t volnodes;
    sxfs_state_t *sxfs = NULL;
    sxfs_sx_data_t sx_data;
    struct gengetopt_args_info args;
    struct fuse_args fargs, fargs_tmp;

    if(cmdline_parser(argc, argv, &args)) {
        cmdline_parser_print_help();
        fprintf(stderr, "\nERROR: Incorrect usage\n");
        return ret;
    }
    if(args.version_given) {
        printf("%s %s\n", CMDLINE_PARSER_PACKAGE, SRC_VERSION);
        cmdline_parser_free(&args);
        return 0;
    }
    memset(&fargs, 0, sizeof(struct fuse_args));
    if(fuse_opt_add_arg(&fargs, argv[0])) {
        fprintf(stderr, "ERROR: Out of memory\n");
        cmdline_parser_free(&args);
        return ret;
    }
    if(args.fuse_help_flag || args.fuse_version_flag) {
        if(fuse_opt_add_arg(&fargs, args.fuse_help_flag ? "-h" : "-V")) {
            fprintf(stderr, "ERROR: Out of memory\n");
            cmdline_parser_free(&args);
            fuse_opt_free_args(&fargs);
            return ret;
        }
        cmdline_parser_free(&args);
        ret = fuse_main(fargs.argc, fargs.argv, &sxfs_oper, NULL);
        fuse_opt_free_args(&fargs);
        return ret;
    }
    if(args.inputs_num != 2) {
        cmdline_parser_print_help();
        fprintf(stderr, "\nERROR: Wrong number of arguments\n");
        cmdline_parser_free(&args);
        fuse_opt_free_args(&fargs);
        return ret;
    }
    if(*args.inputs[1] != '/' || (args.logfile_given && *args.logfile_arg != '/') ||
            (args.tempdir_given && *args.tempdir_arg != '/') || (args.recovery_dir_given && *args.recovery_dir_arg != '/') ||
            (args.config_dir_given && *args.config_dir_arg != '/') || (args.filter_dir_given && *args.filter_dir_arg != '/')) {
        cmdline_parser_print_help();
        fprintf(stderr, "\nERROR: All file/directory arguments must use an absolute path\n");
        cmdline_parser_free(&args);
        fuse_opt_free_args(&fargs);
        return ret;
    }
    if(gettimeofday(&tv, NULL)) {
        fprintf(stderr, "ERROR: Cannot get current time: %s\n", strerror(errno));
        goto main_err;
    }
    tm = localtime(&tv.tv_sec);
    if(!tm) {
        fprintf(stderr, "ERROR: Cannot convert time value\n");
        goto main_err;
    }
    sxfs = (sxfs_state_t*)calloc(1, sizeof(sxfs_state_t));
    if(!sxfs) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    if((err = pthread_cond_init(&sxfs->delete_cond, NULL))) {
        fprintf(stderr, "ERROR: Cannot initialize pthread condition: %s\n", strerror(err));
        free(sxfs);
        sxfs = NULL;
        goto main_err;
    }
    if((err = pthread_cond_init(&sxfs->upload_cond, NULL))) {
        fprintf(stderr, "ERROR: Cannot initialize pthread condition: %s\n", strerror(err));
        pthread_cond_destroy(&sxfs->delete_cond);
        free(sxfs);
        sxfs = NULL;
        goto main_err;
    }
    sxfs->args = &args;
    sxfs->pname = argv[0];
    sxfs->pipefd[0] = sxfs->pipefd[1] = -1;
    if(args.sx_debug_flag)
        args.foreground_flag = 1;
    if(fuse_opt_add_arg(&fargs, "-f")) { /* all SX clients must be created after the fork() */
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
#ifdef __APPLE__
    args.fuse_single_threaded_flag = 1; /* SXFS on OS X only supports FUSE-single-threaded mode (due to stack size) */
#endif
    if(args.fuse_single_threaded_flag && fuse_opt_add_arg(&fargs, "-s")) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    if(args.fuse_debug_flag && fuse_opt_add_arg(&fargs, "-d")) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    /* filter arguments */
    memset(&fargs_tmp, 0, sizeof(struct fuse_args));
    for(j=0; j<args.mount_options_given; j++)
        if(fuse_opt_add_arg(&fargs_tmp, args.mount_options_arg[j])) {
            fprintf(stderr, "ERROR: Out of memory\n");
            goto main_err;
        }
    for(i=0; i<fargs_tmp.argc; i++) { /* check 'runas=' before other options */
        if(!strncmp(fargs_tmp.argv[i], "runas=", lenof("runas="))) {
            const char *user_name = fargs_tmp.argv[i] + lenof("runas=");
            if(runas_found) {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: Please pass runas username exactly once\n");
                goto main_err;
            }
            runas_found = 1;
            if(!*user_name) {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: Please specify username for 'runas' option\n");
                goto main_err;
            }
            if(runas(user_name))
                goto main_err;
        }
    }
#ifndef __APPLE__
    if(fuse_opt_add_arg(&fargs, "-oatomic_o_trunc")) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
#endif
    for(i=0; i<fargs_tmp.argc; i++) {
        if(!strncmp(fargs_tmp.argv[i], "runas=", lenof("runas="))) {
            continue; /* already checked */
        } else if(!strcmp(fargs_tmp.argv[i], "use_queues")) {
            args.use_queues_flag = 1;
        } else if(!strcmp(fargs_tmp.argv[i], "replica_wait")) {
            args.replica_wait_flag = 1;
        } else if(!strncmp(fargs_tmp.argv[i], "logfile=", lenof("logfile="))) {
            const char *logfile = fargs_tmp.argv[i] + lenof("logfile=");
            if(args.logfile_given || sxfs->logfile) {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: Please pass logfile path exactly once\n");
                goto main_err;
            }
            if(!*logfile) {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: Please specify path for logfile\n");
                goto main_err;
            }
            if(*logfile != '/') {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: All file/directory arguments must use an absolute path\n");
                goto main_err;
            }
            sxfs->logfile = fopen(logfile, "a");
            if(!sxfs->logfile) {
                fprintf(stderr, "ERROR: Cannot open logfile: %s\n", strerror(errno));
                goto main_err;
            }
        } else if(!strncmp(fargs_tmp.argv[i], "tempdir=", lenof("tempdir="))) {
            const char *tempdir = fargs_tmp.argv[i] + lenof("tempdir=");
            if(args.tempdir_given || sxfs->tempdir) {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: Please pass temporary directory path exactly once\n");
                goto main_err;
            }
            if(!*tempdir) {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: Please specify path for temporary directory\n");
                goto main_err;
            }
            if(*tempdir != '/') {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: All file/directory arguments must use an absolute path\n");
                goto main_err;
            }
            sxfs->tempdir = strdup(tempdir);
            if(!sxfs->tempdir) {
                fprintf(stderr, "ERROR: Out of memory\n");
                goto main_err;
            }
        } else if(!strncmp(fargs_tmp.argv[i], "recovery_dir=", lenof("recovery_dir="))) {
            const char *lostdir = fargs_tmp.argv[i] + lenof("recovery_dir=");
            if(args.recovery_dir_given || sxfs->lostdir) {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: Please pass recovery directory path exactly once\n");
                goto main_err;
            }
            if(!*lostdir) {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: Please specify path for recovery dir\n");
                goto main_err;
            }
            if(*lostdir != '/') {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: All file/directory arguments must use an absolute path\n");
                goto main_err;
            }
            sxfs->lostdir = strdup(lostdir);
            if(!sxfs->lostdir) {
                fprintf(stderr, "ERROR: Out of memory\n");
                goto main_err;
            }
        } else if(!strncmp(fargs_tmp.argv[i], "cache_size=", lenof("cache_size="))) {
            if(args.cache_size_given || cache_created) {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: Please specify cache size exactly once\n");
                goto main_err;
            }
            cache_size_str = strdup(fargs_tmp.argv[i]+lenof("cache_size="));
            if(!cache_size_str) {
                fprintf(stderr, "ERROR: Out of memory\n");
                goto main_err;
            }
            cache_size = sxi_parse_size(sx, cache_size_str, 1);
            if(cache_size < 0) {
                fprintf(stderr, "%s\n", sxc_geterrmsg(sx));
                goto main_err;
            }
            cache_created = 1;
        } else if(!strncmp(fargs_tmp.argv[i], "cache_dir=", lenof("cache_dir="))) {
            if(args.cache_dir_given || cache_dir) {
                cmdline_parser_print_help();
                fprintf(stderr, "\nERROR: Please specify cache directory path exactly once\n");
                goto main_err;
            }
            cache_dir = strdup(fargs_tmp.argv[i] + lenof("cache_dir="));
            if(!cache_dir) {
                fprintf(stderr, "ERROR: Out of memory\n");
                goto main_err;
            }
        } else {
            if(!strcmp(fargs_tmp.argv[i], "hard_remove")) {
#ifdef __APPLE__
                fprintf(stderr, "WARNING: '-o hard_remove' option is not supported on OS X and will be ignored\n");
                continue;
#else
#if FUSE_VERSION >= 29
                sxfs_oper.flag_nopath = 1; /* FUSE doesn't use unlink on .fuse_hiddenXXXXXX with this option
                                           ** with '-o hard_remove' .fuse_hiddenXXXXXX files are not being created) */
#else
                fprintf(stderr, "WARNING: '-o hard_remove' option is only supported with FUSE 2.9.0 (or newer) and will be ignored\n");
                continue;
#endif
#endif
            }
            if(fuse_opt_add_arg(&fargs, "-o")) {
                fprintf(stderr, "ERROR: Out of memory\n");
                goto main_err;
            }
            if(fuse_opt_add_arg(&fargs, fargs_tmp.argv[i])) {
                fprintf(stderr, "ERROR: Out of memory\n");
                goto main_err;
            }
        }
    }
    if(fuse_opt_add_arg(&fargs, args.inputs[1])) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    if(args.use_queues_flag && !args.logfile_given && !sxfs->logfile)
        fprintf(stderr, "*** It is recommended to always use --logfile together with --use-queues ***\n");

    /* logfile */
    if(args.logfile_given) {
        sxfs->logfile = fopen(args.logfile_arg, "a");
        if(!sxfs->logfile) {
            fprintf(stderr, "ERROR: Cannot open logfile: %s\n", strerror(errno));
            goto main_err;
        }
    } else if(!sxfs->logfile && args.debug_flag) {
        fprintf(stderr, "*** Debug mode has no effect without logfile. Suggested option: --logfile=PATH (-l) ***\n");
    }
    if(sxfs->logfile) {
        fprintf(sxfs->logfile, "%s, version: %s\n", argv[0], SRC_VERSION);
        fprintf(sxfs->logfile, "Command line arguments:");
        for(i=1; i<argc; i++)
            fprintf(sxfs->logfile, " %s", argv[i]);
        fprintf(sxfs->logfile, "\n");
        fflush(sxfs->logfile);
    }
    /* tempdir */
    if((args.tempdir_given && !strcmp(args.tempdir_arg, args.inputs[1])) || (sxfs->tempdir && !strcmp(sxfs->tempdir, args.inputs[1]))) {
        cmdline_parser_print_help();
        fprintf(stderr, "\nERROR: Please do not use the same path for temporary directory and mount point\n");
        goto main_err;
    }
    if(args.tempdir_given || sxfs->tempdir) {
        if(!sxfs->tempdir)
            sxfs->tempdir = args.tempdir_arg;
        if(mkdir(sxfs->tempdir, 0700)) {
            fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", sxfs->tempdir, strerror(errno));
            goto main_err;
        }
    } else {
        size_t n = strlen("/var/tmp/sxfs-") + 14 /* date and time */ + 1 + lenof("XXXXXX") + 1;
        sxfs->tempdir = (char*)malloc(n);
        if(!sxfs->tempdir) {
            fprintf(stderr, "ERROR: Out of memory\n");
            goto main_err;
        }
        snprintf(sxfs->tempdir, n, "/var/tmp/sxfs-%04d%02d%02d%02d%02d%02d-XXXXXX", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
        if(!mkdtemp(sxfs->tempdir)) {
            fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", sxfs->tempdir, strerror(errno));
            goto main_err;
        }
        fprintf(stderr, "Using default tempdir: %s\n", sxfs->tempdir);
        if(sxfs->logfile)
            fprintf(sxfs->logfile, "Using default tempdir: %s\n", sxfs->tempdir);
    }
    tempdir_created = 1;
    /* recovery dir */
    if(args.recovery_dir_given) {
        sxfs->lostdir = args.recovery_dir_arg;
    } else if(!sxfs->lostdir) {
        sxfs->lostdir = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof(SXFS_LOSTDIR_SUFIX) + 1);
        if(!sxfs->lostdir) {
            fprintf(stderr, "ERROR: Out of memory");
            goto main_err;
        }
        sprintf(sxfs->lostdir, "%s%s", sxfs->tempdir, SXFS_LOSTDIR_SUFIX);
    }
    if(mkdir(sxfs->lostdir, 0700)) {
        fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", sxfs->lostdir, strerror(errno));
        goto main_err;
    }
    tempdir_created = 2;

    if(sxfs_daemonize(sxfs))
        goto main_err;

    sxfs->fh_limit = 1024;
    if(args.open_limit_given) {
        if(args.open_limit_arg > 0) /* fh_limit must be a positive number */
            sxfs->fh_limit = (size_t)args.open_limit_arg;
        else
            fprintf(stderr, "WARNING: Open limit must be a pasitive number. Using default value: 1024\n");
    }
    sxfs->fh_table = (sxfs_file_t**)calloc(sxfs->fh_limit, sizeof(sxfs_file_t*));
    if(!sxfs->fh_table) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    sxfs->threads_max = SXFS_ALLOC_ENTRIES;
    sxfs->threads = (int*)calloc(sxfs->threads_max, sizeof(int));
    if(!sxfs->threads) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    sx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), args.foreground_flag ? sxc_input_fn : sxfs_input_fn,  args.foreground_flag ? NULL : (void*)sxfs);
    if(!sx) {
        fprintf(stderr, "ERROR: Cannot initialize the SX client\n");
        goto main_err;
    }
    if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
        fprintf(stderr, "ERROR: Could not set configuration directory to '%s': %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
        goto main_err;
    }
    sxc_set_debug(sx, args.sx_debug_flag);
    if(args.verbose_flag)
        args.debug_flag = 1;
    if(args.filter_dir_given)
        filter_dir = strdup(args.filter_dir_arg);
    else if(filter_dir_env)
        filter_dir = strdup(filter_dir_env);
    else
        filter_dir = strdup(SX_FILTER_DIR);
    if(!filter_dir) {
        fprintf(stderr, "ERROR: Cannot set filter directory");
        goto main_err;
    }
    if(sxc_filter_loadall(sx, filter_dir)) {
	fprintf(stderr, "WARNING: Failed to load filters: %s\n", sxc_geterrmsg(sx));
	sxc_clearerr(sx);
    }
    free(filter_dir);

    if(!args.replica_wait_flag)
	sxc_set_flush_policy(sx, SXC_FLUSH_NOWAIT);
    
    sxfs->uri = sxc_parse_uri(sx, args.inputs[0]);
    if(!sxfs->uri) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        goto main_err;
    }
    if(!sxfs->uri->host) {
        fprintf(stderr, "ERROR: No cluster specified\n");
        goto main_err;
    }
    if(!sxfs->uri->volume) {
        fprintf(stderr, "ERROR: No volume specified\n");
        goto main_err;
    }
    cluster = sxc_cluster_load_and_update(sx, sxfs->uri->host, sxfs->uri->profile);
    if(!cluster) {
        fprintf(stderr, "ERROR: Cannot load config for %s: %s\n", sxfs->uri->host, sxc_geterrmsg(sx));
        goto main_err;
    }
    /* check volume existence and filters usage */
    sxi_hostlist_init(&volnodes);
    volmeta = sxc_meta_new(sx);
    if(!volmeta) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        goto main_err;
    }
    if(sxi_locate_volume(sxi_cluster_get_conns(cluster), sxfs->uri->volume, &volnodes, NULL, volmeta, NULL)) {
        fprintf(stderr, "ERROR: '%s' volume does not exist or you don't have access to it\n", sxfs->uri->volume);
        goto main_err;
    }
    sxi_hostlist_empty(&volnodes);
    if(volmeta) {
        int filters_count = 0;
        unsigned int mval_len;
        const void *mval = NULL;
        const sxf_handle_t *filters = NULL;

        if(!sxc_meta_getval(volmeta, "filterActive", &mval, &mval_len)) {
            char remote_filter_uuid[37];
            if(mval_len == 16) {
                sxi_uuid_unparse(mval, remote_filter_uuid);
                filters = sxc_filter_list(sx, &filters_count);
                for(i=0; i<filters_count; i++) {
                    const sxc_filter_t *f = sxc_get_filter(&filters[i]);
                    if(!strncmp(remote_filter_uuid, f->uuid, 36)) {
                        if(f->data_process)
                            sxfs->need_file = 1;
                        if(!strcmp(f->shortname, "attribs")) /* FIXME: dirty hack */
                            sxfs->attribs = 1;
                        if(!strcmp(f->uuid, "35a5404d-1513-4009-904c-6ee5b0cd8634")) {
                            fprintf(stderr, "ERROR: The old version of this filter is no longer supported. Please create a new volume with the latest version of the aes256 filter from SX 2.x\n");
                            goto main_err;
                        }
                        break;
                    }
                }
                if(i == filters_count) {
                    fprintf(stderr, "ERROR: Cannot load the filter. Check filter directory in your settings.\n");
                    goto main_err;
                }
            } else {
                fprintf(stderr, "ERROR: Wrong size of filter data\n");
                goto main_err;
            }
            if(check_password(sx, cluster, sxfs)) /* for aes filter */
                goto main_err;
        }
    }
    /* get default profile */
    if(!sxfs->uri->profile && sxc_cluster_whoami(cluster, &profile, NULL, NULL, NULL, NULL)) {
        fprintf(stderr, "ERROR: %s", sxc_geterrmsg(sx));
        goto main_err;
    }
    for(i=fargs.argc-1; i>0; i--) { /* index 0 is program name */
        if(!strcmp(fargs.argv[i], "ro"))
            read_only = 1;
        if(!strcmp(fargs.argv[i], "rw"))
            break;
    }
    /* check user permission */
    ulist = sxc_cluster_listaclusers(cluster, sxfs->uri->volume);
    if(!ulist) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        goto main_err;
    }
    while(1) {
        tmp = sxc_cluster_listaclusers_next(ulist, &username, &acl);
        if(tmp) {
            if(tmp < 0) {
                fprintf(stderr, "ERROR: Failed to retrieve user data\n");
                goto main_err;
            }
            if(!strcmp(sxfs->uri->profile ? sxfs->uri->profile : profile, username)) {
                if(!(acl & SX_ACL_READ)) {
                    fprintf(stderr, "ERROR: Permission denied: Not enough privileges: %s\n", args.inputs[0]);
                    goto main_err;
                }
                if(!read_only && !(acl & SX_ACL_WRITE)) {
                    read_only = 1;
                    print_and_log(sxfs->logfile, "*** Read-only mode (no write permission for the volume) ***\n");
                    if(fuse_opt_add_arg(&fargs, "-oro")) {
                        fprintf(stderr, "ERROR: Out of memory\n");
                        goto main_err;
                    }
                }
                break;
            }
            free(username);
            username = NULL;
        } else
            break;
    }
    if(read_only && args.use_queues_flag) {
        args.use_queues_flag = 0;
        fprintf(stderr, "*** Queues do not work in read-only mode ***\n");
    }

    /* cache initialization */
    if(!sxfs->need_file) {
        if(!cache_created) {
            cache_size = sxi_parse_size(sx, args.cache_size_arg, 1);
            if(cache_size < 0) {
                fprintf(stderr, "%s\n", sxc_geterrmsg(sx));
                goto main_err;
            }
        }
        if(args.cache_dir_given) {
            cache_dir = strdup(args.cache_dir_arg);
            if(!cache_dir) {
                fprintf(stderr, "ERROR: Out of memory\n");
                goto main_err;
            }
        }
        if(cache_dir && mkdir(cache_dir, 0700)) {
            fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", cache_dir, strerror(errno));
            goto main_err;
        }
        print_and_log(sxfs->logfile, "Using%s cache size of %s in '%s'\n", (args.cache_size_given || cache_created) ? "" : " default", cache_created ? cache_size_str : args.cache_size_arg, cache_dir ? cache_dir : sxfs->tempdir);
    }
    if(sxfs_cache_init(sx, sxfs, cache_size, cache_dir ? cache_dir : sxfs->tempdir))
        goto main_err;
    /* directory tree */
    sxfs->root = (sxfs_lsdir_t*)calloc(1, sizeof(sxfs_lsdir_t));
    if(!sxfs->root) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    sxfs->root->st.st_mtime = sxfs->root->st.st_ctime = tv.tv_sec;
    sxfs->root->name = strdup("/");
    if(!sxfs->root->name) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    sxfs->root->etag = sxfs_hash(sxfs, sxfs->root->name);
    if(!sxfs->root->etag) {
        fprintf(stderr, "ERROR: Cannot compute hash of '%s'\n", sxfs->root->name);
        goto main_err;
    }
    sxfs->root->st.st_uid = getuid();
    sxfs->root->st.st_gid = getgid();
    sxfs->root->st.st_nlink = 1;
    sxfs->root->st.st_mode = SXFS_DIR_ATTR;
    sxfs->root->st.st_size = SXFS_DIR_SIZE;
    sxfs->root->st.st_blocks = (SXFS_DIR_SIZE + 511) / 512;
    /* directories and files tables will be created on directory tree walking using realloc */
    /* detect subdir */
    for(i=fargs.argc-1; i>0; i--) /* index 0 is program name */
        if(!strncmp(fargs.argv[i], "subdir=", 7)) {
            int fail = 1;
            char *path = NULL, *name, *ptr;
            sxc_cluster_lf_t *flist = NULL;
            sxfs_lsdir_t *dir = sxfs->root;
            sxc_file_t *file = NULL;

            if(sxfs->uri->path) {
                fprintf(stderr, "ERROR: Please specify only one subdir (by FUSE module or SX path)\n");
                goto main_err;
            }
            if(*(fargs.argv[i]+7) != '/') {
                fprintf(stderr, "ERROR: Please use absolute path as a subdir\n");
                goto main_err;
            }
            do {
                path = (char*)malloc(strlen(fargs.argv[i]+7) + 2);
                if(!path) {
                    fprintf(stderr, "ERROR: Out of memory\n");
                    break;
                }
                sprintf(path, "%s", fargs.argv[i]+7);
                if(path[strlen(path)-1] == '/')
                    path[strlen(path)-1] = '\0';
                flist = sxc_cluster_listfiles(cluster, sxfs->uri->volume, path, 0, NULL, 0);
                if(!flist) {
                    fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
                    break;
                }
                tmp = sxc_cluster_listfiles_next(cluster, sxfs->uri->volume, flist, &file);
                if(tmp) {
                    const char *fpath;

                    if(tmp < 0) {
                        fprintf(stderr, "ERROR: Cannot retrieve file name: %s", sxc_geterrmsg(sx));
                        break;
                    }
                    fpath = sxc_file_get_path(file);
                    if(fpath[strlen(fpath)-1] != '/') /* there can be a file with same name as $subdir */
                        tmp = 1;
                    else
                        tmp = 0;
                    sxc_file_free(file);
                    file = NULL;
                    if(tmp) {
                        tmp = sxc_cluster_listfiles_next(cluster, sxfs->uri->volume, flist, &file);
                        if(tmp) {
                            if(tmp < 0) {
                                fprintf(stderr, "ERROR: Cannot retrieve file name: %s", sxc_geterrmsg(sx));
                                break;
                            }
                        } else {
                            fprintf(stderr, "ERROR: Please use existing directory path as a subdir\n");
                            break;
                        }
                    }
                } else {
                    fprintf(stderr, "ERROR: Please use existing path as a subdir\n");
                    break;
                }
                strcat(path, "/"); /* last slash enables to parse last directory using strchr() */
                /* build file tree based on given subdir path (sxfs works on remote root) */
                name = path + 1;
                ptr = strchr(name, '/');
                while(ptr) {
                    *ptr = '\0';
                    dir->maxdirs = dir->ndirs = 1;
                    dir->dirs = (sxfs_lsdir_t**)malloc(sizeof(sxfs_lsdir_t*));
                    if(!dir->dirs) {
                        fprintf(stderr, "ERROR: Out of memory\n");
                        break;
                    }
                    dir->dirs[0] = (sxfs_lsdir_t*)calloc(1, sizeof(sxfs_lsdir_t));
                    if(!dir->dirs[0]) {
                        fprintf(stderr, "ERROR: Out of memory\n");
                        break;
                    }
                    dir->dirs[0]->parent = dir;
                    dir = dir->dirs[0];
                    dir->name = strdup(name);
                    if(!dir->name) {
                        fprintf(stderr, "ERROR: Out of memory\n");
                        break;
                    }
                    *ptr = '/';
                    name = ptr + 1;
                    ptr = strchr(name, '/');
                }
                dir->st.st_uid = getuid();
                dir->st.st_gid = getgid();
                dir->st.st_nlink = 1;
                dir->st.st_mode = SXFS_DIR_ATTR;
                dir->st.st_size = SXFS_DIR_SIZE;
                dir->st.st_blocks = (SXFS_DIR_SIZE + 511) / 512;
                dir->etag = sxfs_hash(sxfs, path);
                if(!dir->etag) {
                    fprintf(stderr, "Cannot compute hash of '%s'\n", path);
                    break;
                }
                fail = 0;
            } while(0);
            sxc_file_free(file);
            free(path);
            sxc_cluster_listfiles_free(flist);
            if(fail)
                goto main_err;
            break;
        }
    if(sxfs->uri->path) {
        char *subdir = (char*)malloc(lenof("-omodules=subdir,subdir=") + 1 + strlen(sxfs->uri->path) + 1);

        if(!subdir) {
            fprintf(stderr, "Out of memory\n");
            goto main_err;
        }
        sprintf(subdir, "-omodules=subdir,subdir=/%s", sxfs->uri->path);
        if(fuse_opt_add_arg(&fargs, subdir)) {
            fprintf(stderr, "ERROR: Out of memory\n");
            free(subdir);
            goto main_err;
        }
        free(subdir);
    }

    sxfs->files = sxi_ht_new(sx, SXFS_ALLOC_ENTRIES);
    if(!sxfs->files) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        goto main_err;
    }
    if(!args.use_queues_flag) {
        int fd;
        sxfs->empty_file_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof("empty_file") + 1);
        if(!sxfs->empty_file_path) {
            fprintf(stderr, "ERROR: Out of memory\n");
            goto main_err;
        }
        sprintf(sxfs->empty_file_path, "%s/empty_file", sxfs->tempdir);
        fd = open(sxfs->empty_file_path, O_CREAT | O_WRONLY, 0600);
        if(fd < 0) {
            fprintf(stderr, "ERROR: Cannot create '%s' file: %s\n", sxfs->empty_file_path, strerror(errno));
            free(sxfs->empty_file_path);
            sxfs->empty_file_path = NULL;
            goto main_err;
        }
        if(close(fd)) {
            fprintf(stderr, "ERROR: Cannot close '%s' file: %s\n", sxfs->empty_file_path, strerror(errno));
            goto main_err;
        }
    }
    if(pthread_mutex_init(&sxfs->sx_data_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create SX data mutex\n");
        goto main_err;
    }
    pthread_flag |= SXFS_SX_DATA_MUTEX;
    if(pthread_mutex_init(&sxfs->ls_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create ls cache mutex\n");
        goto main_err;
    }
    pthread_flag |= SXFS_LS_MUTEX;
    if(pthread_mutex_init(&sxfs->delete_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create files deletion mutex\n");
        goto main_err;
    }
    pthread_flag |= SXFS_DELETE_MUTEX;
    if(pthread_mutex_init(&sxfs->delete_thread_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create deletion thread mutex\n");
        goto main_err;
    }
    pthread_flag |= SXFS_DELETE_THREAD_MUTEX;
    if(pthread_mutex_init(&sxfs->upload_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create files upload mutex\n");
        goto main_err;
    }
    pthread_flag |= SXFS_UPLOAD_MUTEX;
    if(pthread_mutex_init(&sxfs->upload_thread_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create upload thread mutex\n");
        goto main_err;
    }
    pthread_flag |= SXFS_UPLOAD_THREAD_MUTEX;
    if(pthread_mutex_init(&sxfs->files_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create files data mutex\n");
        goto main_err;
    }
    pthread_flag |= SXFS_FILES_MUTEX;
    if(pthread_mutex_init(&sxfs->limits_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create limits mutex\n");
        goto main_err;
    }
    pthread_flag |= SXFS_LIMITS_MUTEX;
    if(pthread_key_create(&sxfs->tid_key, sxfs_sx_data_destroy)) {
        fprintf(stderr, "ERROR: Cannot initialize per-thread memory\n");
        goto main_err;
    }
    sx_data.sx = sx;
    sx_data.cluster = cluster;
    sx_data.sx_data_mutex = &sxfs->sx_data_mutex;
    if(pthread_key_create(&sxfs->sxkey, sxfs_sx_data_destroy)) {
        fprintf(stderr, "ERROR: Cannot initialize per-thread memory\n");
        goto main_err;
    }
    pthread_flag |= SXFS_SX_DATA_KEY;
    if(pthread_key_create(&sxfs->tid_key, sxfs_thread_id_destroy)) {
        fprintf(stderr, "ERROR: Cannot initialize per-thread memory\n");
        goto main_err;
    }
    pthread_flag |= SXFS_THREAD_ID_KEY;
    if(pthread_setspecific(sxfs->sxkey, (void*)&sx_data)) {
        fprintf(stderr, "ERROR: Cannot set per-thread memory\n");
        goto main_err;
    }
    if(sxfs_get_thread_id(sxfs) < 0) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }

    if(sxfs->logfile && args.debug_flag) {
        fprintf(sxfs->logfile, "Parameters passed to FUSE:");
        for(i=1; i<fargs.argc; i++)
            fprintf(sxfs->logfile, " %s", fargs.argv[i]);
        fprintf(sxfs->logfile, "\n");
    }
    if(sxfs->logfile) {
        if(gettimeofday(&tv, NULL)) {
            fprintf(stderr, "ERROR: Cannot get current time: %s\n", strerror(errno));
            goto main_err;
        }
        tm = localtime(&tv.tv_sec);
        if(!tm) {
            fprintf(stderr, "ERROR: Cannot convert time value\n");
            goto main_err;
        }
        fprintf(sxfs->logfile, "%02d-%02d-%04d %02d:%02d:%02d.%03d : Starting FUSE\n", tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)tv.tv_usec / 1000);
    }

    ret = fuse_main(fargs.argc, fargs.argv, &sxfs_oper, sxfs);
    if(ret)
        fprintf(sxfs->logfile ? sxfs->logfile : stderr, "ERROR: FUSE failed\n");
main_err:
    free(cache_size_str);
    if(cache_dir && strcmp(cache_dir, sxfs->tempdir) && sxi_rmdirs(cache_dir) && errno != ENOENT) /* remove cache directory with its content */
        print_and_log(sxfs->logfile, "ERROR: Cannot remove '%s' directory: %s\n", cache_dir, strerror(errno)); /* 'cache_dir' is created after 'sxfs' */
    free(cache_dir);
    free(volume_name);
    free(username);
    free(profile);
    if(sxfs) {
        sxfs_cache_free(sxfs);
        if(pthread_flag & SXFS_THREAD_ID_KEY)
            free(pthread_getspecific(sxfs->tid_key));
        if((err = pthread_cond_destroy(&sxfs->delete_cond)))
            print_and_log(sxfs->logfile, "ERROR: Cannot destroy pthread condition: %s\n", strerror(err));
        if((err = pthread_cond_destroy(&sxfs->upload_cond)))
            print_and_log(sxfs->logfile, "ERROR: Cannot destroy pthread condition: %s\n", strerror(err));
        if(sxfs->files) {
            int files_not_uploaded = 0, recovery_failed = 0;
            unsigned int pathlen;
            char path[SXLIMIT_MAX_FILENAME_LEN+1], path2[PATH_MAX];
            const void *const_path;
            sxfs_file_t *sxfs_file;

            if(sxfs->logfile && sxfs->args->debug_flag)
                fprintf(sxfs->logfile, "%u opened files:\n", sxi_ht_count(sxfs->files));
            sxi_ht_enum_reset(sxfs->files);
            while(!sxi_ht_enum_getnext(sxfs->files, &const_path, &pathlen, NULL)) {
                if(pathlen >= sizeof(path)) {
                    print_and_log(sxfs->logfile, "ERROR: Too long path received (%lu)\n", pathlen);
                    continue;
                }
                memcpy(path, const_path, pathlen);
                path[pathlen] = '\0';
                if(sxfs->logfile && sxfs->args->debug_flag)
                    fprintf(sxfs->logfile, "'%s'\n", path);
                if(sxi_ht_get(sxfs->files, path, strlen(path), (void**)&sxfs_file)) {
                    print_and_log(sxfs->logfile, "ERROR: '%s' file disappeared from hashtable\n", path);
                    files_not_uploaded = recovery_failed = 1; /* don't know what happened, there can be files we don't want to lose */
                    continue;
                }
                if(sxfs_file->write_path) {
                    if(close(sxfs_file->write_fd)) /* write_path and write_fd are always set together */
                        print_and_log(sxfs->logfile, "ERROR: Cannot close '%s' file: %s\n", sxfs_file->write_path, strerror(errno));
                    sxfs_file->write_fd = -1;
                    if(sxfs_file->flush > 0) {
                        files_not_uploaded = 1;
                        snprintf(path2, sizeof(path2), "%s/%s", sxfs->lostdir, path);
                        if(sxfs_move_file(sxfs, sxfs_file->write_path, path2)) {
                            recovery_failed = 1;
                            print_and_log(sxfs->logfile, "ERROR: Cannot move '%s' file to '%s'\n", sxfs_file->write_path, path2);
                        }
                    }
                    free(sxfs_file->write_path);
                    sxfs_file->write_path = NULL;
                }
                sxfs_file_free(sxfs, sxfs_file);
            }
            if(files_not_uploaded) {
                print_and_log(sxfs->logfile, "WARNING: Some files could not be uploaded and have been saved into '%s'\n", sxfs->lostdir);
                if(recovery_failed) {
                    print_and_log(sxfs->logfile, "ERROR: Couldn't move some files to the recovery directory. The files are still available in '%s/%s'\n", sxfs->tempdir, SXFS_UPLOAD_DIR);
                    sxfs->recovery_failed = 1;
                }
            }
        }
        free(sxfs->fh_table);
        free(sxfs->threads);
        if(sxfs->empty_file_path) {
            if(unlink(sxfs->empty_file_path))
                print_and_log(sxfs->logfile, "ERROR: Cannot remove '%s' directory: %s\n", sxfs->empty_file_path, strerror(errno));
            free(sxfs->empty_file_path);
        }
        if(tempdir_created && !sxfs->recovery_failed && sxi_rmdirs(sxfs->tempdir))
            print_and_log(sxfs->logfile, "ERROR: Cannot remove '%s' directory: %s\n", sxfs->tempdir, strerror(errno));
        if(tempdir_created == 2 && rmdir(sxfs->lostdir) && errno != ENOTEMPTY)
            print_and_log(sxfs->logfile, "ERROR: Cannot remove '%s' directory: %s\n", sxfs->lostdir, strerror(errno));
        if(!args.tempdir_given)
            free(sxfs->tempdir);
        if(!args.recovery_dir_given)
            free(sxfs->lostdir);
        sxfs_lsdir_free(sxfs->root);
        sxc_free_uri(sxfs->uri);
        sxi_ht_free(sxfs->files);
        if(pthread_flag & SXFS_SX_DATA_MUTEX && (err = pthread_mutex_destroy(&sxfs->sx_data_mutex)))
            print_and_log(sxfs->logfile, "ERROR: Cannot destroy SX data mutex: %s\n", strerror(err));
        if(pthread_flag & SXFS_LS_MUTEX && (err = pthread_mutex_destroy(&sxfs->ls_mutex)))
            print_and_log(sxfs->logfile, "ERROR: Cannot destroy ls cache mutex: %s\n", strerror(err));
        if(pthread_flag & SXFS_DELETE_MUTEX && (err = pthread_mutex_destroy(&sxfs->delete_mutex)))
            print_and_log(sxfs->logfile, "ERROR: Cannot destroy deletion mutex: %s\n", strerror(err));
        if(pthread_flag & SXFS_DELETE_THREAD_MUTEX && (err = pthread_mutex_destroy(&sxfs->delete_thread_mutex)))
            print_and_log(sxfs->logfile, "ERROR: Cannot destroy deletion thread mutex: %s\n", strerror(err));
        if(pthread_flag & SXFS_UPLOAD_MUTEX && (err = pthread_mutex_destroy(&sxfs->upload_mutex)))
            print_and_log(sxfs->logfile, "ERROR: Cannot destroy upload mutex: %s\n", strerror(err));
        if(pthread_flag & SXFS_UPLOAD_THREAD_MUTEX && (err = pthread_mutex_destroy(&sxfs->upload_thread_mutex)))
            print_and_log(sxfs->logfile, "ERROR: Cannot destroy upload thread mutex: %s\n", strerror(err));
        if(pthread_flag & SXFS_FILES_MUTEX && (err = pthread_mutex_destroy(&sxfs->files_mutex)))
            print_and_log(sxfs->logfile, "ERROR: Cannot destroy files data mutex: %s\n", strerror(err));
        if(pthread_flag & SXFS_LIMITS_MUTEX && (err = pthread_mutex_destroy(&sxfs->limits_mutex)))
            print_and_log(sxfs->logfile, "ERROR: Cannot destroy limits mutex: %s\n", strerror(err));
        if(pthread_flag & SXFS_SX_DATA_KEY && (err = pthread_key_delete(sxfs->sxkey)))
            print_and_log(sxfs->logfile, "ERROR: Cannot delete per-thread memory key: %s\n", strerror(err));
        if(pthread_flag & SXFS_THREAD_ID_KEY && (err = pthread_key_delete(sxfs->tid_key)))
            print_and_log(sxfs->logfile, "ERROR: Cannot delete per-thread memory key: %s\n", strerror(err));
        if(sxfs->logfile)
            fprintf(sxfs->logfile, "sxfs stopped\n");
        if(sxfs->pipefd[0] >= 0 && close(sxfs->pipefd[0]))
            print_and_log(sxfs->logfile, "ERROR: Cannot close read end of the pipe: %s\n", strerror(errno));
        sxfs->pipefd[0] = -1;
        if(sxfs->pipefd[1] >= 0) {
            int status = ret ? 1 : 0;
            char eot = 4;
            write(sxfs->pipefd[1], &eot, 1); /* End of transmission */
            write(sxfs->pipefd[1], &status, sizeof(int));
            if(close(sxfs->pipefd[1]))
                print_and_log(sxfs->logfile, "Cannot close write end of the pipe: %s\n", strerror(errno));
            sxfs->pipefd[1] = -1;
        }
        if(sxfs->logfile && fclose(sxfs->logfile) == EOF)
            fprintf(stderr, "ERROR: Cannot close logfile: %s\n", strerror(errno));
        free(sxfs);
    }
    sxc_meta_free(volmeta);
    sxc_cluster_listaclusers_free(ulist);
    sxc_cluster_free(cluster);
    sxc_shutdown(sx, 0);
    fuse_opt_free_args(&fargs);
    fuse_opt_free_args(&fargs_tmp);
    cmdline_parser_free(&args);
    return ret;
} /* main */

