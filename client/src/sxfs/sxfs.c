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

#include "params.h"
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <inttypes.h>
#include "libsxclient/src/clustcfg.h"
#include "libsxclient/include/version.h"
#include "libsxclient/src/fileops.h"

static int check_path_len (const char *path, int is_dir) {
    if(strlen(path) + (is_dir ? 1 + lenof(EMPTY_DIR_FILE) : 0) > SXLIMIT_MAX_FILENAME_LEN) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if(SXFS_DATA->args->use_queues_flag) {
        char *ptr = strrchr(path, '/');

        if(!ptr) {
            SXFS_LOG("'/' not found in '%s'", path);
            errno = EINVAL;
            return -1;
        }
        ptr++;
        if(strlen(ptr) > NAME_MAX) {
            errno = ENAMETOOLONG;
            return -1;
        }
    }
    return 0;
} /* check_path_len */

static int sxfs_getattr (const char *path, struct stat *st) {
    int tmp;
    char *path2 = NULL;

    if(!path || !st) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s'", path);
    if(check_path_len(path, 0))
        return -errno;
    if(strlen(path) > 1 && path[strlen(path)-1] == '/') {
        path2 = strdup(path);
        if(!path2) {
            SXFS_LOG("Out of memory: %s", path);
            return -errno;
        }
        path2[strlen(path2)-1] = '\0';
    }
    if((tmp = sxfs_ls_stat(path2 ? path2 : path, st))) {
        if(tmp < 0) {
            SXFS_LOG("Cannot check file status: %s", path2 ? path2 : path);
            free(path2);
            return errno ? -errno : -ENOMSG;
        }
        free(path2);
        st->st_atime = st->st_mtime;
        return 0;
    }
    SXFS_DEBUG("%s: %s", strerror(ENOENT), path2 ? path2 : path);
    free(path2);
    return -ENOENT;
} /* sxfs_getattr */

static int sxfs_readlink (const char *path, char *buf, size_t bufsize) {
    return -ENOTSUP;
} /* sxfs_readlink*/

static int sxfs_mknod (const char *path, mode_t mode, dev_t dev) {
    int ret = -1;
    size_t i;
    char *file_name;
    sxfs_lsdir_t *dir;

    if(!path) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', mode: %c%c%c%c%c%c%c%c%c%c (%u)", path, S_ISDIR(mode) ? 'd' : '-',
                        mode & S_IRUSR ? 'r' : '-', mode & S_IWUSR ? 'w' : '-', mode & S_IXUSR ? 'x' : '-',
                        mode & S_IRGRP ? 'r' : '-', mode & S_IWGRP ? 'w' : '-', mode & S_IXGRP ? 'x' : '-',
                        mode & S_IROTH ? 'r' : '-', mode & S_IWOTH ? 'w' : '-', mode & S_IXOTH ? 'x' : '-', (unsigned int)mode);
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    if(check_path_len(path, 0))
        return -errno;
    if(mode && !S_ISREG(mode)) {
        SXFS_LOG("Not supported type of file: %s", S_ISCHR(mode) ? "character special file" : S_ISBLK(mode) ? "block special file" :
                                                   S_ISFIFO(mode) ? "FIFO (named pipe)" : S_ISSOCK(mode) ? "UNIX domain socket" : "unknown type");
        return -ENOTSUP;
    }
    file_name = strrchr(path, '/');
    if(!file_name) {
        SXFS_LOG("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name++;
    /* no 'goto' used before for easy mutex unlock */
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(!(dir = sxfs_ls_update(path))) {
        SXFS_LOG("Cannot load file tree: %s", path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_mknod_err;
    }
    if(sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp) >= 0) {
        SXFS_LOG("File already exists: %s", path);
        ret = -EEXIST;
        goto sxfs_mknod_err;
    }
    if(sxfs_find_entry((const void**)dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp) >= 0) {
        SXFS_LOG("Directory already exists: %s", path);
        ret = -EEXIST;
        goto sxfs_mknod_err;
    }
    if(sxfs_lsdir_add_file(dir, path, NULL)) {
        SXFS_LOG("Cannot add new file to cache: %s", path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_mknod_err;
    }
    if(sxfs_upload(NULL, path, &dir->files[dir->nfiles-1]->st.st_mtime, 0)) {
        SXFS_LOG("Cannot upload empty file: %s", path);
        sxfs_lsfile_free(dir->files[dir->nfiles-1]);
        dir->files[dir->nfiles-1] = NULL;
        dir->nfiles--;
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_mknod_err;
    }
    if(!SXFS_DATA->args->use_queues_flag)
        dir->files[dir->nfiles-1]->remote = 1;
    for(i=dir->nfiles-1; i>0 && strcmp(dir->files[i-1]->name, dir->files[i]->name) > 0; i--) {
        sxfs_lsfile_t *tmp = dir->files[i-1];
        dir->files[i-1] = dir->files[i];
        dir->files[i] = tmp;
    }

    ret = 0;
sxfs_mknod_err:
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    return ret;
} /* sxfs_mknod */

static int sxfs_mkdir (const char *path, mode_t mode) {
    int ret = -1;
    size_t i;
    char *dir_name, *remote_file_path;
    sxfs_lsdir_t *dir;

    if(!path) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', mode: %c%c%c%c%c%c%c%c%c%c (%u)", path, S_ISDIR(mode) ? 'd' : '-',
                        mode & S_IRUSR ? 'r' : '-', mode & S_IWUSR ? 'w' : '-', mode & S_IXUSR ? 'x' : '-',
                        mode & S_IRGRP ? 'r' : '-', mode & S_IWGRP ? 'w' : '-', mode & S_IXGRP ? 'x' : '-',
                        mode & S_IROTH ? 'r' : '-', mode & S_IWOTH ? 'w' : '-', mode & S_IXOTH ? 'x' : '-', (unsigned int)mode);
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    if(check_path_len(path, 1))
        return -errno;
    dir_name = strrchr(path, '/');
    if(!dir_name) {
        SXFS_LOG("'/' not found in '%s'", path);
        return -EINVAL;
    }
    dir_name++;
    remote_file_path = (char*)malloc(strlen(path) + 1 + lenof(EMPTY_DIR_FILE) + 1);
    if(!remote_file_path) {
        SXFS_LOG("Out of memory");
        return -ENOMEM;
    }
    sprintf(remote_file_path, "%s/%s", path, EMPTY_DIR_FILE);
    /* no 'goto' used before for easy mutex unlock */
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(!(dir = sxfs_ls_update(path))) {
        SXFS_LOG("Cannot load file tree: %s", path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_mkdir_err;
    }
    if(sxfs_find_entry((const void**)dir->files, dir->nfiles, dir_name, sxfs_lsfile_cmp) >= 0) {
        SXFS_LOG("File already exists: %s", path);
        ret = -EEXIST;
        goto sxfs_mkdir_err;
    }
    if(sxfs_find_entry((const void**)dir->dirs, dir->ndirs, dir_name, sxfs_lsdir_cmp) >= 0) {
        SXFS_LOG("Directory already exists: %s", path);
        ret = -EEXIST;
        goto sxfs_mkdir_err;
    }
    if(sxfs_lsdir_add_dir(dir, path)) {
        SXFS_LOG("Cannot add new directory to cache: %s", path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_mkdir_err;
    }
    if(sxfs_upload(NULL, remote_file_path, &dir->dirs[dir->ndirs-1]->st.st_mtime, 0)) {
        SXFS_LOG("Cannot upload empty file: %s", remote_file_path);
        sxfs_lsdir_free(dir->dirs[dir->ndirs-1]);
        dir->dirs[dir->ndirs-1] = NULL;
        dir->ndirs--;
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_mkdir_err;
    }
    if(!SXFS_DATA->args->use_queues_flag)
        dir->dirs[dir->ndirs-1]->remote = 1;
    dir->dirs[dir->ndirs-1]->sxnewdir = SXFS_DATA->args->use_queues_flag ? 1 : 2;
    for(i=dir->ndirs-1; i>0 && strcmp(dir->dirs[i-1]->name, dir->dirs[i]->name) > 0; i--) {
        sxfs_lsdir_t *tmp = dir->dirs[i-1];
        dir->dirs[i-1] = dir->dirs[i];
        dir->dirs[i] = tmp;
    }

    ret = 0;
sxfs_mkdir_err:
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    free(remote_file_path);
    return ret;
} /* sxfs_mkdir */

static int sxfs_unlink (const char *path) {
    int ret = -1, index;
    size_t i;
    time_t mctime;
    char *file_name;
    sxfs_lsdir_t *dir;

    if(!path) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s'", path);
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    if(check_path_len(path, 0))
        return -errno;
    if(time(&mctime) < 0) {
        SXFS_LOG("Cannot get current time: %s", strerror(errno));
        return -1;
    }
    file_name = strrchr(path, '/');
    if(!file_name) {
        SXFS_LOG("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name++;
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(!(dir = sxfs_ls_update(path))) {
        SXFS_LOG("Cannot load file tree: %s", path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_unlink_err;
    }
    index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
    if(index < 0) {
        SXFS_LOG("File not found: %s", path);
        ret = -ENOENT;
        goto sxfs_unlink_err;
    }

    /* check whether this is the last entry in directory */
    if(dir->nfiles == 1 && !dir->ndirs && !dir->sxnewdir && strcmp(dir->name, "/")) {
        char *ptr, *newdir_file = (char*)malloc(strlen(path) + 1 + lenof(EMPTY_DIR_FILE) + 1);
        if(!newdir_file) {
            SXFS_LOG("Out of memory");
            ret = -ENOMEM;
            goto sxfs_unlink_err;
        }
        sprintf(newdir_file, "%s", path);
        ptr = strrchr(newdir_file, '/');
        if(!ptr) {
            SXFS_LOG("'/' not found in '%s'", newdir_file);
            free(newdir_file);
            ret = -EINVAL;
            goto sxfs_unlink_err;
        }
        ptr++;
        *ptr = '\0';
        strcat(newdir_file, EMPTY_DIR_FILE);
        if(sxfs_upload(NULL, newdir_file, NULL, 0)) {
            SXFS_LOG("Cannot upload empty file: %s", newdir_file);
            free(newdir_file);
            ret = errno ? -errno : -ENOMSG;
            goto sxfs_unlink_err;
        }
        dir->sxnewdir = SXFS_DATA->args->use_queues_flag ? 1 : 2;
        free(newdir_file);
    }
    if(sxfs_delete(path, dir->files[index]->remote)) {
        SXFS_LOG("Cannot remove file: %s", path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_unlink_err;
    }

    /* remove file from cache */
    sxfs_lsfile_free(dir->files[index]);
    for(i=index+1; i<dir->nfiles; i++)
        dir->files[i-1] = dir->files[i];
    dir->files[dir->nfiles-1] = NULL;
    dir->nfiles--;
    dir->st.st_mtime = dir->st.st_ctime = mctime;

    ret = 0;
sxfs_unlink_err:
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    return ret;
} /* sxfs_unlink */

static int sxfs_rmdir (const char *path) {
    int ret = -1, index;
    size_t i;
    time_t mctime;
    char *dir_name, *dirpath;
    sxfs_lsdir_t *dir;

    if(!path) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s'", path);
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    if(check_path_len(path, 1))
        return -errno;
    if(time(&mctime) < 0) {
        SXFS_LOG("Cannot get current time: %s", strerror(errno));
        return -1;
    }
    dir_name = strrchr(path, '/');
    if(!dir_name) {
        SXFS_LOG("'/' not found in '%s'", path);
        return -EINVAL;
    }
    dir_name++;
    dirpath = (char*)malloc(strlen(path) + 1 + lenof(EMPTY_DIR_FILE) + 1);
    if(!dirpath) {
        SXFS_LOG("Out of memory");
        return -ENOMEM;
    }
    sprintf(dirpath, "%s/%s", path, EMPTY_DIR_FILE);
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(!(dir = sxfs_ls_update(dirpath))) { /* loading content of deleting directory */
        SXFS_LOG("Cannot load file tree: %s", dirpath);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_rmdir_err;
    }
    if(dir->ndirs || dir->nfiles) {
        SXFS_LOG("Directory not empty: %s", path);
        ret = -ENOTEMPTY;
        goto sxfs_rmdir_err;
    }
    dir = dir->parent; /* go back to get deleting directory in dir->dirs[] */
    index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, dir_name, sxfs_lsdir_cmp);
    if(index < 0) { /* should never be true */
        SXFS_LOG("Directory not found: %s", path);
        ret = -ENOENT;
        goto sxfs_rmdir_err;
    }

    /* check whether this is the last entry in directory */
    if(!dir->nfiles && dir->ndirs == 1 && !dir->sxnewdir && strcmp(dir->name, "/")) {
        char *ptr, *newdir_file = (char*)malloc(strlen(path) + 1 + lenof(EMPTY_DIR_FILE) + 1);
        if(!newdir_file) {
            SXFS_LOG("Out of memory");
            ret = -ENOMEM;
            goto sxfs_rmdir_err;
        }
        sprintf(newdir_file, "%s", path);
        ptr = strrchr(newdir_file, '/');
        if(!ptr) {
            SXFS_LOG("'/' not found in '%s'", newdir_file);
            free(newdir_file);
            ret = -EINVAL;
            goto sxfs_rmdir_err;
        }
        ptr++;
        *ptr = '\0';
        strcat(newdir_file, EMPTY_DIR_FILE);
        if(sxfs_upload(NULL, newdir_file, NULL, 0)) {
            SXFS_LOG("Cannot upload empty file: %s", newdir_file);
            free(newdir_file);
            ret = errno ? -errno : -ENOMSG;
            goto sxfs_rmdir_err;
        }
        dir->sxnewdir = SXFS_DATA->args->use_queues_flag ? 1 : 2;
        free(newdir_file);
    }

    if(sxfs_delete(dirpath, dir->dirs[index]->remote || dir->dirs[index]->sxnewdir == 2)) {
        SXFS_LOG("Cannot remove file: %s", dirpath);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_rmdir_err;
    }

    /* remove directory from cache */
    sxfs_lsdir_free(dir->dirs[index]);
    for(i=index+1; i<dir->ndirs; i++)
        dir->dirs[i-1] = dir->dirs[i];
    dir->dirs[dir->ndirs-1] = NULL;
    dir->ndirs--;
    dir->st.st_mtime = dir->st.st_ctime = mctime;

    ret = 0;
sxfs_rmdir_err:
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    free(dirpath);
    return ret;
} /* sxfs_rmdir */

static int sxfs_symlink (const char *path, const char *newpath) {
    return -ENOTSUP;
} /* sxfs_symlink*/

static int sxfs_rename (const char *path, const char *newpath) {
    int ret = -1, operation_type, locked = 0, queue_renamed = 0, tmp_created = 0, sxnewdir = 0, tmp; /* type: 1 - file, 2 - directory */
    ssize_t index_from, index_to;
    size_t i;
    char *file_name_from, *file_name_to, *src_path = NULL, *dst_path = NULL, *dst_path2 = NULL, *local_file_path = NULL, *local_newfile_path = NULL, *local_newfile_path2 = NULL;
    time_t ctime;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *src = NULL, *dest = NULL;
    sxfs_lsdir_t *dir_from, *dir_to;
    sxfs_file_t *sxfs_file;
 
    if(!path || !newpath) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/' || *newpath != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s' -> '%s'", path, newpath);
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    if(check_path_len(path, 0) || check_path_len(newpath, 0))
        return -errno;
    if(!strcmp(path, newpath))
        return -EINVAL;
    if(sxfs_get_sx_data(SXFS_DATA, &sx, &cluster)) {
        SXFS_LOG("Cannot get Sx data");
        return errno ? -errno : -ENOMSG;
    }
    if(time(&ctime) < 0) {
        SXFS_LOG("Cannot get current time: %s", strerror(errno));
        return -errno;
    }
    file_name_from = strrchr(path, '/');
    if(!file_name_from) {
        SXFS_LOG("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name_from++;
    file_name_to = strrchr(newpath, '/');
    if(!file_name_to) {
        SXFS_LOG("'/' not found in '%s'", newpath);
        return -EINVAL;
    }
    file_name_to = strdup(file_name_to + 1);
    if(!file_name_to) {
        SXFS_LOG("Out of memory: %s", strrchr(newpath, '/') + 1);
        return -errno;
    }
    src_path = (char*)malloc(strlen(path) + 1 + lenof(EMPTY_DIR_FILE) + 1);
    if(!src_path) {
        SXFS_LOG("Out of memory");
        ret = -ENOMEM;
        goto sxfs_rename_err;
    }
    dst_path = (char*)malloc(strlen(newpath) + 1 + lenof(EMPTY_DIR_FILE) + 1);
    if(!dst_path) {
        SXFS_LOG("Out of memory");
        ret = -ENOMEM;
        goto sxfs_rename_err;
    }
    dst_path2 = (char*)malloc(strlen(newpath) + lenof("_XXXXXX/") + 1);
    if(!dst_path2) {
        SXFS_LOG("Out of memory");
        ret = -ENOMEM;
        goto sxfs_rename_err;
    }
    local_file_path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + strlen(path) + 1 + lenof(EMPTY_DIR_FILE) + 1);
    if(!local_file_path) {
        SXFS_LOG("Out of memory");
        ret = -ENOMEM;
        goto sxfs_rename_err;
    }
    sprintf(local_file_path, "%s/%s%s", SXFS_DATA->tempdir, SXFS_UPLOAD_DIR, path);
    local_newfile_path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + strlen(newpath) + 1);
    if(!local_newfile_path) {
        SXFS_LOG("Out of memory");
        ret = -ENOMEM;
        goto sxfs_rename_err;
    }
    sprintf(local_newfile_path, "%s/%s%s", SXFS_DATA->tempdir, SXFS_UPLOAD_DIR, newpath);
    local_newfile_path2 = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + strlen(newpath) + lenof("_XXXXXX/") + 1);
    if(!local_newfile_path2) {
        SXFS_LOG("Out of memory");
        ret = -ENOMEM;
        goto sxfs_rename_err;
    }
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    locked = 1;
    if(!(dir_from = sxfs_ls_update(path))) {
        SXFS_LOG("Cannot load file tree: %s", path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_rename_err;
    }
    if(!(dir_to = sxfs_ls_update(newpath))) {
        SXFS_LOG("Cannot load file tree: %s", newpath);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_rename_err;
    }
    index_from = sxfs_find_entry((const void**)dir_from->files, dir_from->nfiles, file_name_from, sxfs_lsfile_cmp);
    if(index_from >= 0) {
        operation_type = 1;
        if(dir_from->nfiles == 1 && !dir_from->ndirs && dir_from != dir_to)
            sxnewdir = 1;
    } else {
        index_from = sxfs_find_entry((const void**)dir_from->dirs, dir_from->ndirs, file_name_from, sxfs_lsdir_cmp);
        if(index_from >= 0) {
            operation_type = 2;
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
        if(operation_type == 2) {
            SXFS_LOG("New name is a file but old is a directory: '%s' and '%s'", path, newpath);
            ret = -ENOTDIR;
            goto sxfs_rename_err;
        }
    } else {
        index_to = sxfs_find_entry((const void**)dir_to->dirs, dir_to->ndirs, file_name_to, sxfs_lsdir_cmp);
        if(index_to >= 0) {
            if(operation_type == 1) {
                SXFS_LOG("New name is a directory but old is a file: '%s' and '%s'", path, newpath);
                ret = -EISDIR;
                goto sxfs_rename_err;
            }
        } else {
            if(operation_type == 1) {
                if(dir_from != dir_to && dir_to->nfiles == dir_to->maxfiles && sxfs_resize((void**)&dir_to->files, &dir_to->maxfiles, sizeof(sxfs_lsfile_t*))) {
                    SXFS_LOG("OOM growing file list: %s", strerror(errno));
                    ret = -errno;
                    goto sxfs_rename_err;
                }
            } else {
                if(dir_from != dir_to && dir_to->ndirs == dir_to->maxdirs && sxfs_resize((void**)&dir_to->dirs, &dir_to->maxdirs, sizeof(sxfs_lsdir_t*))) {
                    SXFS_LOG("OOM growing directories list: %s", strerror(errno));
                    ret = -errno;
                    goto sxfs_rename_err;
                }
            }
        }
    }
    sprintf(src_path, "%s%s", path, operation_type == 2 ? "/" : "");
    sprintf(dst_path, "%s%s", newpath, operation_type == 2 ? "/" : "");
    if(SXFS_DATA->args->use_queues_flag && sxfs_delete_check_path(dst_path)) {
        SXFS_LOG("Cannot check deletion queue: %s", dst_path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_rename_err;
    }
    if(operation_type == 2 && index_to >= 0) {
        sxfs_lsdir_t *dir;
        sprintf(dst_path, "%s/", newpath);
        if(!(dir = sxfs_ls_update(dst_path))) { /* load content of destination directory */
            SXFS_LOG("Cannot load file tree: %s", dst_path);
            ret = errno ? -errno : -ENOMSG;
            goto sxfs_rename_err;
        }
        if(dir->nfiles || dir->ndirs) {
            SXFS_LOG("Destination directory not empty: %s", newpath);
            ret = -ENOTEMPTY;
            goto sxfs_rename_err;
        }
    }
    if(!dir_from->sxnewdir && sxnewdir) {
        char *newdir_file = (char*)malloc(strlen(path) + 1 + lenof(EMPTY_DIR_FILE) + 1);
        if(!newdir_file) {
            SXFS_LOG("Out of memory");
            ret = -ENOMEM;
            goto sxfs_rename_err;
        }
        sprintf(newdir_file, "%s/%s", path, EMPTY_DIR_FILE);
        if(sxfs_upload(NULL, newdir_file, NULL, 0)) {
            SXFS_LOG("Cannot upload empty file: %s", newdir_file);
            free(newdir_file);
            ret = errno ? -errno : -ENOMSG;
            goto sxfs_rename_err;
        }
        dir_from->sxnewdir = SXFS_DATA->args->use_queues_flag ? 1 : 2;
        free(newdir_file);
    }
    if(index_to >= 0) {
        int fd;
        ssize_t index;
        char tmp_name[] = "/tmp/sxfs_namegen_XXXXXX", *name;

        do {
            fd = mkstemp(tmp_name);
            if(fd < 0) {
                SXFS_LOG("Cannot create unique temporary file: %s", strerror(errno));
                ret = -errno;
                goto sxfs_rename_err;
            }
            close(fd);
            unlink(tmp_name);
            sprintf(dst_path2, "%s%s", newpath, tmp_name + lenof(tmp_name) - 7);
            name = strrchr(dst_path2, '/') + 1;
            index = sxfs_find_entry((const void**)dir_to->files, dir_to->nfiles, name, sxfs_lsfile_cmp);
            if(index < 0)
                index = sxfs_find_entry((const void**)dir_to->dirs, dir_to->ndirs, name, sxfs_lsdir_cmp);
        } while(index >= 0);
        if(operation_type == 2)
            strcat(dst_path2, "/");
        sprintf(local_newfile_path2, "%s/%s%s", SXFS_DATA->tempdir, SXFS_UPLOAD_DIR, dst_path2);
    }
    pthread_mutex_lock(&SXFS_DATA->files_mutex);
    if(!sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL)) {
        if(sxc_meta_setval(SXFS_DATA->files, newpath, sxfs_file, sizeof(sxfs_file_t))) {
            SXFS_LOG("Cannot add new file: %s", newpath); /* FIXME: message */
            pthread_mutex_unlock(&SXFS_DATA->files_mutex);
            ret = -ENOMEM;
            goto sxfs_rename_err;
        }
    }
    pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    if(SXFS_DATA->args->use_queues_flag) {
        if(operation_type == 2) { /* there can be something deleted inside directory being renamed */
            tmp = sxfs_delete_rename(src_path, dst_path, 0);
            if(tmp) {
                if(tmp < 0) {
                    SXFS_LOG("Cannot rename files in deletion queue");
                    ret = errno ? -errno : -ENOMSG;
                    goto sxfs_rename_err;
                }
                queue_renamed = 1;
            }
        }
        pthread_mutex_lock(&SXFS_DATA->upload_mutex);
        locked |= 2;
        if(index_to >= 0) {
            tmp = sxfs_upload_rename(dst_path, dst_path2, 0);
            if(tmp) {
                if(tmp < 0) {
                    SXFS_LOG("Cannot temporary rename files in upload queue");
                    ret = errno ? -errno : -ENOMSG;
                    goto sxfs_rename_err;
                }
                tmp_created = 1;
                if(sxfs_build_path(local_newfile_path2)) {
                    SXFS_LOG("Cannot create path: %s", local_newfile_path2);
                    ret = -errno;
                    goto sxfs_rename_err;
                }
                if(rename(local_newfile_path, local_newfile_path2)) {
                    SXFS_LOG("Cannot rename '%s' to '%s': %s", local_newfile_path, local_newfile_path2, strerror(errno));
                    ret = -errno;
                    goto sxfs_rename_err;
                }
                tmp_created |= 2;
            }
        }
        tmp = sxfs_upload_rename(src_path, dst_path, 0);
        if(tmp) {
            if(tmp < 0) {
                SXFS_LOG("Cannot rename files in upload queue");
                ret = errno ? -errno : -ENOMSG;
                goto sxfs_rename_err;
            }
            queue_renamed |= 2;
            if(sxfs_build_path(local_newfile_path)) {
                SXFS_LOG("Cannot create path: %s", local_newfile_path);
                ret = -errno;
                goto sxfs_rename_err;
            }
            if(rename(local_file_path, local_newfile_path)) {
                SXFS_LOG("Cannot rename '%s' to '%s': %s", local_file_path, local_newfile_path, strerror(errno));
                ret = -errno;
                goto sxfs_rename_err;
            }
            queue_renamed |= 4;
        }
        if(!tmp_created && queue_renamed < 2) {
            pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
            locked &= ~2;
        }
    }
    /* move remote file */
    if((operation_type == 1 && dir_from->files[index_from]->remote) || (operation_type == 2 && dir_from->dirs[index_from]->remote)) {
        src = sxc_file_remote(cluster, SXFS_DATA->uri->volume, src_path+1, NULL);
        if(!src) {
            SXFS_LOG("Cannot create file object: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_rename_err;
        }
        dest = sxc_file_remote(cluster, SXFS_DATA->uri->volume, dst_path+1, NULL);
        if(!dest) {
            SXFS_LOG("Cannot create file object: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_rename_err;
        }
        if(sxc_mass_rename(cluster, src, dest, 1)) {
            SXFS_LOG("%s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_rename_err;
        }
    }
    /* cache update */
    if(operation_type == 1) { /* renaming file */
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
        if(queue_renamed & 1 && sxfs_delete_rename(dst_path, src_path, 1) != 1)
            SXFS_LOG("Cannot rename files in deletion queue: %s", strerror(errno));
        if(queue_renamed & 2 && sxfs_upload_rename(dst_path, src_path, 1) != 1)
            SXFS_LOG("Cannot rename files in upload queue: %s", strerror(errno));
        if(queue_renamed & 4 && rename(local_newfile_path, local_file_path))
            SXFS_LOG("Cannot rename '%s' to '%s': %s", local_newfile_path, local_file_path, strerror(errno));
        if(tmp_created & 1 && sxfs_upload_rename(dst_path2, dst_path, 1) != 1)
            SXFS_LOG("Cannot rename temporary files in upload queue: %s", strerror(errno));
        if(tmp_created & 2 && rename(local_newfile_path2, local_newfile_path))
            SXFS_LOG("Cannot rename '%s' to '%s': %s", local_newfile_path, local_file_path, strerror(errno));
    } else {
        if(tmp_created & 1 && sxfs_upload_del_path(dst_path2))
            SXFS_LOG("Cannot remove '%s' from upload queue: %s", dst_path2, strerror(errno));
        if(tmp_created & 2 && sxfs_rmdirs(local_newfile_path2))
            SXFS_LOG("Cannot remove '%s' file: %s", local_newfile_path2, strerror(errno));
    }
    if(locked & 1) {
        pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
        pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    }
    if(locked & 2)
        pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
    pthread_mutex_lock(&SXFS_DATA->files_mutex);
    sxc_meta_delval(SXFS_DATA->files, ret ? newpath : path);
    pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    free(file_name_to);
    free(src_path);
    free(dst_path);
    free(dst_path2);
    free(local_file_path);
    free(local_newfile_path);
    free(local_newfile_path2);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* sxfs_rename */

static int sxfs_link (const char *path, const char *newpath) {
    return -ENOTSUP;
} /* sxfs_link*/

static int sxfs_chmod (const char *path, mode_t mode) {
    int ret = -1;
    ssize_t index;
    time_t ctime;
    char *path2 = NULL, *file_name;
    sxfs_lsdir_t *dir;

    if(!path) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', mode: %c%c%c%c%c%c%c%c%c%c (%u)", path, S_ISDIR(mode) ? 'd' : '-',
                        mode & S_IRUSR ? 'r' : '-', mode & S_IWUSR ? 'w' : '-', mode & S_IXUSR ? 'x' : '-',
                        mode & S_IRGRP ? 'r' : '-', mode & S_IWGRP ? 'w' : '-', mode & S_IXGRP ? 'x' : '-',
                        mode & S_IROTH ? 'r' : '-', mode & S_IWOTH ? 'w' : '-', mode & S_IXOTH ? 'x' : '-', (unsigned int)mode);
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    if(check_path_len(path, 0))
        return -errno;
    if(time(&ctime) < 0) {
        SXFS_LOG("Cannot get current time: %s", strerror(errno));
        return -errno;
    }
    if(!strcmp(path, "/")) {
        pthread_mutex_lock(&SXFS_DATA->ls_mutex);
        SXFS_DATA->root->st.st_ctime = ctime;
        pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
        return 0;
    }
    if(strlen(path) > 1 && path[strlen(path)-1] == '/') {
        path2 = strdup(path);
        if(!path2) {
            SXFS_LOG("Out of memory: %s", path);
            return -errno;
        }
        path2[strlen(path2)-1] = '\0';
    }
    file_name = strrchr(path2 ? path2 : path, '/');
    if(!file_name) {
        SXFS_LOG("'/' not found in '%s'", path2 ? path2 : path);
        free(path2);
        return -EINVAL;
    }
    file_name++;
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    dir = sxfs_ls_update(path2 ? path2 : path);
    if(!dir) {
        SXFS_LOG("Cannot load file tree: %s", path2 ? path2 : path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_chmod_err;
    }
    index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp);
    if(index >= 0) {
        dir->dirs[index]->st.st_ctime = ctime;
    } else {
        index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
        if(index >= 0) {
            dir->files[index]->st.st_ctime = ctime;
        } else {
            SXFS_LOG("%s: %s", strerror(ENOENT), path2 ? path2 : path);
            ret = -ENOENT;
            goto sxfs_chmod_err;
        }
    }

    ret = 0;
sxfs_chmod_err:
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    free(path2);
    return ret;
} /* sxfs_chmod */

static int sxfs_chown (const char *path, uid_t uid, gid_t gid) {
    int ret = -1;
    ssize_t index;
    time_t ctime;
    char *path2 = NULL, *file_name;
    sxfs_lsdir_t *dir;

    if(!path) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', uid: %u, gid: %u", path, (unsigned int)uid, (unsigned int)gid);
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    if(check_path_len(path, 0))
        return -errno;
    if(time(&ctime) < 0) {
        SXFS_LOG("Cannot get current time: %s", strerror(errno));
        return -errno;
    }
    if(!strcmp(path, "/")) {
        pthread_mutex_lock(&SXFS_DATA->ls_mutex);
        SXFS_DATA->root->st.st_ctime = ctime;
        pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
        return 0;
    }
    if(strlen(path) > 1 && path[strlen(path)-1] == '/') {
        path2 = strdup(path);
        if(!path2) {
            SXFS_LOG("Out of memory: %s", path);
            return -errno;
        }
        path2[strlen(path2)-1] = '\0';
    }
    file_name = strrchr(path2 ? path2 : path, '/');
    if(!file_name) {
        SXFS_LOG("'/' not found in '%s'", path2 ? path2 : path);
        free(path2);
        return -EINVAL;
    }
    file_name++;
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    dir = sxfs_ls_update(path2 ? path2 : path);
    if(!dir) {
        SXFS_LOG("Cannot load file tree: %s", path2 ? path2 : path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_chown_err;
    }
    index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp);
    if(index >= 0) {
        dir->dirs[index]->st.st_ctime = ctime;
    } else {
        index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
        if(index >= 0) {
            dir->files[index]->st.st_ctime = ctime;
        } else {
            SXFS_LOG("%s: %s", strerror(ENOENT), path2 ? path2 : path);
            ret = -ENOENT;
            goto sxfs_chown_err;
        }
    }

    ret = 0;
sxfs_chown_err:
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    free(path2);
    return ret;
} /* sxfs_chown */

static int sxfs_truncate (const char *path, off_t length) {
    int ret = -1, fd, locked = 0, tmp = 0;
    ssize_t index;
    char *file_name, *local_file_path = NULL, *storage_file_path = NULL;
    time_t mctime;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *file_remote = NULL, *file_local = NULL;
    sxfs_lsdir_t *dir;
    sxfs_file_t *sxfs_file;

    if(!path) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    if(length < 0) {
        SXFS_LOG("Negative size");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s' (length: %lld)", path, (long long int)length);
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    if(check_path_len(path, 0))
        return -errno;
    if(time(&mctime) < 0) {
        SXFS_LOG("Cannot get current time: %s", strerror(errno));
        return -errno;
    }
    file_name = strrchr(path, '/');
    if(!file_name) {
        SXFS_LOG("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name++;
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(!(dir = sxfs_ls_update(path))) {
        SXFS_LOG("Cannot load file tree: %s", path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_truncate_err;
    }
    index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp);
    if(index >= 0) {
        SXFS_LOG("Named file is a directory: %s", path);
        ret = -EISDIR;
        goto sxfs_truncate_err;
    }
    index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
    if(index < 0) {
        SXFS_LOG("%s: %s", strerror(ENOENT), path);
        ret = -ENOENT;
        goto sxfs_truncate_err;
    }
    if(dir->files[index]->st.st_size != length) {
        storage_file_path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + strlen(path) + 1);
        if(!storage_file_path) {
            SXFS_LOG("Out of memory");
            ret = -ENOMEM;
            goto sxfs_truncate_err;
        }
        sprintf(storage_file_path, "%s/%s%s", SXFS_DATA->tempdir, SXFS_UPLOAD_DIR, path);
        pthread_mutex_lock(&SXFS_DATA->upload_mutex);
        pthread_mutex_lock(&SXFS_DATA->files_mutex);
        locked = 3;
        if(!sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL)) {
            if(sxfs_file->write_fd >= 0) {
                if(ftruncate(sxfs_file->write_fd, length)) {
                    SXFS_LOG("Cannot set '%s' size to %lld: %s", sxfs_file->write_path, (long long int)length, strerror(errno));
                    if(errno == ENOSPC)
                        ret = -ENOBUFS;
                    else
                        ret = -errno;
                    goto sxfs_truncate_err;
                }
                sxfs_file->flush = 1;
            }
        } else {
            sxfs_file = NULL;
        }
        if((!sxfs_file || sxfs_file->write_fd < 0) && (!SXFS_DATA->args->use_queues_flag || (tmp = truncate(storage_file_path, length)))) {
            pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
            locked &= ~1;
            if(tmp && errno != ENOENT) {
                SXFS_LOG("Cannot set '%s' size to %lld: %s", storage_file_path, (long long int)length, strerror(errno));
                if(errno == ENOSPC)
                    ret = -ENOBUFS;
                else
                    ret = -errno;
                goto sxfs_truncate_err;
            }
            if(sxfs_get_sx_data(SXFS_DATA, &sx, &cluster)) {
                SXFS_LOG("Cannot get Sx data");
                ret = errno ? -errno : -ENOMSG;
                goto sxfs_truncate_err;
            }
            local_file_path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + strlen("sxfs_write_XXXXXX") + 1);
            if(!local_file_path) {
                SXFS_LOG("Out of memory");
                ret = -ENOMEM;
                goto sxfs_truncate_err;
            }
            sprintf(local_file_path, "%s/sxfs_write_XXXXXX", SXFS_DATA->tempdir);
            fd = mkstemp(local_file_path);
            if(fd < 0) {
                SXFS_LOG("Cannot create unique temporary file: %s", strerror(errno));
                ret = -errno;
                goto sxfs_truncate_err;
            }
            if(close(fd)) {
                SXFS_LOG("Cannot close '%s' file: %s", local_file_path, strerror(errno));
                ret = -errno;
                goto sxfs_truncate_err;
            }
            file_local = sxc_file_local(sx, local_file_path);
            if(!file_local) {
                SXFS_LOG("Cannot create local file object: %s", sxc_geterrmsg(sx));
                ret = -sxfs_sx_err(sx);
                goto sxfs_truncate_err;
            }
            file_remote = sxc_file_remote(cluster, SXFS_DATA->uri->volume, path+1, NULL);
            if(!file_remote) {
                SXFS_LOG("Cannot create file object: %s", sxc_geterrmsg(sx));
                ret = -sxfs_sx_err(sx);
                goto sxfs_truncate_err;
            }
            if(sxc_copy(file_remote, file_local, 0, 0, 0, NULL, 1)) {
                SXFS_LOG("%s", sxc_geterrmsg(sx));
                ret = -sxfs_sx_err(sx);
                goto sxfs_truncate_err;
            }
            if(truncate(local_file_path, length)) {
                SXFS_LOG("Cannot set '%s' size to %lld: %s", local_file_path, (long long int)length, strerror(errno));
                if(errno == ENOSPC)
                    ret = -ENOBUFS;
                else
                    ret = -errno;
                goto sxfs_truncate_err;
            }
            if(sxfs_file) {
                sxfs_file->write_fd = open(local_file_path, O_RDWR);
                if(sxfs_file->write_fd < 0) {
                    SXFS_LOG("Cannot open '%s' file: %s", local_file_path, strerror(errno));
                    ret = -errno;
                    goto sxfs_truncate_err;
                }
                sxfs_file->write_path = local_file_path;
                local_file_path = NULL;
                sxfs_file->flush = 1;
            } else {
                if(sxfs_upload(local_file_path, path, &mctime, 0)) {
                    SXFS_LOG("Cannot upload file: %s", path);
                    ret = errno ? -errno : -ENOMSG;
                    goto sxfs_truncate_err;
                }
                if(!SXFS_DATA->args->use_queues_flag)
                    dir->files[index]->remote = 1;
            }
        }
        dir->files[index]->st.st_size = length;
        dir->files[index]->st.st_blocks = (length + 511) / 512;
        dir->files[index]->st.st_mtime = dir->files[index]->st.st_ctime = mctime;
    }

    ret = 0;
sxfs_truncate_err:
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    if(locked & 1)
        pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
    if(locked & 2)
        pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        SXFS_LOG("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    free(storage_file_path);
    sxc_file_free(file_local);
    sxc_file_free(file_remote);
    return ret;
} /* sxfs_truncate */

static int sxfs_open (const char *path, struct fuse_file_info *file_info) {
    int ret = -1, fd = -1, tmp, locked = 0, file_moved = 0, file_created = 0;
    size_t i;
    ssize_t index;
    time_t mctime;
    char *local_file_path = NULL, *storage_file_path = NULL, *file_name;
    sxfs_lsdir_t *dir;
    sxfs_file_t *sxfs_file = NULL;
    struct stat st;

    if(!path || !file_info) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s' (%s%s %s)", path, file_info->flags & (O_RDONLY | O_RDWR) ? "r" : "-", file_info->flags & (O_WRONLY | O_RDWR) ? "w" : "-", file_info->flags & O_TRUNC ? "t" : "-");
    if(check_path_len(path, 0))
        return -errno;
    file_info->fh = 0;
    file_name = strrchr(path, '/');
    if(!file_name) {
        SXFS_LOG("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name++;
    if(time(&mctime) < 0) {
        SXFS_LOG("Cannot get current time: %s", strerror(errno));
        return -errno;
    }
    pthread_mutex_lock(&SXFS_DATA->limits_mutex);
    for(i=1; i<SXFS_DATA->fh_limit; i++) { /* 0 is for directories */
        if(!SXFS_DATA->fh_table[i]) {
            file_info->fh = (uint64_t)i;
            SXFS_DATA->fh_table[i] = 1;
            break;
        }
    }
    pthread_mutex_unlock(&SXFS_DATA->limits_mutex);
    if(!file_info->fh) {
        SXFS_LOG("%s", strerror(ENFILE));
        return -ENFILE;
    }
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(!(dir = sxfs_ls_update(path))) { /* no creation flag is passed by FUSE */
        SXFS_LOG("Cannot load file tree: %s", path);
        pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_open_err;
    }
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
    if(index < 0) {
        SXFS_LOG("%s", strerror(ENOENT));
        ret = -ENOENT;
        goto sxfs_open_err;
    }
    local_file_path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof("file_write_XXXXXX") + 1);
    if(!local_file_path) {
        SXFS_LOG("Out of memory");
        ret = -ENOMEM;
        goto sxfs_open_err;
    }
    sprintf(local_file_path, "%s/file_write_XXXXXX", SXFS_DATA->tempdir);
    fd = mkstemp(local_file_path);
    if(fd < 0) {
        SXFS_LOG("Cannot create unique temporary file: %s", strerror(errno));
        ret = -errno;
        goto sxfs_open_err;
    }
    pthread_mutex_lock(&SXFS_DATA->upload_mutex); /* for correct locking order */
    pthread_mutex_lock(&SXFS_DATA->files_mutex);
    locked = 1;
    if(sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL)) {
        /* file not yet opened */
        sxfs_file = (sxfs_file_t*)calloc(1, sizeof(sxfs_file_t));
        if(!sxfs_file) {
            SXFS_LOG("Out of memory");
            ret = -ENOMEM;
            goto sxfs_open_err;
        }
        sxfs_file->write_fd = -1;
        sxfs_file->etag = sxfs_hash(SXFS_DATA, path);
        if(!sxfs_file->etag) {
            SXFS_LOG("Cannot compute hash of '%s'", path);
            free(sxfs_file);
            ret = -errno;
            goto sxfs_open_err;
        }
        if((tmp = pthread_mutex_init(&sxfs_file->block_mutex, NULL))) {
            SXFS_LOG("Cannot create block mutex: %s", strerror(tmp));
            free(sxfs_file->etag);
            free(sxfs_file);
            ret = -tmp;
            goto sxfs_open_err;
        }
        sxfs_file->ls_file = dir->files[index];
        if(sxc_meta_setval(SXFS_DATA->files, path, sxfs_file, sizeof(sxfs_file_t))) {
            SXFS_LOG("Cannot add new file"); /* FIXME: message */
            pthread_mutex_destroy(&sxfs_file->block_mutex);
            free(sxfs_file->etag);
            free(sxfs_file);
            ret = -ENOMEM;
            goto sxfs_open_err;
        }
        free(sxfs_file);
        sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL);
        file_created = 1;
        if(SXFS_DATA->args->use_queues_flag) {
            storage_file_path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + strlen(path) + 1);
            if(!storage_file_path) {
                SXFS_LOG("Out of memory");
                ret = -ENOMEM;
                goto sxfs_open_err;
            }
            sprintf(storage_file_path, "%s/%s%s", SXFS_DATA->tempdir, SXFS_UPLOAD_DIR, path);
            if(stat(storage_file_path, &st)) {
                if(errno != ENOENT) {
                    SXFS_LOG("Cannot stat %s file: %s", storage_file_path, strerror(errno));
                    ret = -errno;
                    goto sxfs_open_err;
                }
            } else if(S_ISREG(st.st_mode)) {
                if(file_info->flags & O_TRUNC) {
                    if(unlink(storage_file_path) && errno != ENOENT) {
                        SXFS_LOG("Cannot remove '%s' file: %s", storage_file_path, strerror(errno));
                        ret = -errno;
                        goto sxfs_open_err;
                    }
                    if(sxfs_upload_del_path(path)) {
                        SXFS_LOG("Cannot remove file from upload list: %s", path);
                        ret = errno ? -errno : -ENOMSG;
                        goto sxfs_open_err;
                    }
                } else if(rename(storage_file_path, local_file_path)) { /* try to use file from upload queue */
                    if(errno != ENOENT) { /* should never be ENOENT (TOCTOU) */
                        SXFS_LOG("Cannot rename '%s' to '%s': %s", storage_file_path, local_file_path, strerror(errno));
                        ret = -errno;
                        goto sxfs_open_err;
                    }
                } else {
                    file_moved = 1;
                    if(SXFS_DATA->args->verbose_flag)
                        SXFS_DEBUG("Using file from upload queue");
                    if(sxfs_update_mtime(local_file_path, path, &sxfs_file->ls_file->st.st_mtime)) {
                        SXFS_LOG("Cannot update modification time");
                        ret = errno ? -errno : -ENOMSG;
                        goto sxfs_open_err;
                    }
                    file_moved = 2;
                    sxfs_file->ls_file->remote = 1;
                    sxfs_file->write_fd = open(local_file_path, O_RDWR);
                    if(sxfs_file->write_fd < 0) {
                        SXFS_LOG("Cannot open '%s' file: %s", local_file_path, strerror(errno));
                        ret = -errno;
                        goto sxfs_open_err;
                    }
                    sxfs_file->write_path = local_file_path;
                    local_file_path = NULL;
                }
            }
        }
    } else if(file_info->flags & O_TRUNC && sxfs_file->write_fd >= 0 && ftruncate(sxfs_file->write_fd, 0)) {
        SXFS_LOG("Cannot truncate '%s' file: %s", sxfs_file->write_path, strerror(errno));
        if(errno == ENOSPC)
            ret = -ENOBUFS;
        else
            ret = -errno;
        goto sxfs_open_err;
    }
    if(file_info->flags & O_TRUNC) {
        if(sxfs_file->write_fd < 0) {
            sxfs_file->write_path = local_file_path;
            sxfs_file->write_fd = fd;
            local_file_path = NULL;
            fd = -1;
        }
        if(sxfs_file->ls_file->st.st_size) {
            sxfs_file->ls_file->st.st_size = 0;
            sxfs_file->ls_file->st.st_mtime = sxfs_file->ls_file->st.st_ctime = mctime;
            sxfs_file->flush = 1;
        }
    }
    sxfs_file->num_open++;
    sxfs_file->ls_file->opened = 1;

    ret = 0;
sxfs_open_err:
    if(fd >= 0 && close(fd))
        SXFS_LOG("Cannot close '%s' file: %s", local_file_path ? local_file_path : sxfs_file->write_path, strerror(errno));
    if(ret) {
        pthread_mutex_lock(&SXFS_DATA->limits_mutex);
        SXFS_DATA->fh_table[file_info->fh] = 0;
        pthread_mutex_unlock(&SXFS_DATA->limits_mutex);
        file_info->fh = 0;
        if(file_created) {
            sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL);
            pthread_mutex_destroy(&sxfs_file->block_mutex);
            free(sxfs_file->etag);
            sxc_meta_delval(SXFS_DATA->files, path);
    /*        free(sxfs_file); */ /* already done in sxc_meta_delval() */
        }
        if(file_moved == 1 && rename(local_file_path, storage_file_path)) /* move the file back to the upload queue */
            SXFS_LOG("Cannot rename '%s' to '%s': %s", local_file_path, storage_file_path, strerror(errno));
    } else if(file_moved && sxfs_upload_del_path(path))
        SXFS_LOG("Cannot remove file from upload list: %s", path);
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    if(locked) {
        pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
        pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    }
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        SXFS_LOG("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    free(storage_file_path);
    return ret;
} /* sxfs_open */

static int get_file (const char *path, sxfs_file_t *sxfs_file) {
    int fd, ret = -1;
    char *local_file_path;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *file_local = NULL, *file_remote = NULL;

    if(SXFS_DATA->args->verbose_flag)
        SXFS_DEBUG("Downloading the file");
    if(sxfs_get_sx_data(SXFS_DATA, &sx, &cluster)) {
        SXFS_LOG("Cannot get Sx data");
        return ret;
    }
    local_file_path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof("file_write_XXXXXX") + 1);
    if(!local_file_path) {
        SXFS_LOG("Out of memory");
        errno = ENOMEM;
        return ret;
    }
    sprintf(local_file_path, "%s/file_write_XXXXXX", SXFS_DATA->tempdir);
    fd = mkstemp(local_file_path);
    if(fd < 0) {
        SXFS_LOG("Cannot create unique temporary file: %s", strerror(errno));
        free(local_file_path);
        return ret;
    }
    if(close(fd)) {
        SXFS_LOG("Cannot close '%s' file: %s", local_file_path, strerror(errno));
        goto get_file_err;
    }
    file_local = sxc_file_local(sx, local_file_path);
    if(!file_local) {
        SXFS_LOG("Cannot create local file object: %s", sxc_geterrmsg(sx));
        errno = sxfs_sx_err(sx);
        goto get_file_err;
    }
    file_remote = sxc_file_remote(cluster, SXFS_DATA->uri->volume, path+1, NULL);
    if(!file_remote) {
        SXFS_LOG("Cannot create file object: %s", sxc_geterrmsg(sx));
        errno = sxfs_sx_err(sx);
        goto get_file_err;
    }
    if(sxc_copy(file_remote, file_local, 0, 0, 0, NULL, 1)) {
        SXFS_LOG("%s", sxc_geterrmsg(sx));
        errno = sxfs_sx_err(sx);
        goto get_file_err;
    }
    sxfs_file->write_fd = open(local_file_path, O_RDWR);
    if(sxfs_file->write_fd < 0) {
        SXFS_LOG("Cannot open '%s' file: %s", local_file_path, strerror(errno));
        goto get_file_err;
    }
    sxfs_file->write_path = local_file_path;
    local_file_path = NULL;

    ret = 0;
get_file_err:
    if(local_file_path && unlink(local_file_path))
        SXFS_LOG("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    sxc_file_free(file_local);
    sxc_file_free(file_remote);
    return ret;
} /* get_file */

static int sxfs_read (const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *file_info) {
    int i, ret = -1, blocks_locked = 0, fd = 0;
    int64_t start, end;
    ssize_t bytes, read = 0;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *src = NULL;
    sxfs_file_t *sxfs_file;
    sxi_sxfs_data_t *fdata = NULL;

    if(!path || !buf || !file_info) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    if(SXFS_DATA->args->verbose_flag)
        SXFS_DEBUG("'%s' (fd: %llu, size: %llu; offset: %lld)", path, (unsigned long long)file_info->fh, (unsigned long long int)size, (long long int)offset);
    if(offset < 0) {
        SXFS_LOG("Negative offset");
        return -EINVAL;
    }
    if(!file_info->fh) {
        SXFS_LOG("Bad file descriptor");
        return -EBADF;
    }
    pthread_mutex_lock(&SXFS_DATA->files_mutex);
    if(sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL)) {
        SXFS_LOG("File not opened: %s", path);
        pthread_mutex_unlock(&SXFS_DATA->files_mutex);
        return -EFAULT;
    }
    pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    if((SXFS_DATA->filter & SXFS_FILTER_NEEDFILE) && sxfs_file->write_fd < 0 && get_file(path, sxfs_file))
        return -errno;
    if(sxfs_file->write_fd >= 0) {
        if(SXFS_DATA->args->verbose_flag)
            SXFS_DEBUG("Reading from write cache file");
        read = pread(sxfs_file->write_fd, buf, size, offset);
        if(read < 0) {
            SXFS_LOG("Cannot read '%s' file: %s", sxfs_file->write_path, strerror(errno));
            return -errno;
        }
    } else {
        if(sxfs_get_sx_data(SXFS_DATA, &sx, &cluster)) {
            SXFS_LOG("Cannot get Sx data");
            return errno ? -errno : -ENOMSG;
        }
        pthread_mutex_lock(&sxfs_file->block_mutex);
        blocks_locked = 1;
        if(!sxfs_file->fdata) {
            if(SXFS_DATA->args->verbose_flag)
                SXFS_DEBUG("Preparing data for reading");
            src = sxc_file_remote(cluster, SXFS_DATA->uri->volume, path+1, NULL);
            if(!src) {
                SXFS_LOG("Cannot create file object: %s", sxc_geterrmsg(sx));
                ret = -sxfs_sx_err(sx);
                goto sxfs_read_err;
            }
            fdata = sxi_sxfs_download_init(src);
            if(!fdata) {
                SXFS_LOG("Cannot initialize file downloading: %s", sxc_geterrmsg(sx));
                ret = -sxfs_sx_err(sx);
                goto sxfs_read_err;
            }
            switch(fdata->blocksize) {
                case SX_BS_SMALL: sxfs_file->blocksize = SXFS_BS_SMALL_AMOUNT * SX_BS_SMALL; break;
                case SX_BS_MEDIUM: sxfs_file->blocksize = SXFS_BS_MEDIUM_AMOUNT * SX_BS_MEDIUM; break;
                case SX_BS_LARGE: sxfs_file->blocksize = SXFS_BS_LARGE_AMOUNT * SX_BS_LARGE; break;
                default: SXFS_LOG("Unknown block size"); ret = -EINVAL; goto sxfs_read_err;
            }
            sxfs_file->nblocks = (fdata->filesize + sxfs_file->blocksize - 1) / sxfs_file->blocksize;
            sxfs_file->blocks = (char*)calloc(sxfs_file->nblocks, sizeof(char));
            if(!sxfs_file->blocks) {
                SXFS_LOG("Out of memory");
                ret = -ENOMEM;
                goto sxfs_read_err;
            }
            sxfs_file->blocks_path = (char**)calloc(sxfs_file->nblocks, sizeof(char*));
            if(!sxfs_file->blocks_path) {
                SXFS_LOG("Out of memory");
                ret = -ENOMEM;
                goto sxfs_read_err;
            }
            sxfs_file->fdata = fdata;
        } else
            fdata = sxfs_file->fdata;
        pthread_mutex_unlock(&sxfs_file->block_mutex);
        blocks_locked = 0;
        if(offset >= fdata->filesize) {
            if(SXFS_DATA->args->verbose_flag)
                SXFS_DEBUG("Reading after EOF");
            ret = 0;
            goto sxfs_read_err; /* this is not a failure */
        }
        /* TODO: file change check */
        start = offset / sxfs_file->blocksize;
        if((int64_t)(offset + size) > fdata->filesize)
            end = (fdata->filesize + sxfs_file->blocksize - 1) / sxfs_file->blocksize;
        else
            end = (offset + size + sxfs_file->blocksize - 1) / sxfs_file->blocksize;
        offset %= sxfs_file->blocksize;
        if(SXFS_DATA->args->verbose_flag)
            SXFS_DEBUG("Blocks: %lld - %lld, first block offset: %lld", (long long int)start, (long long int)end, (long long int)offset);
        if(end < sxfs_file->nblocks && sxfs_get_block_background(sxfs_file, end)) {
            SXFS_LOG("Cannot start background download");
            ret = errno ? -errno : -ENOMSG;
            goto sxfs_read_err;
        }
        if(sxfs_get_file(sxfs_file, sx, cluster, start, end)) {
            SXFS_LOG("Cannot download specified blocks");
            ret = errno ? -errno : -ENOMSG;
            goto sxfs_read_err;
        }
        for(i=start; i<end; i++) {
            fd = open(sxfs_file->blocks_path[i], file_info->flags);
            if(fd < 0) {
                SXFS_LOG("Cannot open '%s' file: %s", sxfs_file->blocks_path[i], strerror(errno));
                ret = -errno;
                goto sxfs_read_err;
            }
            bytes = pread(fd, buf+read, MIN(size - read, sxfs_file->blocksize), offset);
            if(bytes < 0) {
                SXFS_LOG("Cannot read '%s' file: %s", sxfs_file->blocks_path[i], strerror(errno));
                ret = -errno;
                if(close(fd))
                    SXFS_LOG("Cannot close '%s' file: %s", sxfs_file->blocks_path[i], strerror(errno));
                goto sxfs_read_err;
            }
            read += bytes;
            offset = 0;
            if(close(fd)) {
                SXFS_LOG("Cannot close '%s' file: %s", sxfs_file->blocks_path[i], strerror(errno));
                ret = -errno;
                goto sxfs_read_err;
            }
        }
    }
    if(SXFS_DATA->args->verbose_flag)
        SXFS_DEBUG("Read %lld bytes", (long long int)read);

    ret = read;
sxfs_read_err:
    if(blocks_locked)
        pthread_mutex_unlock(&sxfs_file->block_mutex);
    if(!sxfs_file->fdata && fdata)
        sxi_sxfs_download_finish(fdata);
    sxc_file_free(src);
    return ret;
} /* sxfs_read */

static int sxfs_write (const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *file_info) {
    int ret = -1, locked = 0;
    sxfs_file_t *sxfs_file;
    struct stat st;

    if(!path || !buf || !file_info) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    if(SXFS_DATA->args->verbose_flag)
        SXFS_DEBUG("'%s' (fd: %llu, size: %llu; offset: %lld)", path, (unsigned long long)file_info->fh, (unsigned long long)size, (long long)offset);
    if(offset < 0) {
        SXFS_LOG("Negative offset");
        return -EINVAL;
    }
    if(!file_info->fh) {
        SXFS_LOG("Bad file descriptor");
        return -EBADF;
    }
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    pthread_mutex_lock(&SXFS_DATA->files_mutex);
    locked = 1;
    if(sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL)) {
        SXFS_LOG("File not opened: %s", path);
        ret = -EFAULT;
        goto sxfs_write_err;
    }
    if(sxfs_file->write_fd < 0 && get_file(path, sxfs_file)) {
        ret = -errno;
        goto sxfs_write_err;
    }
    ret = pwrite(sxfs_file->write_fd, buf, size, offset);
    if(ret < 0) {
        SXFS_LOG("Cannot write data to '%s' file: %s", sxfs_file->write_path, strerror(errno));
        if(errno == ENOSPC)
            ret = -ENOBUFS;
        else
            ret = -errno;
    } else {
        if(SXFS_DATA->args->verbose_flag)
            SXFS_DEBUG("Wrote %d bytes", ret); /* FUSE defines write() to return int */
        sxfs_file->flush = 1;
        pthread_mutex_unlock(&SXFS_DATA->files_mutex);
        locked = 0;
        pthread_mutex_lock(&SXFS_DATA->ls_mutex);
        if(fstat(sxfs_file->write_fd, &st)) {
            SXFS_LOG("Cannot stat %s file: %s", sxfs_file->write_path, strerror(errno));
            pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
            goto sxfs_write_err;
        }
        sxfs_file->ls_file->st.st_mtime = st.st_mtime;
        sxfs_file->ls_file->st.st_ctime = st.st_ctime;
        sxfs_file->ls_file->st.st_size = st.st_size;
        sxfs_file->ls_file->st.st_blocks = (st.st_size + 511) / 512;
        pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    }

sxfs_write_err:
    if(locked)
        pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    return ret;
} /* sxfs_write */

static int sxfs_statfs (const char *path, struct statvfs *st) {
    int ret = -1, tmp;
    int64_t volsize, used_volsize;
    char *volname = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_cluster_lv_t *vlist;

    if(!st) {
        SXFS_LOG("NULL argument");
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
    if(sxfs_get_sx_data(SXFS_DATA, &sx, &cluster)) {
        SXFS_LOG("Cannot get Sx data");
        return errno ? -errno : -ENOMSG;
    }
    vlist = sxc_cluster_listvolumes(cluster, 1);
    if(!vlist) {
        SXFS_LOG("%s", sxc_geterrmsg(sx));
        return -sxfs_sx_err(sx);
    }
    while(1) {
        tmp = sxc_cluster_listvolumes_next(vlist, &volname, NULL, &used_volsize, &volsize, NULL, NULL, NULL, NULL);
        if(tmp) {
            if(tmp < 0) {
                SXFS_LOG("Failed to retrieve volume data");
                ret = -sxfs_sx_err(sx);
                goto sxfs_statfs_err;
            }
            if(!strcmp(SXFS_DATA->uri->volume, volname))
                break;
            free(volname);
            volname = NULL;
        } else
            break;
    }
    if(!volname) {
        SXFS_LOG("'%s' volume not found", SXFS_DATA->uri->volume);
        ret = -ENOENT;
        goto sxfs_statfs_err;
    }
    st->f_bsize = st->f_frsize = SX_BS_SMALL;
    st->f_blocks = (fsblkcnt_t)((volsize + SX_BS_SMALL - 1) / SX_BS_SMALL); /* f_frsize * f_blocks should be equal volsize (value rounded up) */
    st->f_bfree = st->f_bavail = (fsblkcnt_t)((volsize - used_volsize + SX_BS_SMALL - 1) / SX_BS_SMALL);
    st->f_files = (fsblkcnt_t)(volsize / SX_BS_SMALL);
    st->f_ffree = st->f_favail = (fsblkcnt_t)((volsize - used_volsize) / SX_BS_SMALL);
    st->f_namemax = SXFS_DATA->args->use_queues_flag ? NAME_MAX : SXLIMIT_MAX_FILENAME_LEN; /* upload queue is stored in local directory and this enforces shorter filenames */

    ret = 0;
sxfs_statfs_err:
    free(volname);
    sxc_cluster_listvolumes_free(vlist);
    return ret;
} /* sxfs_statfs */

static int sxfs_flush (const char *path, struct fuse_file_info *file_info) {
    int ret = -1, fd = -1, locked = 0;
    ssize_t rd;
    off_t offset = 0;
    char *file_path = NULL, buff[65536];
    sxfs_file_t *sxfs_file;

    if(!path || !file_info) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s' (fd: %llu)", path, (unsigned long long)file_info->fh);
    if(file_info->flags & (O_WRONLY | O_RDWR) && SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    pthread_mutex_lock(&SXFS_DATA->files_mutex);
    locked = 1;
    if(sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL)) {
        SXFS_LOG("File not opened: %s", path);
        ret = -EFAULT;
        goto sxfs_flush_err;
    }
    if(sxfs_file->flush) {
        file_path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof("file_flush_XXXXXX") + 1);
        if(!file_path) {
            SXFS_LOG("Out of memory");
            ret = -ENOMEM;
            goto sxfs_flush_err;
        }
        sprintf(file_path, "%s/file_flush_XXXXXX", SXFS_DATA->tempdir);
        fd = mkstemp(file_path);
        if(fd < 0) {
            SXFS_LOG("Cannot create unique temporary file: %s", strerror(errno));
            ret = -errno;
            goto sxfs_flush_err;
        }
        while((rd = pread(sxfs_file->write_fd, buff, sizeof(buff), offset)) > 0) {
            if(write(fd, buff, rd) < 0) {
                SXFS_LOG("Cannot write to '%s' file: %s", file_path, strerror(errno));
                ret = -errno;
                goto sxfs_flush_err;
            }
            offset += rd;
        }
        if(rd < 0) {
            SXFS_LOG("Cannot read from '%s' file: %s", sxfs_file->write_path, strerror(errno));
            ret = -errno;
            goto sxfs_flush_err;
        }
        if(!SXFS_DATA->args->use_queues_flag)
            sxfs_file->ls_file->remote = 1;
        sxfs_file->flush = 0;
    }
    pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    locked = 0;
    if(file_path) {
        pthread_mutex_lock(&SXFS_DATA->delete_mutex);
        if(sxfs_upload(file_path, path, &sxfs_file->ls_file->st.st_mtime, 1)) {
            SXFS_LOG("Cannot upload file: %s", path);
            ret = errno ? -errno : -ENOMSG;
            pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
            goto sxfs_flush_err;
        }
        if(!SXFS_DATA->args->use_queues_flag)
            sxfs_file->ls_file->remote = 1;
        pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    }

    ret = 0;
sxfs_flush_err:
    if(locked)
        pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    if(fd >= 0 && close(fd))
        SXFS_LOG("Cannot close '%s' file: %s", file_path, strerror(errno));
    if(file_path && unlink(file_path) && errno != ENOENT)
        SXFS_LOG("Cannot remove '%s' file: %s", file_path, strerror(errno));
    free(file_path);
    return ret;
} /* sxfs_flush */

static int sxfs_release (const char *path, struct fuse_file_info *file_info) {
    int i;
    sxfs_file_t *sxfs_file;

    if(!path || !file_info) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    /* return value of release() is ignored by FUSE */
    SXFS_DEBUG("'%s' (fd: %llu)", path, (unsigned long long)file_info->fh);
    if(!file_info->fh) {
        SXFS_LOG("Bad file descriptor");
        return -EBADF;
    }
    if(file_info->fh >= SXFS_DATA->fh_limit) {
        SXFS_LOG("File handle out of scope");
        return -EBADF;
    }
    pthread_mutex_lock(&SXFS_DATA->ls_mutex); /* sxfs_file->ls_file->opened */
    pthread_mutex_lock(&SXFS_DATA->delete_mutex); /* sxfs_upload() - checking delete queue */
    pthread_mutex_lock(&SXFS_DATA->files_mutex);
    if(sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL)) {
        SXFS_LOG("File not opened: %s", path);
        goto sxfs_release_err;
    }
    sxfs_file->num_open--;
    pthread_mutex_lock(&SXFS_DATA->limits_mutex);
    if(!SXFS_DATA->fh_table[file_info->fh]) {
        SXFS_LOG("File handle not used or already released");
        pthread_mutex_unlock(&SXFS_DATA->limits_mutex);
        goto sxfs_release_err;
    }
    SXFS_DATA->fh_table[file_info->fh] = 0;
    pthread_mutex_unlock(&SXFS_DATA->limits_mutex);
    if(!sxfs_file->num_open) {
        if(sxfs_file->write_path) {
            if(close(sxfs_file->write_fd))
                SXFS_LOG("Cannot close '%s' file: %s", sxfs_file->write_path, strerror(errno));
            if(sxfs_file->flush) {
                if(sxfs_upload(sxfs_file->write_path, path, &sxfs_file->ls_file->st.st_mtime, 1))
                    SXFS_LOG("Cannot upload file: %s", path);
                else if(!SXFS_DATA->args->use_queues_flag)
                    sxfs_file->ls_file->remote = 1;
            } else if(unlink(sxfs_file->write_path))
                SXFS_LOG("Cannot remove '%s' file '%s': %s", sxfs_file->write_path, strerror(errno));
            free(sxfs_file->write_path);
        }
        if(sxfs_file->ls_file->opened == 2) {
            sxfs_file->ls_file->opened = 0;
            sxfs_lsfile_free(sxfs_file->ls_file);
        } else
            sxfs_file->ls_file->opened = 0;
        if(sxfs_file->blocks) {
            pthread_mutex_lock(&sxfs_file->block_mutex);
            for(i=0; i<sxfs_file->nblocks; i++)
                sxfs_file->blocks[i] |= 4;
            for(i=0; i<sxfs_file->nblocks; i++) {
                if(sxfs_file->blocks[i] & 3) {
                    while(sxfs_file->blocks[i] & 1) {
                        pthread_mutex_unlock(&sxfs_file->block_mutex);
                        usleep(THREAD_WAIT_USEC);
                        pthread_mutex_lock(&sxfs_file->block_mutex);
                    }
                    if(sxfs_file->blocks[i] & 2 && unlink(sxfs_file->blocks_path[i]))
                        SXFS_LOG("Cannot remove '%s' file: %s", sxfs_file->blocks_path[i], strerror(errno));
                }
                free(sxfs_file->blocks_path[i]);
                sxfs_file->blocks[i] = 0;
                sxfs_file->blocks_path[i] = NULL;
            }
            free(sxfs_file->blocks);
            free(sxfs_file->blocks_path);
            pthread_mutex_unlock(&sxfs_file->block_mutex);
        }
        free(sxfs_file->etag);
        pthread_mutex_destroy(&sxfs_file->block_mutex);
        sxi_sxfs_download_finish(sxfs_file->fdata);
        sxc_meta_delval(SXFS_DATA->files, path);
/*        free(sxfs_file);*/ /* already done in sxc_meta_delval() */
    }

sxfs_release_err:
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    return 0; /* return value of release() is ignored by FUSE */
} /* sxfs_release */

static int sxfs_fsync (const char *path, int datasync, struct fuse_file_info *file_info) {
    int ret = -1;
    sxfs_file_t *sxfs_file;

    if(!path || !file_info) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', datasync: %d", path, datasync);
    if(!file_info->fh) {
        SXFS_LOG("Bad file descriptor");
        return -EBADF;
    }
    if(file_info->fh >= SXFS_DATA->fh_limit) {
        SXFS_LOG("File handle out of scope");
        return -EBADF;
    }
    pthread_mutex_lock(&SXFS_DATA->files_mutex);
    if(sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL)) {
        SXFS_LOG("File not opened: %s", path);
        ret = -EFAULT;
        goto sxfs_fsync_err;
    }
    if(sxfs_file->flush) {
        if(sxfs_update_mtime(sxfs_file->write_path, path, &sxfs_file->ls_file->st.st_mtime)) {
            SXFS_LOG("Cannot update modification time");
            ret = errno ? -errno : -ENOMSG;
            goto sxfs_fsync_err;
        }
        sxfs_file->flush = 0;
    }

    ret = 0;
sxfs_fsync_err:
    pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    return ret;
} /* sxfs_fsync */

static int sxfs_setxattr (const char *path, const char *name, const char *value, size_t size, int flags) {
    return -ENOTSUP;
} /* sxfs_setxattr */

static int sxfs_getxattr (const char *path, const char *name, char *value, size_t size) {
    return -ENOTSUP;
} /* sxfs_getxattr */

static int sxfs_listxattr (const char *path, char *list, size_t size) {
    return -ENOTSUP;
} /* sxfs_listxattr */

static int sxfs_removexattr (const char *path, const char *name) {
    return -ENOTSUP;
} /* sxfs_removexattr */

static int sxfs_opendir (const char *path, struct fuse_file_info *file_info) {
    int tmp;
    char *path2 = NULL;

    if(!path || !file_info) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s'", path);
    if(check_path_len(path, 0))
        return -errno;
    if(strlen(path) > 1 && path[strlen(path)-1] == '/') {
        path2 = strdup(path);
        if(!path2) {
            SXFS_LOG("Out of memory: %s", path);
            return -errno;
        }
        path2[strlen(path2)-1] = '\0';
    }
    if((tmp = sxfs_ls_stat(path2 ? path2 : path, NULL))) {
        if(tmp < 0) {
            SXFS_LOG("Cannot check file status: %s", path2 ? path2 : path);
            free(path2);
            return errno ? -errno : -ENOMSG;
        }
        if(tmp == 1) {
            SXFS_LOG("'%s' is a file", path2 ? path2 : path);
            free(path2);
            return -ENOTDIR;
        }
    } else {
        SXFS_LOG("%s: %s", strerror(ENOENT), path2 ? path2 : path);
        free(path2);
        return -ENOENT;
    }
    file_info->fh = 0;
    free(path2);
    return 0;
} /* sxfs_opendir */

static int sxfs_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *file_info) {
    int ret = -1;
    size_t i;
    char *dirpath = NULL;
    sxfs_lsdir_t *dir;

    if(!path || !buf || !file_info) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    /* sxfs does not use offset here */
    SXFS_DEBUG("'%s', offset: %lld", path, (long long int)offset);
    dirpath = (char*)malloc(strlen(path) + 2); /* slash and null */
    if(!dirpath) {
        SXFS_LOG("OOM for dirpath");
        return -ENOMEM;
    }
    sprintf(dirpath, "%s%s", path, path[strlen(path)-1] != '/' ? "/" : "");
    if(filler(buf, ".", NULL, 0)) {
        SXFS_LOG("filler failed on current directory");
        free(dirpath);
        return -ENOBUFS;
    }
    if(filler(buf, "..", NULL, 0)) {
        SXFS_LOG("filler failed on parent directory");
        free(dirpath);
        return -ENOBUFS;
    }
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(!(dir = sxfs_ls_update(dirpath))) {
        SXFS_LOG("Cannot load file tree: %s", dirpath);
        pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_readdir_err;
    }
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    for(i=0; i<dir->ndirs; i++)
        if(filler(buf, dir->dirs[i]->name, NULL, 0)) {
            SXFS_LOG("filler failed on '%s': buffer is full", dir->dirs[i]->name);
            ret = -ENOBUFS;
            goto sxfs_readdir_err;
        }
    for(i=0; i<dir->nfiles; i++)
        if(filler(buf, dir->files[i]->name, NULL, 0)) {
            SXFS_LOG("filler failed on '%s': buffer is full", dir->files[i]->name);
            ret = -ENOBUFS;
            goto sxfs_readdir_err;
        }

    ret = 0;
sxfs_readdir_err:
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    free(dirpath);
    return ret;
} /* sxfs_readdir */

static int sxfs_releasedir (const char *path, struct fuse_file_info *file_info) {
    SXFS_DEBUG("'%s'", path);
    return 0;
} /* sxfs_releasedir */

static void* sxfs_init () {
    if(SXFS_DATA->args->use_queues_flag) {
        SXFS_DEBUG("Starting additional threads");
        pthread_mutex_lock(&SXFS_DATA->delete_mutex);
        sxfs_delete_start();
        pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
        sxfs_upload_start();
    }
    return SXFS_DATA;
} /* sxfs_init */

static void sxfs_destroy (void *ptr) {
    if(SXFS_DATA->args->use_queues_flag) {
        SXFS_DEBUG("Stopping additional threads");
        sxfs_delete_stop();
        sxfs_upload_stop();
    }
} /* sxfs_destroy */

static int sxfs_access (const char *path, int mode) {
    int tmp;
    char *path2 = NULL;

    if(!path) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', mode: %c%c%c%c (%d)", path, mode & F_OK ? 'F' : '-', mode & R_OK ? 'R' : '-', mode & W_OK ? 'W' : '-', mode & X_OK ? 'X' : '-', mode);
    if(check_path_len(path, 0))
        return -errno;
    if(strlen(path) > 1 && path[strlen(path)-1] == '/') {
        path2 = strdup(path);
        if(!path2) {
            SXFS_LOG("Cannot duplicate the path: %s", strerror(errno));
            return -errno;
        }
        path2[strlen(path2)-1] = '\0';
    }
    if((tmp = sxfs_ls_stat(path2 ? path2 : path, NULL))) {
        if(tmp < 0) {
            SXFS_LOG("Cannot check file status: %s", path2 ? path2 : path);
            free(path2);
            return errno ? -errno : -ENOMSG;
        }
    } else {
        SXFS_LOG("%s: %s", strerror(ENOENT), path2 ? path2 : path);
        free(path2);
        return -ENOENT;
    }
    free(path2);
    if(mode == F_OK)
        return 0;
    if((mode & X_OK) && tmp != 2)
        return -EACCES;
    return 0; /* you always have access to the file you can list.
               * if you can't see the file it doesn't exist
               *   or you have no access to it (can't tell which one, so ENOENT). */
} /* sxfs_access */

static int sxfs_create (const char *path, mode_t mode, struct fuse_file_info *file_info) {
    int ret = -1, fd = -1, locked = 0, tmp;
    size_t i;
    char *file_name, *local_file_path;
    sxfs_file_t *sxfs_file = NULL;
    sxfs_lsdir_t *dir = NULL;

    if(!path || !file_info) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s', mode: %c%c%c%c%c%c%c%c%c%c (%u)", path, S_ISDIR(mode) ? 'd' : '-',
                        mode & S_IRUSR ? 'r' : '-', mode & S_IWUSR ? 'w' : '-', mode & S_IXUSR ? 'x' : '-',
                        mode & S_IRGRP ? 'r' : '-', mode & S_IWGRP ? 'w' : '-', mode & S_IXGRP ? 'x' : '-',
                        mode & S_IROTH ? 'r' : '-', mode & S_IWOTH ? 'w' : '-', mode & S_IXOTH ? 'x' : '-', (unsigned int)mode);
    file_info->fh = 0;
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    if(check_path_len(path, 0))
        return -errno;
    if(mode && !S_ISREG(mode)) {
        SXFS_LOG("Not supported type of file: %s", S_ISCHR(mode) ? "character special file" : S_ISBLK(mode) ? "block special file" :
                                                   S_ISFIFO(mode) ? "FIFO (named pipe)" : S_ISSOCK(mode) ? "UNIX domain socket" : "unknown type");
        return -ENOTSUP;
    }
    file_name = strrchr(path, '/');
    if(!file_name) {
        SXFS_LOG("'/' not found in '%s'", path);
        return -EINVAL;
    }
    file_name++;
    local_file_path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof("file_write_XXXXXX") + 1);
    if(!local_file_path) {
        SXFS_LOG("Out of memory");
        return -ENOMEM;
    }
    sprintf(local_file_path, "%s/file_write_XXXXXX", SXFS_DATA->tempdir);
    fd = mkstemp(local_file_path);
    if(fd < 0) {
        SXFS_LOG("Cannot create unique temporary file: %s", strerror(errno));
        free(local_file_path);
        return -errno;
    }
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(SXFS_DATA->args->use_queues_flag && sxfs_delete_check_path(path)) {
        SXFS_LOG("Cannot check deletion queue: %s", path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_create_err;
    }
    if(!(dir = sxfs_ls_update(path))) {
        SXFS_LOG("Cannot load file tree: %s", path);
        pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_create_err;
    }
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    if(sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp) >= 0) {
        SXFS_LOG("File already exists: %s", path);
        ret = -EEXIST;
        goto sxfs_create_err;
    }
    if(sxfs_find_entry((const void**)dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp) >= 0) {
        SXFS_LOG("Directory already exists: %s", path);
        ret = -EEXIST;
        goto sxfs_create_err;
    }
    if(sxfs_lsdir_add_file(dir, path, NULL)) {
        SXFS_LOG("Cannot add new file to cache: %s", path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_create_err;
    }
    sxfs_file = (sxfs_file_t*)calloc(1, sizeof(sxfs_file_t));
    if(!sxfs_file) {
        SXFS_LOG("Out of memory");
        ret = -ENOMEM;
        goto sxfs_create_err;
    }
    sxfs_file->write_fd = -1;
    sxfs_file->ls_file = dir->files[dir->nfiles-1];
    sxfs_file->etag = sxfs_hash(SXFS_DATA, path);
    if(!sxfs_file->etag) {
        SXFS_LOG("Cannot compute hash of '%s'", path);
        ret = -errno;
        goto sxfs_create_err;
    }
    if((tmp = pthread_mutex_init(&sxfs_file->block_mutex, NULL))) {
        SXFS_LOG("Cannot create block mutex: %s", strerror(tmp));
        ret = -tmp;
        goto sxfs_create_err;
    }
    pthread_mutex_lock(&SXFS_DATA->files_mutex);
    locked = 1;
    if(sxc_meta_setval(SXFS_DATA->files, path, sxfs_file, sizeof(sxfs_file_t))) {
        SXFS_LOG("Cannot add new file"); /* FIXME: message */
        pthread_mutex_destroy(&sxfs_file->block_mutex);
        ret = -ENOMEM;
        goto sxfs_create_err;
    }
    free(sxfs_file);
    sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL);
    sxfs_file->write_fd = fd;
    sxfs_file->write_path = local_file_path;
    fd = -1;
    local_file_path = NULL;
    pthread_mutex_lock(&SXFS_DATA->limits_mutex);
    for(i=1; i<SXFS_DATA->fh_limit; i++) { /* 0 is for directories */
        if(!SXFS_DATA->fh_table[i]) {
            file_info->fh = (uint64_t)i;
            SXFS_DATA->fh_table[i] = 1;
            break;
        }
    }
    if(!file_info->fh) {
        SXFS_LOG("%s", strerror(ENFILE));
        ret = -ENFILE;
        pthread_mutex_unlock(&SXFS_DATA->limits_mutex);
        pthread_mutex_destroy(&sxfs_file->block_mutex);
        goto sxfs_create_err;
    }
    sxfs_file->flush = 1;
    sxfs_file->num_open++;
    sxfs_file->ls_file->opened = 1;
    pthread_mutex_unlock(&SXFS_DATA->limits_mutex);
    for(i=dir->nfiles-1; i>0 && strcmp(dir->files[i-1]->name, dir->files[i]->name) > 0; i--) {
        sxfs_lsfile_t *tmp_file = dir->files[i-1];
        dir->files[i-1] = dir->files[i];
        dir->files[i] = tmp_file;
    }

    ret = 0;
sxfs_create_err:
    if(fd >= 0) {
        if(close(fd))
            SXFS_LOG("Cannot close '%s' file: %s", local_file_path, strerror(errno));
        if(unlink(local_file_path))
            SXFS_LOG("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
    }
    free(local_file_path);
    if(ret) {
        if(dir && dir->nfiles && !strcmp(dir->files[dir->nfiles-1]->name, file_name)) {
            sxfs_lsfile_free(dir->files[dir->nfiles-1]);
            dir->files[dir->nfiles-1] = NULL;
            dir->nfiles--;
        }
        if(sxfs_file) {
            sxfs_file_t *tmp_file;
            free(sxfs_file->etag);
            if(sxfs_file->write_fd >= 0) {
                if(close(sxfs_file->write_fd))
                    SXFS_LOG("Cannot close '%s' file: %s", sxfs_file->write_path, strerror(errno));
                if(unlink(sxfs_file->write_path))
                    SXFS_LOG("Cannot remove '%s' file: %s", sxfs_file->write_path, strerror(errno));
            }
            free(sxfs_file->write_path);
            if(sxc_meta_getval(SXFS_DATA->files, path, (const void**)&tmp_file, NULL))
                free(sxfs_file);
            else
                sxc_meta_delval(SXFS_DATA->files, path); /* free(tmp_file) has been done inside */
        }
    }
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    if(locked)
        pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    return ret;
} /* sxfs_create */

static int sxfs_fgetattr (const char *path, struct stat *st, struct fuse_file_info *file_info) {
    sxfs_file_t *sxfs_file;

    if(!path || !st || !file_info) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s'", path);
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->files_mutex); /* correct mutexes order */
    if(sxc_meta_getval(SXFS_DATA->files, path, (const void**)&sxfs_file, NULL)) {
        SXFS_LOG("File not opened: %s", path);
        pthread_mutex_unlock(&SXFS_DATA->files_mutex);
        pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
        return -EFAULT;
    }
    memcpy(st, &sxfs_file->ls_file->st, sizeof(struct stat));
    pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    st->st_atime = st->st_mtime;
    return 0;
} /* sxfs_fgetattr */

static int sxfs_utimens (const char *path, const struct timespec tv[2]) {
    int ret = -1;
    ssize_t index;
    char *path2 = NULL, *file_name;
    sxfs_lsdir_t *dir;

    if(!path) {
        SXFS_LOG("NULL argument");
        return -EINVAL;
    }
    if(*path == '\0') {
        SXFS_LOG("Empty path");
        return -ENOENT;
    }
    if(*path != '/') {
        SXFS_LOG("Not an absolute path");
        return -EINVAL;
    }
    SXFS_DEBUG("'%s'", path);
    if(SXFS_DATA->read_only) {
        SXFS_DEBUG("%s", strerror(EROFS));
        return -EROFS;
    }
    if(check_path_len(path, 0))
        return -errno;
    if(!strcmp(path, "/")) {
        pthread_mutex_lock(&SXFS_DATA->ls_mutex);
        SXFS_DATA->root->st.st_mtime = tv[1].tv_sec;
        pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
        return 0;
    }
    if(strlen(path) > 1 && path[strlen(path)-1] == '/') {
        path2 = strdup(path);
        if(!path2) {
            SXFS_LOG("Out of memory: %s", path);
            return -errno;
        }
        path2[strlen(path2)-1] = '\0';
    }
    file_name = strrchr(path2 ? path2 : path, '/');
    if(!file_name) {
        SXFS_LOG("'/' not found in '%s'", path2 ? path2 : path);
        free(path2);
        return -EINVAL;
    }
    file_name++;
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(!(dir = sxfs_ls_update(path2 ? path2 : path))) {
        SXFS_LOG("Cannot load file tree: %s", path2 ? path2 : path);
        ret = errno ? -errno : -ENOMSG;
        goto sxfs_utimens_err;
    }
    index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp);
    if(index >= 0) {
        dir->dirs[index]->st.st_mtime = tv[1].tv_sec;
    } else {
        index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
        if(index >= 0) {
            dir->files[index]->st.st_mtime = tv[1].tv_sec;
        } else {
            SXFS_LOG("%s: %s", strerror(ENOENT), path2 ? path2 : path);
            ret = -ENOENT;
            goto sxfs_utimens_err;
        }
    }

    ret = 0;
sxfs_utimens_err:
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
    free(path2);
    return ret;
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
};

static const char *args_whitelist[] = {"ro", "rw", "debug", "allow_other", "allow_root", "auto_unmount", "large_read", "direct_io", "async_read", "sync_read", "atomic_o_trunc", "big_writes", NULL};
static const char *args_whitelist_len[] = {"fsname=", "subtype=", "max_read=", "umask=", "uid=", "gid=", "entry_timeout=", "negative_timeout=", "attr_timeout=", "modules=", "max_write=", "max_readahead=", "max_background=", "subdir=", NULL};

static int check_arg (const char *arg) {
    int i = 0;
    for(; args_whitelist[i]; i++)
        if(!strcmp(arg, args_whitelist[i]))
            return 1;
    for(i=0; args_whitelist_len[i]; i++)
        if(!strncmp(arg, args_whitelist_len[i], strlen(args_whitelist_len[i])))
            return 1;
    return 0;
} /* check_arg */

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
    uid = pw->pw_uid;
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

static int str_to_filter (const char *filter) {
    if(!strcmp(filter, "aes256"))
        return SXFS_FILTER_AES;
    if(!strcmp(filter, "attribs"))
        return SXFS_FILTER_ATTRIBS;
    if(!strcmp(filter, "undelete"))
        return SXFS_FILTER_UNDELETE;
    if(!strcmp(filter, "zcomp"))
        return SXFS_FILTER_ZCOMP;
    return -1;
} /* str_to_filter */

static const char *filters_whitelist[] = {"attribs", "undelete", NULL};
static int check_filter (const char *filter) {
    int i = 0;
    for(; filters_whitelist[i]; i++)
        if(!strcmp(filters_whitelist[i], filter))
            return 1;
    return 0;
} /* check_filter */

int main (int argc, char **argv) {
    int i, ret = 1, acl, runas_found = 0, pthread_flag = 0, tempdir_created = 0, tmp;
    unsigned int j;
    char *volume_name = NULL, *username = NULL, *filter_dir, *profile = NULL;
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
    sxfs = (sxfs_state_t*)calloc(1, sizeof(sxfs_state_t));
    if(!sxfs) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    sxfs->args = &args;
    sxfs->pname = argv[0];
    if(args.sx_debug_flag)
        args.foreground_flag = 1;
    if(args.foreground_flag && fuse_opt_add_arg(&fargs, "-f")) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
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
    for(i=0; i<fargs_tmp.argc; i++) {
        if(check_arg(fargs_tmp.argv[i])) {
            if(fuse_opt_add_arg(&fargs, "-o")) {
                fprintf(stderr, "ERROR: Out of memory\n");
                goto main_err;
            }
            if(fuse_opt_add_arg(&fargs, fargs_tmp.argv[i])) {
                fprintf(stderr, "ERROR: Out of memory\n");
                goto main_err;
            }
        } else {
            if(!strcmp(fargs_tmp.argv[i], "use_queues")) {
                args.use_queues_flag = 1;
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
                sxfs->lostdir = strdup(lostdir);
                if(!sxfs->lostdir) {
                    fprintf(stderr, "ERROR: Out of memory\n");
                    goto main_err;
                }
            }
        }
    }
    if(fuse_opt_add_arg(&fargs, args.inputs[1])) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }

    if((args.tempdir_given && !strcmp(args.tempdir_arg, args.inputs[1])) || (sxfs->tempdir && !strcmp(sxfs->tempdir, args.inputs[1]))) {
        cmdline_parser_print_help();
        fprintf(stderr, "\nERROR: Please do not use the same path for temporary directory and mount point\n");
        goto main_err;
    }
    if(args.open_limit_given && args.open_limit_arg > 0) /* fh_limit must be a positive number */
        sxfs->fh_limit = (size_t)args.open_limit_arg + 1; /* 0 is for directories */
    else
        sxfs->fh_limit = 1025;
    sxfs->fh_table = (int*)calloc(sxfs->fh_limit, sizeof(int));
    if(!sxfs->fh_table) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    sx = sxc_init(NULL, sxc_default_logger(&log, argv[0]), sxc_input_fn, NULL);
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
    if(sxfs->uri->path) {
        fprintf(stderr, "ERROR: Do not specify path\n");
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
                        sxfs->filter = str_to_filter(f->shortname);
                        if(sxfs->filter < 0) {
                            fprintf(stderr, "ERROR: Unknown filter\n");
                            goto main_err;
                        }
                        if(!check_filter(f->shortname)) {
                            sxfs->read_only = 1;
                            fprintf(stderr, "*** '%s' filter is not yet fully supported - enabling read-only mode ***\n", f->shortname);
                        }
                        if(sxfs->filter & SXFS_FILTER_ATTRIBS)
                            fprintf(stderr, "*** File attributes are not yet supported ***\n");
                        break;
                    }
                }
                if(i == filters_count) {
                    fprintf(stderr, "ERROR: Unknown filter\n");
                    goto main_err;
                }
            } else {
                fprintf(stderr, "ERROR: Wrong size of filter data\n");
                goto main_err;
            }
        }
    }
    /* get default profile */
    if(!sxfs->uri->profile && sxc_cluster_whoami(cluster, &profile, NULL, NULL, NULL, NULL)) {
        fprintf(stderr, "ERROR: %s", sxc_geterrmsg(sx));
        goto main_err;
    }
    for(i=fargs.argc-1; i>0; i--) { /* index 0 is program name */
        if(!strcmp(fargs.argv[i], "ro"))
            sxfs->read_only = 1;
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
                if(!sxfs->read_only && !(acl & SX_ACL_WRITE)) {
                    sxfs->read_only = 1;
                    fprintf(stderr, "*** Read-only mode (no write permission for the volume) ***\n");
                }
                break;
            }
            free(username);
            username = NULL;
        } else
            break;
    }
    if(sxfs->read_only && args.use_queues_flag) {
        args.use_queues_flag = 0;
        fprintf(stderr, "*** Queues do not work in read-only mode ***\n");
    }
    if(args.use_queues_flag && !args.logfile_given && !sxfs->logfile)
        fprintf(stderr, "*** It is recommended to always use --logfile together with --use-queues ***\n");

    if(gettimeofday(&tv, NULL)) {
        fprintf(stderr, "ERROR: Cannot get current time: %s\n", strerror(errno));
        goto main_err;
    }
    tm = localtime(&tv.tv_sec);
    if(!tm) {
        fprintf(stderr, "ERROR: Cannot convert time value\n");
        goto main_err;
    }
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
        fprintf(sxfs->logfile, "Used parameters: sxfs");
        for(i=1; i<argc; i++)
            fprintf(sxfs->logfile, " %s", argv[i]);
        if(args.debug_flag) {
            fprintf(sxfs->logfile, "\nParameters passed to FUSE:");
            for(i=1; i<fargs.argc; i++)
                fprintf(sxfs->logfile, " %s", fargs.argv[i]);
        }
        fprintf(sxfs->logfile, "\n");
    }
    if(args.tempdir_given || sxfs->tempdir) {
        if(!sxfs->tempdir)
            sxfs->tempdir = args.tempdir_arg;
        if(mkdir(sxfs->tempdir, 0700)) {
            fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", sxfs->tempdir, strerror(errno));
            goto main_err;
        }
    } else if(!sxfs->tempdir) {
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
    sxfs->root->st.st_mode = DIR_ATTR;
    sxfs->root->st.st_size = DIRECTORY_SIZE;
    sxfs->root->st.st_blocks = (DIRECTORY_SIZE + 511) / 512;
    /* directories and files tables will be created on directory tree walking using realloc */
    /* detect subdir */
    for(i=fargs.argc-1; i>0; i--) /* index 0 is program name */
        if(!strncmp(fargs.argv[i], "subdir=", 7)) {
            int fail = 1;
            char *path = NULL, *name, *ptr, *fpath;
            sxc_cluster_lf_t *flist = NULL;
            sxfs_lsdir_t *dir = sxfs->root;

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
                flist = sxc_cluster_listfiles(cluster, sxfs->uri->volume, path, 0, NULL, NULL, NULL, NULL, 0);
                if(!flist) {
                    fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
                    break;
                }
                tmp = sxc_cluster_listfiles_next(flist, &fpath, NULL, NULL, NULL);
                if(tmp) {
                    if(tmp < 0) {
                        fprintf(stderr, "ERROR: Cannot retrieve file name: %s", sxc_geterrmsg(sx));
                        break;
                    }
                    if(fpath[strlen(fpath)-1] != '/') /* there can be a file with same name as $subdir */
                        tmp = 1;
                    else
                        tmp = 0;
                    free(fpath);
                    if(tmp) {
                        tmp = sxc_cluster_listfiles_next(flist, NULL, NULL, NULL, NULL);
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
                dir->st.st_mode = DIR_ATTR;
                dir->st.st_size = DIRECTORY_SIZE;
                dir->st.st_blocks = (DIRECTORY_SIZE + 511) / 512;
                dir->etag = sxfs_hash(sxfs, path);
                if(!dir->etag) {
                    fprintf(stderr, "Cannot compute hash of '%s'\n", path);
                    break;
                }
                fail = 0;
            } while(0);
            free(path);
            sxc_cluster_listfiles_free(flist);
            if(fail)
                goto main_err;
            break;
        }

    sxfs->files = sxc_meta_new(sx);
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
    sxfs->read_block_template = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof("file_read_XXXXXX") + 1);
    if(!sxfs->read_block_template) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto main_err;
    }
    sprintf(sxfs->read_block_template, "%s/file_read_XXXXXX", sxfs->tempdir);
    if(pthread_key_create(&sxfs->pkey, sxfs_sx_data_destroy)) {
        fprintf(stderr, "ERROR: Cannot initialize per-thread memory\n");
        goto main_err;
    }
    sx_data.sx = sx;
    sx_data.cluster = cluster;
    if(pthread_mutex_init(&sxfs->sx_data_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create Sx data mutex\n");
        goto main_err;
    }
    pthread_flag++; // 1
    if(pthread_mutex_init(&sxfs->ls_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create ls cache mutex\n");
        goto main_err;
    }
    pthread_flag++; // 2
    if(pthread_mutex_init(&sxfs->delete_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create files deletion mutex\n");
        goto main_err;
    }
    pthread_flag++; // 3
    if(pthread_mutex_init(&sxfs->upload_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create files upload mutex\n");
        goto main_err;
    }
    pthread_flag++; // 4
    if(pthread_mutex_init(&sxfs->files_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create files data mutex\n");
        goto main_err;
    }
    pthread_flag++; // 5
    if(pthread_mutex_init(&sxfs->limits_mutex, NULL)) {
        fprintf(stderr, "ERROR: Cannot create limits mutex\n");
        goto main_err;
    }
    pthread_flag++; // 6
    sx_data.sx_data_mutex = &sxfs->sx_data_mutex;
    if(pthread_setspecific(sxfs->pkey, (void*)&sx_data)) {
        fprintf(stderr, "ERROR: Cannot set per-thread memory\n");
        goto main_err;
    }
    pthread_flag++; // 7
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
main_err:
    free(volume_name);
    free(username);
    free(profile);
    if(sxfs) {
        free(sxfs->fh_table);
        if(sxfs->empty_file_path) {
            if(unlink(sxfs->empty_file_path)) {
                if(sxfs->logfile)
                    fprintf(sxfs->logfile, "Cannot remove '%s' directory: %s\n", sxfs->empty_file_path, strerror(errno));
                fprintf(stderr, "ERROR: Cannot remove '%s' directory: %s\n", sxfs->empty_file_path, strerror(errno));
            }
            free(sxfs->empty_file_path);
        }
        free(sxfs->read_block_template);
        if(tempdir_created && !sxfs->recovery_failed && sxfs_rmdirs(sxfs->tempdir)) {
            if(sxfs->logfile)
                fprintf(sxfs->logfile, "Cannot remove '%s' directory: %s\n", sxfs->tempdir, strerror(errno));
            fprintf(stderr, "ERROR: Cannot remove '%s' directory: %s\n", sxfs->tempdir, strerror(errno));
        }
        if(tempdir_created == 2 && rmdir(sxfs->lostdir) && errno != ENOTEMPTY) {
            if(sxfs->logfile)
                fprintf(sxfs->logfile, "Cannot remove '%s' directory: %s\n", sxfs->lostdir, strerror(errno));
            fprintf(stderr, "ERROR: Cannot remove '%s' directory: %s\n", sxfs->lostdir, strerror(errno));
        }
        if(!args.tempdir_given)
            free(sxfs->tempdir);
        if(!args.recovery_dir_given)
            free(sxfs->lostdir);
        sxfs_lsdir_free(sxfs->root);
        sxc_free_uri(sxfs->uri);
        sxc_meta_free(sxfs->files);
        if(pthread_flag && (i = pthread_mutex_destroy(&sxfs->sx_data_mutex))) {
            if(sxfs->logfile)
                fprintf(sxfs->logfile, "Cannot destroy Sx data mutex: %s\n", strerror(i));
            fprintf(stderr, "ERROR: Cannot destroy Sx data mutex: %s\n", strerror(i));
        }
        if(pthread_flag > 1 && (i = pthread_mutex_destroy(&sxfs->ls_mutex))) {
            if(sxfs->logfile)
                fprintf(sxfs->logfile, "Cannot destroy ls cache mutex: %s\n", strerror(i));
            fprintf(stderr, "ERROR: Cannot destroy ls cache mutex: %s\n", strerror(i));
        }
        if(pthread_flag > 2 && (i = pthread_mutex_destroy(&sxfs->delete_mutex))) {
            if(sxfs->logfile)
                fprintf(sxfs->logfile, "Cannot destroy deletion mutex: %s\n", strerror(i));
            fprintf(stderr, "ERROR: Cannot destroy deletion mutex: %s\n", strerror(i));
        }
        if(pthread_flag > 3 && (i = pthread_mutex_destroy(&sxfs->upload_mutex))) {
            if(sxfs->logfile)
                fprintf(sxfs->logfile, "Cannot destroy upload mutex: %s\n", strerror(i));
            fprintf(stderr, "ERROR: Cannot destroy upload mutex: %s\n", strerror(i));
        }
        if(pthread_flag > 4 && (i = pthread_mutex_destroy(&sxfs->files_mutex))) {
            if(sxfs->logfile)
                fprintf(sxfs->logfile, "Cannot destroy files data mutex: %s\n", strerror(i));
            fprintf(stderr, "ERROR: Cannot destroy files data mutex: %s\n", strerror(i));
        }
        if(pthread_flag > 5 && (i = pthread_mutex_destroy(&sxfs->limits_mutex))) {
            if(sxfs->logfile)
                fprintf(sxfs->logfile, "Cannot destroy limits mutex: %s\n", strerror(i));
            fprintf(stderr, "ERROR: Cannot destroy limits mutex: %s\n", strerror(i));
        }
        if(pthread_flag > 6 && (i = pthread_key_delete(sxfs->pkey))) {
            if(sxfs->logfile)
                fprintf(sxfs->logfile, "Cannot delete per-thread memory key: %s\n", strerror(i));
            fprintf(stderr, "ERROR: Cannot delete per-thread memory key: %s\n", strerror(i));
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

