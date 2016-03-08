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
#include "cache.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include "libsxclient/src/fileops.h"

#define SXFS_DOWNLOAD_IN_PROGRESS 0x1
#define SXFS_DOWNLOAD_FINISHED 0x2
#define SXFS_DOWNLOAD_BUSY 0x4
#define SXFS_DOWNLOAD_INFO (SXFS_DOWNLOAD_IN_PROGRESS|SXFS_DOWNLOAD_FINISHED|SXFS_DOWNLOAD_BUSY)
#define SXFS_DOWNLOAD_BIT_SHIFT 3

#define SXFS_THREAD_NOT_WORKING 0
#define SXFS_THREAD_WORKING 1
#define SXFS_THREAD_STOPPED (-1)

/* stuff for threads */
int delete_flag, upload_flag;
size_t nfiles_del, maxfiles_del, nfiles_up, maxfiles_up;
char **delete_list = NULL, **upload_list = NULL;
struct timeval last_deletion_time, last_upload_time;

static const char truncated[] = "[...]";

void sxfs_log (sxfs_state_t *sxfs, const char *fn, int log_type, const char *format_string, ...) {
    int len = 0, n, tid;
    char buff[65536];
    int size = sizeof(buff) - sizeof(truncated) + 1;
    struct timeval tv;
    struct tm *tm = NULL;
    va_list vl;

    if(!sxfs || !sxfs->logfile ||
        (log_type == SXFS_LOG_TYPE_DEBUG && !sxfs->args->debug_flag) ||
        (log_type == SXFS_LOG_TYPE_VERBOSE && !sxfs->args->verbose_flag))
        return;
    tid = sxfs_get_thread_id(sxfs);
    if(tid < 0)
        tid = -1;
    if(!gettimeofday(&tv, NULL)) {
        tm = localtime(&tv.tv_sec);
        if(tm)
            n = snprintf(buff, size, "%02d-%02d-%04d %02d:%02d:%02d.%03d ", tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)(tv.tv_usec / 1000));
    }
    if(!tm)
        n = snprintf(buff, size, "dd-mm-yyyy hh:mm:ss ");
    size -= n;
    len += n;
    if(fn && size > 0) {
        n = snprintf(buff + len, size, "[%d|%s] ", tid, fn);
        size -= n;
        len += n;
    }
    if(size > 0) {
        n = snprintf(buff + len, size, "%s: ", log_type == SXFS_LOG_TYPE_ERROR ? "ERROR " : "");
        size -= n;
        len += n;
    }
    if(size > 0) {
        va_start(vl, format_string);
        n = vsnprintf(buff + len, size, format_string, vl);
        va_end(vl);
        size -= n;
    }
    if(size <= 0)
        memcpy(buff + sizeof(buff) - sizeof(truncated), truncated, sizeof(truncated));
    fprintf(sxfs->logfile, "%s\n", buff);
    fflush(sxfs->logfile);
} /* sxfs_log */

int sxfs_diglen (long int n) {
    int i = 0;
    if(n < 0)
        return -1;
    while(n > 0) {
        i++;
        n /= 10;
    }
    return i;
} /* sxfs_diglen */

int sxfs_sx_err (sxc_client_t *sx) {
    switch(sxc_geterrnum(sx)) {
        case SXE_NOERROR: return 0;         /* No error */
        case SXE_EARG: return EINVAL;       /* Invalid argument */
        case SXE_EMEM: return ENOMEM;       /* Out of memory */
        case SXE_EREAD: return EIO;         /* Error reading from disk */
        case SXE_EWRITE: return EIO;        /* Error writing to disk */
        case SXE_ETMP: return EIO;          /* Error with temporary file creation and IO */
        case SXE_ECRYPT: return ENOMSG;     /* Error reported by the cryto library */
        case SXE_EAUTH: return EACCES;      /* Authentication related error */
        case SXE_ECURL: return ECONNABORTED; /* Error reported by the connector library */
        case SXE_ECOMM: return ECONNABORTED; /* Error in the communication with the cluster */
        case SXE_ECFG: return ENOMSG;       /* Error parsing the configuration */
        case SXE_ETIME: return ETIMEDOUT;   /* Error retrieving the current time */
        case SXE_EFILTER: return ENOMSG;    /* Filter related error */
        case SXE_SKIP: return ENOMSG;       /* File was skipped */
        case SXE_EAGAIN: return EAGAIN;     /* Try again later  */
        case SXE_ABORT: return ECANCELED;   /* Operation aborted */
        default: return ENOMSG;
    }
} /* sxfs_sx_err */

int sxfs_resize (void **ptr, size_t *size, size_t elsize) {
    void *new_ptr = realloc(*ptr, (*size + SXFS_ALLOC_ENTRIES) * elsize);
    if(!new_ptr)
        return -1;
    *ptr = new_ptr;
    memset((char*)*ptr + *size * elsize, 0, SXFS_ALLOC_ENTRIES * elsize);
    *size += SXFS_ALLOC_ENTRIES;
    return 0;
} /* sxfs_resize */

char* sxfs_hash (sxfs_state_t *sxfs, const char *name) {
    char *ret;
    unsigned char checksum[SXI_SHA1_BIN_LEN];

    ret = (char*)malloc(SXI_SHA1_TEXT_LEN + 1);
    if(!ret)
        return NULL;
    if(sxi_sha1_calc(sxfs->tempdir, strlen(sxfs->tempdir), name, strlen(name), checksum)) {
        free(ret);
        errno = ENOMEM;
        return NULL;
    }
    sxi_bin2hex(checksum, SXI_SHA1_BIN_LEN, ret);
    ret[SXI_SHA1_TEXT_LEN] = '\0';
    return ret;
} /* sxfs_hash */

int sxfs_thread_create (sxfs_state_t *sxfs, pthread_t *thread, void *(start_routine)(void*), void *arg) {
    int err;
    pthread_attr_t attr;

    if((err = pthread_attr_init(&attr))) {
        SXFS_ERROR("Failed to initialize thread attribute: %s", strerror(err));
        return -err;
    }

    if((err = pthread_attr_setstacksize(&attr, 2 * 1024 * 1024))) {
        SXFS_ERROR("Failed to set thread stack size: %s", strerror(err));
	pthread_attr_destroy(&attr);
        return -err;
    }

    pthread_mutex_lock(&sxfs->limits_mutex);
    if(sxfs->threads_num < SXFS_THREADS_LIMIT) {
        sxfs->threads_num++;
    } else {
        pthread_mutex_unlock(&sxfs->limits_mutex);
	pthread_attr_destroy(&attr);
        SXFS_DEBUG("Reached threads limit");
        return -ENOMSG;
    }
    pthread_mutex_unlock(&sxfs->limits_mutex);

    if((err = pthread_create(thread, &attr, start_routine, arg))) {
        pthread_mutex_lock(&sxfs->limits_mutex);
        sxfs->threads_num--;
        pthread_mutex_unlock(&sxfs->limits_mutex);
	pthread_attr_destroy(&attr);
        SXFS_ERROR("Cannot start new thread: %s", strerror(err));
        return -err;
    }
    pthread_attr_destroy(&attr);
    return 0;
} /* sxfs_thread_create */

int sxfs_build_path (const char* path) {
    int ret;
    char *ptr, *path2 = strdup(path);
    if(!path2)
        return -ENOMEM;
    ptr = strchr(path2 + 1, '/');
    while(ptr) {
        *ptr = '\0';
        if(mkdir(path2, 0700) && errno != EEXIST) {
            ret = -errno;
            goto sxfs_build_path_err;
        }
        *ptr = '/';
        ptr = strchr(ptr + 1, '/');
    }

    ret = 0;
sxfs_build_path_err:
    free(path2);
    return ret;
} /* sxfs_build_path */

int sxfs_copy_file (sxfs_state_t *sxfs, const char *source, const char *dest) {
    int ret, fd_src, fd_dst;
    ssize_t rd;
    char buff[65536];

    if((ret = sxfs_build_path(dest))) {
        SXFS_ERROR("Cannot create path: %s", dest);
        return ret;
    }
    fd_src = open(source, O_RDONLY);
    if(fd_src < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot open '%s' file: %s", source, strerror(errno));
        return ret;
    }
    fd_dst = open(dest, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if(fd_dst < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot create '%s' file: %s", dest, strerror(errno));
        goto sxfs_copy_file_err;
    }
    while((rd = read(fd_src, buff, sizeof(buff))) > 0) {
        if(write(fd_dst, buff, rd) < 0) {
            ret = -errno;
            SXFS_ERROR("Cannot write to '%s' file: %s", dest, strerror(errno));
            goto sxfs_copy_file_err;
        }
    }
    if(rd < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot read from '%s' file: %s", source, strerror(errno));
        goto sxfs_copy_file_err;
    }

    ret = 0;
sxfs_copy_file_err:
    close(fd_src);
    if(fd_dst >= 0)
        close(fd_dst);
    return ret;
} /* sxfs_copy_file */

int sxfs_clear_path (const char *path) {
    char *path2 = strdup(path), *ptr;
    size_t minlen = strlen(SXFS_DATA->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + 1 + 1;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!path2) {
        SXFS_ERROR("Out of memory: %s", path);
        return -ENOMEM;
    }
    ptr = strrchr(path2, '/');
    while(ptr) {
        *ptr = '\0';
        if(strlen(path2) < minlen)
            break;
        if(rmdir(path2)) {
            if(errno != ENOTEMPTY && errno != ENOENT) {
                int ret = -errno;
                SXFS_ERROR("Cannot remove '%s' directory: %s", path2, strerror(errno));
                free(path2);
                return ret;
            }
            break;
        }
        ptr = strrchr(path2, '/');
    }
    free(path2);
    return 0;
} /* sxfs_clear_path */

int sxfs_get_file (sxfs_state_t *sxfs, sxfs_file_t *sxfs_file) {
    int ret, fd = -1;
    ssize_t bytes;
    off_t offset = 0;
    char *local_file_path, buff[4096];

    pthread_mutex_lock(&sxfs_file->mutex);
    if(sxfs_file->write_fd >= 0) { /* in case of race condition */
        pthread_mutex_unlock(&sxfs_file->mutex);
        return 0;
    }
    SXFS_VERBOSE("Downloading the file");
    local_file_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof("file_XXXXXX") + 1);
    if(!local_file_path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_get_file_err;
    }
    sprintf(local_file_path, "%s/file_XXXXXX", sxfs->tempdir);
    fd = mkstemp(local_file_path);
    if(fd < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot create unique temporary file: %s", strerror(errno));
        free(local_file_path);
        local_file_path = NULL;
        goto sxfs_get_file_err;
    }
    if(sxfs_file->fdata->blocksize == SX_BS_SMALL) {
        sxc_client_t *sx;
        sxc_cluster_t *cluster;
        sxc_file_t *file_local, *file_remote;

        if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
            SXFS_ERROR("Cannot get SX data");
            goto sxfs_get_file_err;
        }
        file_local = sxc_file_local(sx, local_file_path);
        if(!file_local) {
            SXFS_ERROR("Cannot create local file object: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_get_file_err;
        }
        file_remote = sxc_file_remote(cluster, sxfs->uri->volume, sxfs_file->remote_path+1, NULL);
        if(!file_remote) {
            SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            sxc_file_free(file_local);
            goto sxfs_get_file_err;
        }
        if(sxc_copy_single(file_remote, file_local, 0, 0, 0, NULL, 0)) {
            SXFS_ERROR("Cannot download '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            sxc_file_free(file_local);
            sxc_file_free(file_remote);
            goto sxfs_get_file_err;
        }
        sxc_file_free(file_local);
        sxc_file_free(file_remote);
    } else {
        while((bytes = sxfs_cache_read(sxfs, sxfs_file, buff, sizeof(buff), offset)) > 0) {
            if(write(fd, buff, bytes) < 0) {
                ret = -errno;
                SXFS_ERROR("Cannot write to '%s' file: %s", sxfs_file->write_path, strerror(errno));
                goto sxfs_get_file_err;
            }
            offset += bytes;
        }
        if(bytes < 0) {
            ret = -errno;
            SXFS_ERROR("Cannot read from '%s' file: %s", local_file_path, strerror(errno));
            goto sxfs_get_file_err;
        }
    }
    sxfs_file->write_fd = fd;
    sxfs_file->write_path = local_file_path;
    fd = -1;
    local_file_path = NULL;
    SXFS_VERBOSE("New file descriptor: %d", sxfs_file->write_fd);

    ret = 0;
sxfs_get_file_err:
    pthread_mutex_unlock(&sxfs_file->mutex);
    if(fd >= 0 && close(fd))
        SXFS_ERROR("Cannot close '%s' file: %s", local_file_path, strerror(errno));
    if(local_file_path && unlink(local_file_path))
        SXFS_ERROR("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    return ret;
} /* sxfs_get_file */

void sxfs_file_free (sxfs_state_t *sxfs, sxfs_file_t *sxfs_file) {
    int err;

    if(!sxfs_file)
        return;
    if(sxfs_file->write_path) {
        if(close(sxfs_file->write_fd))
            SXFS_ERROR("Cannot close '%s' file: %s", sxfs_file->write_path, strerror(errno));
        if(unlink(sxfs_file->write_path) && errno != ENOENT)
            SXFS_ERROR("Cannot remove '%s' file: %s", sxfs_file->write_path, strerror(errno));
        free(sxfs_file->write_path);
    }
    free(sxfs_file->remote_path);
    if(sxfs_file->ls_file->opened & SXFS_FILE_REMOVED) {
        sxfs_file->ls_file->opened = 0;
        sxfs_lsfile_free(sxfs_file->ls_file);
    } else
        sxfs_file->ls_file->opened = 0;
    pthread_mutex_lock(&sxfs->limits_mutex);
    while(sxfs_file->threads_num) {
        pthread_mutex_unlock(&sxfs->limits_mutex);
        usleep(SXFS_THREAD_WAIT);
        pthread_mutex_lock(&sxfs->limits_mutex);
    }
    pthread_mutex_unlock(&sxfs->limits_mutex);
    sxi_sxfs_download_finish(sxfs_file->fdata);
    if((err = pthread_mutex_destroy(&sxfs_file->mutex)))
        SXFS_ERROR("Cannot destroy mutex: %s", strerror(err));
    free(sxfs_file);
} /* sxfs_file_free */

void sxfs_sx_data_destroy (void *ptr) {
    sxfs_sx_data_t *sx_data = (sxfs_sx_data_t*)ptr;
    if(sx_data) {
        pthread_mutex_lock(sx_data->sx_data_mutex);
        sxc_cluster_free(sx_data->cluster);
        sxc_client_shutdown(sx_data->sx, 0);
        pthread_mutex_unlock(sx_data->sx_data_mutex);
        free(sx_data);
    }
} /* sxfs_sx_data_destory */

int sxfs_get_sx_data (sxfs_state_t *sxfs, sxc_client_t **sx, sxc_cluster_t **cluster) {
    int ret;
    sxfs_sx_data_t *sx_data = (sxfs_sx_data_t*)pthread_getspecific(sxfs->sxkey);
    if(!sx_data) {
        char *filter_dir = NULL;
        const char *filter_dir_env = sxi_getenv("SX_FILTER_DIR");

        if(sxfs->args->filter_dir_given)
            filter_dir = strdup(sxfs->args->filter_dir_arg);
        else if(filter_dir_env)
            filter_dir = strdup(filter_dir_env);
        else
            filter_dir = strdup(SX_FILTER_DIR);
        if(!filter_dir) {
            SXFS_ERROR("OOM for filter directory");
            return -ENOMEM;
        }
        pthread_mutex_lock(&sxfs->sx_data_mutex);
        do {
            sx_data = (sxfs_sx_data_t*)calloc(sizeof(sxfs_sx_data_t), 1);
            if(!sx_data) {
                SXFS_ERROR("Out of memory");
                ret = -ENOMEM;
                break;
            }
            sx_data->sx = sxc_client_init(sxc_default_logger(&sx_data->log, sxfs->pname), sxc_input_fn, NULL);
            if(!sx_data->sx) {
                SXFS_ERROR("Cannot initialize SX");
                ret = -ENOMEM;
                break;
            }
            if(sxfs->args->config_dir_given && sxc_set_confdir(sx_data->sx, sxfs->args->config_dir_arg)) {
                SXFS_ERROR("Could not set configuration directory to '%s': %s", sxfs->args->config_dir_arg, sxc_geterrmsg(sx_data->sx));
                ret = -sxfs_sx_err(sx_data->sx);
                break;
            }
            sxc_set_debug(sx_data->sx, sxfs->args->sx_debug_flag);
            if(sxc_filter_loadall(sx_data->sx, filter_dir)) {
                SXFS_ERROR("Failed to load filters: %s", sxc_geterrmsg(sx_data->sx));
                sxc_clearerr(sx_data->sx);
            }
            sx_data->cluster = sxc_cluster_load_and_update(sx_data->sx, sxfs->uri->host, sxfs->uri->profile);
            if(!sx_data->cluster) {
                SXFS_ERROR("Cannot load config for %s: %s", sxfs->uri->host, sxc_geterrmsg(sx_data->sx));
                ret = -sxfs_sx_err(sx_data->sx);
                break;
            }
            sx_data->sx_data_mutex = &sxfs->sx_data_mutex;
        } while(0);
        free(filter_dir);
        if(sx_data) {
            if(sx_data->cluster) {
                int err;
                if((err = pthread_setspecific(sxfs->sxkey, (void*)sx_data))) {
                    SXFS_ERROR("Cannot set per-thread memory: %s", strerror(err));
                    sxc_client_shutdown(sx_data->sx, 0);
                    sxc_cluster_free(sx_data->cluster);
                    free(sx_data);
                    sx_data = NULL;
                    ret = -err;
                }
            } else {
                sxc_client_shutdown(sx_data->sx, 0);
                free(sx_data);
                sx_data = NULL;
            }
        }
        pthread_mutex_unlock(&sxfs->sx_data_mutex);
        if(!sx_data)
            return ret;
    }
    *sx = sx_data->sx;
    *cluster = sx_data->cluster;
    return 0;
} /* sxfs_get_sx_data */

struct _thread_id_data {
    int id;
    sxfs_state_t *sxfs;
};
typedef struct _thread_id_data thread_id_data_t;

void sxfs_thread_id_destroy (void *ptr) {
    thread_id_data_t *td = (thread_id_data_t*)ptr;
    if(td) {
        pthread_mutex_lock(&td->sxfs->limits_mutex);
        td->sxfs->threads[td->id] = 0;
        pthread_mutex_unlock(&td->sxfs->limits_mutex);
        free(td);
    }
} /* sxfs_thread_id_destroy */

/* this function is being used in sxfs_log so it cannot use SXFS_LOG etc. */
int sxfs_get_thread_id (sxfs_state_t *sxfs) {
    size_t i;
    int err;
    thread_id_data_t *td = (thread_id_data_t*)pthread_getspecific(sxfs->tid_key);

    if(!td) {
        td = (thread_id_data_t*)malloc(sizeof(thread_id_data_t));
        if(!td) {
            fprintf(sxfs->logfile, "[%s] ERROR: Out of memory\n", __func__);
            return -ENOMEM;
        }
        td->id = -1;
        pthread_mutex_lock(&sxfs->limits_mutex);
        for(i=0; i<sxfs->threads_max; i++)
            if(!sxfs->threads[i]) {
                td->id = i;
                sxfs->threads[i] = 1;
                break;
            }
        if(td->id < 0) {
            if(sxfs_resize((void**)&sxfs->threads, &sxfs->threads_max, sizeof(int))) {
                pthread_mutex_unlock(&sxfs->limits_mutex);
                fprintf(sxfs->logfile, "[%s] ERROR: Out of memory\n", __func__);
                free(td);
                return -ENOMEM;
            }
            td->id = i;
            sxfs->threads[i] = 1;
        }
        pthread_mutex_unlock(&sxfs->limits_mutex);
        if((err = pthread_setspecific(sxfs->tid_key, (void*)td))) {
            fprintf(sxfs->logfile, "[%s] ERROR: Cannot set per-thread memory: %s\n", __func__, strerror(err));
            pthread_mutex_lock(&sxfs->limits_mutex);
            sxfs->threads[i] = 0;
            pthread_mutex_unlock(&sxfs->limits_mutex);
            free(td);
            return -err;
        }
        td->sxfs = sxfs;
    }
    return td->id;
} /* sxfs_get_thread_id */

void sxfs_lsfile_free (sxfs_lsfile_t *file) {
    if(!file)
        return;
    if(file->opened) {
        file->opened |= SXFS_FILE_REMOVED;
        return;
    }
    free(file->name);
    free(file);
} /* sxfs_lsfile_free */

/* st.st_dev        Device ID of device containing file.
 * st.st_ino        File serial number.
 * st.st_mode       Mode of file.
 * st.st_nlink      Number of hard links to the file.
 * st.st_uid        User ID of file.
 * st.st_gid        Group ID of file.
 * st.st_rdev       Device ID (if file is character or block special).
 * st.st_size       For regular files, the file size in bytes.
 * st_atime         Time of last access.
 * st_mtime         Time of last modification.
 * st_ctime         Time of last status change.
 * st.st_blksize    A file system-specific preferred I/O block size for
                    this object. In some file system types, this may
                    vary from file to file.
 * st.st_blocks     Number of blocks allocated for this object. */
int sxfs_lsdir_add_file (sxfs_lsdir_t *dir, const char *path, struct stat *st) {
    int ret;
    time_t mctime;
    char *name;
    sxfs_lsfile_t *file;
    sxfs_state_t *sxfs = SXFS_DATA;

    if((mctime = time(NULL)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
        return ret;
    }
    name = strrchr(path, '/') + 1;
    if(dir->nfiles == dir->maxfiles && sxfs_resize((void**)&dir->files, &dir->maxfiles, sizeof(sxfs_lsfile_t*))) {
        SXFS_ERROR("OOM growing files cache table: %s", strerror(errno));
        return -ENOMEM;
    }
    file = (sxfs_lsfile_t*)calloc(1, sizeof(sxfs_lsfile_t));
    if(!file) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    file->name = strdup(name);
    if(!file->name) {
        SXFS_ERROR("Out of memory: %s", name);
        ret = -ENOMEM;
        goto sxfs_lsdir_add_file_err;
    }
    if(st) {
        file->st.st_mtime = file->st.st_ctime = st->st_mtime;
        file->st.st_uid = st->st_uid;
        file->st.st_gid = st->st_gid;
        file->st.st_mode = st->st_mode;
        file->st.st_size = st->st_size;
    } else {
        file->st.st_mtime = file->st.st_ctime = mctime;
        file->st.st_uid = getuid();
        file->st.st_gid = getgid();
        file->st.st_mode = SXFS_FILE_ATTR;
/*        file->st.st_size = 0;*/ /* calloc() has been used */
    }
    file->st.st_nlink = 1;
    file->st.st_blocks = (file->st.st_size + 511) / 512;
    dir->files[dir->nfiles] = file;
    dir->nfiles++;
    file = NULL;
    dir->st.st_mtime = dir->st.st_ctime = mctime;

    ret = 0;
sxfs_lsdir_add_file_err:
    sxfs_lsfile_free(file);
    return ret;
} /* sxfs_lsdir_add_file */

int sxfs_lsdir_add_dir (sxfs_lsdir_t *dir, const char *path) {
    int ret, slash = 0;
    time_t mctime;
    char *path2, *name;
    sxfs_lsdir_t *subdir = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(path[strlen(path)-1] == '/') {
        slash = 1;
        path2 = strdup(path);
        if(!path2) {
            SXFS_ERROR("Out of memory: %s", path);
            return -ENOMEM;
        }
        path2[strlen(path2)-1] = '\0';
        name = strrchr(path2, '/') + 1;
    } else {
        path2 = (char*)malloc(strlen(path) + 2);
        if(!path2) {
            SXFS_ERROR("Out of memory");
            return -ENOMEM;
        }
        sprintf(path2, "%s/", path);
        name = strrchr(path, '/') + 1;
    }
    if((mctime = time(NULL)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
        goto sxfs_lsdir_add_dir_err;
    }
    if(dir->ndirs == dir->maxdirs && sxfs_resize((void**)&dir->dirs, &dir->maxdirs, sizeof(sxfs_lsdir_t*))) {
        SXFS_ERROR("OOM growing dirs cache table: %s", strerror(errno));
        ret = -ENOMEM;
        goto sxfs_lsdir_add_dir_err;
    }
    subdir = (sxfs_lsdir_t*)calloc(1, sizeof(sxfs_lsdir_t));
    if(!subdir) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_lsdir_add_dir_err;
    }
    subdir->maxdirs = subdir->maxfiles = SXFS_ALLOC_ENTRIES;
    subdir->dirs = (sxfs_lsdir_t**)calloc(subdir->maxdirs, sizeof(sxfs_lsdir_t*));
    if(!subdir->dirs) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_lsdir_add_dir_err;
    }
    subdir->files = (sxfs_lsfile_t**)calloc(subdir->maxfiles, sizeof(sxfs_lsfile_t*));
    if(!subdir->files) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_lsdir_add_dir_err;
    }
    subdir->name = strdup(name);
    if(!subdir->name) {
        SXFS_ERROR("Out of memory: %s", name);
        ret = -ENOMEM;
        goto sxfs_lsdir_add_dir_err;
    }
    subdir->etag = sxfs_hash(sxfs, slash ? path : path2);
    if(!subdir->etag) {
        ret = -errno;
        SXFS_ERROR("Cannot compute hash of '%s'", slash ? path : path2);
        goto sxfs_lsdir_add_dir_err;
    }
    subdir->st.st_mtime = subdir->st.st_ctime = mctime;
    subdir->parent = dir;
    subdir->st.st_uid = getuid();
    subdir->st.st_gid = getgid();
    subdir->st.st_nlink = 1;
    subdir->st.st_mode = SXFS_DIR_ATTR;
    subdir->st.st_size = SXFS_DIR_SIZE;
    subdir->st.st_blocks = (SXFS_DIR_SIZE + 511) / 512;
    dir->dirs[dir->ndirs] = subdir;
    dir->ndirs++;
    dir->st.st_mtime = dir->st.st_ctime = mctime;
    subdir = NULL;

    ret = 0;
sxfs_lsdir_add_dir_err:
    free(path2);
    sxfs_lsdir_free(subdir);
    return ret;
} /* sxfs_lsdir_add_dir */

void sxfs_lsdir_free (sxfs_lsdir_t *dir) {
    size_t i;
    if(!dir)
        return;
    if(dir->files) {
        for(i=0; i<dir->nfiles; i++)
            sxfs_lsfile_free(dir->files[i]);
        free(dir->files);
    }
    if(dir->dirs) {
        for(i=0; i<dir->ndirs; i++)
            sxfs_lsdir_free(dir->dirs[i]);
        free(dir->dirs);
    }
    free(dir->name);
    free(dir->etag);
    free(dir);
} /* sxfs_lsdir_free */

int sxfs_str_cmp (const void **ptr, size_t index, const char *file_name) {
    const char *str = ((const char**)ptr)[index];
    size_t filelen = strlen(file_name), len = strlen(str);

    if(file_name[filelen-1] == '/' && len == filelen + lenof(SXFS_SXNEWDIR) && !strcmp(str + len - lenof(SXFS_SXNEWDIR), SXFS_SXNEWDIR))
        return strncmp(str, file_name, filelen);
    return strcmp(str, file_name);
} /* sxfs_str_cmp */

int sxfs_lsfile_cmp (const void **files, size_t index, const char *file_name) {
    return strcmp(((const sxfs_lsfile_t**)files)[index]->name, file_name);
} /* sxfs_lsfile_cmp */

int sxfs_lsdir_cmp (const void **dirs, size_t index, const char *dir_name) {
    return strcmp(((const sxfs_lsdir_t**)dirs)[index]->name, dir_name);
} /* sxfs_lsdir_cmp */

ssize_t sxfs_find_entry (const void **table, size_t size, const char *name, int (*compare)(const void**, size_t, const char*)) {
    int tmp;
    ssize_t i;
    size_t from = 0, to;

    if(!size)
        return -1;
    if(!table || !name || !compare) {
        errno = EINVAL;
        return -1;
    }
    to = size - 1;
    while(1) {
        i = (from + to) / 2;
        tmp = compare(table, i, name);
        if(!tmp) {
            return i;
        } else {
            if(from == to) {
                return -1;
            }
            if(tmp > 0)
                to = i;
            else
                from = i + 1;
        }
    }
} /* sxfs_find_entry */

static int sxfs_str_compare (const void *ptr1, const void *ptr2) {
    return strcmp(*((const char* const*)ptr1), *((const char* const*)ptr2));
} /* sxfs_str_compare */

static int sxfs_lsfile_compare (const void *ptr1, const void *ptr2) {
    return strcmp((*(const sxfs_lsfile_t* const*)ptr1)->name, (*(const sxfs_lsfile_t* const*)ptr2)->name);
} /* sxfs_lsfile_compare */

static int sxfs_lsdir_compare (const void *ptr1, const void *ptr2) {
    return strcmp((*(const sxfs_lsdir_t* const*)ptr1)->name, (*(const sxfs_lsdir_t* const*)ptr2)->name);
} /* sxfs_lsdir_compare */

static int sxfs_set_attr (const char *path, struct stat *st) {
    struct utimbuf utb;

    if(chmod(path, st->st_mode))
        return -1;
    if(chown(path, st->st_uid, st->st_gid) && errno != EPERM) /* root only */
        return -1;
    utb.actime = st->st_atime;
    utb.modtime = st->st_mtime;
    if(utime(path, &utb))
        return -1;
    return 0;
} /* sxfs_set_attr */

static int sxfs_ls_ftw (sxfs_state_t *sxfs, const char *path, sxfs_lsdir_t **given_dir) {
    ssize_t index;
    char *ptr, *slash, *path2;
    sxfs_lsdir_t *dir = sxfs->root;

    path2 = strdup(path);
    if(!path2) {
        SXFS_ERROR("Out of memory: %s", path);
        return -ENOMEM;
    }
    ptr = path2 + 1;
    slash = strchr(ptr, '/');
    while(slash) {
        *slash = '\0';
        index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, ptr, sxfs_lsdir_cmp);
        if(index < 0) {
            int ret;
            if(sxfs_find_entry((const void**)dir->files, dir->nfiles, ptr, sxfs_lsfile_cmp) >= 0) {
                SXFS_ERROR("%s: %s (%s)", strerror(ENOTDIR), ptr, path);
                ret = -ENOTDIR;
            } else {
                SXFS_ERROR("%s: %s (%s)", strerror(ENOENT), ptr, path);
                ret = -ENOENT;
            }
            free(path2);
            return ret;
        }
        dir = dir->dirs[index];
        *slash = '/';
        ptr = slash + 1;
        slash = strchr(ptr, '/');
    }
    free(path2);
    *given_dir = dir;
    return 0;
} /* sxfs_ls_ftw */

#ifdef WORDS_BIGENDIAN
static uint32_t swapu32 (uint32_t v) {
    v = ((v << 8) & 0xff00ff00) | ((v >> 8) & 0xff00ff);
    return (v << 16) | (v >> 16);
} /* swapu32 */

static uint64_t swapu64 (uint64_t v) {
    v = ((v << 8) & 0xff00ff00ff00ff00ULL) | ((v >> 8) & 0x00ff00ff00ff00ffULL);
    v = ((v << 16) & 0xffff0000ffff0000ULL) | ((v >> 16) & 0x0000ffff0000ffffULL);
    return (v << 32) | (v >> 32);
} /* swapu64 */
#else
#define swapu32(x) (x)
#define swapu64(x) (x)
#endif

int sxfs_ls_update (const char *absolute_path, sxfs_lsdir_t **given_dir) {
    int ret, upload_locked = 0, tmp, *check_files = NULL, *check_dirs = NULL;
    unsigned int remote_files;
    ssize_t index;
    size_t i, j, ncfiles, ncdirs, pathlen;
    time_t tmptime;
    char *path = NULL, *ptr, *fpath = NULL, *fname;
    struct stat st;
    struct timeval tv;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_cluster_lf_t *flist = NULL;
    sxc_file_t *file = NULL;
    sxc_meta_t *fmeta = NULL;
    sxfs_lsdir_t *dir = NULL, *subdir;
    sxfs_state_t *sxfs = SXFS_DATA;

    if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
        SXFS_ERROR("Cannot get SX data");
        return ret;
    }
    pathlen = strlen(sxfs->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + strlen(absolute_path) + 1;
    path = (char*)malloc(pathlen);
    if(!path) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }

    /* check whether directory is already loaded */
    if((ret = sxfs_ls_ftw(sxfs, absolute_path, &dir))) { /* FUSE checks each directory in the path */
        SXFS_ERROR("File tree walk failed");
        goto sxfs_ls_update_err;
    }
    if(dir->init) {
        if(gettimeofday(&tv, NULL)) {
            ret = -errno;
            SXFS_ERROR("Cannot get current time: %s", strerror(errno));
            goto sxfs_ls_update_err;
        }
        if(sxi_timediff(&tv, &dir->tv) < SXFS_LS_RELOAD) {
            ret = 0;
            *given_dir = dir;
            dir = NULL; /* do not convert remote flag (2 -> 1) */
            goto sxfs_ls_update_err; /* this is not a failure */
        }
    }

    sprintf(path, "%s", absolute_path);
    ptr = strrchr(path, '/') + 1;
    *ptr = '\0';
    flist = sxc_cluster_listfiles_etag(cluster, sxfs->uri->volume, path, 0, &remote_files, 0, dir->etag);
    if(!flist) {
        if(sxc_geterrnum(sx) != SXE_SKIP) {
            SXFS_ERROR("%s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_ls_update_err;
        }
        if(!dir->init) {
            flist = sxc_cluster_listfiles(cluster, sxfs->uri->volume, path, 0, &remote_files, 0);
            if(!flist) {
                SXFS_ERROR("%s", sxc_geterrmsg(sx));
                ret = -sxfs_sx_err(sx);
                goto sxfs_ls_update_err;
            }
        } else {
            if(gettimeofday(&tv, NULL)) {
                ret = -errno;
                SXFS_ERROR("Cannot get current time: %s", strerror(errno));
                goto sxfs_ls_update_err;
            }
            *given_dir = dir;
            dir->tv = tv;
            dir = NULL; /* do not convert remote flag (2 -> 1) */
            goto sxfs_ls_update_err; /* this is not a failure */
        }
    }

    if(remote_files)
        dir->remote = 1;
    else
        dir->remote = 0;
    dir->sxnewdir = 0;

    ncfiles = dir->nfiles;
    ncdirs = dir->ndirs;
    check_files = (int*)calloc(ncfiles, sizeof(int));
    if(!check_files) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_ls_update_err;
    }
    check_dirs = (int*)calloc(ncdirs, sizeof(int));
    if(!check_dirs) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto sxfs_ls_update_err;
    }
    /* save opened but not yet uploaded files */
    pthread_mutex_lock(&sxfs->files_mutex);
    for(i=0; i<ncfiles; i++)
        if(dir->files[i]->opened == SXFS_FILE_OPENED)
            check_files[i] = 1;
    pthread_mutex_unlock(&sxfs->files_mutex);
    /* load directory content from upload queue */
    if(sxfs->args->use_queues_flag) {
        tmp = strrchr(absolute_path, '/') - absolute_path + 1;
        i = 0;
        pthread_mutex_lock(&sxfs->upload_mutex);
        upload_locked = 1;
        while(i < nfiles_up && strncmp(upload_list[i], absolute_path, tmp) < 0)
            i++;
        for(; i<nfiles_up && !strncmp(upload_list[i], absolute_path, tmp); i++) {
            if(strchr(upload_list[i] + tmp, '/')) { /* directory */
                while(pathlen < strlen(upload_list[i]) + 1) {
                    if(sxfs_resize((void**)&path, &pathlen, sizeof(char))) {
                        SXFS_ERROR("OOM growing the path: %s", strerror(errno));
                        ret = -ENOMEM;
                        goto sxfs_ls_update_err;
                    }
                }
                snprintf(path, pathlen, "%s", upload_list[i] + tmp);
                ptr = strchr(path, '/');
                if(ptr)
                    *ptr = '\0';
                index = sxfs_find_entry((const void**)dir->dirs, ncdirs, path, sxfs_lsdir_cmp);
                if(index >= 0) {
                    check_dirs[index] = 1;
                } else {
                    SXFS_ERROR("'%s' directory is missing in ls cache", path);
                    ret = -EAGAIN;
                    goto sxfs_ls_update_err;
                }
            } else { /* file */
                ptr = strrchr(upload_list[i] ,'/') + 1;
                if(!strcmp(ptr, SXFS_SXNEWDIR)) {
                    dir->sxnewdir = 1;
                } else {
                    index = sxfs_find_entry((const void**)dir->files, ncfiles, ptr, sxfs_lsfile_cmp);
                    if(index >= 0) {
                        check_files[index] = 1;
                    } else {
                        SXFS_ERROR("'%s' file is missing in ls cache", ptr);
                        ret = -EAGAIN;
                        goto sxfs_ls_update_err;
                    }
                }
            }
        }
    }

    /* load the content of the directory */
    while(1) {
        file = NULL;
        tmp = sxc_cluster_listfiles_next(cluster, sxfs->uri->volume, flist, &file);
        if(tmp <= 0) {
            if(tmp) {
                SXFS_ERROR("Failed to retrieve file name: %s", sxc_geterrmsg(sx));
                ret = -sxfs_sx_err(sx);
                goto sxfs_ls_update_err;
            }
            break;
        }
        free(fpath);
        fpath = strdup(sxc_file_get_path(file));
        if(!fpath) {
            SXFS_ERROR("Out of memory duplicating remote file path");
            sxc_file_free(file);
            goto sxfs_ls_update_err;
        }
        tmptime = sxc_file_get_created_at(file);
        st.st_size = sxc_file_get_size(file);
        st.st_uid = sxc_file_get_uid(file) == (uid_t)SXC_UINT32_UNDEFINED ? getuid() : sxc_file_get_uid(file);
        st.st_gid = sxc_file_get_gid(file) == (gid_t)SXC_UINT32_UNDEFINED ? getgid() : sxc_file_get_gid(file);
        st.st_mtime = sxc_file_get_mtime(file) == (time_t)SXC_UINT64_UNDEFINED ? tmptime : sxc_file_get_mtime(file);
        tmp = strlen(fpath) - 1;
        if(fpath[tmp] == '/') {
            fpath[tmp] = '\0';
            st.st_mode = SXFS_DIR_ATTR;
        } else {
            tmp = 0;
            st.st_mode = sxc_file_get_mode(file) == (mode_t)SXC_UINT32_UNDEFINED ? SXFS_FILE_ATTR : sxc_file_get_mode(file);
        }
        sxc_file_free(file);
        file = NULL;
        fname = strrchr(fpath, '/');
        if(!fname)
            fname = fpath + 1;
        else
            fname++;
        if(tmp)
            fpath[tmp] = '/';
        if(!sxfs->args->use_queues_flag || sxfs_find_entry((const void**)delete_list, nfiles_del, fpath, sxfs_str_cmp) < 0) {
            if(!strcmp(fname, SXFS_SXNEWDIR)) {
                dir->sxnewdir = 2; /* file is on the server */
            } else {
                if(S_ISDIR(st.st_mode)) {
                    fpath[tmp] = '\0';
                    index = sxfs_find_entry((const void**)dir->dirs, ncdirs, fname, sxfs_lsdir_cmp);
                    fpath[tmp] = '/';
                    if(index >= 0) {
                        check_dirs[index] = 1;
                        if(tmptime > dir->dirs[index]->st.st_mtime)
                            dir->dirs[index]->st.st_mtime = tmptime;
                        dir->dirs[index]->remote = 2;
                    } else {
                        if((ret = sxfs_lsdir_add_dir(dir, fpath))) {
                            SXFS_ERROR("Cannot add new directory to cache: %s", fpath);
                            goto sxfs_ls_update_err;
                        }
                        dir->dirs[dir->ndirs-1]->remote = 2;
                    }
                } else {
                    index = sxfs_find_entry((const void**)dir->files, ncfiles, fname, sxfs_lsfile_cmp);
                    if(index >= 0) {
                        if(!check_files[index] && tmptime > dir->files[index]->remote_mtime) {
                            struct stat *tmpst = &dir->files[index]->st;
                            tmpst->st_mtime = st.st_mtime;
                            tmpst->st_ctime = MAX(tmpst->st_ctime, st.st_mtime); /* since ctime is not handled by SX there can already be newer ctime in sxfs) */
                            tmpst->st_uid = st.st_uid;
                            tmpst->st_gid = st.st_gid;
                            tmpst->st_mode = st.st_mode;
                            tmpst->st_size = st.st_size;
                            tmpst->st_blocks = (st.st_size + 511) / 512;
                            dir->files[index]->remote_mtime = tmptime;
                        }
                        check_files[index] = 1;
                        dir->files[index]->remote = 2;
                    } else {
                        if((ret = sxfs_lsdir_add_file(dir, fpath, &st))) {
                            SXFS_ERROR("Cannot add new file to cache: %s", fpath);
                            goto sxfs_ls_update_err;
                        }
                        dir->files[dir->nfiles-1]->remote = 2;
                    }
                }
            }
        }
        free(fpath);
        fpath = NULL;
    }

    /* remove files */
    for(i=0; i<ncfiles; i++)
        if(!check_files[i]) {
            sxfs_lsfile_free(dir->files[i]);
            dir->files[i] = NULL;
        }
    for(i=0; i<ncdirs; i++)
        if(!check_dirs[i]) {
            sxfs_lsdir_free(dir->dirs[i]);
            dir->dirs[i] = NULL;
        }
    for(i=0; i<dir->nfiles; i++)
        if(!dir->files[i]) {
            for(j=i+1; j<dir->nfiles; j++)
                dir->files[j-1] = dir->files[j];
            dir->files[dir->nfiles-1] = NULL;
            dir->nfiles--;
            i--;
        }
    for(i=0; i<dir->ndirs; i++)
        if(!dir->dirs[i]) {
            for(j=i+1; j<dir->ndirs; j++)
                dir->dirs[j-1] = dir->dirs[j];
            dir->dirs[dir->ndirs-1] = NULL;
            dir->ndirs--;
            i--;
        }
    if(dir->nfiles)
        qsort(dir->files, dir->nfiles, sizeof(sxfs_lsfile_t*), sxfs_lsfile_compare);
    if(dir->ndirs)
        qsort(dir->dirs, dir->ndirs, sizeof(sxfs_lsdir_t*), sxfs_lsdir_compare);
    /* hide files if there are directories with the same names */
    for(i=0, j=0; i<dir->ndirs && j<dir->nfiles;) {
        tmp = strcmp(dir->dirs[i]->name, dir->files[j]->name);
        if(tmp) {
            if(tmp > 0)
                j++;
            else
                i++;
        } else {
            size_t k;
            sxfs_lsfile_free(dir->files[j]);
            for(k=j+1; k<dir->nfiles; k++)
                dir->files[k-1] = dir->files[k];
            dir->files[k-1] = NULL;
            dir->nfiles--;
        }
    }
    dir->init = 1;
    if(gettimeofday(&tv, NULL))
        SXFS_ERROR("Cannot get current time: %s", strerror(errno)); /* no fail, because content is already fully loaded */
    else
        dir->tv = tv;
    subdir = dir;
    /* update directories modification time */
    while(subdir->parent) {
        if(subdir->st.st_mtime > subdir->parent->st.st_mtime)
            subdir->parent->st.st_mtime = subdir->st.st_mtime;
        else
            break;
        subdir = subdir->parent;
    }

    *given_dir = dir;
    ret = 0;
sxfs_ls_update_err:
    if(upload_locked)
        pthread_mutex_unlock(&sxfs->upload_mutex);
    free(path);
    free(fpath);
    free(check_files);
    free(check_dirs);
    sxc_cluster_listfiles_free(flist);
    sxc_file_free(file);
    sxc_meta_free(fmeta);
    if(dir) {
        for(i=0; i<dir->nfiles; i++) {
            if(dir->files[i]->remote == 2) {
                dir->files[i]->remote = 1;
            } else if(ret) {
                dir->files[i]->remote = 0;
            }
        }
        for(i=0; i<dir->ndirs; i++) {
            if(dir->dirs[i]->remote == 2) {
                dir->dirs[i]->remote = 1;
            } else if(ret) {
                dir->dirs[i]->remote = 0;
            }
        }
    }
    return ret;
} /* sxfs_ls_update */

/* return values:
 * negative - error
 * 0 - not found
 * 1 - regular file
 * 2 - directory */
/* must be run when ls_mutex is locked */
int sxfs_ls_stat (const char *path, struct stat *st) {
    int ret;
    ssize_t index;
    char *file_name;
    sxfs_lsdir_t *dir;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(!strcmp(path, "/")) {
        if(st) {
            pthread_mutex_lock(&sxfs->ls_mutex);
            memcpy(st, &sxfs->root->st, sizeof(struct stat));
            pthread_mutex_unlock(&sxfs->ls_mutex);
        }
        return 2;
    }
    pthread_mutex_lock(&sxfs->ls_mutex);
    pthread_mutex_lock(&sxfs->delete_mutex);
    if((ret = sxfs_ls_update(path, &dir))) {
        SXFS_ERROR("Cannot load file tree: %s", path);
        pthread_mutex_unlock(&sxfs->ls_mutex);
        pthread_mutex_unlock(&sxfs->delete_mutex);
        return ret;
    }
    pthread_mutex_unlock(&sxfs->delete_mutex);
    file_name = strrchr(path, '/') + 1; /* already checked in sxfs_ls_update() */
    index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp);
    if(index >= 0) {
        if(st)
            memcpy(st, &dir->dirs[index]->st, sizeof(struct stat));
        ret = 2;
    } else {
        index = sxfs_find_entry((const void**)dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
        if(index >= 0) {
            if(st)
                memcpy(st, &dir->files[index]->st, sizeof(struct stat));
            ret = 1;
        } else
            ret = -ENOENT;
    }
    pthread_mutex_unlock(&sxfs->ls_mutex);
    return ret;
} /* sxfs_ls_stat */

int sxfs_update_mtime (const char *local_file_path, const char *remote_file_path, sxfs_lsfile_t *lsfile) {
    int ret, tmp;
    time_t tmptime;
    struct stat st;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_cluster_lf_t *flist = NULL;
    sxc_file_t *file_local, *file_remote = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
        SXFS_ERROR("Cannot get SX data");
        return ret;
    }
    if(sxfs->attribs && lsfile) {
        if(stat(local_file_path, &st)) {
            ret = -errno;
            SXFS_ERROR("Cannot stat '%s' file: %s", local_file_path, strerror(errno));
            return ret;
        }
        if(sxfs_set_attr(local_file_path, &lsfile->st)) {
            ret = -errno;
            SXFS_ERROR("Cannot set file attributes: %s", strerror(errno));
            return ret;
        }
    }
    file_local = sxc_file_local(sx, local_file_path);
    if(!file_local) {
        SXFS_ERROR("Cannot create local file object: %s", sxc_geterrmsg(sx));
        ret = -sxfs_sx_err(sx);
        goto sxfs_update_mtime_err;
    }
    file_remote = sxc_file_remote(cluster, sxfs->uri->volume, remote_file_path+1, NULL);
    if(!file_remote) {
        SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
        ret = -sxfs_sx_err(sx);
        goto sxfs_update_mtime_err;
    }
    if(sxc_copy_single(file_local, file_remote, 0, 0, 0, NULL, 0)) {
        SXFS_ERROR("Cannot upload '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        ret = -sxfs_sx_err(sx);
        goto sxfs_update_mtime_err;
    }
    if(lsfile)
        lsfile->remote = 1;
    flist = sxc_cluster_listfiles(cluster, sxfs->uri->volume, remote_file_path, 0, NULL, 0);
    if(!flist) {
        SXFS_ERROR("%s", sxc_geterrmsg(sx));
        ret = -sxfs_sx_err(sx);
        goto sxfs_update_mtime_err;
    }
    sxc_file_free(file_remote);
    file_remote = NULL;
    tmp = sxc_cluster_listfiles_next(cluster, sxfs->uri->volume, flist, &file_remote);
    if(tmp) {
        const char *fpath;

        if(tmp < 0) {
            SXFS_ERROR("Cannot retrieve file name: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_update_mtime_err;
        }
        fpath = sxc_file_get_path(file_remote);
        tmptime = sxc_file_get_created_at(file_remote);
        if(fpath[strlen(fpath)-1] == '/') {
            SXFS_ERROR("Not a file");
            ret = -EISDIR;
            goto sxfs_update_mtime_err;
        }
    } else {
        SXFS_ERROR("No such file");
        ret = -ENOENT;
        goto sxfs_update_mtime_err;
    }
    if(lsfile && tmptime > lsfile->remote_mtime) {
        lsfile->remote_mtime = tmptime;
        lsfile->st.st_size = sxc_file_get_size(file_remote);
        lsfile->st.st_uid = sxc_file_get_uid(file_remote) == (uid_t)SXC_UINT32_UNDEFINED ? getuid() : sxc_file_get_uid(file_remote);
        lsfile->st.st_gid = sxc_file_get_gid(file_remote) == (gid_t)SXC_UINT32_UNDEFINED ? getgid() : sxc_file_get_gid(file_remote);
        lsfile->st.st_mtime = sxc_file_get_mtime(file_remote) == (time_t)SXC_UINT64_UNDEFINED ? tmptime : sxc_file_get_mtime(file_remote);
        lsfile->st.st_ctime = MAX(lsfile->st.st_ctime, lsfile->st.st_mtime); /* since ctime is not handled by SX there can already be newer ctime in sxfs) */
    }

    ret = 0;
sxfs_update_mtime_err:
    if(sxfs->attribs && lsfile) {
        struct stat st2;
        if(stat(local_file_path, &st2)) {
            SXFS_ERROR("Cannot stat '%s' file: %s", local_file_path, strerror(errno));
        } else { /* sxfs can have no permission to change uid/gid - be up to date with remote data */
            lsfile->st.st_uid = st2.st_uid;
            lsfile->st.st_gid = st2.st_gid;
        }
        sxfs_set_attr(local_file_path, &st);
    }
    sxc_file_free(file_local);
    sxc_file_free(file_remote);
    sxc_cluster_listfiles_free(flist);
    return ret;
} /* sxfs_update_mtime */

static void sxfs_tick_dirs_reload (sxfs_lsdir_t *dir) {
    size_t i;
    dir->init = 0;
    for(i=0; i<dir->ndirs; i++)
        sxfs_tick_dirs_reload(dir->dirs[i]);
} /* sxfs_tick_dirs_reload */

/* must be run when delete_mutex is locked */
static int sxfs_delete_check (sxc_client_t *sx, sxc_cluster_t *cluster, sxfs_state_t *sxfs) {
    int ret, tmp;
    size_t i, j;
    sxc_cluster_lf_t *flist;

    SXFS_DEBUG("Checking deletion list");
    for(i=0; i<nfiles_del; i++) {
        sxc_file_t *file = NULL;
        flist = sxc_cluster_listfiles(cluster, sxfs->uri->volume, delete_list[i], 0, NULL, 0);
        if(!flist) {
            SXFS_ERROR("Cannot check '%s' file existence on the server: %s", delete_list[i], sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_check_err;
        }
        tmp = sxc_cluster_listfiles_next(cluster, sxfs->uri->volume, flist, &file);
        sxc_cluster_listfiles_free(flist);
        if(tmp) {
            const char *fpath;

            if(tmp < 0) {
                SXFS_ERROR("Failed to retrieve file name");
                ret = -sxfs_sx_err(sx);
                sxc_file_free(file);
                goto sxfs_delete_check_err;
            }

            fpath = sxc_file_get_path(file);
            if(fpath[strlen(fpath)-1] == '/') {
                free(delete_list[i]);
                delete_list[i] = NULL;
            }
        } else {
            free(delete_list[i]);
            delete_list[i] = NULL;
        }
        sxc_file_free(file);
    }

    ret = 0;
sxfs_delete_check_err:
    i = j = 0;
    while(i < nfiles_del) {
        while(i < nfiles_del && !delete_list[i])
            i++;
        if(i < nfiles_del)
            delete_list[j++] = delete_list[i++];
    }
    nfiles_del = j;
    for(i=nfiles_del; i<maxfiles_del; i++)
        delete_list[i] = NULL;
    SXFS_DEBUG("Current deletion queue:");
    for(i=0; i<nfiles_del; i++)
        SXFS_DEBUG("'%s'", delete_list[i]);
    return ret;
} /* sxfs_delete_check */

static int sxfs_delete_dir_rec (sxfs_state_t *sxfs, char *path, int upload_checked) {
    int ret;
    size_t i, endlen = strlen(path);
    sxfs_lsdir_t *dir;
    
    if((ret = sxfs_ls_ftw(sxfs, path, &dir))) {
        SXFS_ERROR("Cannot load file tree: %s", path);
        return ret;
    }
    if(dir->sxnewdir == 2) {
        strcat(path, SXFS_SXNEWDIR);
        if((ret = sxfs_delete(path, 1, upload_checked))) {
            SXFS_ERROR("Cannot delete '%s' file", path);
            return ret;
        }
        *(path + endlen) = '\0';
    }
    for(i=0; i<dir->nfiles; i++) {
        strcat(path, dir->files[i]->name);
        if((ret = sxfs_delete(path, dir->files[i]->remote, upload_checked))) {
            SXFS_ERROR("Cannot delete '%s' file", path);
            return ret;
        }
        *(path + endlen) = '\0';
    }
    for(i=0; i<dir->ndirs; i++) {
        sprintf(path+endlen, "%s/", dir->dirs[i]->name);
        if((ret = sxfs_delete_dir_rec(sxfs, path, upload_checked)))
            return ret;
        *(path + endlen) = '\0';
    }
    return 0;
} /* sxfs_delete_dir_rec */

static int sxfs_queue_rename (char **queue, size_t size, const char *path, const char *newpath, int avoid_resize) {
    char buff[PATH_MAX];
    size_t i, from = 0, to, len = strlen(path);
    while(from < size && strcmp(path, queue[from]) > 0)
        from++;
    if(from == size)
        return 0;
    if(path[len-1] == '/' ? strncmp(path, queue[from], len) : strcmp(path, queue[from]))
        return 0;
    to = from + 1;
    if(path[len-1] == '/')
        while(to < size && !strncmp(path, queue[to], len))
            to++;
    if(!avoid_resize && len < strlen(newpath)) {
        size_t sizediff = strlen(newpath) - len;
        char *ptr;
        for(i=from; i<to; i++) {
            ptr = (char*)realloc(queue[i], strlen(queue[i]) + sizediff + 1);
            if(!ptr)
                return -ENOMEM;
            queue[i] = ptr;
        }
    }
    for(i=from; i<to; i++) {
        snprintf(buff, sizeof(buff), "%s", queue[i] + len);
        sprintf(queue[i], "%s%s", newpath, buff);
    }
    qsort(queue, size, sizeof(char*), sxfs_str_compare);
    return 1;
} /* sxfs_queue_rename */

int sxfs_delete_rename (const char *path, const char *newpath, int avoid_resize) {
    return sxfs_queue_rename(delete_list, nfiles_del, path, newpath, avoid_resize);
} /* sxfs_delete_rename */

static const char special_chars[] = {'\\', '*', '?', '[', '\0'};

static char* parse_path (const char *path) {
    size_t i = 0, j, pos = 0, n = 0, len = strlen(path);
    char *new_path = NULL;

    for(; i<len; i++)
        for(j=0; special_chars[j]; j++)
            if(path[i] == special_chars[j])
                n++;
    new_path = (char*)malloc(len + n + 1);
    if(!new_path) {
        errno = ENOMEM;
        return NULL;
    }
    for(i=0; i<len; i++) {
        for(j=0; special_chars[j]; j++)
            if(path[i] == special_chars[j])
                new_path[pos++] = '\\';
        new_path[pos++] = path[i];
    }
    new_path[pos] = '\0';

    return new_path;
} /* parse_path */

/* must be run when delete_mutex is locked */
int sxfs_delete (const char *path, int is_remote, int upload_checked) {
    int ret;
    ssize_t index;
    size_t i;
    char *local_file_path = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *file;
    sxc_file_list_t *flist = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(sxfs->args->use_queues_flag) {
        if(path[strlen(path)-1] == '/') {
            char workpath[SXLIMIT_MAX_FILENAME_LEN + 1];
            sprintf(workpath, "%s", path);
            if((ret = sxfs_delete_dir_rec(sxfs, workpath, upload_checked))) {
                SXFS_ERROR("Cannot delete '%s' directory", workpath);
                return ret;
            }
            return 0;
        } else {
            if(delete_flag != SXFS_THREAD_WORKING && (ret = sxfs_delete_start())) { /* check whether deletion thread still works */
                SXFS_ERROR("Cannot restart deletion thread");
                return ret;
            }
            if(sxfs_find_entry((const void**)delete_list, nfiles_del, path, sxfs_str_cmp) >= 0) {
                SXFS_ERROR("File already queued: %s", path);
                return -EINVAL;
            }
            if(!upload_checked) {
                pthread_mutex_lock(&sxfs->upload_mutex);
                /* check whether this file is queued for upload */
                index = sxfs_find_entry((const void**)upload_list, nfiles_up, path, sxfs_str_cmp);
                if(index >= 0) {
                    free(upload_list[index]);
                    for(i=index+1; i<nfiles_up; i++)
                        upload_list[i-1] = upload_list[i];
                    upload_list[nfiles_up-1] = NULL;
                    nfiles_up--;
                    local_file_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + strlen(path) + 1);
                    if(!local_file_path) {
                        SXFS_ERROR("Out of memory");
                        return -ENOMEM;
                    }
                    sprintf(local_file_path, "%s/%s%s", sxfs->tempdir, SXFS_UPLOAD_DIR, path);
                    if(unlink(local_file_path)) {
                        ret = -errno;
                        SXFS_ERROR("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
                        goto sxfs_delete_err;
                    }
                    if((ret = sxfs_clear_path(local_file_path)))
                        goto sxfs_delete_err;
                    SXFS_DEBUG("File removed from upload queue: %s", path);
                }
            }
            if(is_remote) {
                char *path_to_list;
                if(nfiles_del == maxfiles_del && sxfs_resize((void**)&delete_list, &maxfiles_del, sizeof(char*))) {
                    SXFS_ERROR("OOM growing deletion list: %s", strerror(errno));
                    ret = -ENOMEM;
                    goto sxfs_delete_err;
                }
                path_to_list = strdup(path);
                if(!path_to_list) {
                    SXFS_ERROR("Out of memory: %s", path);
                    ret = -ENOMEM;
                    goto sxfs_delete_err;
                }
                for(i=nfiles_del; i>0 && strcmp(delete_list[i-1], path_to_list) > 0; i--)
                    delete_list[i] = delete_list[i-1];
                delete_list[i] = path_to_list;
                nfiles_del++;
                SXFS_DEBUG("File added: %s", path);
            }
        }
        if(gettimeofday(&last_deletion_time, NULL)) {
            SXFS_ERROR("Cannot get current time: %s", strerror(errno)); /* file succeffuly added into the list, in worst case deletion thread will pause next deletions */
        }
    } else {
        char *tmp_path = parse_path(path);

        if(!tmp_path) {
            ret = -errno;
            SXFS_ERROR("Out of memory");
            return ret;
        }
        if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
            SXFS_ERROR("Cannot get SX data");
            pthread_mutex_unlock(&sxfs->delete_mutex);
            free(tmp_path);
            return ret;
        }
        flist = sxc_file_list_new(sx, 1, 1);
        if(!flist) {
            SXFS_ERROR("Cannot create new file list: %s", sxc_geterrmsg(sx));
            free(tmp_path);
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        file = sxc_file_remote(cluster, sxfs->uri->volume, tmp_path+1, NULL);
        if(!file) {
            SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
            free(tmp_path);
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        if(sxc_file_list_add(flist, file, 1)) {
            SXFS_ERROR("Cannot add file: %s", sxc_geterrmsg(sx));
            free(tmp_path);
            sxc_file_free(file);
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        if(sxc_rm(flist, 0)) {
            SXFS_ERROR("Cannot remove file: %s", sxc_geterrmsg(sx));
            free(tmp_path);
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        free(tmp_path);
    }

    ret = 0;
sxfs_delete_err:
    if(sxfs->args->use_queues_flag && !upload_checked)
        pthread_mutex_unlock(&sxfs->upload_mutex);
    free(local_file_path);
    sxc_file_list_free(flist);
    return ret;
} /* sxfs_delete */

/* must be run when delete_mutex is locked */
static int sxfs_delete_run (sxfs_state_t *sxfs, sxc_client_t *sx, sxc_cluster_t *cluster, int ignore_error) {
    int ret;
    size_t i;
    char *path;
    sxc_file_t *file;
    sxc_file_list_t *flist = NULL;

    SXFS_DEBUG("Deleting files:");
    for(i=0; i<nfiles_del; i++)
        SXFS_DEBUG("'%s'", delete_list[i]);
    flist = sxc_file_list_new(sx, 0, ignore_error);
    if(!flist) {
        SXFS_ERROR("Cannot create new file list: %s", sxc_geterrmsg(sx));
        ret = -sxfs_sx_err(sx);
        goto sxfs_delete_run_err;
    }
    for(i=0; i<nfiles_del; i++) {
        path = parse_path(delete_list[i]);
        if(!path) {
            ret = -errno;
            SXFS_ERROR("Out of memory");
            free(path);
            goto sxfs_delete_run_err;
        }
        file = sxc_file_remote(cluster, sxfs->uri->volume, path+1, NULL);
        if(!file) {
            SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
            free(path);
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_run_err;
        }
        if(sxc_file_list_add(flist, file, 1)) {
            SXFS_ERROR("Cannot add file: %s", sxc_geterrmsg(sx));
            free(path);
            sxc_file_free(file);
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_run_err;
        }
        free(path);
    }
    if(sxc_rm(flist, 0) && sxc_geterrnum(sx) != SXE_EARG) {
        SXFS_ERROR("Cannot remove file list: %s", sxc_geterrmsg(sx));
        sxfs_tick_dirs_reload(sxfs->root);
        sxfs_delete_check(sx, cluster, sxfs);
        if(!ignore_error) {
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_run_err;
        }
    } else {
        for(i=0; i<nfiles_del; i++) {
            free(delete_list[i]);
            delete_list[i] = NULL;
        }
        nfiles_del = 0;
    }
    SXFS_DEBUG("Files removed correctly");

    ret = 0;
sxfs_delete_run_err:
    sxc_file_list_free(flist);
    return ret;
} /* sxfs_delete_run */

/* delete_mutex must be locked when starting this function */
static void* sxfs_delete_thread (void *ptr) {
    int *ret = (int*)calloc(1, sizeof(int)), err, mutex_locked = 0;
    size_t i;
    struct timeval tv;
    struct timespec wait_time;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxfs_state_t *sxfs = (sxfs_state_t*)ptr;

    memset(&wait_time, 0, sizeof(struct timespec));
    if(!ret) {
        SXFS_ERROR("Out of memory");
        goto sxfs_delete_thread_err;
    }
    if((*ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
        SXFS_ERROR("Cannot get SX data");
        goto sxfs_delete_thread_err;
    }
    delete_list = (char**)calloc(SXFS_ALLOC_ENTRIES, sizeof(char*));
    if(!delete_list) {
        SXFS_ERROR("Out of memory");
        *ret = ENOMEM;
        goto sxfs_delete_thread_err;
    }
    nfiles_del = 0;
    maxfiles_del = SXFS_ALLOC_ENTRIES;
    pthread_mutex_lock(&sxfs->delete_thread_mutex);
    mutex_locked = 1;
    pthread_mutex_lock(&sxfs->delete_mutex);
    delete_flag = SXFS_THREAD_WORKING;
    pthread_mutex_unlock(&sxfs->delete_mutex);
    SXFS_LOG("Deletion thread has been started");

    while(1) {
        if((wait_time.tv_sec = time(NULL)) < 0) {
            *ret = errno;
            SXFS_ERROR("Cannot get current time: %s", strerror(errno));
            goto sxfs_delete_thread_err;
        }
        wait_time.tv_sec += SXFS_THREAD_SLEEP / 1000000L;
        if((err = pthread_cond_timedwait(&sxfs->delete_cond, &sxfs->delete_thread_mutex, &wait_time))) {
            if(err == ETIMEDOUT) {
                pthread_mutex_lock(&sxfs->delete_mutex);
                if(nfiles_del) {
                    if(gettimeofday(&tv, NULL)) {
                        *ret = errno;
                        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
                        pthread_mutex_unlock(&sxfs->delete_mutex);
                        goto sxfs_delete_thread_err;
                    }
                    if(sxi_timediff(&tv, &last_deletion_time) >= SXFS_LAST_ACTION_WAIT) {
                        if((*ret = sxfs_delete_run(sxfs, sx, cluster, 1))) {
                            SXFS_ERROR("Deletion failed");
                            pthread_mutex_unlock(&sxfs->delete_mutex);
                            goto sxfs_delete_thread_err;
                        }
                    }
                }
                pthread_mutex_unlock(&sxfs->delete_mutex);
            } else {
                *ret = err;
                SXFS_ERROR("Pthread condition waiting failed: %s", strerror(err));
                goto sxfs_delete_thread_err;
            }
        } else {
            SXFS_LOG("Deletion thread has been stopped");
            break;
        }
    }

    *ret = 0;
sxfs_delete_thread_err:
    if(mutex_locked)
        pthread_mutex_unlock(&sxfs->delete_thread_mutex);
    pthread_mutex_lock(&sxfs->delete_mutex);
    if(delete_list) {
        for(i=0; i<nfiles_del; i++)
            free(delete_list[i]);
        free(delete_list);
    }
    nfiles_del = maxfiles_del = 0;
    delete_flag = SXFS_THREAD_STOPPED;
    pthread_mutex_unlock(&sxfs->delete_mutex);
    return (void*)ret;
} /* sxfs_delete_thread */

int sxfs_delete_check_path (sxfs_state_t *sxfs, const char *path) {
    int run = 0;
    size_t len = strlen(path);
    if(path[len-1] != '/') {
        if(sxfs_find_entry((const void**)delete_list, nfiles_del, path, sxfs_str_cmp) >= 0)
            run = 1;
    } else {
        size_t i = 0;
        while(i < nfiles_del && strcmp(path, delete_list[i]) > 0)
            i++;
        if(i < nfiles_del && !strncmp(path, delete_list[i], len))
            run = 1;
    }
    if(run) {
        int ret;
        sxc_client_t *sx;
        sxc_cluster_t *cluster;

        if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
            SXFS_ERROR("Cannot get SX data");
            return ret;
        }
        if((ret = sxfs_delete_run(sxfs, sx, cluster, 0))) {
            SXFS_ERROR("Cannot force files deletion");
            return ret;
        }
    }
    return 0;
} /* sxfs_delete_check_path */

/* must be run when delete_mutex is locked */
int sxfs_delete_start (void) {
    int tmp;
    sxfs_state_t *sxfs = SXFS_DATA;

    delete_flag = SXFS_THREAD_NOT_WORKING;
    if((tmp = sxfs_thread_create(sxfs, &sxfs->delete_thread, sxfs_delete_thread, (void*)sxfs))) {
        SXFS_ERROR("Cannot create deletion thread");
        return -tmp;
    }
    while(delete_flag == SXFS_THREAD_NOT_WORKING) {
        pthread_mutex_unlock(&sxfs->delete_mutex);
        usleep(SXFS_THREAD_WAIT);
        pthread_mutex_lock(&sxfs->delete_mutex);
    }
    if(delete_flag == SXFS_THREAD_STOPPED) { /* thread function executed and failed */
        int ret, *status = NULL;
        if((tmp = pthread_join(sxfs->delete_thread, (void**)&status))) {
            SXFS_ERROR("Cannot join deletion thread: %s", strerror(tmp));
            ret = -tmp;
        } else {
            ret = status ? -(*status) : -ENOMEM;
            SXFS_ERROR("Cannot start deletion thread: %s", strerror(status ? *status : ENOMEM));
            free(status);
        }
        return ret;
    }
    return 0;
} /* sxfs_delete_start */

void sxfs_delete_stop (void) {
    int err, *status = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    pthread_mutex_lock(&sxfs->delete_mutex);
    if(delete_flag == SXFS_THREAD_WORKING) {
        pthread_mutex_unlock(&sxfs->delete_mutex);
        pthread_mutex_lock(&sxfs->delete_thread_mutex);
        pthread_cond_signal(&sxfs->delete_cond);
        pthread_mutex_unlock(&sxfs->delete_thread_mutex);
        if((err = pthread_join(sxfs->delete_thread, (void**)&status)))
            SXFS_ERROR("Cannot join deletion thread: %s", strerror(err));
        else
            free(status);
    } else
        pthread_mutex_unlock(&sxfs->delete_mutex);
} /* sxfs_delete_stop */

/* must be run when upload_mutex is locked */
int sxfs_upload_del_path (sxfs_state_t *sxfs, const char *path) {
    size_t i, j, len = strlen(path);

    if(path[len-1] != '/') {
        ssize_t index = sxfs_find_entry((const void**)upload_list, nfiles_up, path, sxfs_str_cmp);
        if(index >= 0) {
            free(upload_list[index]);
            for(i=index+1; i<nfiles_up; i++)
                upload_list[i-1] = upload_list[i];
            upload_list[nfiles_up-1] = NULL;
            nfiles_up--;
            SXFS_DEBUG("File removed: %s", path);
        } else {
            SXFS_ERROR("File not queued: %s", path);
            return -ENOENT;
        }
    } else {
        i = 0;
        while(i<nfiles_up && strcmp(path, upload_list[i]) > 0)
            i++;
        if(strncmp(path, upload_list[i], len)) {
            SXFS_ERROR("Directory not queued: %s", path);
            return -ENOENT;
        }
        for(j=i; j<nfiles_up && !strncmp(path, upload_list[j], len); j++) {
            free(upload_list[j]);
            upload_list[j] = NULL;
        }
        while(j < nfiles_up) {
            upload_list[i] = upload_list[j];
            upload_list[j] = NULL;
            i++;
            j++;
        }
        nfiles_up = i;
        SXFS_DEBUG("Directory removed: %s", path);
    }
    return 0;
} /* sxfs_upload_del_path */

int sxfs_upload_rename (const char *path, const char *newpath, int avoid_resize) {
    return sxfs_queue_rename(upload_list, nfiles_up, path, newpath, avoid_resize);
} /* sxfs_upload_rename */

/* src - local path
 * dest - remote path */
/* must be run when delete_mutex is locked */
int sxfs_upload (const char *src, const char *dest, sxfs_lsfile_t *lsfile, int force) {
    int ret;
    size_t i;
    ssize_t index;
    char *ptr, *path = NULL, *path_to_list = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxfs_state_t *sxfs = SXFS_DATA;

    if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
        SXFS_ERROR("Cannot get SX data");
        return ret;
    }
    if(sxfs->args->use_queues_flag) {
        if(upload_flag != SXFS_THREAD_WORKING && (ret = sxfs_upload_start())) { /* check whether upload thread still works */
            SXFS_ERROR("Cannot restart upload thread");
            return ret;
        }
        path_to_list = strdup(dest);
        if(!path_to_list) {
            SXFS_ERROR("Out of memory: %s", dest);
            return -ENOMEM;
        }
        path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR)  + strlen(dest) + 1);
        if(!path) {
            SXFS_ERROR("Out of memory");
            free(path_to_list);
            return -ENOMEM;
        }
        sprintf(path, "%s", dest);
        ptr = strrchr(path, '/');
        if(!ptr) {
            SXFS_ERROR("'/' not found in '%s'", path);
            free(path);
            free(path_to_list);
            return -EINVAL;
        }
        ptr++;
        if(!strcmp(ptr, SXFS_SXNEWDIR))
            *ptr = '\0';
        if((ret = sxfs_delete_check_path(sxfs, path))) {
            SXFS_ERROR("Cannot check deletion queue: %s", path);
            free(path);
            free(path_to_list);
            return ret;
        }
        pthread_mutex_lock(&sxfs->upload_mutex);
        if((index = sxfs_find_entry((const void**)upload_list, nfiles_up, dest, sxfs_str_cmp)) >= 0 && !force) {
            SXFS_ERROR("File already queued: %s", dest);
            ret = -EINVAL;
            goto sxfs_upload_err;
        }
        if(nfiles_up == maxfiles_up && sxfs_resize((void**)&upload_list, &maxfiles_up, sizeof(char*))) {
            SXFS_ERROR("OOM growing upload list: %s", strerror(errno));
            ret = -ENOMEM;
            goto sxfs_upload_err;
        }
        sprintf(path, "%s/%s%s", sxfs->tempdir, SXFS_UPLOAD_DIR, dest);
        if((ret = sxfs_build_path(path))) {
            SXFS_ERROR("Cannot create path: %s", path);
            goto sxfs_upload_err;
        }
        if(!src) { /* uploading empty file */
            int fd = open(path, O_WRONLY | O_CREAT, 0600);
            if(fd < 0) {
                ret = -errno;
                SXFS_ERROR("Cannot create '%s' file: %s", path, strerror(errno));
                goto sxfs_upload_err;
            }
            if(close(fd)) {
                ret = -errno;
                SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
                goto sxfs_upload_err;
            }
        } else if(rename(src, path)) {
            ret = -errno;
            SXFS_ERROR("Cannot rename '%s' to '%s': %s", src, path, strerror(errno));
            goto sxfs_upload_err;
        }
        if(index < 0) {
            for(i=nfiles_up; i>0 && strcmp(upload_list[i-1], path_to_list) > 0; i--)
                upload_list[i] = upload_list[i-1];
            upload_list[i] = path_to_list;
            path_to_list = NULL;
            nfiles_up++;
        }
        if(gettimeofday(&last_upload_time, NULL)) {
            SXFS_ERROR("Cannot get current time: %s", strerror(errno)); /* file succeffuly added into upload cache directory, in worst case upload thread will pause next uploads */
        }
        SXFS_DEBUG("File added: %s", dest);
    } else {
        if((ret = sxfs_update_mtime(src ? src : sxfs->empty_file_path, dest, lsfile))) {
            SXFS_ERROR("Cannot update modification time");
            goto sxfs_upload_err;
        }
        if(src && unlink(src)) {
            ret = -errno;
            SXFS_ERROR("Cannot remove '%s' file: %s", src, strerror(errno));
            goto sxfs_upload_err;
        }
    }

    ret = 0;
sxfs_upload_err:
    if(sxfs->args->use_queues_flag)
        pthread_mutex_unlock(&sxfs->upload_mutex);
    free(path);
    free(path_to_list);
    return ret;
} /* sxfs_upload */

static int sxfs_upload_status (const sxc_xfer_stat_t *xfer_stat) {
    static size_t counter = 1;
    sxfs_state_t *sxfs;

    if(!xfer_stat)
        return SXE_NOERROR;
    sxfs = xfer_stat->ctx;
    if(xfer_stat->status == SXC_XFER_STATUS_WAITING && xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_UPLOAD) {
        char *file_name = strdup(xfer_stat->current_xfer.file_name);

        if(file_name)
            sxc_escstr(file_name);
        SXFS_LOG("'%s' ready to flush (%llu/%llu)", file_name, (unsigned long long int)counter++, (unsigned long long int)nfiles_up);
        free(file_name);
    }
    if(xfer_stat->status == SXC_XFER_STATUS_FINISHED) {
        counter = 1;
        SXFS_LOG("Files upload finished");
    }
    return SXE_NOERROR;
} /* sxfs_upload_status */

/* must be run when delete_mutex and upload_mutex are locked */
static int sxfs_upload_run (sxfs_state_t *sxfs, sxc_client_t *sx, sxc_cluster_t *cluster, int ignore_error) {
    int ret;
    size_t i;
    ssize_t index;
    char storage_path[PATH_MAX], *ptr;
    sxc_file_t *src = NULL, *dest = NULL;
    sxfs_lsdir_t *dir;

    SXFS_DEBUG("Uploading files:");
    for(i=0; i<nfiles_up; i++)
        SXFS_DEBUG("'%s'", upload_list[i]);
    if(sxfs->attribs)
        for(i=0; i<nfiles_up; i++) {
            ptr = strrchr(upload_list[i], '/');
            if(ptr) {
                ptr++;
                if(!strcmp(ptr, SXFS_SXNEWDIR))
                    continue; /* skip '.sxnewdir' files */
            }
            if((ret = sxfs_ls_ftw(sxfs, upload_list[i], &dir))) {
                SXFS_ERROR("File tree walk failed: %s", upload_list[i]);
                return ret;
            }
            index = sxfs_find_entry((const void **)dir->files, dir->nfiles, strrchr(upload_list[i], '/')+1, sxfs_lsfile_cmp);
            if(index < 0) {
                SXFS_ERROR("'%s' file is missing in ls cache", upload_list[i]);
                return -EAGAIN;
            }
            snprintf(storage_path, PATH_MAX, "%s/%s%s", sxfs->tempdir, SXFS_UPLOAD_DIR, upload_list[i]);
            if(sxfs_set_attr(storage_path, &dir->files[index]->st)) {
                ret = -errno;
                SXFS_ERROR("Cannot set file attributes: %s", strerror(errno));
                return ret;
            }
        }
    sprintf(storage_path, "%s/%s/", sxfs->tempdir, SXFS_UPLOAD_DIR);
    src = sxc_file_local(sx, storage_path);
    if(!src) {
        SXFS_ERROR("Cannot create local file object: %s", sxc_geterrmsg(sx));
        ret = -sxfs_sx_err(sx);
        goto sxfs_upload_run_err;
    }
    dest = sxc_file_remote(cluster, sxfs->uri->volume, "/", NULL);
    if(!dest) {
        SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
        ret = -sxfs_sx_err(sx);
        goto sxfs_upload_run_err;
    }
    if(sxc_copy_single(src, dest, 1, 0, 0, NULL, 0)) {
        SXFS_ERROR("Cannot upload '%s' file: %s", storage_path, sxc_geterrmsg(sx));
        sxfs_tick_dirs_reload(sxfs->root);
        if(!ignore_error) {
            ret = -sxfs_sx_err(sx);
            goto sxfs_upload_run_err;
        }
    } else { /* mark uploaded files as remote */
        struct stat st;

        for(i=0; i<nfiles_up; i++) {
            ptr = strrchr(upload_list[i], '/');
            if(ptr) {
                ptr++;
                if(!sxfs_ls_ftw(sxfs, upload_list[i], &dir)) {
                    if(!strcmp(ptr, SXFS_SXNEWDIR)) {
                        dir->remote = 1;
                        dir->sxnewdir = 2;
                    } else {
                        index = sxfs_find_entry((const void**)dir->files, dir->nfiles, ptr, sxfs_lsfile_cmp);
                        if(index < 0) {
                            SXFS_ERROR("File not found: %s", upload_list[i]);
                        } else {
                            dir->files[index]->remote = 1;
                            if(sxfs->attribs) {
                                snprintf(storage_path, PATH_MAX, "%s/%s%s", sxfs->tempdir, SXFS_UPLOAD_DIR, upload_list[i]);
                                if(stat(storage_path, &st)) {
                                    SXFS_ERROR("Cannot stat '%s' file: %s", storage_path, strerror(errno));
                                } else { /* sxfs can have no permission to change uid/gid - be up to date with remote data */
                                    dir->files[index]->st.st_uid = st.st_uid;
                                    dir->files[index]->st.st_gid = st.st_gid;
                                }
                            }
                        }
                    }
                } else
                    SXFS_ERROR("File tree walk failed: %s", upload_list[i]);
            } else
                SXFS_ERROR("'/' not found in '%s'", upload_list[i]);
        }
        sprintf(storage_path, "%s/%s/", sxfs->tempdir, SXFS_UPLOAD_DIR);
        /* refresh upload queue directory */
        if(sxi_rmdirs(storage_path)) {
            ret = -errno;
            SXFS_ERROR("Cannot remove local storage directory: %s", strerror(errno));
            goto sxfs_upload_run_err;
        }
        if(mkdir(storage_path, 0700)) {
            ret = -errno;
            SXFS_ERROR("Cannot recreate local storage directory: %s", strerror(errno));
            goto sxfs_upload_run_err;
        }
        /* clean up upload list */
        for(i=0; i<nfiles_up; i++) {
            free(upload_list[i]);
            upload_list[i] = NULL;
        }
        nfiles_up = 0;
    }

    ret = 0;
sxfs_upload_run_err:
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* sxfs_upload_run */

static int move_files (sxfs_state_t *sxfs, const char *source, const char *dest) {
    if(rename(source, dest)) {
        if(errno == EXDEV) {
            size_t i = 0, len = 0;
            char *src_path, *dst_path;

            SXFS_DEBUG("Moving files between different filesystems");
            for(; i<nfiles_up; i++)
                if(strlen(upload_list[i]) > len)
                    len = strlen(upload_list[i]);
            src_path = (char*)malloc(strlen(source) + len + 1);
            if(!src_path) {
                SXFS_ERROR("Out of memory");
                return -ENOMEM;
            }
            dst_path = (char*)malloc(strlen(dest) + len + 1);
            if(!dst_path) {
                SXFS_ERROR("Out of memory");
                free(src_path);
                return -ENOMEM;
            }
            for(i=0; i<nfiles_up; i++) {
                int ret;
                sprintf(src_path, "%s%s", source, upload_list[i]);
                sprintf(dst_path, "%s%s", dest, upload_list[i]);
                if((ret = sxfs_copy_file(sxfs, src_path, dst_path))) {
                    free(src_path);
                    free(dst_path);
                    return ret;
                }
            }
            free(src_path);
            free(dst_path);
            return 0;
        }
        return -errno;
    }
    return 0;
} /* move_files */

static void* sxfs_upload_thread (void *ptr) {
    int *ret = (int*)calloc(1, sizeof(int)), err, mutex_locked = 0;
    size_t i;
    char *storage_path = NULL;
    struct timeval tv;
    struct timespec wait_time;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxfs_state_t *sxfs = (sxfs_state_t*)ptr;

    memset(&wait_time, 0, sizeof(struct timespec));
    if(!ret) {
        SXFS_ERROR("Out of memory");
        goto sxfs_upload_thread_err;
    }
    storage_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + 1);
    if(!storage_path) {
        SXFS_ERROR("Out of memory");
        *ret = ENOMEM;
        goto sxfs_upload_thread_err;
    }
    sprintf(storage_path, "%s/%s", sxfs->tempdir, SXFS_UPLOAD_DIR);
    if(sxi_rmdirs(storage_path) && errno != ENOENT) {
        *ret = errno;
        SXFS_ERROR("Cannot remove local storage directory: %s", strerror(errno));
        goto sxfs_upload_thread_err;
    }
    if(mkdir(storage_path, 0700)) {
        *ret = errno;
        SXFS_ERROR("Cannot recreate local storage directory: %s", strerror(errno));
        goto sxfs_upload_thread_err;
    }
    if((*ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
        SXFS_ERROR("Cannot get SX data");
        goto sxfs_upload_thread_err;
    }
    if(sxc_cluster_set_progress_cb(sx, cluster, sxfs_upload_status, sxfs)) {
        SXFS_ERROR("Cannot set progress callback: %s", sxc_geterrmsg(sx));
        *ret = sxfs_sx_err(sx);
        goto sxfs_upload_thread_err;
    }
    upload_list = (char**)calloc(SXFS_ALLOC_ENTRIES, sizeof(char*));
    if(!upload_list) {
        SXFS_ERROR("Out of memory");
        *ret = ENOMEM;
        goto sxfs_upload_thread_err;
    }
    nfiles_up = 0;
    maxfiles_up = SXFS_ALLOC_ENTRIES;
    pthread_mutex_lock(&sxfs->upload_thread_mutex);
    mutex_locked = 1;
    pthread_mutex_lock(&sxfs->upload_mutex);
    upload_flag = SXFS_THREAD_WORKING;
    pthread_mutex_unlock(&sxfs->upload_mutex);
    SXFS_LOG("Upload thread has been started");

    while(1) {
        if((wait_time.tv_sec = time(NULL)) < 0) {
            *ret = errno;
            SXFS_ERROR("Cannot get current time: %s", strerror(errno));
            goto sxfs_upload_thread_err;
        }
        wait_time.tv_sec += SXFS_THREAD_SLEEP / 1000000L;
        if((err = pthread_cond_timedwait(&sxfs->upload_cond, &sxfs->upload_thread_mutex, &wait_time))) {
            if(err == ETIMEDOUT) {
                pthread_mutex_lock(&sxfs->delete_mutex);
                pthread_mutex_lock(&sxfs->upload_mutex);
                if(nfiles_up) {
                    if(gettimeofday(&tv, NULL)) {
                        *ret = errno;
                        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
                        pthread_mutex_unlock(&sxfs->delete_mutex);
                        pthread_mutex_unlock(&sxfs->upload_mutex);
                        goto sxfs_upload_thread_err;
                    }
                    if(sxi_timediff(&tv, &last_upload_time) >= SXFS_LAST_ACTION_WAIT) {
                        if((*ret = sxfs_upload_run(sxfs, sx, cluster, 1))) {
                            pthread_mutex_unlock(&sxfs->delete_mutex);
                            pthread_mutex_unlock(&sxfs->upload_mutex);
                            goto sxfs_upload_thread_err;
                        }
                    }
                }
                pthread_mutex_unlock(&sxfs->delete_mutex);
                pthread_mutex_unlock(&sxfs->upload_mutex);
            } else {
                *ret = err;
                SXFS_ERROR("Pthread condition waiting failed: %s", strerror(err));
                goto sxfs_upload_thread_err;
            }
        } else {
            pthread_mutex_lock(&sxfs->upload_mutex);
            if(nfiles_up) { /* save not yet uploaded files */
                SXFS_LOG("Some files from upload queue could not be uploaded and have been saved into '%s'", sxfs->lostdir);
                if(move_files(sxfs, storage_path, sxfs->lostdir)) {
                    SXFS_ERROR("Cannot move some files to the recovery directory. These files are available in '%s'", storage_path);
                    sxfs->recovery_failed = 1;
                }
            }
            pthread_mutex_unlock(&sxfs->upload_mutex);
            SXFS_LOG("Upload thread has been stopped");
            break;
        }

    }

    *ret = 0;
sxfs_upload_thread_err:
    if(mutex_locked)
        pthread_mutex_unlock(&sxfs->upload_thread_mutex);
    pthread_mutex_lock(&sxfs->upload_mutex);
    if(upload_list) {
        for(i=0; i<nfiles_up; i++)
            free(upload_list[i]);
        free(upload_list);
    }
    nfiles_up = maxfiles_up = 0;
    upload_flag = SXFS_THREAD_STOPPED;
    pthread_mutex_unlock(&sxfs->upload_mutex);
    free(storage_path);
    return (void*)ret;
} /* sxfs_upload_thread */

int sxfs_upload_start (void) {
    int tmp;
    sxfs_state_t *sxfs = SXFS_DATA;

    pthread_mutex_lock(&sxfs->upload_mutex);
    upload_flag = SXFS_THREAD_NOT_WORKING;
    if((tmp = sxfs_thread_create(sxfs, &sxfs->upload_thread, sxfs_upload_thread, (void*)sxfs))) {
        SXFS_ERROR("Cannot create upload thread");
        pthread_mutex_unlock(&sxfs->upload_mutex);
        return -tmp;
    }
    while(upload_flag == SXFS_THREAD_NOT_WORKING) {
        pthread_mutex_unlock(&sxfs->upload_mutex);
        usleep(SXFS_THREAD_WAIT);
        pthread_mutex_lock(&sxfs->upload_mutex);
    }
    if(upload_flag == SXFS_THREAD_STOPPED)
        tmp = 1;
    else
        tmp = 0;
    pthread_mutex_unlock(&sxfs->upload_mutex);
    if(tmp) {
        int ret, *status = NULL;
        if((tmp = pthread_join(sxfs->upload_thread, (void**)&status))) {
            SXFS_ERROR("Cannot join upload thread: %s", strerror(tmp));
            ret = -tmp;
        } else {
            SXFS_ERROR("Cannot start upload thread: %s", strerror(status ? *status : ENOMEM));
            ret = status ? -(*status) : -ENOMEM;
            free(status);
        }
        return ret;
    }
    return 0;
} /* sxfs_upload_start */

void sxfs_upload_stop (void) {
    int tmp, *status = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    pthread_mutex_lock(&sxfs->upload_mutex);
    if(upload_flag == SXFS_THREAD_WORKING) {
        pthread_mutex_unlock(&sxfs->upload_mutex);
        pthread_mutex_lock(&sxfs->upload_thread_mutex);
        pthread_cond_signal(&sxfs->upload_cond);
        pthread_mutex_unlock(&sxfs->upload_thread_mutex);
        if((tmp = pthread_join(sxfs->upload_thread, (void**)&status)))
            SXFS_ERROR("Cannot join upload thread: %s", strerror(tmp));
        else
            free(status);
    } else
        pthread_mutex_unlock(&sxfs->upload_mutex);
} /* sxfs_upload_stop */

