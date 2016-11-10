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

#define SXFS_QUEUE_THREADS_LIMIT 5
#define SXFS_DELETE_WORKER_NFILES 10

#define SXFS_QUEUE_IDLE 0x0
#define SXFS_QUEUE_DONE 0x1
#define SXFS_QUEUE_IN_PROGRESS 0x2
#define SXFS_QUEUE_RENAMING 0x4
#define SXFS_QUEUE_BUSY (SXFS_QUEUE_IN_PROGRESS|SXFS_QUEUE_RENAMING)
#define SXFS_QUEUE_REMOTE 0x8 /* to make difference between uploaded file
                                 and file removed from queue  */

#define SXFS_QUEUE_WAIT(entry, mutex)           \
    entry->waiting++;                           \
    while(entry->state & SXFS_QUEUE_BUSY) {     \
        pthread_mutex_unlock(mutex);            \
        usleep(SXFS_THREAD_WAIT);               \
        pthread_mutex_lock(mutex);              \
    }                                           \
    entry->waiting--;

/* stuff for threads */
int delete_flag, upload_flag, delete_stop, upload_stop;
size_t threads_del, threads_up;
sxfs_queue_entry_t delete_queue, upload_queue;

struct _sxfs_queue_entry_t {
    int state;
    unsigned int waiting;
    uint64_t mtime;
    char *local_path, *remote_path;
    sxfs_queue_entry_t *prev, *next;
};

struct _sxfs_queue_data_t {
    sxfs_state_t *sxfs;
    sxfs_queue_entry_t *entry;
};

static void sxfs_queue_free (sxfs_queue_entry_t *entry, int all_queue) {
    if(!entry)
        return;
    free(entry->local_path);
    free(entry->remote_path);
    if(all_queue)
        sxfs_queue_free(entry->next, 1);
    free(entry);
} /* sxfs_queue_free */

/* returns next entry from the list */
static sxfs_queue_entry_t* sxfs_queue_cleanup_single (sxfs_queue_entry_t *entry, int remote_too) {
    sxfs_state_t *sxfs = SXFS_DATA;
    sxfs_queue_entry_t *next = NULL;

    if(entry) {
        next = entry->next;
        if(entry->state & SXFS_QUEUE_DONE && !(entry->state & SXFS_QUEUE_BUSY) && !entry->waiting && (!(entry->state & SXFS_QUEUE_REMOTE) || remote_too)) {
            entry->prev->next = entry->next; /* the very first element is the head of the queue */
            if(entry->next)
                entry->next->prev = entry->prev;
            if(entry->local_path && unlink(entry->local_path))
                SXFS_ERROR("Cannot remove '%s' file: %s", entry->local_path, strerror(errno));
            sxfs_queue_free(entry, 0);
        }
    }
    return next;
} /* sxfs_queue_cleanup_single */

static void sxfs_queue_cleanup (sxfs_queue_entry_t *entry, int remote_too) {
    entry = entry->next;
    while(entry)
        entry = sxfs_queue_cleanup_single(entry, remote_too);
} /* sxfs_queue_cleanup */

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

int sxfs_resize (void *ptr, size_t *size, size_t elsize) {
    void *new_ptr = realloc(*((void**)ptr), (*size + SXFS_ALLOC_ENTRIES) * elsize);
    if(!new_ptr)
        return -1;
    *((void**)ptr) = new_ptr;
    memset((char*)(*((void**)ptr)) + *size * elsize, 0, SXFS_ALLOC_ENTRIES * elsize);
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

static int copy_file (sxfs_state_t *sxfs, const char *source, const char *dest) {
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
        goto copy_file_err;
    }
    while((rd = sxi_read_hard(fd_src, buff, sizeof(buff))) > 0) {
        if(sxi_write_hard(fd_dst, buff, rd) < 0) {
            ret = -errno;
            SXFS_ERROR("Cannot write to '%s' file: %s", dest, strerror(errno));
            goto copy_file_err;
        }
    }
    if(rd < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot read from '%s' file: %s", source, strerror(errno));
        goto copy_file_err;
    }

    ret = 0;
copy_file_err:
    close(fd_src);
    if(fd_dst >= 0)
        close(fd_dst);
    return ret;
} /* copy_file */

int sxfs_move_file (sxfs_state_t *sxfs, const char *source, const char *dest) {
    int ret;

    if((ret = sxfs_build_path(dest))) {
        SXFS_ERROR("Cannot create path: %s", dest);
        return ret;
    }
    if(rename(source, dest)) { /* EXDEV handling; why don't try to copy the file on any error? */
        SXFS_DEBUG("rename failed: %s; falling back to copy + unlink", strerror(errno));
        return copy_file(sxfs, source, dest);
    }
    return 0;
} /* sxfs_move_file */

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
    int ret, fd = -1, got_sem = 0;
    ssize_t retval;
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
    if(sxfs->need_file) {
        sxc_client_t *sx;
        sxc_cluster_t *cluster;
        sxc_file_t *file_local, *file_remote;

        if(sem_wait(&sxfs->download_sem)) {
            ret = -errno;
            SXFS_ERROR("Failed to wait for semaphore: %s", strerror(errno));
            goto sxfs_get_file_err;
        }
        got_sem = 1;
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
        close(fd);
        fd = open(local_file_path, O_RDWR);
        if(fd < 0) {
            ret = -errno;
            SXFS_ERROR("Cannot open '%s' file: %s", local_file_path, strerror(errno));
            goto sxfs_get_file_err;
        }
    } else {
        while((retval = sxfs_cache_read(sxfs, sxfs_file, buff, sizeof(buff), offset)) > 0) {
            if(sxi_write_hard(fd, buff, retval) < 0) {
                ret = -errno;
                SXFS_ERROR("Cannot write to '%s' file: %s", sxfs_file->write_path, strerror(errno));
                goto sxfs_get_file_err;
            }
            offset += retval;
        }
        if(retval < 0) {
            ret = retval;
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
    if(got_sem && sem_post(&sxfs->download_sem))
        SXFS_ERROR("Failed to post the semaphore: %s", strerror(errno));
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
    pthread_mutex_lock(&sxfs->limits_mutex);
    while(sxfs_file->threads_num) {
        pthread_mutex_unlock(&sxfs->limits_mutex);
        usleep(SXFS_THREAD_WAIT);
        pthread_mutex_lock(&sxfs->limits_mutex);
    }
    pthread_mutex_unlock(&sxfs->limits_mutex);
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
	    if(!sxfs->args->replica_wait_flag)
		sxc_set_flush_policy(sx_data->sx, SXC_FLUSH_NOWAIT);
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
            if(sxfs_resize(&sxfs->threads, &sxfs->threads_max, sizeof(int))) {
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
    if(dir->nfiles == dir->maxfiles && sxfs_resize(&dir->files, &dir->maxfiles, sizeof(sxfs_lsfile_t*))) {
        SXFS_ERROR("OOM growing files cache table");
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
    if(dir->ndirs == dir->maxdirs && sxfs_resize(&dir->dirs, &dir->maxdirs, sizeof(sxfs_lsdir_t*))) {
        SXFS_ERROR("OOM growing dirs cache table");
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

int sxfs_str_cmp (const void *ptr, size_t index, const char *file_name) {
    const char *str = ((const char* const*)ptr)[index];
    size_t filelen = strlen(file_name), len = strlen(str);

    if(file_name[filelen-1] == '/' && len == filelen + lenof(SXFS_SXNEWDIR) && !strcmp(str + len - lenof(SXFS_SXNEWDIR), SXFS_SXNEWDIR))
        return strncmp(str, file_name, filelen);
    return strcmp(str, file_name);
} /* sxfs_str_cmp */

int sxfs_lsfile_cmp (const void *files, size_t index, const char *file_name) {
    return strcmp(((const sxfs_lsfile_t* const*)files)[index]->name, file_name);
} /* sxfs_lsfile_cmp */

int sxfs_lsdir_cmp (const void *dirs, size_t index, const char *dir_name) {
    return strcmp(((const sxfs_lsdir_t* const*)dirs)[index]->name, dir_name);
} /* sxfs_lsdir_cmp */

ssize_t sxfs_find_entry (const void *table, size_t size, const char *name, int (*compare)(const void*, size_t, const char*)) {
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
        index = sxfs_find_entry(dir->dirs, dir->ndirs, ptr, sxfs_lsdir_cmp);
        if(index < 0) {
            int ret;
            if(sxfs_find_entry(dir->files, dir->nfiles, ptr, sxfs_lsfile_cmp) >= 0) {
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
    const void *value;
    int ret, delete_locked = 0, upload_locked = 0, found, tmp, *check_files = NULL, *check_dirs = NULL;
    unsigned int remote_files, val_len;
    uint64_t mtime;
    ssize_t index;
    size_t i, j, ncfiles, ncdirs, len, pathlen;
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
    sxfs_queue_entry_t *entry;

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
    pthread_mutex_lock(&sxfs->delete_mutex); /* there can be entry removed from delete_queue between sxc_cluster_listfiles_etag() and sxc_cluster_listfiles_next() */
    delete_locked = 1;
    flist = sxc_cluster_listfiles_etag(cluster, sxfs->uri->volume, path, 0, &remote_files, 0, 1, dir->etag);
    if(!flist) {
        if(sxc_geterrnum(sx) != SXE_SKIP) {
            SXFS_ERROR("%s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_ls_update_err;
        }
        if(!dir->init) {
            flist = sxc_cluster_listfiles(cluster, sxfs->uri->volume, path, 0, &remote_files, 0, 1);
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
    for(i=0; i<ncfiles; i++)
        if(dir->files[i]->opened == SXFS_FILE_OPENED)
            check_files[i] = 1;

    /* load directory content from upload queue and try to clean the queue */
    if(sxfs->args->use_queues_flag) {
        len = strrchr(absolute_path, '/') - absolute_path + 1;
        pthread_mutex_lock(&sxfs->upload_mutex);
        upload_locked = 1;
        entry = upload_queue.next;
        while(entry) {
            entry->waiting++;
            while(entry->state & SXFS_QUEUE_RENAMING) {
                pthread_mutex_unlock(&sxfs->upload_mutex);
                usleep(SXFS_THREAD_WAIT);
                pthread_mutex_lock(&sxfs->upload_mutex);
            }
            entry->waiting--;
            if((entry->state & SXFS_QUEUE_DONE) && !(entry->state & SXFS_QUEUE_REMOTE)) {
                entry = entry->next;
                continue;
            }
            if(!strncmp(absolute_path, entry->remote_path, len)) {
                if(strchr(entry->remote_path + len, '/')) { /* directory */
                    while(pathlen < strlen(entry->remote_path + len) + 1)
                        if(sxfs_resize((void**)&path, &pathlen, sizeof(char))) {
                            SXFS_ERROR("OOM growing the path: %s", strerror(errno));
                            ret = -ENOMEM;
                            goto sxfs_ls_update_err;
                        }
                    snprintf(path, pathlen, "%s", entry->remote_path + len);
                    ptr = strchr(path, '/');
                    if(ptr)
                        *ptr = '\0';
                    index = sxfs_find_entry(dir->dirs, ncdirs, path, sxfs_lsdir_cmp);
                    if(index >= 0) {
                        check_dirs[index] = 1;
                        if(entry->state & SXFS_QUEUE_REMOTE)
                            dir->dirs[index]->remote = 2;
                    } else {
                        SXFS_ERROR("'%s' directory is missing in ls cache", path);
                        ret = -EAGAIN;
                        goto sxfs_ls_update_err;
                    }
                    entry = entry->next;
                } else { /* file */
                    ptr = strrchr(entry->remote_path ,'/') + 1;
                    if(!strcmp(ptr, SXFS_SXNEWDIR)) {
                        dir->sxnewdir = entry->state & SXFS_QUEUE_REMOTE ? 2 : 1;
                    } else {
                        index = sxfs_find_entry(dir->files, ncfiles, ptr, sxfs_lsfile_cmp);
                        if(index >= 0) {
                            check_files[index] = 1;
                            if(entry->state & SXFS_QUEUE_REMOTE)
                                dir->files[index]->remote = 2;
                        } else {
                            SXFS_ERROR("'%s' file is missing in ls cache", ptr);
                            ret = -EAGAIN;
                            goto sxfs_ls_update_err;
                        }
                    }
                    entry = sxfs_queue_cleanup_single(entry, 1);
                }
            } else {
                entry = entry->next;
            }
        }
        pthread_mutex_unlock(&sxfs->upload_mutex);
        upload_locked = 0;
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
            ret = -ENOMEM;
            goto sxfs_ls_update_err;
        }
        len = strlen(fpath) - 1;
        sxc_meta_free(fmeta);
        fmeta = NULL;
        if(fpath[len] != '/') {
            fmeta = sxc_filemeta_new(file);
            if(!fmeta && sxc_geterrnum(sx) != SXE_ECOMM) { /* workaround for race condition (remote file can be deleted between listing and sxc_filemeta_new()) */
                SXFS_ERROR("Cannot get '%s' filemeta: %s", fpath, sxc_geterrmsg(sx));
                ret = -sxfs_sx_err(sx);
                goto sxfs_ls_update_err;
            }
        }
        tmptime = sxc_file_get_created_at(file);
        st.st_size = sxc_file_get_size(file);
        st.st_uid = sxc_file_get_uid(file) == (uid_t)SXC_UINT32_UNDEFINED ? getuid() : sxc_file_get_uid(file);
        st.st_gid = sxc_file_get_gid(file) == (gid_t)SXC_UINT32_UNDEFINED ? getgid() : sxc_file_get_gid(file);
        if(!fmeta || sxc_meta_getval(fmeta, "sxfsMtime", &value, &val_len) || val_len != 8) {
            st.st_mtime = sxc_file_get_mtime(file) == (time_t)SXC_UINT64_UNDEFINED ? tmptime : sxc_file_get_mtime(file);
        } else {
            mtime = *((const uint64_t*)value); /* savely cast the pointer (size is correct) */
            st.st_mtime = sxi_swapu64(mtime); /* copy by the value */
        }
        if(fpath[len] == '/') {
            fpath[len] = '\0';
            st.st_mode = SXFS_DIR_ATTR;
        } else {
            len = 0;
            st.st_mode = sxc_file_get_mode(file) == (mode_t)SXC_UINT32_UNDEFINED ? SXFS_FILE_ATTR : sxc_file_get_mode(file);
        }
        sxc_file_free(file);
        file = NULL;
        fname = strrchr(fpath, '/');
        if(!fname)
            fname = fpath + 1;
        else
            fname++;
        if(len)
            fpath[len] = '/';
        found = 0;
        if(sxfs->args->use_queues_flag) {
            entry = delete_queue.next;
            while(entry) {
                if(!strcmp(fpath, entry->remote_path)) {
                    if(!(entry->state & SXFS_QUEUE_DONE))
                        found = 1;
                    break;
                }
                entry = entry->next;
            }
        }
        if(!found) {
            if(!strcmp(fname, SXFS_SXNEWDIR)) {
                dir->sxnewdir = 2; /* file is on the server */
            } else {
                if(S_ISDIR(st.st_mode)) {
                    fpath[len] = '\0';
                    index = sxfs_find_entry(dir->dirs, ncdirs, fname, sxfs_lsdir_cmp);
                    fpath[len] = '/';
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
                    index = sxfs_find_entry(dir->files, ncfiles, fname, sxfs_lsfile_cmp);
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
    pthread_mutex_unlock(&sxfs->delete_mutex);
    delete_locked = 0;

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

    /* update all done files from upload_queue */
    if(sxfs->args->use_queues_flag) {
        sxfs_lsdir_t *tmpdir;
        pthread_mutex_lock(&sxfs->upload_mutex);
        /* no 'upload_locked = 1' because of no 'goto' */
        entry = upload_queue.next;
        while(entry) {
            entry->waiting++;
            while(entry->state & SXFS_QUEUE_RENAMING) {
                pthread_mutex_unlock(&sxfs->upload_mutex);
                usleep(SXFS_THREAD_WAIT);
                pthread_mutex_lock(&sxfs->upload_mutex);
            }
            entry->waiting--;
            if(entry->state & SXFS_QUEUE_DONE) {
                if(entry->state & SXFS_QUEUE_REMOTE) {
                    if((ret = sxfs_ls_ftw(sxfs, entry->remote_path, &tmpdir))) {
                        SXFS_ERROR("File tree walk failed");
                        entry = entry->next;
                        continue; /* not a critical fail */
                    }
                    ptr = strrchr(entry->remote_path ,'/') + 1;
                    if(!strcmp(ptr, SXFS_SXNEWDIR)) {
                        tmpdir->sxnewdir = entry->state & SXFS_QUEUE_REMOTE ? 2 : 1;
                    } else {
                        index = sxfs_find_entry(tmpdir->files, tmpdir->nfiles, ptr, sxfs_lsfile_cmp);
                        if(index >= 0) {
                            tmpdir->files[index]->remote = 1;
                        } else {
                            SXFS_ERROR("'%s' file is missing in ls cache", ptr);
                            entry = entry->next;
                            continue; /* not a critical fail */
                        }
                    }
                }
                entry = sxfs_queue_cleanup_single(entry, 1);
            } else {
                entry = entry->next;
            }
        }
        pthread_mutex_unlock(&sxfs->upload_mutex);
    }

    *given_dir = dir;
    ret = 0;
sxfs_ls_update_err:
    if(delete_locked)
        pthread_mutex_unlock(&sxfs->delete_mutex);
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
    if((ret = sxfs_ls_update(path, &dir))) {
        SXFS_ERROR("Cannot load file tree: %s", path);
        pthread_mutex_unlock(&sxfs->ls_mutex);
        return ret;
    }
    file_name = strrchr(path, '/') + 1; /* already checked in sxfs_ls_update() */
    index = sxfs_find_entry(dir->dirs, dir->ndirs, file_name, sxfs_lsdir_cmp);
    if(index >= 0) {
        if(st)
            memcpy(st, &dir->dirs[index]->st, sizeof(struct stat));
        ret = 2;
    } else {
        index = sxfs_find_entry(dir->files, dir->nfiles, file_name, sxfs_lsfile_cmp);
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

int sxfs_upload_force (const char *local_file_path, const char *remote_file_path, sxfs_lsfile_t *lsfile) {
    int ret;
    struct stat st;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
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
        goto sxfs_upload_force_err;
    }
    file_remote = sxc_file_remote(cluster, sxfs->uri->volume, remote_file_path+1, NULL);
    if(!file_remote) {
        SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
        ret = -sxfs_sx_err(sx);
        goto sxfs_upload_force_err;
    }
    if(lsfile) {
        uint64_t mtime = lsfile->st.st_mtime;
        mtime = sxi_swapu64(mtime);
        if(sxi_file_meta_add(file_local, "sxfsMtime", &mtime, sizeof(mtime))) {
            SXFS_ERROR("Cannot add filemeta entry: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_upload_force_err;
        }
    }
    SXFS_DEBUG("Uploading '%s'", remote_file_path);
    if(sxc_copy_single(file_local, file_remote, 0, 0, 0, NULL, 0)) {
        SXFS_ERROR("Cannot upload '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        ret = -sxfs_sx_err(sx);
        goto sxfs_upload_force_err;
    }
    if(lsfile)
        lsfile->remote = 1;

    ret = 0;
sxfs_upload_force_err:
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
    return ret;
} /* sxfs_upload_force */

static int sxfs_queue_rename_prepare (sxfs_queue_entry_t *queue, const char *path, const char *newpath, pthread_mutex_t *mutex) {
    int ret = 0, is_dir = 0;
    size_t len = strlen(path), lendiff;
    sxfs_queue_entry_t *entry;

    pthread_mutex_lock(mutex);
    if(path[len-1] == '/')
        is_dir = 1;
    if(len < strlen(newpath)) {
        lendiff = strlen(newpath) - len;
        entry = queue->next;
        while(entry) {
            if((is_dir ? !strncmp(path, entry->remote_path, len) : !strcmp(path, entry->remote_path))) { /* the entry can be busy - realloc doesn't change the string */
                char *ptr = (char*)realloc(entry->remote_path, strlen(entry->remote_path) + lendiff + 1);
                if(!ptr) {
                    pthread_mutex_unlock(mutex);
                    return -ENOMEM;
                }
                entry->remote_path = ptr;
                if(!is_dir)
                    break; /* there can be only one entry */
            }
            entry = entry->next;
        }
    }
    entry = queue->next;
    while(entry) {
        if(is_dir ? !strncmp(path, entry->remote_path, len) : !strcmp(path, entry->remote_path)) {
            SXFS_QUEUE_WAIT(entry, mutex);
            entry->state |= SXFS_QUEUE_RENAMING;
            ret = 1;
            if(!is_dir)
                break; /* there can be only one entry */
        }
        entry = entry->next;
    }
    sxfs_queue_cleanup(queue, 0);
    pthread_mutex_unlock(mutex);
    return ret;
} /* sxfs_queue_rename_prepare */

static void sxfs_queue_rename (sxfs_queue_entry_t *queue, const char *path, const char *newpath) {
    int is_dir = 0;
    size_t len = strlen(path);
    char buff[SXLIMIT_MAX_FILENAME_LEN + 1];
    sxfs_queue_entry_t *entry = queue->next;

    if(path[len-1] == '/')
        is_dir = 1;
    while(entry) {
        if(entry->state & SXFS_QUEUE_RENAMING) {
            if(is_dir) {
                if(!strncmp(path, entry->remote_path, len)) {
                    snprintf(buff, sizeof(buff), "%s", entry->remote_path + len);
                    sprintf(entry->remote_path, "%s%s", newpath, buff);
                    entry->state &= ~SXFS_QUEUE_RENAMING;
                }
            } else {
                if(!strcmp(path, entry->remote_path)) {
                    sprintf(entry->remote_path, "%s", newpath);
                    entry->state &= ~SXFS_QUEUE_RENAMING;
                    break; /* there can be only one entry */
                }
            }
        }
        entry = entry->next;
    }
    sxfs_queue_cleanup(queue, 0);
} /* sxfs_queue_rename */

static void sxfs_queue_rename_abort (sxfs_queue_entry_t *queue, const char *path) {
    int is_dir = 0;
    size_t len = strlen(path);
    sxfs_queue_entry_t *entry = queue->next;

    if(path[len-1] == '/')
        is_dir = 1;
    while(entry) {
        if(entry->state == SXFS_QUEUE_RENAMING && (is_dir ? !strncmp(path, entry->remote_path, len) : !strcmp(path, entry->remote_path))) {
            entry->state &= ~SXFS_QUEUE_RENAMING;
            if(!is_dir)
                break; /* there can be only one entry */
        }
        entry = entry->next;
    }
    sxfs_queue_cleanup(queue, 0);
} /* sxfs_queue_rename_abort */

int sxfs_delete_rename_prepare (const char *path, const char *newpath) {
    return sxfs_queue_rename_prepare(&delete_queue, path, newpath, &SXFS_DATA->delete_mutex);
} /* sxfs_delete_rename_prepare */

void sxfs_delete_rename (const char *path, const char *newpath) {
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    sxfs_queue_rename(&delete_queue, path, newpath);
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
} /* sxfs_delete_rename */

void sxfs_delete_rename_abort (const char *path) {
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    sxfs_queue_rename_abort(&delete_queue, path);
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
} /* sxfs_delete_rename_abort */

int sxfs_upload_rename_prepare (const char *path, const char *newpath) {
    return sxfs_queue_rename_prepare(&upload_queue, path, newpath, &SXFS_DATA->upload_mutex);
} /* sxfs_upload_rename_prepare */

void sxfs_upload_rename (const char *path, const char *newpath) {
    pthread_mutex_lock(&SXFS_DATA->upload_mutex);
    sxfs_queue_rename(&upload_queue, path, newpath);
    pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
} /* sxfs_upload_rename */

void sxfs_upload_rename_abort (const char *path) {
    pthread_mutex_lock(&SXFS_DATA->upload_mutex);
    sxfs_queue_rename_abort(&upload_queue, path);
    pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
} /* sxfs_upload_rename_abort */

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

int sxfs_delete (const char *path, int is_remote, int upload_checked) {
    int ret, is_dir;
    size_t len = strlen(path);
    sxfs_state_t *sxfs = SXFS_DATA;
    sxfs_queue_entry_t *entry, *new_entry = NULL;

    is_dir = path[len-1] == '/';
    if(sxfs->args->use_queues_flag) {
        if((ret = sxfs_delete_start())) { /* check whether deletion thread is still working */
            SXFS_ERROR("Cannot restart deletion thread");
            return ret;
        }
        pthread_mutex_lock(&sxfs->upload_mutex);
        if(!upload_checked) { /* check whether this file is queued for upload */
            entry = upload_queue.next;
            while(entry) {
                if(is_dir ? !strncmp(path, entry->remote_path, len) : !strcmp(path, entry->remote_path)) {
                    SXFS_QUEUE_WAIT(entry, &sxfs->upload_mutex);
                    if(entry->state & SXFS_QUEUE_REMOTE)
                        is_remote = 1;
                    entry->state &= ~SXFS_QUEUE_REMOTE;
                    if(!(entry->state & SXFS_QUEUE_DONE)) {
                        entry->state |= SXFS_QUEUE_DONE;
                        SXFS_DEBUG("File marked as done in upload queue: %s", entry->remote_path);
                    }
                    entry = sxfs_queue_cleanup_single(entry, 1);
                    if(!is_dir)
                        break; /* there can be only one entry */
                } else {
                    entry = entry->next;
                }
            }
        }
        pthread_mutex_unlock(&sxfs->upload_mutex);
        pthread_mutex_lock(&sxfs->delete_mutex);
        entry = delete_queue.next;
        while(entry) {
            if(!strcmp(path, entry->remote_path)) {
                SXFS_QUEUE_WAIT(entry, &sxfs->delete_mutex);
                if(entry->state & SXFS_QUEUE_DONE) {
                    if(is_remote) {
                        new_entry = entry;
                        new_entry->state &= ~SXFS_QUEUE_DONE;
                    }
                } else {
                    SXFS_ERROR("File already queued: %s", entry->remote_path);
                    ret = -EINVAL;
                    goto sxfs_delete_err;
                }
            }
            entry = entry->next;
        }
        if(is_remote) {
            if(!new_entry) {
                new_entry = (sxfs_queue_entry_t*)calloc(1, sizeof(sxfs_queue_entry_t));
                if(!new_entry) {
                    SXFS_ERROR("Out of memory");
                    ret = -ENOMEM;
                    goto sxfs_delete_err;
                }
                new_entry->remote_path = strdup(path);
                if(!new_entry->remote_path) {
                    SXFS_ERROR("Out of memory: %s", path);
                    ret = -ENOMEM;
                    free(new_entry);
                    goto sxfs_delete_err;
                }
            }
            if(!new_entry->prev) {
                entry = &delete_queue;
                while(entry->next)
                    entry = entry->next;
                entry->next = new_entry;
                new_entry->prev = entry;
            }
            SXFS_DEBUG("File added: %s", path);
            if(path[len-1] == '/') { /* remove single files from the queue, recursive deletion will be used */
                entry = delete_queue.next;
                while(entry) {
                    if(!strncmp(path, entry->remote_path, len) && entry != new_entry) {
                        entry->state |= SXFS_QUEUE_DONE;
                        SXFS_DEBUG("File marked as done in deletion queue: %s", entry->remote_path);
                        entry = sxfs_queue_cleanup_single(entry, 1);
                    } else {
                        entry = entry->next;
                    }
                }
            }
        }
    } else {
        char *tmp_path = parse_path(path);
        sxc_client_t *sx;
        sxc_cluster_t *cluster;
        sxc_file_t *file;
        sxc_file_list_t *flist;

        if(!tmp_path) {
            SXFS_ERROR("Out of memory");
            return -ENOMEM;
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
            sxc_file_list_free(flist);
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        if(sxc_file_list_add(flist, file, 1)) {
            SXFS_ERROR("Cannot add file: %s", sxc_geterrmsg(sx));
            free(tmp_path);
            sxc_file_free(file);
            sxc_file_list_free(flist);
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        if(sxc_rm(flist, 0)) {
            SXFS_ERROR("Cannot remove file: %s", sxc_geterrmsg(sx));
            free(tmp_path);
            sxc_file_list_free(flist);
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        free(tmp_path);
        sxc_file_list_free(flist);
    }

    ret = 0;
sxfs_delete_err:
    if(sxfs->args->use_queues_flag)
        pthread_mutex_unlock(&sxfs->delete_mutex);
    return ret;
} /* sxfs_delete */

static void* sxfs_delete_worker (void *ctx) {
    int err, i, nfiles = 0;
    char *path = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *file = NULL;
    sxc_file_list_t *flist = NULL;
    sxfs_state_t *sxfs = (sxfs_state_t*)ctx;
    sxfs_queue_entry_t *entry = NULL, *list[SXFS_DELETE_WORKER_NFILES];

    if(sxfs_get_sx_data(sxfs, &sx, &cluster)) {
        SXFS_ERROR("Cannot get SX data");
        goto sxfs_delete_worker_err;
    }
    flist = sxc_file_list_new(sx, 1, 0);
    if(!flist) {
        SXFS_ERROR("Cannot create new file list: %s", sxc_geterrmsg(sx));
        goto sxfs_delete_worker_err;
    }
    pthread_mutex_lock(&sxfs->delete_mutex);
    entry = delete_queue.next;
    while(entry) {
        if(!(entry->state & SXFS_QUEUE_IN_PROGRESS)) {
            SXFS_QUEUE_WAIT(entry, &sxfs->delete_mutex);
            if(entry->state & SXFS_QUEUE_DONE) {
                entry = sxfs_queue_cleanup_single(entry, 1);
                continue;
            }
            entry->state |= SXFS_QUEUE_IN_PROGRESS;
            pthread_mutex_unlock(&sxfs->delete_mutex);

            list[nfiles] = entry;
            nfiles++;
            free(path);
            path = parse_path(entry->remote_path);
            if(!path) {
                SXFS_ERROR("Out of memory");
                goto sxfs_delete_worker_err;
            }
            sxc_file_free(file);
            file = sxc_file_remote(cluster, sxfs->uri->volume, path+1, NULL);
            if(!file) {
                SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
                goto sxfs_delete_worker_err;
            }
            if(sxc_file_list_add(flist, file, 1)) {
                SXFS_ERROR("Cannot add file: %s", sxc_geterrmsg(sx));
                goto sxfs_delete_worker_err;
            }
            file = NULL;
            if(nfiles == SXFS_DELETE_WORKER_NFILES || !entry->next) {
                for(i=0; i<nfiles; i++) {
                    entry = list[i];
                    SXFS_DEBUG("Removing '%s' %s", entry->remote_path, entry->remote_path[strlen(entry->remote_path)-1] == '/' ? "directory" : "file");
                }
                if((err = sxc_rm(flist, 0))) {
                    if(sxc_geterrnum(sx) == SXE_EARG) {
                        SXFS_DEBUG("No such remote file(s)");
                        err = 0; /* cleanup the error flag, missing remote files are not the problem (someone sxrm'ed them?) */
                    } else {
                        SXFS_ERROR("Cannot remove file(s): %s", sxc_geterrmsg(sx));
                    }
                } else {
                    SXFS_DEBUG("%d file(s) removed correctly", nfiles);
                }
                pthread_mutex_lock(&sxfs->delete_mutex);
                for(i=0; i<nfiles; i++) {
                    entry = list[i];
                    entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
                    if(!err)
                        entry->state |= SXFS_QUEUE_DONE;
                    sxfs_queue_cleanup_single(entry, 1);
                }
                nfiles = 0;
                entry = &delete_queue;
                sxc_file_list_free(flist);
                flist = sxc_file_list_new(sx, 1, 0);
                if(!flist) {
                    SXFS_ERROR("Cannot create new file list: %s", sxc_geterrmsg(sx));
                    pthread_mutex_unlock(&sxfs->delete_mutex);
                    goto sxfs_delete_worker_err;
                }
            } else {
                pthread_mutex_lock(&sxfs->delete_mutex);
            }
            entry = entry->next;
        } else {
            entry = entry->next;
        }
    }
    pthread_mutex_unlock(&sxfs->delete_mutex);

sxfs_delete_worker_err:
    free(path);
    sxc_file_free(file);
    sxc_file_list_free(flist);
    pthread_mutex_lock(&sxfs->delete_mutex);
    for(i=0; i<nfiles; i++) {
        entry = list[i];
        entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
    }
    pthread_mutex_unlock(&sxfs->delete_mutex);
    pthread_mutex_lock(&sxfs->limits_mutex);
    threads_del--;
    sxfs->threads_num--;
    pthread_mutex_unlock(&sxfs->limits_mutex);
    pthread_exit(NULL);
} /* sxfs_delete_worker */

static void sxfs_queue_run (sxfs_state_t *sxfs, sxfs_queue_entry_t *entry, size_t *nthreads, pthread_mutex_t *mutex, void* (*thread_worker)(void*)) {
    int err;

    while(entry) {
        pthread_t thread;

        memset(&thread, 0, sizeof(pthread_t));
        if(entry->state & SXFS_QUEUE_IN_PROGRESS) {
            entry = entry->next;
            continue;
        }
        pthread_mutex_lock(&sxfs->limits_mutex);
        if(*nthreads == SXFS_QUEUE_THREADS_LIMIT) {
            pthread_mutex_unlock(&sxfs->limits_mutex);
            return;
        }
        (*nthreads)++;
        pthread_mutex_unlock(&sxfs->limits_mutex);
        if((err = sxfs_thread_create(sxfs, &thread, thread_worker, (void*)sxfs))) {
            SXFS_ERROR("Cannot start new thread: %s", strerror(-err));
            pthread_mutex_lock(&sxfs->limits_mutex);
            (*nthreads)--;
            pthread_mutex_unlock(&sxfs->limits_mutex);
            return;
        }
        if((err = pthread_detach(thread)))
            SXFS_ERROR("Cannot detach the thread: %s", strerror(err));
        entry = entry->next;
    }
} /* sxfs_queue_run */

static void* sxfs_delete_thread (void *ptr) {
    int *ret = (int*)calloc(1, sizeof(int)), err;
    size_t prev;
    struct timespec wait_time;
    sxfs_state_t *sxfs = (sxfs_state_t*)ptr;

    memset(&wait_time, 0, sizeof(struct timespec));
    pthread_mutex_lock(&sxfs->delete_thread_mutex);
    if(!ret) {
        SXFS_ERROR("Out of memory");
        goto sxfs_delete_thread_err;
    }
    pthread_mutex_lock(&sxfs->delete_mutex);
    delete_flag = SXFS_THREAD_WORKING;
    pthread_mutex_unlock(&sxfs->delete_mutex);
    SXFS_LOG("Deletion thread has been started");
    delete_stop = 0;

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
                sxfs_queue_run(sxfs, delete_queue.next, &threads_del, &sxfs->delete_mutex, sxfs_delete_worker);
                pthread_mutex_unlock(&sxfs->delete_mutex);
            } else {
                *ret = err;
                SXFS_ERROR("Pthread condition waiting failed: %s", strerror(err));
                goto sxfs_delete_thread_err;
            }
        } else {
            break;
        }
    }

    *ret = 0;
sxfs_delete_thread_err:
    pthread_mutex_unlock(&sxfs->delete_thread_mutex);
    pthread_mutex_lock(&sxfs->limits_mutex);
    prev = threads_del + 1;
    while(threads_del) {
        if(prev != threads_del) {
            SXFS_DEBUG("Waiting for workers (%llu)", (long long unsigned int)threads_del);
            prev = threads_del;
        }
        pthread_mutex_unlock(&sxfs->limits_mutex);
        usleep(SXFS_THREAD_WAIT);
        pthread_mutex_lock(&sxfs->limits_mutex);
    }
    pthread_mutex_unlock(&sxfs->limits_mutex);
    pthread_mutex_lock(&sxfs->delete_mutex);
    sxfs_queue_free(delete_queue.next, 1);
    delete_queue.next = NULL;
    delete_flag = SXFS_THREAD_STOPPED;
    SXFS_LOG("Deletion thread has been stopped");
    pthread_mutex_unlock(&sxfs->delete_mutex);
    pthread_mutex_lock(&sxfs->limits_mutex);
    sxfs->threads_num--;
    pthread_mutex_unlock(&sxfs->limits_mutex);
    pthread_exit((void*)ret);
} /* sxfs_delete_thread */

int sxfs_delete_check_path (const char *path) {
    int ret;
    size_t i, n = 0, max = 0, len = strlen(path);
    char *ptr;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *file = NULL;
    sxc_file_list_t *flist = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;
    sxfs_queue_entry_t *entry, **array = NULL;

    if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
        SXFS_ERROR("Cannot get SX data");
        return ret;
    }
    ptr = strrchr(path, '/');
    if(!ptr) {
        SXFS_ERROR("'/' not found in '%s'", path);
        return -EINVAL;
    }
    ptr++;
    flist = sxc_file_list_new(sx, 1, 0);
    if(!flist) {
        SXFS_ERROR("Cannot create new file list: %s", sxc_geterrmsg(sx));
        return -sxfs_sx_err(sx);
    }
    if(!strcmp(ptr, SXFS_SXNEWDIR) || path[len-1] == '/') {
        if(!strcmp(ptr, SXFS_SXNEWDIR))
            len -= lenof(SXFS_SXNEWDIR);
        max = SXFS_ALLOC_ENTRIES;
        array = (sxfs_queue_entry_t**)calloc(max, sizeof(sxfs_queue_entry_t*));
        if(!array) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            goto sxfs_delete_check_path_err;
        }
        pthread_mutex_lock(&sxfs->delete_mutex);
        entry = delete_queue.next;
        while(entry) {
            if(!strncmp(path, entry->remote_path, len) || (strlen(entry->remote_path) == len - 1 && !strncmp(path, entry->remote_path, len-1))) {
                SXFS_QUEUE_WAIT(entry, &sxfs->delete_mutex);
                if(!(entry->state & SXFS_QUEUE_DONE)) {
                    entry->state |= SXFS_QUEUE_IN_PROGRESS;
                    pthread_mutex_unlock(&sxfs->delete_mutex);
                    if(n == max && sxfs_resize((void**)&array, &max, sizeof(sxfs_queue_entry_t*))) {
                        SXFS_ERROR("OOM growing queue entries table");
                        ret = -ENOMEM;
                        pthread_mutex_lock(&sxfs->delete_mutex);
                        entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
                        pthread_mutex_unlock(&sxfs->delete_mutex);
                        goto sxfs_delete_check_path_err;
                    }
                    file = sxc_file_remote(cluster, sxfs->uri->volume, entry->remote_path+1, NULL);
                    if(!file) {
                        SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
                        ret = -sxfs_sx_err(sx);
                        pthread_mutex_lock(&sxfs->delete_mutex);
                        entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
                        pthread_mutex_unlock(&sxfs->delete_mutex);
                        goto sxfs_delete_check_path_err;
                    }
                    if(sxc_file_list_add(flist, file, 1)) {
                        SXFS_ERROR("Cannot add file: %s", sxc_geterrmsg(sx));
                        ret = -sxfs_sx_err(sx);
                        pthread_mutex_lock(&sxfs->delete_mutex);
                        entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
                        pthread_mutex_unlock(&sxfs->delete_mutex);
                        goto sxfs_delete_check_path_err;
                    }
                    file = NULL; /* will be freed by sxc_file_list_free() */
                    array[n] = entry;
                    n++;
                    pthread_mutex_lock(&sxfs->delete_mutex);
                }
            }
            entry = entry->next;
        }
        pthread_mutex_unlock(&sxfs->delete_mutex);
        if(sxc_rm(flist, 0) && sxc_geterrnum(sx) != SXE_EARG) {
            SXFS_ERROR("Cannot remove files: %s", sxc_geterrmsg(sx));
            ret = -sxfs_sx_err(sx);
            goto sxfs_delete_check_path_err;
        }
    } else {
        pthread_mutex_lock(&sxfs->delete_mutex);
        entry = delete_queue.next;
        while(entry) {
            len = strlen(entry->remote_path);
            if(entry->remote_path[len-1] != '/')
                len = 0;
            if(len ? !strncmp(path, entry->remote_path, len) : !strcmp(path, entry->remote_path)) {
                SXFS_QUEUE_WAIT(entry, &sxfs->delete_mutex);
                if(!(entry->state & SXFS_QUEUE_DONE)) {
                    entry->state |= SXFS_QUEUE_IN_PROGRESS;
                    pthread_mutex_unlock(&sxfs->delete_mutex);
                    file = sxc_file_remote(cluster, sxfs->uri->volume, path+1, NULL);
                    if(!file) {
                        SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
                        ret = -sxfs_sx_err(sx);
                        pthread_mutex_lock(&sxfs->delete_mutex);
                        entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
                        pthread_mutex_unlock(&sxfs->delete_mutex);
                        goto sxfs_delete_check_path_err;
                    }
                    if(sxc_file_list_add(flist, file, 1)) {
                        SXFS_ERROR("Cannot add file: %s", sxc_geterrmsg(sx));
                        ret = -sxfs_sx_err(sx);
                        pthread_mutex_lock(&sxfs->delete_mutex);
                        entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
                        pthread_mutex_unlock(&sxfs->delete_mutex);
                        goto sxfs_delete_check_path_err;
                    }
                    file = NULL; /* will be freed by sxc_file_list_free() */
                    if(sxc_rm(flist, 0) && sxc_geterrnum(sx) != SXE_EARG) {
                        SXFS_ERROR("Cannot remove files: %s", sxc_geterrmsg(sx));
                        ret = -sxfs_sx_err(sx);
                        pthread_mutex_lock(&sxfs->delete_mutex);
                        entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
                        pthread_mutex_unlock(&sxfs->delete_mutex);
                        goto sxfs_delete_check_path_err;
                    }
                    pthread_mutex_lock(&sxfs->delete_mutex);
                    entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
                    entry->state |= SXFS_QUEUE_DONE;
                    SXFS_DEBUG("File marked as done in deletion queue: %s", entry->remote_path);
                    sxfs_queue_cleanup_single(entry, 1);
                }
                break; /* there can be only one entry */
            }
            entry = entry->next;
        }
        pthread_mutex_unlock(&sxfs->delete_mutex);
    }

    ret = 0;
sxfs_delete_check_path_err:
    sxc_file_free(file);
    sxc_file_list_free(flist);
    if(array) {
        pthread_mutex_lock(&sxfs->delete_mutex);
        for(i=0; i<n; i++) {
            entry = array[i];
            if(!ret) {
                entry->state |= SXFS_QUEUE_DONE;
                SXFS_DEBUG("File marked as done in deletion queue: %s", entry->remote_path);
            }
            entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
        }
        sxfs_queue_cleanup(&delete_queue, 1);
        pthread_mutex_unlock(&sxfs->delete_mutex);
        free(array);
    }
    return ret;
} /* sxfs_delete_check_path */

int sxfs_delete_start (void) {
    int err;
    sxfs_state_t *sxfs = SXFS_DATA;

    pthread_mutex_lock(&sxfs->delete_mutex);
    if(delete_flag != SXFS_THREAD_WORKING) {
        delete_queue.state = delete_queue.waiting = 0;
        delete_queue.local_path = delete_queue.remote_path = NULL;
        delete_queue.prev = delete_queue.next = NULL;
        delete_flag = SXFS_THREAD_NOT_WORKING;
        if((err = sxfs_thread_create(sxfs, &sxfs->delete_thread, sxfs_delete_thread, (void*)sxfs))) {
            SXFS_ERROR("Cannot create deletion thread");
            pthread_mutex_unlock(&sxfs->delete_mutex);
            return -err;
        }
        while(delete_flag == SXFS_THREAD_NOT_WORKING) {
            pthread_mutex_unlock(&sxfs->delete_mutex);
            usleep(SXFS_THREAD_WAIT);
            pthread_mutex_lock(&sxfs->delete_mutex);
        }
        if(delete_flag == SXFS_THREAD_STOPPED) { /* thread function executed and failed */
            int *status = NULL;
            if((err = pthread_join(sxfs->delete_thread, (void**)&status))) {
                SXFS_ERROR("Cannot join deletion thread: %s", strerror(err));
            } else {
                err = status ? *status : ENOMEM;
                SXFS_ERROR("Cannot start deletion thread: %s", strerror(status ? *status : ENOMEM));
                free(status);
            }
            pthread_mutex_unlock(&sxfs->delete_mutex);
            return -err;
        }
    }
    pthread_mutex_unlock(&sxfs->delete_mutex);
    return 0;
} /* sxfs_delete_start */

void sxfs_delete_stop (void) {
    int err, *status = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    pthread_mutex_lock(&sxfs->delete_mutex);
    if(delete_flag == SXFS_THREAD_WORKING) {
        delete_stop = 1;
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

int sxfs_upload_get_file (const char *path, sxfs_file_t *sxfs_file) {
    int ret, fd;
    size_t len = strlen(path);
    sxfs_state_t *sxfs = SXFS_DATA;
    sxfs_queue_entry_t *entry;

    if(path[len-1] == '/') {
        SXFS_ERROR("Directory received: %s", path);
        return -EISDIR;
    }
    pthread_mutex_lock(&sxfs->upload_mutex);
    entry = upload_queue.next;
    while(entry) {
        if(!strcmp(path, entry->remote_path)) {
            SXFS_QUEUE_WAIT(entry, &sxfs->upload_mutex);
            if(entry->state & SXFS_QUEUE_DONE) {
                sxfs_queue_cleanup_single(entry, 0);
                pthread_mutex_unlock(&sxfs->upload_mutex);
                return -ENOENT;
            }
            fd = open(entry->local_path, O_RDWR);
            if(fd < 0) {
                ret = -errno;
                SXFS_ERROR("Cannot open '%s' file: %s", entry->local_path, strerror(errno));
                pthread_mutex_unlock(&sxfs->upload_mutex);
                return ret;
            }
            sxfs_file->write_fd = fd;
            sxfs_file->write_path = entry->local_path;
            entry->local_path = NULL;
            sxfs_file->flush = 1;
            entry->state |= SXFS_QUEUE_DONE;
            sxfs_queue_cleanup_single(entry, 0);
            break;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&sxfs->upload_mutex);
    return sxfs_file->write_path ? 0 : -ENOENT;
} /* sxfs_upload_get_file */

void sxfs_upload_del_path (const char *path) {
    int is_dir = 0;
    size_t len = strlen(path);
    sxfs_state_t *sxfs = SXFS_DATA;
    sxfs_queue_entry_t *entry;

    if(path[len-1] == '/')
        is_dir = 1;
    pthread_mutex_lock(&sxfs->upload_mutex);
    entry = upload_queue.next;
    while(entry) {
        if(is_dir ? !strncmp(path, entry->remote_path, len) : !strcmp(path, entry->remote_path)) {
            entry->state |= SXFS_QUEUE_DONE;
            SXFS_DEBUG("File marked as done in upload queue: %s", entry->remote_path);
            sxfs_queue_cleanup_single(entry, 0);
            if(!is_dir)
                break; /* there can be only one entry */
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&sxfs->upload_mutex);
} /* sxfs_upload_del_path */

int sxfs_upload_remote_check (sxfs_state_t *sxfs, const char *path) {
    int is_dir;
    size_t len = strlen(path);
    sxfs_queue_entry_t *entry;

    is_dir = path[len-1] == '/';
    pthread_mutex_lock(&sxfs->upload_mutex);
    entry = upload_queue.next;
    while(entry) {
        if((is_dir ? !strncmp(path, entry->remote_path, len) : !strcmp(path, entry->remote_path))) {
            entry->waiting++;
            while(entry->state & SXFS_QUEUE_IN_PROGRESS) {
                pthread_mutex_unlock(&sxfs->upload_mutex);
                usleep(SXFS_THREAD_WAIT);
                pthread_mutex_lock(&sxfs->upload_mutex);
            }
            entry->waiting--;
            if(entry->state & SXFS_QUEUE_REMOTE) {
                pthread_mutex_unlock(&sxfs->upload_mutex);
                return 1;
            }
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&sxfs->upload_mutex);
    return 0;
} /* sxfs_upload_remote_check */

int sxfs_upload_truncate (const char *path, off_t length) {
    sxfs_queue_entry_t *entry;
    sxfs_state_t *sxfs = SXFS_DATA;

    if(path[strlen(path)-1] == '/') {
        SXFS_ERROR("Directory received: %s", path);
        return -EISDIR;
    }
    pthread_mutex_lock(&sxfs->upload_mutex);
    entry = upload_queue.next;
    while(entry) {
        if(!strcmp(path, entry->remote_path)) {
            SXFS_QUEUE_WAIT(entry, &sxfs->upload_mutex);
            if(!(entry->state & SXFS_QUEUE_DONE)) {
                if(truncate(entry->local_path, length)) {
                    int ret = -errno;
                    SXFS_ERROR("Cannot set '%s' size to %lld: %s", entry->local_path, (long long int)length, strerror(errno));
                    pthread_mutex_unlock(&sxfs->upload_mutex);
                    return ret;
                }
                pthread_mutex_unlock(&sxfs->upload_mutex);
                return 0;
            } else {
                sxfs_queue_cleanup_single(entry, 0);
                pthread_mutex_unlock(&sxfs->upload_mutex);
                return -ENOENT;
            }
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&sxfs->upload_mutex);
    return -ENOENT;
} /* sxfs_upload_truncate */

/* src - local path
 * dest - remote path */
int sxfs_upload (const char *src, const char *dest, sxfs_lsfile_t *lsfile, int force) {
    int ret;
    sxfs_state_t *sxfs = SXFS_DATA;
    sxfs_queue_entry_t *entry, *new_entry = NULL;

    if(sxfs->args->use_queues_flag) {
        if((ret = sxfs_upload_start())) { /* check whether upload thread is still working */
            SXFS_ERROR("Cannot restart upload thread");
            return ret;
        }
        /* remove the file from deletion queue */
        if((ret = sxfs_delete_check_path(dest))) {
            SXFS_ERROR("Cannot check deletion queue");
            return ret;
        }
        pthread_mutex_lock(&sxfs->upload_mutex);
        entry = upload_queue.next;
        while(entry) {
            if(!strcmp(dest, entry->remote_path)) {
                SXFS_QUEUE_WAIT(entry, &sxfs->upload_mutex);
                if(entry->state & SXFS_QUEUE_REMOTE)
                    lsfile->remote = 1;
                if((entry->state & SXFS_QUEUE_DONE) || force) {
                    entry->state = 0;
                    new_entry = entry;
                } else {
                    sxfs_queue_cleanup_single(entry, 1);
                    SXFS_ERROR("File already queued: %s", dest);
                    ret = -EINVAL;
                    goto sxfs_upload_err;
                }
                break;
            }
            entry = entry->next;
        }
        if(!new_entry) {
            new_entry = (sxfs_queue_entry_t*)calloc(1, sizeof(sxfs_queue_entry_t));
            if(!new_entry) {
                SXFS_ERROR("Out of memory");
                ret = -ENOMEM;
                goto sxfs_upload_err;
            }
            if(!src) { /* uploading empty file */
                int fd;

                new_entry->local_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof("file_XXXXXX") + 1);
                if(!new_entry->local_path) {
                    SXFS_ERROR("Out of memory");
                    ret = -ENOMEM;
                    goto sxfs_upload_err;
                }
                sprintf(new_entry->local_path, "%s/file_XXXXXX", sxfs->tempdir);
                fd = mkstemp(new_entry->local_path);
                if(fd < 0) {
                    ret = -errno;
                    SXFS_ERROR("Cannot create '%s' file: %s", new_entry->local_path, strerror(errno));
                    goto sxfs_upload_err;
                }
                if(close(fd)) {
                    ret = -errno;
                    SXFS_ERROR("Cannot close '%s' file: %s", new_entry->local_path, strerror(errno));
                    goto sxfs_upload_err;
                }
            } else {
                new_entry->local_path = strdup(src);
                if(!new_entry->local_path) {
                    SXFS_ERROR("Out of memory");
                    ret = -ENOMEM;
                    goto sxfs_upload_err;
                }
            }
            new_entry->remote_path = strdup(dest);
            if(!new_entry->remote_path) {
                SXFS_ERROR("Out of memory");
                ret = -ENOMEM;
                goto sxfs_upload_err;
            }
            if(lsfile) {
                new_entry->mtime = lsfile->st.st_mtime;
                new_entry->mtime = sxi_swapu64(new_entry->mtime);
            }
            entry = &upload_queue;
            while(entry->next)
                entry = entry->next;
            entry->next = new_entry;
            new_entry->prev = entry;
        } else {
            char *path = strdup(src);

            if(!path) {
                SXFS_ERROR("Out of memory: %s", src);
                ret = -ENOMEM;
                goto sxfs_upload_err;
            }
            if(unlink(new_entry->local_path))
                SXFS_ERROR("Cannot remove '%s' file: %s", new_entry->local_path, strerror(errno));
            free(new_entry->local_path);
            new_entry->local_path = path;
        }

        if(lsfile && sxfs->attribs) {
            char *ptr = strrchr(new_entry->remote_path, '/');
            struct stat st;

            if(ptr) {
                ptr++;
                if(strcmp(ptr, SXFS_SXNEWDIR)) { /* ignore '.sxnewdir' files */
                    if(sxfs_set_attr(new_entry->local_path, &lsfile->st)) {
                        ret = -errno;
                        SXFS_ERROR("Cannot set file attributes for '%s': %s", entry->local_path, strerror(errno));
                        goto sxfs_upload_err;
                    }
                    if(stat(new_entry->local_path, &st)) {
                        SXFS_ERROR("Cannot stat '%s' file: %s", new_entry->local_path, strerror(errno));
                        /* uid/gid correctness is not critical */
                    } else { /* sxfs can have no permission to change uid/gid - be up to date with remote data */
                        lsfile->st.st_uid = st.st_uid;
                        lsfile->st.st_gid = st.st_gid;
                    }
                }
            }
        }
        new_entry = NULL;
        SXFS_DEBUG("File added: %s", dest);

    } else {
        if((ret = sxfs_upload_force(src ? src : sxfs->empty_file_path, dest, lsfile))) {
            SXFS_ERROR("Cannot upload %s file", dest);
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
    sxfs_queue_free(new_entry, 0);
    if(sxfs->args->use_queues_flag)
        pthread_mutex_unlock(&sxfs->upload_mutex);
    return ret;
} /* sxfs_upload */

static void* sxfs_upload_worker (void *ctx) {
    int err;
    sxc_client_t *sx = NULL; /* shut up warnings */
    sxc_cluster_t *cluster = NULL; /* shut up warnings */
    sxc_file_t *src = NULL, *dest = NULL;
    sxfs_state_t *sxfs = (sxfs_state_t*)ctx;
    sxfs_queue_entry_t *entry;

    if(sxfs_get_sx_data(sxfs, &sx, &cluster)) {
        SXFS_ERROR("Cannot get SX data");
        err = 0;
        goto sxfs_upload_worker_err;
    }
    pthread_mutex_lock(&sxfs->upload_mutex);
    entry = upload_queue.next;
    while(entry) {
        if(!(entry->state & SXFS_QUEUE_IN_PROGRESS)) {
            SXFS_QUEUE_WAIT(entry, &sxfs->upload_mutex);
            if(entry->state & SXFS_QUEUE_DONE) {
                entry = sxfs_queue_cleanup_single(entry, 0);
                continue;
            }
            entry->state |= SXFS_QUEUE_IN_PROGRESS;
            pthread_mutex_unlock(&sxfs->upload_mutex);

            SXFS_DEBUG("Uploading '%s' file", entry->remote_path);
            sxc_file_free(src);
            src = sxc_file_local(sx, entry->local_path);
            if(!src) {
                SXFS_ERROR("Cannot create local file object: %s", sxc_geterrmsg(sx));
                err = 1;
                goto sxfs_upload_worker_err;
            }
            sxc_file_free(dest);
            dest = sxc_file_remote(cluster, sxfs->uri->volume, entry->remote_path+1, NULL);
            if(!dest) {
                SXFS_ERROR("Cannot create file object: %s", sxc_geterrmsg(sx));
                err = 1;
                goto sxfs_upload_worker_err;
            }
            pthread_mutex_lock(&sxfs->upload_mutex);
            if(upload_stop) {
                pthread_mutex_unlock(&sxfs->upload_mutex);
                SXFS_DEBUG("Worker forced to stop");
                err = 1;
                goto sxfs_upload_worker_err;
            }
            pthread_mutex_unlock(&sxfs->upload_mutex);
            if(sxi_file_meta_add(src, "sxfsMtime", &entry->mtime, sizeof(entry->mtime))) {
                SXFS_ERROR("Cannot add filemeta entry: %s", sxc_geterrmsg(sx));
                err = 1;
                goto sxfs_upload_worker_err;
            }
            err = sxc_copy_single(src, dest, 0, 0, 0, NULL, 0);
            pthread_mutex_lock(&sxfs->upload_mutex);
            if(err)
                SXFS_ERROR("Cannot upload '%s' (%s) file: %s", entry->remote_path, entry->local_path, sxc_geterrmsg(sx));
            else
                SXFS_DEBUG("'%s' file uploaded", entry->remote_path);
            entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
            if(!err)
                entry->state |= (SXFS_QUEUE_DONE | SXFS_QUEUE_REMOTE);
            entry = sxfs_queue_cleanup_single(entry, 0);
        } else {
            entry = entry->next;
        }
    }
    pthread_mutex_unlock(&sxfs->upload_mutex);

    err = 0;
sxfs_upload_worker_err:
    sxc_file_free(src);
    sxc_file_free(dest);
    if(err) {
        pthread_mutex_lock(&sxfs->upload_mutex);
        entry->state &= ~SXFS_QUEUE_IN_PROGRESS;
        sxfs_queue_cleanup_single(entry, 0);
        pthread_mutex_unlock(&sxfs->upload_mutex);
    }
    pthread_mutex_lock(&sxfs->limits_mutex);
    threads_up--;
    sxfs->threads_num--;
    pthread_mutex_unlock(&sxfs->limits_mutex);
    pthread_exit(NULL);
} /* sxfs_upload_worker */

static void sxfs_upload_clean (sxfs_state_t *sxfs) {
    ssize_t index;
    char *filename;
    sxfs_lsdir_t *dir;
    sxfs_queue_entry_t *entry;

    pthread_mutex_lock(&sxfs->ls_mutex);
    pthread_mutex_lock(&sxfs->upload_mutex);
    entry = upload_queue.next;
    while(entry) {
        entry->waiting++;
        while(entry->state & SXFS_QUEUE_RENAMING) {
            pthread_mutex_unlock(&sxfs->upload_mutex);
            usleep(SXFS_THREAD_WAIT);
            pthread_mutex_lock(&sxfs->upload_mutex);
        }
        entry->waiting--;
        if(entry->state & SXFS_QUEUE_DONE) {
            if(!(entry->state & SXFS_QUEUE_REMOTE)) {
                entry = sxfs_queue_cleanup_single(entry, 0);
                continue;
            }
        } else {
            entry = entry->next;
            continue;
        }
        filename = strrchr(entry->remote_path, '/');
        if(!filename) {
            SXFS_ERROR("'/' not found in '%s'", entry->remote_path);
            goto sxfs_upload_clean_err;
        }
        filename++;
        if(sxfs_ls_ftw(sxfs, entry->remote_path, &dir)) {
            SXFS_ERROR("File tree walk failed");
            goto sxfs_upload_clean_err;
        }
        if(!strcmp(filename, SXFS_SXNEWDIR)) {
            dir->remote = 1;
            dir->sxnewdir = 2;
        } else {
            index = sxfs_find_entry(dir->files, dir->nfiles, filename, sxfs_lsfile_cmp);
            if(index >= 0) {
                dir->files[index]->remote = 1;
                while(dir) {
                    dir->remote = 1;
                    dir = dir->parent;
                }
            } else {
                SXFS_ERROR("'%s' file is missing in ls cache", entry->remote_path);
            }
        }
        entry = sxfs_queue_cleanup_single(entry, 1);
    }

sxfs_upload_clean_err:
    pthread_mutex_unlock(&sxfs->upload_mutex);
    pthread_mutex_unlock(&sxfs->ls_mutex);
} /* sxfs_upload_clean */

static void* sxfs_upload_thread (void *ptr) {
    int *ret = (int*)calloc(1, sizeof(int)), err;
    size_t prev;
    struct timespec wait_time;
    sxfs_state_t *sxfs = (sxfs_state_t*)ptr;

    memset(&wait_time, 0, sizeof(struct timespec));
    pthread_mutex_lock(&sxfs->upload_thread_mutex);
    if(!ret) {
        SXFS_ERROR("Out of memory");
        goto sxfs_upload_thread_err;
    }
    pthread_mutex_lock(&sxfs->upload_mutex);
    upload_flag = SXFS_THREAD_WORKING;
    pthread_mutex_unlock(&sxfs->upload_mutex);
    SXFS_LOG("Upload thread has been started");
    upload_stop = 0;

    while(1) {
        if((wait_time.tv_sec = time(NULL)) < 0) {
            *ret = errno;
            SXFS_ERROR("Cannot get current time: %s", strerror(errno));
            goto sxfs_upload_thread_err;
        }
        wait_time.tv_sec += SXFS_THREAD_SLEEP / 1000000L;
        if((err = pthread_cond_timedwait(&sxfs->upload_cond, &sxfs->upload_thread_mutex, &wait_time))) {
            if(err == ETIMEDOUT) {
                pthread_mutex_lock(&sxfs->upload_mutex);
                sxfs_queue_run(sxfs, upload_queue.next, &threads_up, &sxfs->upload_mutex, sxfs_upload_worker);
                pthread_mutex_unlock(&sxfs->upload_mutex);
                sxfs_upload_clean(sxfs);
            } else {
                *ret = err;
                SXFS_ERROR("Pthread condition waiting failed: %s", strerror(err));
                goto sxfs_upload_thread_err;
            }
        } else {
            break;
        }

    }

    *ret = 0;
sxfs_upload_thread_err:
    pthread_mutex_unlock(&sxfs->upload_thread_mutex);
    pthread_mutex_lock(&sxfs->limits_mutex);
    prev = threads_up + 1;
    while(threads_up) {
        if(prev != threads_up) {
            SXFS_DEBUG("Waiting for workers (%llu)", (long long unsigned int)threads_up);
            prev = threads_up;
        }
        pthread_mutex_unlock(&sxfs->limits_mutex);
        usleep(SXFS_THREAD_WAIT);
        pthread_mutex_lock(&sxfs->limits_mutex);
    }
    pthread_mutex_unlock(&sxfs->limits_mutex);
    pthread_mutex_lock(&sxfs->upload_mutex);
    sxfs_queue_cleanup(&upload_queue, 1);
    if(upload_queue.next) { /* check whether queue contains not yet uploaded files */
        char path[PATH_MAX];
        sxfs_queue_entry_t *entry = upload_queue.next;

        SXFS_LOG("Some files from upload queue could not be uploaded and have been saved into '%s'", sxfs->lostdir);
        /* no need to wait for the workers, they are already done (see 'while' loop above)) */
        /* uploaded and deleted files are already removed from the queue (see 'sxfs_queue_cleanup' above) */
        while(entry) {
            snprintf(path, sizeof(path), "%s/%s", sxfs->lostdir, entry->remote_path);
            if(sxfs_move_file(sxfs, entry->local_path, path)) {
                if(!sxfs->recovery_failed)
                    SXFS_ERROR("Cannot move some files to the recovery directory. These files are available in '%s'", sxfs->tempdir);
                sxfs->recovery_failed = 1;
            }
            entry = entry->next;
        }
    }
    sxfs_queue_free(upload_queue.next, 1);
    upload_queue.next = NULL;
    upload_flag = SXFS_THREAD_STOPPED;
    SXFS_LOG("Upload thread has been stopped");
    pthread_mutex_unlock(&sxfs->upload_mutex);
    pthread_mutex_lock(&sxfs->limits_mutex);
    sxfs->threads_num--;
    pthread_mutex_unlock(&sxfs->limits_mutex);
    pthread_exit((void*)ret);
} /* sxfs_upload_thread */

int sxfs_upload_start (void) {
    int err;
    sxfs_state_t *sxfs = SXFS_DATA;

    pthread_mutex_lock(&sxfs->upload_mutex);
    if(upload_flag != SXFS_THREAD_WORKING) {
        upload_queue.state = upload_queue.waiting = 0;
        upload_queue.local_path = upload_queue.remote_path = NULL;
        upload_queue.prev = upload_queue.next = NULL;
        upload_flag = SXFS_THREAD_NOT_WORKING;
        if((err = sxfs_thread_create(sxfs, &sxfs->upload_thread, sxfs_upload_thread, (void*)sxfs))) {
            SXFS_ERROR("Cannot create upload thread");
            pthread_mutex_unlock(&sxfs->upload_mutex);
            return -err;
        }
        while(upload_flag == SXFS_THREAD_NOT_WORKING) {
            pthread_mutex_unlock(&sxfs->upload_mutex);
            usleep(SXFS_THREAD_WAIT);
            pthread_mutex_lock(&sxfs->upload_mutex);
        }
        if(upload_flag == SXFS_THREAD_STOPPED) { /* thread function executed and failed */
            int *status = NULL;
            if((err = pthread_join(sxfs->upload_thread, (void**)&status))) {
                SXFS_ERROR("Cannot join upload thread: %s", strerror(err));
            } else {
                err = status ? *status : ENOMEM;
                SXFS_ERROR("Cannot start upload thread: %s", strerror(status ? *status : ENOMEM));
                free(status);
            }
            pthread_mutex_unlock(&sxfs->upload_mutex);
            return -err;
        }
    }
    pthread_mutex_unlock(&sxfs->upload_mutex);
    return 0;
} /* sxfs_upload_start */

void sxfs_upload_stop (void) {
    int tmp, *status = NULL;
    sxfs_state_t *sxfs = SXFS_DATA;

    pthread_mutex_lock(&sxfs->upload_mutex);
    if(upload_flag == SXFS_THREAD_WORKING) {
        upload_stop = 1;
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

