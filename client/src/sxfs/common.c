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

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include "libsxclient/src/fileops.h"


/* stuff for threads */
int delete_flag, upload_flag; /* -2 - not working
                               * -1 - signal to stop
                               *  0 - starting
                               *  1 - working */
size_t nfiles_del, maxfiles_del, nfiles_up, maxfiles_up;
char **delete_list = NULL, **upload_list = NULL;
struct timeval last_deletion_time, last_upload_time;

static const char truncated[] = "[...]";

void sxfs_log (const sxfs_state_t *sxfs, const char *fn, int debug, const char *format_string, ...) {
    int len = 0, n;
    char buff[65536];
    int size = sizeof(buff) - sizeof(truncated) + 1;
    struct timeval tv;
    struct tm *tm = NULL;
    va_list vl;

    if(!sxfs->logfile || (debug == 1 && !sxfs->args->debug_flag))
        return;
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
        n = snprintf(buff + len, size, "[%s] ", fn);
        size -= n;
        len += n;
    }
    if(size > 0) {
        n = snprintf(buff + len, size, "%s: ", !debug && sxfs->args->debug_flag ? "ERROR " : "");
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
        case SXE_EARG: return EINVAL;       /* Invalid argument */
        case SXE_EMEM: return ENOMEM;       /* Out of memory */
        case SXE_EREAD: return EIO;   /* Error reading from disk */
        case SXE_EWRITE: return EIO;  /* Error writing to disk */
        case SXE_ETMP: return EIO;    /* Error with temporary file creation and IO */
        case SXE_ECRYPT: return ENOMSG;     /* Error reported by the cryto library */
        case SXE_EAUTH: return EACCES;      /* Authentication related error */
        case SXE_ECURL: return ECONNABORTED;       /* Error reported by the connector library */
        case SXE_ECOMM: return ECONNABORTED;       /* Error in the communication with the cluster */
        case SXE_ECFG: return ENOMSG;       /* Error parsing the configuration */
        case SXE_ETIME: return ETIMEDOUT;   /* Error retrieving the current time */
        case SXE_EFILTER: return ENOMSG;    /* Filter related error */
        case SXE_EAGAIN: return EAGAIN;     /* Try again later  */
        default: return 0;
    }
} /* sxfs_sx_err */

int sxfs_resize (void **ptr, size_t *size, size_t elsize) {
    void *new_ptr = realloc(*ptr, (*size + ALLOC_AMOUNT) * elsize);
    if(!new_ptr) {
        errno = ENOMEM;
        return -1;
    }
    *ptr = new_ptr;
    memset((char*)*ptr + *size * elsize, 0, ALLOC_AMOUNT * elsize);
    *size += ALLOC_AMOUNT;
    return 0;
} /* sxfs_resize */

char* sxfs_hash (sxfs_state_t *sxfs, const char *name) {
    char *ret;
    unsigned char checksum[SXI_SHA1_BIN_LEN];

    ret = (char*)malloc(SXI_SHA1_TEXT_LEN + 1);
    if(!ret) {
        errno = ENOMEM;
        return NULL;
    }
    if(sxi_sha1_calc(sxfs->tempdir, strlen(sxfs->tempdir), name, strlen(name), checksum)) {
        errno = ENOMEM;
        free(ret);
        return NULL;
    }
    sxi_bin2hex(checksum, SXI_SHA1_BIN_LEN, ret);
    ret[SXI_SHA1_TEXT_LEN] = '\0';
    return ret;
} /* sxfs_hash */

int sxfs_build_path (const char* path) {
    int ret = -1;
    char *ptr, *path2 = strdup(path);
    if(!path2) {
        SXFS_LOG("Out of memory: %s", path);
        return ret;
    }
    ptr = strchr(path2 + 1, '/');
    while(ptr) {
        *ptr = '\0';
        if(mkdir(path2, 0700) && errno != EEXIST) {
            SXFS_LOG("Cannot create '%s' directory: %s", path2, strerror(errno));
            goto sxfs_build_path_err;
        }
        *ptr = '/';
        ptr = strchr(ptr + 1, '/');
    }
    if(sxfs_rmdirs(path) && errno != ENOENT) {
        SXFS_LOG("Cannot remove '%s': %s", path, strerror(errno));
        goto sxfs_build_path_err;
    }

    ret = 0;
sxfs_build_path_err:
    free(path2);
    return ret;
} /* sxfs_build_path */

static int sxfs_rm_cb (const char *path, const struct stat *st, int flag, struct FTW *ftwbuf) {
    return remove(path);
} /* sxfs_rm_cb */

int sxfs_rmdirs (const char *path) {
    return nftw(path, sxfs_rm_cb, 10, FTW_DEPTH | FTW_PHYS);
} /* sxfs_rmdirs */

int sxfs_get_file (sxfs_file_t *sxfs_file, sxc_client_t *sx, sxc_cluster_t *cluster, int start_block, int end_block) {
    int i, ret = -1;
    unsigned long int block_size;
    sxc_file_t *dest = NULL;

    if(start_block >= sxfs_file->nblocks) {
        SXFS_LOG("Block number out of range");
        errno = EINVAL;
        return ret;
    }
    if(end_block > sxfs_file->nblocks) {
        end_block = sxfs_file->nblocks;
        SXFS_DEBUG("End of the blocks out of bounds [corrected]");
    }
    switch(sxfs_file->fdata->blocksize) {
        case SX_BS_SMALL: block_size = SXFS_BS_SMALL_AMOUNT * SX_BS_SMALL; break;
        case SX_BS_MEDIUM: block_size = SXFS_BS_MEDIUM_AMOUNT * SX_BS_MEDIUM; break;
        case SX_BS_LARGE: block_size = SXFS_BS_LARGE_AMOUNT * SX_BS_LARGE; break;
        default: SXFS_LOG("Unknown block size"); errno = EINVAL; return ret;
    }
    for(i=start_block; i<end_block; i++) {
        pthread_mutex_lock(&sxfs_file->block_mutex);
        if(!(sxfs_file->blocks[i] & 7)) {
            sxfs_file->blocks[i] |= 1; /* downloading the block in progress */
            pthread_mutex_unlock(&sxfs_file->block_mutex);
            if(!sxfs_file->blocks_path[i]) {
                int fd;
                sxfs_file->blocks_path[i] = strdup(SXFS_DATA->read_block_template);
                if(!sxfs_file->blocks_path[i]) {
                    SXFS_LOG("Out of memory: %s", SXFS_DATA->read_block_template);
                    goto sxfs_get_file_err;
                }
                fd = mkstemp(sxfs_file->blocks_path[i]);
                if(fd < 0) {
                    SXFS_LOG("Cannot create unique temporary file: %s", strerror(errno));
                    free(sxfs_file->blocks_path[i]);
                    sxfs_file->blocks_path[i] = NULL;
                    goto sxfs_get_file_err;
                }
                if(close(fd)) {
                    SXFS_LOG("Cannot close '%s' file: %s", sxfs_file->blocks_path[i], strerror(errno));
                    goto sxfs_get_file_err;
                }
            }
            sxc_file_free(dest);
            dest = sxc_file_local(sx, sxfs_file->blocks_path[i]);
            if(!dest) {
                SXFS_LOG("Cannot create local file object: %s", sxc_geterrmsg(sx));
                sxfs_file->blocks[i] &= ~1; /* downloading the block is already not in progress */
                errno = sxfs_sx_err(sx);
                goto sxfs_get_file_err;
            }
            if(sxi_sxfs_download_run(sxfs_file->fdata, cluster, dest, i * block_size, block_size)) {
                SXFS_LOG("Cannot download part of the file: %s", sxc_geterrmsg(sx));
                sxfs_file->blocks[i] &= ~1; /* downloading the block is already not in progress */
                errno = sxfs_sx_err(sx);
                goto sxfs_get_file_err;
            }
            pthread_mutex_lock(&sxfs_file->block_mutex);
            sxfs_file->blocks[i] |= 2; /* file has been downloaded */
            sxfs_file->blocks[i] &= 6; /* clean up error code & downloading the block has been finished */
            pthread_mutex_unlock(&sxfs_file->block_mutex);
        } else {
            while(sxfs_file->blocks[i] & 1) {
                pthread_mutex_unlock(&sxfs_file->block_mutex);
                usleep(THREAD_WAIT_USEC); /* wait for the file */
                pthread_mutex_lock(&sxfs_file->block_mutex);
            }
            if(!(sxfs_file->blocks[i] & 2)) {
                errno = sxfs_file->blocks[i] >> 3;
                pthread_mutex_unlock(&sxfs_file->block_mutex);
                goto sxfs_get_file_err; /* downloading failed, there is no file to read */
            }
            pthread_mutex_unlock(&sxfs_file->block_mutex); /* 'goto' inside if() statement */
        }
    }
    
    ret = 0;
sxfs_get_file_err:
    sxc_file_free(dest);
    return ret;
} /* sxfs_get_file */

struct _sxfs_thread_data_t {
    int block_num;
    sxfs_state_t *sxfs;
    sxfs_file_t *sxfs_file;
};
typedef struct _sxfs_thread_data_t sxfs_thread_data_t;

static void *sxfs_get_file_thread (void *ptr) {
    int err = 0;
    sxc_client_t *sx = NULL;
    sxc_cluster_t *cluster = NULL;
    sxc_file_t *dest = NULL;
    sxfs_thread_data_t *tdata = (sxfs_thread_data_t*)ptr;

    if(sxfs_get_sx_data(tdata->sxfs, &sx, &cluster)) {
        sxfs_log(tdata->sxfs, __FUNCTION__, 0, "Cannot get Sx data");
        err = errno;
        goto sxfs_get_file_thread_err;
    }
    dest = sxc_file_local(sx, tdata->sxfs_file->blocks_path[tdata->block_num]);
    if(!dest) {
        sxfs_log(tdata->sxfs, __FUNCTION__, 0, "Cannot create local file object: %s", sxc_geterrmsg(sx));
        err = sxfs_sx_err(sx);
        goto sxfs_get_file_thread_err;
    }
    if(sxi_sxfs_download_run(tdata->sxfs_file->fdata, cluster, dest, tdata->block_num * tdata->sxfs_file->blocksize, tdata->sxfs_file->blocksize)) {
        sxfs_log(tdata->sxfs, __FUNCTION__, 0, "Cannot download part of the file");
        err = sxfs_sx_err(sx);
        goto sxfs_get_file_thread_err;
    }

sxfs_get_file_thread_err:
    sxc_file_free(dest);
    pthread_mutex_lock(&tdata->sxfs_file->block_mutex);
    tdata->sxfs_file->blocks[tdata->block_num] = (err << 3) | (tdata->sxfs_file->blocks[tdata->block_num] & 4) | (err ? 0 : 2); /* save error code & set block status */
    pthread_mutex_unlock(&tdata->sxfs_file->block_mutex);
    pthread_mutex_lock(&tdata->sxfs->limits_mutex);
    tdata->sxfs->threads_num--;
    pthread_mutex_unlock(&tdata->sxfs->limits_mutex);
    free(tdata);
    return NULL;
} /* sxfs_get_file_thread */

int sxfs_get_block_background (sxfs_file_t *sxfs_file, int block_num) {
    int ret = -1, tmp;
    sxfs_thread_data_t *tdata = NULL;
    pthread_t thread;

    if(block_num >= sxfs_file->nblocks) {
        SXFS_LOG("Block number out of range");
        errno = EINVAL;
        return ret;
    }
    pthread_mutex_lock(&sxfs_file->block_mutex);
    if(sxfs_file->blocks[block_num] & 7) {
        pthread_mutex_unlock(&sxfs_file->block_mutex);
        return 0;
    }
    pthread_mutex_lock(&SXFS_DATA->limits_mutex);
    if(SXFS_DATA->threads_num < SXFS_THREADS_LIMIT) {
        SXFS_DATA->threads_num++;
    } else {
        pthread_mutex_unlock(&sxfs_file->block_mutex);
        pthread_mutex_unlock(&SXFS_DATA->limits_mutex);
        SXFS_DEBUG("Reached threads limit");
        return 0;
    }
    sxfs_file->blocks[block_num] |= 1; /* downloading the block in progress */
    pthread_mutex_unlock(&sxfs_file->block_mutex);
    pthread_mutex_unlock(&SXFS_DATA->limits_mutex);
    if(!sxfs_file->blocks_path[block_num]) {
        int fd;
        sxfs_file->blocks_path[block_num] = strdup(SXFS_DATA->read_block_template);
        if(!sxfs_file->blocks_path[block_num]) {
            SXFS_LOG("Out of memory: %s", SXFS_DATA->read_block_template);
            goto sxfs_get_file_background_err;
        }
        fd = mkstemp(sxfs_file->blocks_path[block_num]);
        if(fd < 0) {
            SXFS_LOG("Cannot create unique temporary file: %s", strerror(errno));
            free(sxfs_file->blocks_path[block_num]);
            sxfs_file->blocks_path[block_num] = NULL;
            goto sxfs_get_file_background_err;
        }
        if(close(fd)) {
            SXFS_LOG("Cannot close '%s' file: %s", sxfs_file->blocks_path[block_num], strerror(errno));
            goto sxfs_get_file_background_err;
        }
    }
    tdata = (sxfs_thread_data_t*)calloc(1, sizeof(sxfs_thread_data_t));
    if(!tdata) {
        SXFS_LOG("Out of memory");
        errno = ENOMEM;
        goto sxfs_get_file_background_err;
    }
    tdata->block_num = block_num;
    tdata->sxfs = SXFS_DATA;
    tdata->sxfs_file = sxfs_file;
    if((tmp = pthread_create(&thread, NULL, sxfs_get_file_thread, (void*)tdata))) {
        SXFS_LOG("Cannot start new thread: %s", strerror(tmp));
        errno = tmp;
        goto sxfs_get_file_background_err;
    }
    if((tmp = pthread_detach(thread))) {
        SXFS_LOG("Cannot detach the thread: %s", strerror(tmp));
    }

    ret = 0;
sxfs_get_file_background_err:
    if(ret) {
        pthread_mutex_lock(&sxfs_file->block_mutex);
        sxfs_file->blocks[block_num] &= ~1;
        pthread_mutex_unlock(&sxfs_file->block_mutex);
        pthread_mutex_lock(&SXFS_DATA->limits_mutex);
        SXFS_DATA->threads_num--;
        pthread_mutex_unlock(&SXFS_DATA->limits_mutex);
        free(tdata);
    }
    return ret;
} /* sxfs_get_block_background */

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
    sxfs_sx_data_t *sx_data = (sxfs_sx_data_t*)pthread_getspecific(sxfs->pkey);
    if(!sx_data) {
        pthread_mutex_lock(&sxfs->sx_data_mutex);
        do {
            sx_data = (sxfs_sx_data_t*)calloc(sizeof(sxfs_sx_data_t), 1);
            if(!sx_data) {
                sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory");
                errno = ENOMEM;
                break;
            }
            sx_data->sx = sxc_client_init(sxc_default_logger(&sx_data->log, sxfs->pname), sxc_input_fn, NULL);
            if(!sx_data->sx) {
                sxfs_log(sxfs, __FUNCTION__, 0, "Cannot initialize Sx");
                errno = ENOMEM;
                break;
            }
            if(sxfs->args->config_dir_given && sxc_set_confdir(sx_data->sx, sxfs->args->config_dir_arg)) {
                sxfs_log(sxfs, __FUNCTION__, 0, "Could not set configuration directory to '%s': %s", sxfs->args->config_dir_arg, sxc_geterrmsg(sx_data->sx));
                errno = sxfs_sx_err(sx_data->sx);
                break;
            }
            sxc_set_debug(sx_data->sx, sxfs->args->sx_debug_flag);
            sx_data->cluster = sxc_cluster_load_and_update(sx_data->sx, sxfs->uri->host, sxfs->uri->profile);
            if(!sx_data->cluster) {
                sxfs_log(sxfs, __FUNCTION__, 0, "Cannot load config for %s: %s\n", sxfs->uri->host, sxc_geterrmsg(sx_data->sx));
                errno = sxfs_sx_err(sx_data->sx);
                break;
            }
            sx_data->sx_data_mutex = &sxfs->sx_data_mutex;
        } while(0);
        if(sx_data) {
            if(sx_data->cluster) {
                int tmp;
                if((tmp = pthread_setspecific(sxfs->pkey, (void*)sx_data))) {
                    sxfs_log(sxfs, __FUNCTION__, 0, "Cannot set per-thread memory: %s", strerror(tmp));
                    sxc_client_shutdown(sx_data->sx, 0);
                    sxc_cluster_free(sx_data->cluster);
                    free(sx_data);
                    sx_data = NULL;
                    errno = tmp;
                }
            } else {
                sxc_client_shutdown(sx_data->sx, 0);
                free(sx_data);
                sx_data = NULL;
            }
        }
        pthread_mutex_unlock(&sxfs->sx_data_mutex);
        if(!sx_data)
            return -1;
    }
    *sx = sx_data->sx;
    *cluster = sx_data->cluster;
    return 0;
} /* sxfs_get_sx_data */

void sxfs_lsfile_free (sxfs_lsfile_t *file) {
    if(!file)
        return;
    if(file->opened) {
        file->opened = 2;
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
    int ret = -1;
    time_t mctime;
    char *name;
    sxfs_lsfile_t *file;

    if(time(&mctime) < 0) {
        SXFS_LOG("Cannot get current time: %s", strerror(errno));
        return -1;
    }
    name = strrchr(path, '/') + 1;
    if(dir->nfiles == dir->maxfiles && sxfs_resize((void**)&dir->files, &dir->maxfiles, sizeof(sxfs_lsfile_t*))) {
        SXFS_LOG("OOM growing files cache table: %s", strerror(errno));
        return -1;
    }
    file = (sxfs_lsfile_t*)calloc(1, sizeof(sxfs_lsfile_t));
    if(!file) {
        SXFS_LOG("Out of memory");
        errno = ENOMEM;
        return -1;
    }
    file->name = strdup(name);
    if(!file->name) {
        SXFS_LOG("Out of memory: %s", name);
        goto sxfs_lsdir_add_file_err;
    }
    if(st) {
        file->st.st_size = st->st_size;
        file->st.st_mtime = file->st.st_ctime = st->st_mtime;
    } else {
/*        file->st.st_size = 0;*/ /* calloc() has been used */
        file->st.st_mtime = file->st.st_ctime = mctime;
    }
    file->st.st_uid = getuid();
    file->st.st_gid = getgid();
    file->st.st_nlink = 1;
    file->st.st_mode = FILE_ATTR;
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
    int ret = -1, slash = 0;
    time_t mctime;
    char *path2, *name;
    sxfs_lsdir_t *subdir = NULL;

    if(path[strlen(path)-1] == '/') {
        slash = 1;
        path2 = strdup(path);
        if(!path2) {
            SXFS_LOG("Out of memory: %s", path);
            return ret;
        }
        path2[strlen(path2)-1] = '\0';
        name = strrchr(path2, '/') + 1;
    } else {
        path2 = (char*)malloc(strlen(path) + 2);
        if(!path2) {
            SXFS_LOG("Out of memory");
            errno = ENOMEM;
            return ret;
        }
        sprintf(path2, "%s/", path);
        name = strrchr(path, '/') + 1;
    }
    if(time(&mctime) < 0) {
        SXFS_LOG("Cannot get current time: %s", strerror(errno));
        goto sxfs_lsdir_add_dir_err;
    }
    if(dir->ndirs == dir->maxdirs && sxfs_resize((void**)&dir->dirs, &dir->maxdirs, sizeof(sxfs_lsdir_t*))) {
        SXFS_LOG("OOM growing dirs cache table: %s", strerror(errno));
        goto sxfs_lsdir_add_dir_err;
    }
    subdir = (sxfs_lsdir_t*)calloc(1, sizeof(sxfs_lsdir_t));
    if(!subdir) {
        SXFS_LOG("Out of memory");
        errno = ENOMEM;
        goto sxfs_lsdir_add_dir_err;
    }
    subdir->maxdirs = subdir->maxfiles = ALLOC_AMOUNT;
    subdir->dirs = (sxfs_lsdir_t**)calloc(subdir->maxdirs, sizeof(sxfs_lsdir_t*));
    if(!subdir->dirs) {
        SXFS_LOG("Out of memory");
        errno = ENOMEM;
        goto sxfs_lsdir_add_dir_err;
    }
    subdir->files = (sxfs_lsfile_t**)calloc(subdir->maxfiles, sizeof(sxfs_lsfile_t*));
    if(!subdir->files) {
        SXFS_LOG("Out of memory");
        errno = ENOMEM;
        goto sxfs_lsdir_add_dir_err;
    }
    subdir->name = strdup(name);
    if(!subdir->name) {
        SXFS_LOG("Out of memory: %s", name);
        goto sxfs_lsdir_add_dir_err;
    }
    subdir->etag = sxfs_hash(SXFS_DATA, slash ? path : path2);
    if(!subdir->etag) {
        SXFS_LOG("Cannot compute hash of '%s'", slash ? path : path2);
        goto sxfs_lsdir_add_dir_err;
    }
    subdir->st.st_mtime = subdir->st.st_ctime = mctime;
    subdir->parent = dir;
    subdir->st.st_uid = getuid();
    subdir->st.st_gid = getgid();
    subdir->st.st_nlink = 1;
    subdir->st.st_mode = DIR_ATTR;
    subdir->st.st_size = DIRECTORY_SIZE;
    subdir->st.st_blocks = (DIRECTORY_SIZE + 511) / 512;
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

    if(file_name[filelen-1] == '/' && len == filelen + lenof(EMPTY_DIR_FILE) && !strcmp(str + len - lenof(EMPTY_DIR_FILE), EMPTY_DIR_FILE))
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
        SXFS_LOG("NULL argument");
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

static sxfs_lsdir_t* sxfs_ls_ftw (sxfs_state_t *sxfs, const char *path) {
    ssize_t index;
    char *ptr, *slash, *path2;
    sxfs_lsdir_t *dir = sxfs->root;

    path2 = strdup(path);
    if(!path2) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory: %s", path);
        return NULL;
    }
    ptr = path2 + 1;
    slash = strchr(ptr, '/');
    while(slash) {
        *slash = '\0';
        index = sxfs_find_entry((const void**)dir->dirs, dir->ndirs, ptr, sxfs_lsdir_cmp);
        if(index < 0) {
            if(sxfs_find_entry((const void**)dir->files, dir->nfiles, ptr, sxfs_lsfile_cmp) >= 0) {
                sxfs_log(sxfs, __FUNCTION__, 0, "%s: %s", strerror(ENOTDIR), ptr);
                errno = ENOTDIR;
            } else {
                sxfs_log(sxfs, __FUNCTION__, 0, "%s: %s", strerror(ENOENT), ptr);
                errno = ENOENT;
            }
            free(path2);
            return NULL;
        }
        dir = dir->dirs[index];
        *slash = '/';
        ptr = slash + 1;
        slash = strchr(ptr, '/');
    }
    free(path2);
    return dir;
} /* sxfs_ls_ftw */

sxfs_lsdir_t* sxfs_ls_update (const char *absolute_path) {
    int locked = 0, tmp, *check_files = NULL, *check_dirs = NULL;
    ssize_t index;
    size_t i, j, ncfiles, ncdirs, pathlen;
    char *path = NULL, *ptr, *fpath = NULL, *fname;
    struct stat st;
    struct timeval tv;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_cluster_lf_t *flist = NULL;
    sxfs_lsdir_t *ret = NULL, *dir = NULL, *subdir;

    if(sxfs_get_sx_data(SXFS_DATA, &sx, &cluster)) {
        SXFS_LOG("Cannot get Sx data");
        return ret;
    }
    pathlen = strlen(SXFS_DATA->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + strlen(absolute_path) + 1;
    path = (char*)malloc(pathlen);
    if(!path) {
        SXFS_LOG("Out of memory");
        errno = ENOMEM;
        return ret;
    }

    /* check whether directory is already loaded */
    if(!(dir = sxfs_ls_ftw(SXFS_DATA, absolute_path))) { /* FUSE checks each directory in the path */
        SXFS_LOG("File tree walk failed: %s", strerror(errno));
        goto sxfs_ls_update_err;
    }
    if(dir->init) {
        if(gettimeofday(&tv, NULL)) {
            SXFS_LOG("Cannot get current time: %s", strerror(errno));
            goto sxfs_ls_update_err;
        }
        if((tv.tv_sec - dir->tv.tv_sec) * 1000000L + tv.tv_usec - dir->tv.tv_usec < LS_RELOAD_TIME) {
            ret = dir;
            dir = NULL; /* do not convert remote flag (2 -> 1) */
            goto sxfs_ls_update_err; /* this is not a failure */
        }
    }

    ncfiles = dir->nfiles;
    ncdirs = dir->ndirs;
    check_files = (int*)calloc(ncfiles, sizeof(int));
    if(!check_files) {
        SXFS_LOG("Out of memory");
        errno = ENOMEM;
        goto sxfs_ls_update_err;
    }
    check_dirs = (int*)calloc(ncdirs, sizeof(int));
    if(!check_dirs) {
        SXFS_LOG("Out of memory");
        errno = ENOMEM;
        goto sxfs_ls_update_err;
    }
    /* save opened but not yet uploaded files */
    pthread_mutex_lock(&SXFS_DATA->files_mutex);
    for(i=0; i<ncfiles; i++)
        if(dir->files[i]->opened == 1) /* if opened == 2 it means that file has been removed by  another tool, e.g. sxrm */
            check_files[i] = 1;
    pthread_mutex_unlock(&SXFS_DATA->files_mutex);
    /* load directory content from upload queue */
    if(SXFS_DATA->args->use_queues_flag) {
        tmp = strrchr(absolute_path, '/') - absolute_path + 1;
        i = 0;
        pthread_mutex_lock(&SXFS_DATA->upload_mutex);
        locked = 1;
        while(i < nfiles_up && strncmp(upload_list[i], absolute_path, tmp) < 0)
            i++;
        for(; i<nfiles_up && !strncmp(upload_list[i], absolute_path, tmp); i++) {
            if(strchr(upload_list[i] + tmp, '/')) { /* directory */
                while(pathlen < strlen(upload_list[i]) + 1) {
                    if(sxfs_resize((void**)&path, &pathlen, sizeof(char))) {
                        SXFS_LOG("OOM growing the path: %s", strerror(errno));
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
                    SXFS_LOG("'%s' directory is missing in ls cache");
                    errno = EAGAIN;
                    goto sxfs_ls_update_err;
                }
            } else { /* file */
                ptr = strrchr(upload_list[i] ,'/') + 1;
                if(!strcmp(ptr, EMPTY_DIR_FILE)) {
                    dir->sxnewdir = 1;
                } else {
                    index = sxfs_find_entry((const void**)dir->files, ncfiles, ptr, sxfs_lsfile_cmp);
                    if(index >= 0) {
                        check_files[index] = 1;
                    } else {
                        SXFS_LOG("'%s' file is missing in ls cache");
                        errno = EAGAIN;
                        goto sxfs_ls_update_err;
                    }
                }
            }
        }
    }

    sprintf(path, "%s", absolute_path);
    ptr = strrchr(path, '/') + 1;
    *ptr = '\0';
    flist = sxc_cluster_listfiles_etag(cluster, SXFS_DATA->uri->volume, path, 0, NULL, NULL, NULL, NULL, 0, dir->etag);
    if(!flist) {
        if(sxc_geterrnum(sx) != SXE_SKIP) {
            SXFS_LOG("%s", sxc_geterrmsg(sx));
            errno = sxfs_sx_err(sx);
            goto sxfs_ls_update_err;
        }
        if(!dir || !dir->init) {
            flist = sxc_cluster_listfiles(cluster, SXFS_DATA->uri->volume, path, 0, NULL, NULL, NULL, NULL, 0);
            if(!flist) {
                SXFS_LOG("%s", sxc_geterrmsg(sx));
                errno = sxfs_sx_err(sx);
                goto sxfs_ls_update_err;
            }
        } else {
            ret = dir;
            if(gettimeofday(&tv, NULL)) {
                SXFS_LOG("Cannot get current time: %s", strerror(errno));
                goto sxfs_ls_update_err;
            }
            dir->tv = tv;
            dir = NULL; /* do not convert remote flag (2 -> 1) */
            goto sxfs_ls_update_err; /* this is not a failure */
        }
    }

    /* load the content of the directory */
    while(1) {
        tmp = sxc_cluster_listfiles_next(flist, &fpath, &st.st_size, &st.st_mtime, NULL);
        if(tmp <= 0) {
            if(tmp) {
                SXFS_LOG("Failed to retrieve file name: %s", sxc_geterrmsg(sx));
                errno = sxfs_sx_err(sx);
                goto sxfs_ls_update_err;
            }
            break;
        }
        tmp = strlen(fpath) - 1;
        if(fpath[tmp] == '/') {
            fpath[tmp] = '\0';
            st.st_mode = DIR_ATTR;
        } else {
            tmp = 0;
            st.st_mode = FILE_ATTR;
        }
        fname = strrchr(fpath, '/');
        if(!fname)
            fname = fpath + 1;
        else
            fname++;
        if(tmp)
            fpath[tmp] = '/';
        if(!SXFS_DATA->args->use_queues_flag || sxfs_find_entry((const void**)delete_list, nfiles_del, fpath, sxfs_str_cmp) < 0) {
            if(!strcmp(fname, EMPTY_DIR_FILE)) {
                dir->remote = 2;
                dir->sxnewdir = 2; /* file is on the server */
            } else {
                if(S_ISDIR(st.st_mode)) {
                    fpath[tmp] = '\0';
                    index = sxfs_find_entry((const void**)dir->dirs, ncdirs, fname, sxfs_lsdir_cmp);
                    fpath[tmp] = '/';
                    if(index >= 0) {
                        check_dirs[index] = 1;
                        if(st.st_mtime > dir->dirs[index]->st.st_mtime)
                            dir->dirs[index]->st.st_mtime = st.st_mtime;
                        dir->dirs[index]->remote = 2;
                    } else {
                        if(sxfs_lsdir_add_dir(dir, fpath)) {
                            SXFS_LOG("Cannot add new directory to cache: %s", fpath);
                            goto sxfs_ls_update_err;
                        }
                        dir->dirs[dir->ndirs-1]->remote = 2;
                    }
                } else {
                    index = sxfs_find_entry((const void**)dir->files, ncfiles, fname, sxfs_lsfile_cmp);
                    if(index >= 0) {
                        check_files[index] = 1;
                        if(st.st_mtime > dir->files[index]->st.st_mtime) {
                            dir->files[index]->st.st_size = st.st_size;
                            dir->files[index]->st.st_mtime = st.st_mtime;
                        }
                        dir->files[index]->remote = 2;
                    } else {
                        if(sxfs_lsdir_add_file(dir, fpath, &st)) {
                            SXFS_LOG("Cannot add new file to cache: %s", fpath);
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
    qsort(dir->files, dir->nfiles, sizeof(sxfs_lsfile_t*), sxfs_lsfile_compare);
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
        SXFS_LOG("Cannot get current time: %s", strerror(errno)); /* no fail, because content is already fully loaded */
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

    ret = dir;
sxfs_ls_update_err:
    if(locked)
        pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
    free(path);
    free(fpath);
    free(check_files);
    free(check_dirs);
    sxc_cluster_listfiles_free(flist);
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
    int ret = -1;
    ssize_t index;
    char *file_name;
    sxfs_lsdir_t *dir;

    if(!strcmp(path, "/")) {
        if(st) {
            pthread_mutex_lock(&SXFS_DATA->ls_mutex);
            memcpy(st, &SXFS_DATA->root->st, sizeof(struct stat));
            pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
        }
        return 2;
    }
    pthread_mutex_lock(&SXFS_DATA->ls_mutex);
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(!(dir = sxfs_ls_update(path))) {
        SXFS_LOG("Cannot load file tree: %s", path);
        pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
        pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
        return ret;
    }
    pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
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
            ret = 0;
    }
    pthread_mutex_unlock(&SXFS_DATA->ls_mutex);
    return ret;
} /* sxfs_ls_stat */

int sxfs_update_mtime (const char *local_file_path, const char *remote_file_path, time_t *mtime) {
    int ret = -1, tmp;
    time_t tmpmtime;
    char *fpath = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_cluster_lf_t *flist = NULL;
    sxc_file_t *file_local, *file_remote;

    if(sxfs_get_sx_data(SXFS_DATA, &sx, &cluster)) {
        SXFS_LOG("Cannot get Sx data");
        return ret;
    }
    file_local = sxc_file_local(sx, local_file_path);
    if(!file_local) {
        SXFS_LOG("Cannot create local file object: %s", sxc_geterrmsg(sx));
        errno = sxfs_sx_err(sx);
        return ret;
    }
    file_remote = sxc_file_remote(cluster, SXFS_DATA->uri->volume, remote_file_path+1, NULL);
    if(!file_remote) {
        SXFS_LOG("Cannot create file object: %s", sxc_geterrmsg(sx));
        errno = sxfs_sx_err(sx);
        goto sxfs_update_mtime_err;
    }
    if(sxc_copy(file_local, file_remote, 0, 0, 0, NULL, 1)) {
        SXFS_LOG("%s", sxc_geterrmsg(sx));
        errno = sxfs_sx_err(sx);
        goto sxfs_update_mtime_err;
    }
    flist = sxc_cluster_listfiles(cluster, SXFS_DATA->uri->volume, remote_file_path, 0, NULL, NULL, NULL, NULL, 0);
    if(!flist) {
        SXFS_LOG("%s", sxc_geterrmsg(sx));
        errno = -sxfs_sx_err(sx);
        goto sxfs_update_mtime_err;
    }
    tmp = sxc_cluster_listfiles_next(flist, &fpath, NULL, &tmpmtime, NULL);
    if(tmp) {
        if(tmp < 0) {
            SXFS_LOG("Cannot retrieve file name: %s", sxc_geterrmsg(sx));
            errno = -sxfs_sx_err(sx);
            goto sxfs_update_mtime_err;
        }
        if(fpath[strlen(fpath)-1] == '/') {
            SXFS_LOG("Not a file");
            errno = EISDIR;
            goto sxfs_update_mtime_err;
        }
    } else {
        SXFS_LOG("No such a file");
        errno = ENOENT;
        goto sxfs_update_mtime_err;
    }
    if(mtime && tmpmtime > *mtime)
        *mtime = tmpmtime;

    ret = 0;
sxfs_update_mtime_err:
    free(fpath);
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
    int ret = -1, tmp;
    size_t i, j;
    char *fpath = NULL;
    sxc_cluster_lf_t *flist;

    sxfs_log(sxfs, __FUNCTION__, 1, "Checking deletion list");
    for(i=0; i<nfiles_del; i++) {
        flist = sxc_cluster_listfiles(cluster, sxfs->uri->volume, delete_list[i], 0, NULL, NULL, NULL, NULL, 0);
        if(!flist) {
            sxfs_log(sxfs, __FUNCTION__, 0, "Cannot check '%s' file existence on the server: %s", delete_list[i], sxc_geterrmsg(sx));
            errno = sxfs_sx_err(sx);
            goto sxfs_delete_check_err;
        }
        tmp = sxc_cluster_listfiles_next(flist, &fpath, NULL, NULL, NULL);
        sxc_cluster_listfiles_free(flist);
        if(tmp) {
            if(tmp < 0) {
                sxfs_log(sxfs, __FUNCTION__, 0, "Failed to retrieve file name");
                errno = sxfs_sx_err(sx);
                goto sxfs_delete_check_err;
            }
            if(fpath[strlen(fpath)-1] == '/') {
                free(delete_list[i]);
                delete_list[i] = NULL;
            }
        } else {
            free(delete_list[i]);
            delete_list[i] = NULL;
        }
    }

    ret = 0;
sxfs_delete_check_err:
    free(fpath);
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
    return ret;
} /* sxfs_delete_check */

static int sxfs_delete_dir_rec (char **path, size_t *pathlen, size_t *free_space) {
    size_t i, endlen = strlen(*path);
    sxfs_lsdir_t *dir = sxfs_ls_update(*path);

    if(!dir) {
        SXFS_LOG("Cannot load file tree: %s", *path);
        return -1;
    }
    if(dir->sxnewdir == 2) {
        while(lenof(EMPTY_DIR_FILE) > *free_space) {
            if(sxfs_resize((void**)path, pathlen, 1)) {
                SXFS_LOG("OOM growing the path: %s", strerror(errno));
                return -1;
            }
            *free_space += ALLOC_AMOUNT;
        }
        strcat(*path, EMPTY_DIR_FILE);
        if(sxfs_delete(*path, 1)) {
            SXFS_LOG("Cannot delete '%s' file", *path);
            return -1;
        }
        *(*path + endlen) = '\0';
    }
    for(i=0; i<dir->nfiles; i++) {
        while(strlen(dir->files[i]->name) > *free_space) {
            if(sxfs_resize((void**)path, pathlen, 1)) {
                SXFS_LOG("OOM growing the path: %s", strerror(errno));
                return -1;
            }
            *free_space += ALLOC_AMOUNT;
        }
        strcat(*path, dir->files[i]->name);
        if(sxfs_delete(*path, dir->files[i]->remote)) {
            SXFS_LOG("Cannot delete '%s' file", *path);
            return -1;
        }
        *(*path + endlen) = '\0';
    }
    for(i=0; i<dir->ndirs; i++) {
        while(strlen(dir->dirs[i]->name) + 1 > *free_space) {
            if(sxfs_resize((void**)path, pathlen, 1)) {
                SXFS_LOG("OOM growing the path: %s", strerror(errno));
                return -1;
            }
            *free_space += ALLOC_AMOUNT;
        }
        sprintf(*path, "%s%s/", *path, dir->dirs[i]->name);
        *free_space -= strlen(dir->dirs[i]->name) + 1;
        if(sxfs_delete_dir_rec(path, pathlen, free_space))
            return -1;
        *(*path + endlen) = '\0';
        *free_space += strlen(dir->dirs[i]->name) + 1;
    }
    return 0;
} /* sxfs_delete_dir_rec */

static int sxfs_queue_rename (char **queue, size_t size, const char *path, const char *newpath, int avoid_resize) {
    char buff[PATH_MAX];
    size_t i, from = 0, to, len = strlen(path);
    while(from < size && strcmp(path, queue[from]) > 0)
        from++;
    if(from == size) {
        errno = ENOENT;
        return 0;
    }
    if(path[len-1] == '/' ? strncmp(path, queue[from], len) : strcmp(path, queue[from])) {
        errno = ENOENT;
        return 0;
    }
    to = from + 1;
    if(path[len-1] == '/')
        while(to < size && !strncmp(path, queue[to], len))
            to++;
    if(!avoid_resize && len < strlen(newpath)) {
        size_t sizediff = strlen(newpath) - len;
        char *ptr;
        for(i=from; i<to; i++) {
            ptr = (char*)realloc(queue[i], strlen(queue[i]) + sizediff + 1);
            if(!ptr) {
                errno = ENOMEM;
                return -1;
            }
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
int sxfs_delete (const char *path, int is_remote) {
    int ret = -1;
    ssize_t index;
    size_t i, pathlen;
    char *local_file_path = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *file;
    sxc_file_list_t *flist = NULL;

    if(SXFS_DATA->args->use_queues_flag) {
        pathlen = strlen(path);
        if(path[pathlen-1] == '/') {
            size_t free_space = ALLOC_AMOUNT;
            char *workpath = (char*)malloc(pathlen + ALLOC_AMOUNT + 1);
            if(!workpath) {
                SXFS_LOG("Out of memory");
                errno = ENOMEM;
                return ret;
            }
            pathlen += ALLOC_AMOUNT;
            sprintf(workpath, "%s", path);
            if(sxfs_delete_dir_rec(&workpath, &pathlen, &free_space)) {
                SXFS_LOG("Cannot delete '%s' directory", workpath);
                free(workpath);
                return ret;
            }
            free(workpath);
            return 0;
        } else {
            if(delete_flag < 0 && sxfs_delete_start()) { /* check whether deletion thread still works */
                SXFS_LOG("Cannot restart deletion thread");
                return ret;
            }
            if(sxfs_find_entry((const void**)delete_list, nfiles_del, path, sxfs_str_cmp) >= 0) {
                SXFS_LOG("File already queued: %s", path);
                errno = EINVAL;
                return ret;
            }
            pthread_mutex_lock(&SXFS_DATA->upload_mutex);
            /* check whether this file is queued for upload */
            index = sxfs_find_entry((const void**)upload_list, nfiles_up, path, sxfs_str_cmp);
            if(index >= 0) {
                free(upload_list[index]);
                for(i=index+1; i<nfiles_up; i++)
                    upload_list[i-1] = upload_list[i];
                upload_list[nfiles_up-1] = NULL;
                nfiles_up--;
                SXFS_DEBUG("File removed from upload queue: %s", path);
            }
            local_file_path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + strlen(path) + 1);
            if(!local_file_path) {
                SXFS_LOG("Out of memory");
                errno = ENOMEM;
                return ret;
            }
            sprintf(local_file_path, "%s/%s%s", SXFS_DATA->tempdir, SXFS_UPLOAD_DIR, path);
            if(unlink(local_file_path)) {
                if(errno != ENOENT) {
                    SXFS_LOG("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
                    goto sxfs_delete_err;
                }
            } else
                SXFS_DEBUG("'%s' not yet uploaded - removing from upload queue", local_file_path);
            if(is_remote) {
                char *path_to_list;
                if(nfiles_del == maxfiles_del && sxfs_resize((void**)&delete_list, &maxfiles_del, sizeof(char*))) {
                    SXFS_LOG("OOM growing deletion list: %s", strerror(errno));
                    goto sxfs_delete_err;
                }
                path_to_list = strdup(path);
                if(!path_to_list) {
                    SXFS_LOG("Out of memory: %s", path);
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
            SXFS_LOG("Cannot get current time: %s", strerror(errno)); /* file succeffuly added into the list, in worst case deletion thread will pause next deletions */
        }
    } else if(is_remote) {
        char *tmp_path = parse_path(path);

        if(!tmp_path) {
            SXFS_LOG("Out of memory");
            return -1;
        }
        if(sxfs_get_sx_data(SXFS_DATA, &sx, &cluster)) {
            SXFS_LOG("Cannot get Sx data");
            pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
            free(tmp_path);
            return -1;
        }
        flist = sxc_file_list_new(sx, 1);
        if(!flist) {
            SXFS_LOG("Cannot create new file list: %s", sxc_geterrmsg(sx));
            free(tmp_path);
            errno = sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        file = sxc_file_remote(cluster, SXFS_DATA->uri->volume, tmp_path+1, NULL);
        if(!file) {
            SXFS_LOG("Cannot create file object: %s", sxc_geterrmsg(sx));
            free(tmp_path);
            errno = sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        if(sxc_file_list_add(flist, file, 1)) {
            SXFS_LOG("Cannot add file: %s", sxc_geterrmsg(sx));
            free(tmp_path);
            sxc_file_free(file);
            errno = sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        if(sxc_rm(flist, 0, 0)) {
            SXFS_LOG("Cannot remove file: %s", sxc_geterrmsg(sx));
            free(tmp_path);
            errno = sxfs_sx_err(sx);
            goto sxfs_delete_err;
        }
        free(tmp_path);
    }

    ret = 0;
sxfs_delete_err:
    if(SXFS_DATA->args->use_queues_flag)
        pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
    free(local_file_path);
    sxc_file_list_free(flist);
    return ret;
} /* sxfs_delete */

/* must be run when delete_mutex is locked */
static int sxfs_delete_run (sxfs_state_t *sxfs, sxc_client_t *sx, sxc_cluster_t *cluster, int ignore_error) {
    int ret = -1;
    size_t i;
    char *path;
    sxc_file_t *file;
    sxc_file_list_t *flist = NULL;

    sxfs_log(sxfs, __FUNCTION__, 1, "Deleting files:");
    for(i=0; i<nfiles_del; i++)
        sxfs_log(sxfs, __FUNCTION__, 1, "'%s'", delete_list[i]);
    flist = sxc_file_list_new(sx, 0);
    if(!flist) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot create new file list: %s", sxc_geterrmsg(sx));
        errno = sxfs_sx_err(sx);
        goto sxfs_delete_run_err;
    }
    for(i=0; i<nfiles_del; i++) {
        path = parse_path(delete_list[i]);
        if(!path) {
            sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory");
            free(path);
            goto sxfs_delete_run_err;
        }
        file = sxc_file_remote(cluster, sxfs->uri->volume, path+1, NULL);
        if(!file) {
            sxfs_log(sxfs, __FUNCTION__, 0, "Cannot create file object: %s", sxc_geterrmsg(sx));
            free(path);
            errno = sxfs_sx_err(sx);
            goto sxfs_delete_run_err;
        }
        if(sxc_file_list_add(flist, file, 1)) {
            sxfs_log(sxfs, __FUNCTION__, 0, "Cannot add file: %s", sxc_geterrmsg(sx));
            free(path);
            sxc_file_free(file);
            errno = sxfs_sx_err(sx);
            goto sxfs_delete_run_err;
        }
        free(path);
    }
    if(sxc_rm(flist, 0, 0) && sxc_geterrnum(sx) != SXE_EARG) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot remove file list: %s", sxc_geterrmsg(sx));
        sxfs_tick_dirs_reload(sxfs->root);
        sxfs_delete_check(sx, cluster, sxfs);
        if(!ignore_error)
            goto sxfs_delete_run_err;
    } else {
        for(i=0; i<nfiles_del; i++) {
            free(delete_list[i]);
            delete_list[i] = NULL;
        }
        nfiles_del = 0;
    }

    ret = 0;
sxfs_delete_run_err:
    sxc_file_list_free(flist);
    return ret;
} /* sxfs_delete_run */

/* delete_mutex must be locked when starting this function */
static void* sxfs_delete_thread (void *ptr) {
    int *ret = (int*)calloc(1, sizeof(int));
    size_t i;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxfs_state_t *sxfs = (sxfs_state_t*)ptr;
    struct timeval tv;

    if(!ret) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory");
        goto sxfs_delete_thread_err;
    }
    if(sxfs_get_sx_data(sxfs, &sx, &cluster)) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot get Sx data");
        *ret = errno;
        goto sxfs_delete_thread_err;
    }
    delete_list = (char**)calloc(ALLOC_AMOUNT, sizeof(char*));
    if(!delete_list) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory");
        *ret = ENOMEM;
        goto sxfs_delete_thread_err;
    }
    nfiles_del = 0;
    maxfiles_del = ALLOC_AMOUNT;
    pthread_mutex_lock(&sxfs->delete_mutex);
    delete_flag = 1;
    pthread_mutex_unlock(&sxfs->delete_mutex);
    sxfs_log(sxfs, __FUNCTION__, 2, "Deletion thread has been started");

    while(1) {
        usleep(JOB_SLEEP_USEC);
        pthread_mutex_lock(&sxfs->delete_mutex);
        if(delete_flag < 0) {
            pthread_mutex_unlock(&sxfs->delete_mutex);
            sxfs_log(sxfs, __FUNCTION__, 2, "Deletion thread has been stopped");
            goto sxfs_delete_thread_err;
        }
        if(nfiles_del) {
            if(gettimeofday(&tv, NULL)) {
                sxfs_log(sxfs, __FUNCTION__, 0, "Cannot get current time: %s", strerror(errno));
                *ret = errno;
                pthread_mutex_unlock(&sxfs->delete_mutex);
                goto sxfs_delete_thread_err;
            }
            if((tv.tv_sec - last_deletion_time.tv_sec) * 1000000L + tv.tv_usec - last_deletion_time.tv_usec >= LAST_ACTION_WAIT_USEC) {
                if(sxfs_delete_run(sxfs, sx, cluster, 1)) {
                    sxfs_log(sxfs, __FUNCTION__, 0, "Deletion failed");
                    *ret = errno;
                    pthread_mutex_unlock(&sxfs->delete_mutex);
                    goto sxfs_delete_thread_err;
                }
            }
        }
        pthread_mutex_unlock(&sxfs->delete_mutex);
    }

sxfs_delete_thread_err:
    pthread_mutex_lock(&sxfs->delete_mutex);
    if(delete_list) {
        for(i=0; i<nfiles_del; i++)
            free(delete_list[i]);
        free(delete_list);
    }
    nfiles_del = maxfiles_del = 0;
    delete_flag = -2;
    pthread_mutex_unlock(&sxfs->delete_mutex);
    return (void*)ret;
} /* sxfs_delete_thread */

int sxfs_delete_check_path (const char *path) {
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
        sxc_client_t *sx;
        sxc_cluster_t *cluster;

        if(sxfs_get_sx_data(SXFS_DATA, &sx, &cluster)) {
            SXFS_LOG("Cannot get Sx data");
            return -1;
        }
        if(sxfs_delete_run(SXFS_DATA, sx, cluster, 0)) {
            SXFS_LOG("Cannot force files deletion");
            return -1;
        }
    }
    return 0;
} /* sxfs_delete_check_path */

/* must be run when delete_mutex is locked */
int sxfs_delete_start (void) {
    int tmp;

    delete_flag = 0;
    if((tmp = pthread_create(&SXFS_DATA->delete_thread, NULL, sxfs_delete_thread, (void*)SXFS_DATA))) {
        SXFS_LOG("Cannot create deletion thread: %s", strerror(tmp));
        delete_flag = -2;
        errno = tmp;
        return -1;
    }
    while(!delete_flag) {
        pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
        usleep(THREAD_WAIT_USEC);
        pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    }
    if(delete_flag < 0) {
        int *status = NULL;
        if((tmp = pthread_join(SXFS_DATA->delete_thread, (void**)&status))) {
            SXFS_LOG("Cannot join deletion thread: %s", strerror(tmp));
            errno = tmp;
        } else {
            SXFS_LOG("Cannot start deletion thread: %s", strerror(status ? *status : ENOMEM));
            errno = status ? *status : ENOMEM;
            if(status)
                free(status);
        }
        return -1;
    }
    return 0;
} /* sxfs_delete_start */

void sxfs_delete_stop (void) {
    int tmp, *status = NULL;
    pthread_mutex_lock(&SXFS_DATA->delete_mutex);
    if(delete_flag > 0) {
        delete_flag = -1;
        pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
        if((tmp = pthread_join(SXFS_DATA->delete_thread, (void**)&status))) {
            SXFS_LOG("Cannot join deletion thread: %s", strerror(tmp));
        } else {
            if(status)
                free(status);
        }
    } else
        pthread_mutex_unlock(&SXFS_DATA->delete_mutex);
} /* sxfs_delete_stop */

/* must be run when upload_mutex is locked */
int sxfs_upload_del_path (const char *path) {
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
            SXFS_LOG("File not queued: %s", path);
            errno = ENOENT;
            return -1;
        }
    } else {
        i = 0;
        while(i<nfiles_up && strcmp(path, upload_list[i]) > 0)
            i++;
        if(strncmp(path, upload_list[i], len)) {
            SXFS_LOG("Directory not queued: %s", path);
            errno = ENOENT;
            return -1;
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
int sxfs_upload (const char *src, const char *dest, time_t *mtime, int force) {
    int ret = -1;
    size_t i;
    ssize_t index;
    char *ptr, *path = NULL, *path_to_list = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;

    if(sxfs_get_sx_data(SXFS_DATA, &sx, &cluster)) {
        SXFS_LOG("Cannot get Sx data");
        return ret;
    }
    if(SXFS_DATA->args->use_queues_flag) {
        if(upload_flag < 0 && sxfs_upload_start()) { /* check whether upload thread still works */
            SXFS_LOG("Cannot restart upload thread");
            return ret;
        }
        path_to_list = strdup(dest);
        if(!path_to_list) {
            SXFS_LOG("Out of memory: %s", dest);
            return ret;
        }
        path = (char*)malloc(strlen(SXFS_DATA->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR)  + strlen(dest) + 1);
        if(!path) {
            SXFS_LOG("Out of memory");
            errno = ENOMEM;
            free(path_to_list);
            return ret;
        }
        sprintf(path, "%s", dest);
        ptr = strrchr(path, '/');
        if(!ptr) {
            SXFS_LOG("'/' not found in '%s'", path);
            free(path);
            free(path_to_list);
            errno = EINVAL;
            return ret;
        }
        ptr++;
        if(!strcmp(ptr, EMPTY_DIR_FILE))
            *ptr = '\0';
        if(sxfs_delete_check_path(path)) {
            SXFS_LOG("Cannot check deletion queue: %s", path);
            free(path);
            free(path_to_list);
            return ret;
        }
        pthread_mutex_lock(&SXFS_DATA->upload_mutex);
        if((index = sxfs_find_entry((const void**)upload_list, nfiles_up, dest, sxfs_str_cmp)) >= 0 && !force) {
            SXFS_LOG("File already queued: %s", dest);
            errno = EINVAL;
            goto sxfs_upload_err;
        }
        if(nfiles_up == maxfiles_up && sxfs_resize((void**)&upload_list, &maxfiles_up, sizeof(char*))) {
            SXFS_LOG("OOM growing upload list: %s", strerror(errno));
            goto sxfs_upload_err;
        }
        sprintf(path, "%s/%s%s", SXFS_DATA->tempdir, SXFS_UPLOAD_DIR, dest);
        if(sxfs_build_path(path)) {
            SXFS_LOG("Cannot create path: %s", path);
            goto sxfs_upload_err;
        }
        if(sxfs_rmdirs(path) && errno != ENOENT) {
            SXFS_LOG("Cannot remove '%s': %s", path, strerror(errno));
            goto sxfs_upload_err;
        }
        if(!src) { /* uploading empty file */
            int fd = open(path, O_WRONLY | O_CREAT, 0600);
            if(fd < 0) {
                SXFS_LOG("Cannot create '%s' file: %s", path, strerror(errno));
                goto sxfs_upload_err;
            }
            if(close(fd)) {
                SXFS_LOG("Cannot close '%s' file: %s", path, strerror(errno));
                goto sxfs_upload_err;
            }
        } else if(rename(src, path)) {
            SXFS_LOG("Cannot rename '%s' to '%s': %s", src, path, strerror(errno));
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
            SXFS_LOG("Cannot get current time: %s", strerror(errno)); /* file succeffuly added into upload cache directory, in worst case upload thread will pause next uploads */
        }
        SXFS_DEBUG("File added: %s", dest);
    } else {
        if(sxfs_update_mtime(src ? src : SXFS_DATA->empty_file_path, dest, mtime))
            SXFS_LOG("Cannot update modification time");
        if(src && unlink(src)) {
            SXFS_LOG("Cannot remove '%s' file: %s", src, strerror(errno));
            goto sxfs_upload_err;
        }
    }

    ret = 0;
sxfs_upload_err:
    if(SXFS_DATA->args->use_queues_flag)
        pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
    free(path);
    free(path_to_list);
    return ret;
} /* sxfs_upload */

/* must be run when delete_mutex and upload_mutex are locked */
static int sxfs_upload_run (sxfs_state_t *sxfs, sxc_client_t *sx, sxc_cluster_t *cluster, int ignore_error) {
    int ret = -1;
    size_t i;
    char *storage_path = NULL;
    sxc_file_t *src = NULL, *dest = NULL;

    sxfs_log(sxfs, __FUNCTION__, 1, "Uploading files:");
    for(i=0; i<nfiles_up; i++)
        sxfs_log(sxfs, __FUNCTION__, 1, "'%s'", upload_list[i]);
    storage_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + 2);
    if(!storage_path) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory");
        errno = ENOMEM;
        return ret;
    }
    sprintf(storage_path, "%s/%s/", sxfs->tempdir, SXFS_UPLOAD_DIR);
    src = sxc_file_local(sx, storage_path);
    if(!src) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot create local file object: %s", sxc_geterrmsg(sx));
        errno = sxfs_sx_err(sx);
        goto sxfs_upload_run_err;
    }
    dest = sxc_file_remote(cluster, sxfs->uri->volume, "/", NULL);
    if(!dest) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot create file object: %s", sxc_geterrmsg(sx));
        errno = sxfs_sx_err(sx);
        goto sxfs_upload_run_err;
    }
    if(sxc_copy(src, dest, 1, 0, 0, NULL, 1)) {
        sxfs_log(sxfs, __FUNCTION__, 0, "%s", sxc_geterrmsg(sx));
        sxfs_tick_dirs_reload(sxfs->root);
        if(!ignore_error)
            goto sxfs_upload_run_err;
    } else {
        ssize_t index;
        char *ptr;
        sxfs_lsdir_t *dir;

        /* mark uploaded files as remote */
        for(i=0; i<nfiles_up; i++) {
            ptr = strrchr(upload_list[i], '/');
            if(ptr) {
                ptr++;
                dir = sxfs_ls_ftw(sxfs, upload_list[i]);
                if(dir) {
                    if(!strcmp(ptr, EMPTY_DIR_FILE)) {
                        dir->remote = 1;
                        dir->sxnewdir = 2;
                    } else {
                        index = sxfs_find_entry((const void**)dir->files, dir->nfiles, ptr, sxfs_lsfile_cmp);
                        if(index < 0)
                            sxfs_log(sxfs, __FUNCTION__, 0, "File not found: %s", upload_list[i]);
                        else
                            dir->files[index]->remote = 1;
                    }
                } else
                    sxfs_log(sxfs, __FUNCTION__, 0, "File tree walk failed: %s", strerror(errno));
            } else
                sxfs_log(sxfs, __FUNCTION__, 0, "'/' not found in '%s'", upload_list[i]);
        }
        storage_path[strlen(storage_path)-1] = '\0';
        /* refresh upload queue directory */
        if(sxfs_rmdirs(storage_path)) {
            sxfs_log(sxfs, __FUNCTION__, 0, "Cannot remove local storage directory: %s", strerror(errno));
            goto sxfs_upload_run_err;
        }
        if(mkdir(storage_path, 0700)) {
            sxfs_log(sxfs, __FUNCTION__, 0, "Cannot recreate local storage directory: %s", strerror(errno));
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
    free(storage_path);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* sxfs_upload_run */

static int copy_file (sxfs_state_t *sxfs, const char *source, const char *dest) {
    int ret = -1, err = 0, fd_src, fd_dst = -1;
    ssize_t rd;
    char buff[65536];

    if(sxfs_build_path(dest)) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot create path: %s", dest);
        return -1;
    }
    fd_src = open(source, O_RDONLY);
    if(fd_src < 0) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot open '%s' file: %s", source, strerror(errno));
        return -1;
    }
    fd_dst = open(dest, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if(fd_dst < 0) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot create '%s' file: %s", dest, strerror(errno));
        goto copy_file_err;
    }
    while((rd = read(fd_src, buff, sizeof(buff))) > 0) {
        if(write(fd_dst, buff, rd) < 0) {
            sxfs_log(sxfs, __FUNCTION__, 0, "Cannot write to '%s' file: %s", dest, strerror(errno));
            goto copy_file_err;
        }
    }
    if(rd < 0) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot read from '%s' file: %s", source, strerror(errno));
        goto copy_file_err;
    }

    ret = 0;
copy_file_err:
    if(ret)
        err = errno;
    close(fd_src);
    if(fd_dst >= 0)
        close(fd_dst);
    if(ret)
        errno = err;
    return ret;
} /* copy_file */

static int move_files (sxfs_state_t *sxfs, const char *source, const char *dest) {
    if(rename(source, dest)) {
        if(errno == EXDEV) {
            size_t i = 0, len = 0;
            char *src_path, *dst_path;

            sxfs_log(sxfs, __FUNCTION__, 1, "Moving files between different filesystems");
            for(; i<nfiles_up; i++)
                if(strlen(upload_list[i]) > len)
                    len = strlen(upload_list[i]);
            src_path = (char*)malloc(strlen(source) + len + 1);
            if(!src_path) {
                sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory");
                errno = ENOMEM;
                return -1;
            }
            dst_path = (char*)malloc(strlen(dest) + len + 1);
            if(!dst_path) {
                sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory");
                free(src_path);
                errno = ENOMEM;
                return -1;
            }
            for(i=0; i<nfiles_up; i++) {
                sprintf(src_path, "%s%s", source, upload_list[i]);
                sprintf(dst_path, "%s%s", dest, upload_list[i]);
                if(copy_file(sxfs, src_path, dst_path)) {
                    free(src_path);
                    free(dst_path);
                    return -1;
                }
            }
            free(src_path);
            free(dst_path);
            return 0;
        }
        return -1;
    }
    return 0;
} /* move_files */

static void* sxfs_upload_thread (void *ptr) {
    int *ret = (int*)calloc(1, sizeof(int));
    size_t i;
    char *storage_path = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxfs_state_t *sxfs = (sxfs_state_t*)ptr;
    struct timeval tv;

    if(!ret) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory");
        goto sxfs_upload_thread_err;
    }
    storage_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof(SXFS_UPLOAD_DIR) + 1);
    if(!storage_path) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory");
        *ret = ENOMEM;
        goto sxfs_upload_thread_err;
    }
    sprintf(storage_path, "%s/%s", sxfs->tempdir, SXFS_UPLOAD_DIR);
    if(sxfs_rmdirs(storage_path) && errno != ENOENT) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot remove local storage directory: %s", strerror(errno));
        *ret = errno;
        goto sxfs_upload_thread_err;
    }
    if(mkdir(storage_path, 0700)) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot recreate local storage directory: %s", strerror(errno));
        *ret = errno;
        goto sxfs_upload_thread_err;
    }
    if(sxfs_get_sx_data(sxfs, &sx, &cluster)) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Cannot get Sx data");
        *ret = errno;
        goto sxfs_upload_thread_err;
    }
    upload_list = (char**)calloc(ALLOC_AMOUNT, sizeof(char*));
    if(!upload_list) {
        sxfs_log(sxfs, __FUNCTION__, 0, "Out of memory");
        *ret = ENOMEM;
        goto sxfs_upload_thread_err;
    }
    nfiles_up = 0;
    maxfiles_up = ALLOC_AMOUNT;
    pthread_mutex_lock(&sxfs->upload_mutex);
    upload_flag = 1;
    pthread_mutex_unlock(&sxfs->upload_mutex);
    sxfs_log(sxfs, __FUNCTION__, 2, "Upload thread has been started");

    while(1) {
        usleep(JOB_SLEEP_USEC);
        pthread_mutex_lock(&sxfs->delete_mutex);
        pthread_mutex_lock(&sxfs->upload_mutex);
        if(upload_flag < 0) {
            if(nfiles_up) { /* save not yet uploaded files */
                if(move_files(sxfs, storage_path, sxfs->lostdir)) {
                    sxfs_log(sxfs, __FUNCTION__, 0, "Cannot move not yet uploaded files to recover directory. Files available in '%s'", storage_path);
                    sxfs->recovery_failed = 1;
                } else {
                    sxfs_log(sxfs, __FUNCTION__, 2, "Files from upload queue saved in '%s'", sxfs->lostdir);
                }
            }
            pthread_mutex_unlock(&sxfs->delete_mutex);
            pthread_mutex_unlock(&sxfs->upload_mutex);
            sxfs_log(sxfs, __FUNCTION__, 2, "Upload thread has been stopped");
            goto sxfs_upload_thread_err;
        }
        if(nfiles_up) {
            if(gettimeofday(&tv, NULL)) {
                sxfs_log(sxfs, __FUNCTION__, 0, "Cannot get current time: %s", strerror(errno));
                *ret = errno;
                pthread_mutex_unlock(&sxfs->delete_mutex);
                pthread_mutex_unlock(&sxfs->upload_mutex);
                goto sxfs_upload_thread_err;
            }
            if((tv.tv_sec - last_upload_time.tv_sec) * 1000000L + tv.tv_usec - last_upload_time.tv_usec >= LAST_ACTION_WAIT_USEC) {
                if(sxfs_upload_run(sxfs, sx, cluster, 1)) {
                    *ret = errno;
                    pthread_mutex_unlock(&sxfs->delete_mutex);
                    pthread_mutex_unlock(&sxfs->upload_mutex);
                    goto sxfs_upload_thread_err;
                }
            }
        }
        pthread_mutex_unlock(&sxfs->delete_mutex);
        pthread_mutex_unlock(&sxfs->upload_mutex);
    }

sxfs_upload_thread_err:
    pthread_mutex_lock(&sxfs->upload_mutex);
    if(upload_list) {
        for(i=0; i<nfiles_up; i++)
            free(upload_list[i]);
        free(upload_list);
    }
    nfiles_up = maxfiles_up = 0;
    upload_flag = -2;
    pthread_mutex_unlock(&sxfs->upload_mutex);
    free(storage_path);
    return (void*)ret;
} /* sxfs_upload_thread */

int sxfs_upload_start (void) {
    int tmp;

    pthread_mutex_lock(&SXFS_DATA->upload_mutex);
    upload_flag = 0;
    if((tmp = pthread_create(&SXFS_DATA->upload_thread, NULL, sxfs_upload_thread, (void*)SXFS_DATA))) {
        SXFS_LOG("Cannot create upload thread: %s", strerror(tmp));
        upload_flag = -2;
        pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
        errno = tmp;
        return -1;
    }
    while(!upload_flag) {
        pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
        usleep(THREAD_WAIT_USEC);
        pthread_mutex_lock(&SXFS_DATA->upload_mutex);
    }
    if(upload_flag < 0)
        tmp = 1;
    else
        tmp = 0;
    pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
    if(tmp) {
        int *status = NULL;
        if((tmp = pthread_join(SXFS_DATA->upload_thread, (void**)&status))) {
            SXFS_LOG("Cannot join upload thread: %s", strerror(tmp));
            errno = tmp;
        } else {
            SXFS_LOG("Cannot start upload thread: %s", strerror(status ? *status : ENOMEM));
            errno = status ? *status : ENOMEM;
            if(status)
                free(status);
        }
        return -1;
    }
    return 0;
} /* sxfs_upload_start */

void sxfs_upload_stop (void) {
    int tmp, *status = NULL;
    pthread_mutex_lock(&SXFS_DATA->upload_mutex);
    if(upload_flag > 0) {
        upload_flag = -1;
        pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
        if((tmp = pthread_join(SXFS_DATA->upload_thread, (void**)&status))) {
            SXFS_LOG("Cannot join upload thread: %s", strerror(tmp));
        } else {
            if(status)
                free(status);
        }
    } else
        pthread_mutex_unlock(&SXFS_DATA->upload_mutex);
} /* sxfs_upload_stop */

