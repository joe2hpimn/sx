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

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <utime.h>
#include <limits.h>
#include <errno.h>
#include "cache.h"
#include "common.h"

#define BLOCK_STATUS_BUSY 1
#define BLOCK_STATUS_DONE 2
#define BLOCK_STATUS_FAILED 3

struct _block_state_t {
    int waiting, status;
};
typedef struct _block_state_t block_state_t;

struct _sxfs_cache_t {
    ssize_t used, size; /* can be negative due to race conditions with small size */
    char *dir_medium, *dir_large;
    pthread_mutex_t mutex;
    sxi_ht *blocks;
};

static void cache_free (sxfs_state_t *sxfs, sxfs_cache_t *cache) {
    int err;

    if(!sxfs || !cache)
        return;
    free(cache->dir_medium);
    free(cache->dir_large);
    sxi_ht_free(cache->blocks);
    if((err = pthread_mutex_destroy(&cache->mutex)))
        SXFS_ERROR("Cannot destroy cache mutex: %s", strerror(err));
    free(cache);
} /* cache_free */

int sxfs_cache_init (sxc_client_t *sx, sxfs_state_t *sxfs, size_t size, const char *path) {
    int ret = -1, err;
    sxfs_cache_t *cache;

    if(!sxfs)
        return ret;
    if(!sx || !path) {
        fprintf(stderr, "ERROR: NULL argument in cache initialization");
        return ret;
    }
    if(size < 64 * SX_BS_LARGE) {
        fprintf(stderr, "ERROR: Cache size must be at least %d\n", 64 * SX_BS_LARGE);
        return ret;
    }
    cache = (sxfs_cache_t*)calloc(1, sizeof(sxfs_cache_t));
    if(!cache) {
        fprintf(stderr, "ERROR: Out of memory");
        return ret;
    }
    if((err = pthread_mutex_init(&cache->mutex, NULL))) {
        fprintf(stderr, "ERROR: Cannot create cache mutex: %s", strerror(err));
        free(cache);
        return ret;
    }
    cache->blocks = sxi_ht_new(sx, 10000); /* more than 128 * 64 for ht efficiency */
    if(!cache->blocks) {
        fprintf(stderr, "ERROR: Out of memory");
        goto sxfs_cache_init_err;
    }
    cache->dir_medium = (char*)malloc(strlen(path) + 1 + lenof("medium") + 1);
    if(!cache->dir_medium) {
        fprintf(stderr, "ERROR: Out of memory");
        goto sxfs_cache_init_err;
    }
    cache->dir_large = (char*)malloc(strlen(path) + 1 + lenof("large") + 1);
    if(!cache->dir_large) {
        fprintf(stderr, "ERROR: Out of memory");
        goto sxfs_cache_init_err;
    }
    sprintf(cache->dir_medium, "%s/medium", path);
    sprintf(cache->dir_large, "%s/large", path);
    if(mkdir(cache->dir_medium, 0700)) {
        fprintf(stderr, "ERROR: Cannot create '%s' directory: %s", cache->dir_medium, strerror(errno));
        goto sxfs_cache_init_err;
    }
    if(mkdir(cache->dir_large, 0700)) {
        fprintf(stderr, "ERROR: Cannot create '%s' directory: %s", cache->dir_large, strerror(errno));
        if(rmdir(cache->dir_medium))
            fprintf(stderr, "ERROR: Cannot remove '%s' directory: %s", cache->dir_medium, strerror(errno));
        goto sxfs_cache_init_err;
    }
    cache->used = 0;
    cache->size = size;

    sxfs->cache = cache;
    cache = NULL;
    ret = 0;
sxfs_cache_init_err:
    cache_free(sxfs, cache);
    return ret;
} /* sxfs_cache_init */

struct _blockfile_t {
    char *name;
    time_t mtime;
};
typedef struct _blockfile_t blockfile_t;

static int blockfile_cmp (const void *ptr1, const void *ptr2) {
    const blockfile_t *bf1 = ((const blockfile_t*)ptr1), *bf2 = ((const blockfile_t*)ptr2);
    return bf1->mtime - bf2->mtime;
} /* blockfile_cmp */

static int load_files (sxfs_state_t *sxfs, const char *dir_path, blockfile_t **list, size_t *nfiles) {
    int ret;
    size_t maxfiles;
    char path[PATH_MAX];
    DIR *dir = opendir(dir_path);
    struct stat st;
    struct dirent *entry;

    if(!dir) {
        ret = -errno;
        SXFS_ERROR("Cannot open '%s' directory: %s", dir_path, strerror(errno));
        return ret;
    }
    maxfiles = SXFS_ALLOC_ENTRIES;
    *list = (blockfile_t*)malloc(maxfiles * sizeof(blockfile_t));
    if(!*list) {
        ret = -errno;
        SXFS_ERROR("Out of memory");
        goto load_files_err;
    }
    *nfiles = 0;
    entry = readdir(dir);
    while(entry) {
        if(strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            if(*nfiles == maxfiles && sxfs_resize((void**)list, &maxfiles, sizeof(blockfile_t))) {
                SXFS_ERROR("OOM growing files list");
                ret = -ENOMEM;
                goto load_files_err;
            }
            snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
            if(stat(path, &st)) {
                ret = -errno;
                SXFS_ERROR("Cannot stat '%s' file: %s", path, strerror(errno));
                goto load_files_err;
            }
            (*list)[*nfiles].name = strdup(entry->d_name);
            if(!(*list)[*nfiles].name) {
                SXFS_ERROR("Out of memory");
                ret = -ENOMEM;
                goto load_files_err;
            }
            (*list)[*nfiles].mtime = st.st_mtime;
            (*nfiles)++;
        }
        entry = readdir(dir);
    }
    if(*nfiles)
        qsort(*list, *nfiles, sizeof(blockfile_t), blockfile_cmp);
    
    ret = 0;
load_files_err:
    closedir(dir);
    if(ret && *list) {
        size_t i=0;
        for(; i<*nfiles; i++)
            free((*list)[i].name);
        free(*list);
        *list = NULL;
        *nfiles = 0;
    }
    return ret;
} /* load_files */

static int cache_make_space (sxfs_state_t *sxfs, unsigned int size) {
    int ret;
    unsigned int blocksize;
    char path[PATH_MAX];
    size_t i_m = 0, i_l = 0, nfiles_medium = 0, nfiles_large = 0, removed = 0;
    blockfile_t *list_medium = NULL, *list_large = NULL;

    if(sxfs->cache->used + size > sxfs->cache->size) {
        if((ret = load_files(sxfs, sxfs->cache->dir_medium, &list_medium, &nfiles_medium)))
            goto cache_make_space_err;
        if((ret = load_files(sxfs, sxfs->cache->dir_large, &list_large, &nfiles_large)))
            goto cache_make_space_err;

        while(sxfs->cache->used + size > sxfs->cache->size) {
            if(i_m == nfiles_medium && i_l == nfiles_large) {
                SXFS_ERROR("Cache inconsistency error");
                ret = -ENOMSG;
                goto cache_make_space_err;
            }
            if(i_l == nfiles_large || (i_m != nfiles_medium && list_medium[i_m].mtime < list_large[i_l].mtime)) {
                snprintf(path, sizeof(path), "%s/%s", sxfs->cache->dir_medium, list_medium[i_m].name);
                i_m++;
                blocksize = SX_BS_MEDIUM;
            } else {
                snprintf(path, sizeof(path), "%s/%s", sxfs->cache->dir_large, list_large[i_l].name);
                i_l++;
                blocksize = SX_BS_LARGE;
            }
            if(unlink(path)) {
                ret = -errno;
                SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
                goto cache_make_space_err;
            }
            removed++;
            sxfs->cache->used -= blocksize;
        }
    }
    if(removed)
        SXFS_VERBOSE("%llu files have been removed", (unsigned long long int)removed);

    ret = 0;
cache_make_space_err:
    if(list_medium) {
        for(i_m = 0; i_m<nfiles_medium; i_m++)
            free(list_medium[i_m].name);
        free(list_medium);
    }
    if(list_large) {
        for(i_l = 0; i_l<nfiles_large; i_l++)
            free(list_large[i_l].name);
        free(list_large);
    }
    return ret;
} /* cache_make_space */

static int cache_download (sxfs_state_t *sxfs, sxi_sxfs_data_t *fdata, unsigned int block, const char *path, int *file_fd) {
    int ret, fd, tmp_fd = -1, mutex_locked = 1, used_added = 0;
    ssize_t bytes;
    char *tmp_path = NULL, buff[SX_BS_LARGE];
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *dest = NULL;
    block_state_t *state;

    pthread_mutex_lock(&sxfs->cache->mutex);
    fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if(fd < 0) {
        if(errno != EEXIST) {
            ret = -errno;
            SXFS_ERROR("Cannot create '%s' file: %s", path, strerror(errno));
            goto cache_download_err;
        } else if(file_fd) {
            fd = open(path, O_RDWR);
            if(fd < 0) {
                ret = -errno;
                SXFS_ERROR("Cannot open '%s' file: %s", path, strerror(errno));
                goto cache_download_err;
            }
            *file_fd = fd;
            fd = -1;
        }
        ret = 0;
        goto cache_download_err; /* this is not a failure */
    }
    if((ret = cache_make_space(sxfs, fdata->blocksize)))
        goto cache_download_err;
    sxfs->cache->used += fdata->blocksize;
    pthread_mutex_unlock(&sxfs->cache->mutex);
    mutex_locked = 0;
    used_added = 1;
    tmp_path = (char*)malloc(strlen(sxfs->tempdir) + 1 + lenof("cache_XXXXXX") + 1);
    if(!tmp_path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto cache_download_err;
    }
    sprintf(tmp_path, "%s/cache_XXXXXX", sxfs->tempdir);
    tmp_fd = mkstemp(tmp_path); /* different fd to be sure that sxfs_cache_read() works on the file *file_fd is possibly pointing to */
    if(tmp_fd < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot create unique temporary file: %s", strerror(errno));
        goto cache_download_err;
    }
    if((ret = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
        SXFS_ERROR("Cannot get SX data");
        goto cache_download_err;
    }
    /* download new block */
    dest = sxc_file_local(sx, tmp_path);
    if(!dest) {
        ret = -sxfs_sx_err(sx);
        SXFS_ERROR("Cannot create local file object: %s", sxc_geterrmsg(sx));
        goto cache_download_err;
    }
    if(sxi_sxfs_download_run(fdata, cluster, dest, block * fdata->blocksize, fdata->blocksize)) { /* this can download data to another (newly created) file */
        ret = -sxfs_sx_err(sx);
        goto cache_download_err;
    }
    if((bytes = read(tmp_fd, buff, fdata->blocksize)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot read from '%s' file: %s", tmp_path, strerror(errno));
        goto cache_download_err;
    }
    if(bytes != fdata->blocksize) {
        SXFS_ERROR("Read less than expected (%lld != %u)", (long long int)bytes, fdata->blocksize);
        ret = -EINVAL;
        goto cache_download_err;
    }
    if((bytes = write(fd, buff, fdata->blocksize)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot write to '%s' file: %s", path, strerror(errno));
        goto cache_download_err;
    }
    if(bytes != fdata->blocksize) {
        SXFS_ERROR("Wrote less than expected (%lld != %u)", (long long int)bytes, fdata->blocksize);
        ret = -EINVAL;
        goto cache_download_err;
    }
    if(file_fd) {
        *file_fd = fd;
        fd = -1;
    }

    ret = 0;
cache_download_err:
    if(mutex_locked)
        pthread_mutex_unlock(&sxfs->cache->mutex);
    if(fd >= 0 && close(fd))
        SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
    if(tmp_fd >= 0 && close(tmp_fd))
        SXFS_ERROR("Cannot close '%s' file: %s", tmp_path, strerror(errno));
    if(ret) {
        if(fd >= 0 && unlink(path))
            SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
        if(used_added) {
            pthread_mutex_lock(&sxfs->cache->mutex);
            sxfs->cache->used -= fdata->blocksize;
            pthread_mutex_unlock(&sxfs->cache->mutex);
        }
    }
    pthread_mutex_lock(&sxfs->cache->mutex);
    if(!sxi_ht_get(sxfs->cache->blocks, fdata->ha[block], strlen(fdata->ha[block]), (void**)&state))
        state->status = ret ? BLOCK_STATUS_FAILED : BLOCK_STATUS_DONE;
    pthread_mutex_unlock(&sxfs->cache->mutex);
    free(tmp_path);
    sxc_file_free(dest);
    return ret;
} /* cache_download */

struct _cache_thread_data_t {
    int fds[MAX(SXFS_BS_MEDIUM_AMOUNT, SXFS_BS_LARGE_AMOUNT)];
    unsigned int nblocks, blocks[MAX(SXFS_BS_MEDIUM_AMOUNT, SXFS_BS_LARGE_AMOUNT)];
    char *dir;
    sxfs_state_t *sxfs;
    sxfs_file_t *sxfs_file;
};
typedef struct _cache_thread_data_t cache_thread_data_t;

static void* cache_download_thread (void *ptr) {
    int fd = -1;
    unsigned int i;
    ssize_t bytes;
    char path[PATH_MAX], buff[SX_BS_LARGE];
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *file = NULL;
    sxfs_state_t *sxfs;
    cache_thread_data_t *cdata = (cache_thread_data_t*)ptr;
    block_state_t *state;
    sxi_sxfs_data_t *fdata, fdata2;

    sxfs = cdata->sxfs;
    fdata = cdata->sxfs_file->fdata;
    memcpy(&fdata2, fdata, sizeof(sxi_sxfs_data_t));
    fdata2.ha = (char**)calloc(cdata->nblocks, sizeof(char*));
    if(!fdata2.ha) {
        SXFS_ERROR("Out of memory");
        goto cache_download_thread_err;
    }
    for(i=0; i<cdata->nblocks; i++) {
        fdata2.ha[i] = strdup(fdata->ha[cdata->blocks[i]]);
        if(!fdata2.ha[i]) {
            SXFS_ERROR("Out of memory");
            goto cache_download_thread_err;
        }
    }
    fdata2.nhashes = cdata->nblocks;
    snprintf(path, sizeof(path), "%s/cache_XXXXXX", sxfs->tempdir);
    fd = mkstemp(path);
    if(fd < 0) {
        SXFS_ERROR("Cannot create unique temporary file: %s", strerror(errno));
        goto cache_download_thread_err;
    }
    if(sxfs_get_sx_data(sxfs, &sx, &cluster)) {
        SXFS_ERROR("Cannot get SX data");
        goto cache_download_thread_err;
    }
    file = sxc_file_local(sx, path);
    if(!file) {
        SXFS_ERROR("Cannot create local file object: %s", sxc_geterrmsg(sx));
        goto cache_download_thread_err;
    }
    if(sxi_sxfs_download_run(&fdata2, cluster, file, 0, cdata->nblocks * fdata->blocksize)) { /* 0 offset - fdata2.ha is 'hacked' */
        SXFS_ERROR("Cannot download the part of '%s' file: %s", cdata->sxfs_file->remote_path, sxc_geterrmsg(sx));
        goto cache_download_thread_err;
    }
    for(i=0; i<cdata->nblocks; i++) {
        if((bytes = read(fd, buff, fdata->blocksize)) < 0) {
            SXFS_ERROR("Cannot read from '%s' file: %s", path, strerror(errno));
            goto cache_download_thread_err;
        }
        if(bytes < fdata->blocksize) {
            SXFS_ERROR("Read less data than expected (%lu != %u)", (unsigned long int)bytes, fdata->blocksize);
            goto cache_download_thread_err;
        }
        if((bytes = write(cdata->fds[i], buff, fdata->blocksize)) < 0) {
            SXFS_ERROR("Cannot write to %d (%s) file descriptor: %s", cdata->fds[i], fdata->ha[cdata->blocks[i]], strerror(errno));
            goto cache_download_thread_err;
        }
        if(bytes < fdata->blocksize) {
            SXFS_ERROR("Wrote less data than expected (%lu != %u)", (unsigned long int)bytes, fdata->blocksize);
            goto cache_download_thread_err;
        }
        if(close(cdata->fds[i]))
            SXFS_ERROR("Cannot close %d file descriptor: %s", cdata->fds[i], strerror(errno));
        cdata->fds[i] = -1;
        pthread_mutex_lock(&sxfs->cache->mutex);
        if(!sxi_ht_get(sxfs->cache->blocks, fdata2.ha[i], strlen(fdata2.ha[i]), (void**)&state))
            state->status = BLOCK_STATUS_DONE;
        pthread_mutex_unlock(&sxfs->cache->mutex);
    }

cache_download_thread_err:
    if(fd >= 0) {
        if(close(fd))
            SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
        if(unlink(path))
            SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
    }
    for(i=0; i<cdata->nblocks; i++) {
        if(fdata2.ha)
            free(fdata2.ha[i]);
        if(cdata->fds[i] >= 0) {
            snprintf(path, sizeof(path), "%s/%s", cdata->dir, fdata->ha[cdata->blocks[i]]);
            if(close(cdata->fds[i]))
                SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
            if(unlink(path)) {
                if(errno != ENOENT)
                    SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
            } else {
                pthread_mutex_lock(&sxfs->cache->mutex);
                sxfs->cache->used -= fdata->blocksize;
                pthread_mutex_unlock(&sxfs->cache->mutex);
            }
        }
        pthread_mutex_lock(&sxfs->cache->mutex);
        if(!sxi_ht_get(sxfs->cache->blocks, fdata->ha[cdata->blocks[i]], strlen(fdata->ha[cdata->blocks[i]]), (void**)&state) && state->status == BLOCK_STATUS_BUSY)
            state->status = BLOCK_STATUS_FAILED;
        pthread_mutex_unlock(&sxfs->cache->mutex);
    }
    free(fdata2.ha);
    free(cdata->dir);
    sxc_file_free(file);
    pthread_mutex_lock(&sxfs->limits_mutex);
    sxfs->threads_num--;
    cdata->sxfs_file->threads_num--;
    pthread_mutex_unlock(&sxfs->limits_mutex);
    free(cdata);
    return NULL;
} /* cache_download_thread */

static void cache_read_background (sxfs_state_t *sxfs, sxfs_file_t *sxfs_file, const char *dir, unsigned int block, unsigned int nblocks) {
    int err, end_reached = 0, duplicate, cache_locked = 0;
    unsigned int i, j;
    char *path;
    cache_thread_data_t *cdata = NULL;
    pthread_t thread;

    if(block >= sxfs_file->fdata->nhashes)
        return;
    if(block + nblocks > sxfs_file->fdata->nhashes)
        nblocks = sxfs_file->fdata->nhashes - block;
    if(!nblocks)
        return;
    path = (char*)malloc(strlen(dir) + 1 + SXI_SHA1_TEXT_LEN + 1);
    if(!path) {
        SXFS_ERROR("Out of memory");
        return;
    }
    cdata = (cache_thread_data_t*)calloc(1, sizeof(cache_thread_data_t));
    if(!cdata) {
        SXFS_ERROR("Out of memory");
        goto cache_read_background_err;
    }
    cdata->sxfs = sxfs;
    cdata->sxfs_file = sxfs_file;
    cdata->dir = strdup(dir);
    if(!cdata->dir) {
        SXFS_ERROR("Out of memory");
        goto cache_read_background_err;
    }
    pthread_mutex_lock(&sxfs->cache->mutex);
    cache_locked = 1;
    for(i=0; cdata->nblocks < nblocks; i++) {
        if(block + i == sxfs_file->fdata->nhashes) {
            end_reached = 1;
            break;
        }
        if(i > 2 * nblocks) /* do not try to read too far from given block */
            break;
        duplicate = 0;
        for(j=0; j<cdata->nblocks; j++)
            if(!strcmp(sxfs_file->fdata->ha[block+i], sxfs_file->fdata->ha[cdata->blocks[j]])) {
                duplicate = 1;
                break;
            }
        if(!duplicate) {
            sprintf(path, "%s/%s", dir, sxfs_file->fdata->ha[block+i]);
            if(access(path, F_OK)) {
                if(errno == ENOENT) {
                    cdata->fds[cdata->nblocks] = -1;
                    cdata->blocks[cdata->nblocks] = block + i;
                    cdata->nblocks++;
                } else {
                    SXFS_ERROR("Cannot access '%s' file: %s", path, strerror(errno));
                    goto cache_read_background_err;
                }
            } else if(utime(path, NULL)) /* this can be the least recently used file - avoid removing it */
                SXFS_ERROR("Cannot update mtime of '%s' file: %s", path, strerror(errno));
        }
    }
    if(cdata->nblocks && ((end_reached || 2 * (cdata->blocks[0] - block) < nblocks) || cdata->nblocks == nblocks)) { /* near to EOF  OR  filling holes  OR  limit reached */
        if(cache_make_space(sxfs, cdata->nblocks * sxfs_file->fdata->blocksize))
            goto cache_read_background_err;
        for(i=0; i<cdata->nblocks; i++) {
            sprintf(path, "%s/%s", dir, sxfs_file->fdata->ha[cdata->blocks[i]]);
            cdata->fds[i] = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
            if(cdata->fds[i] < 0) {
                SXFS_ERROR("Cannot create '%s' file: %s", path, strerror(errno));
                goto cache_read_background_err;
            }
            sxfs->cache->used += sxfs_file->fdata->blocksize;
        }
        pthread_mutex_unlock(&sxfs->cache->mutex);
        cache_locked = 0;
        pthread_mutex_lock(&sxfs->limits_mutex);
        sxfs_file->threads_num++;
        pthread_mutex_unlock(&sxfs->limits_mutex);
        if((err = sxfs_thread_create(sxfs, &thread, cache_download_thread, (void*)cdata))) {
            pthread_mutex_lock(&sxfs->limits_mutex);
            sxfs_file->threads_num--;
            pthread_mutex_unlock(&sxfs->limits_mutex);
            SXFS_ERROR("Cannot start new thread");
            goto cache_read_background_err;
        }
        if((err = pthread_detach(thread)))
            SXFS_ERROR("Cannot detach the thread: %s", strerror(err));
        cdata = NULL;
    }

cache_read_background_err:
    if(cdata) {
        if(!cache_locked) {
            pthread_mutex_lock(&sxfs->cache->mutex);
            cache_locked = 1;
        }
        for(i=0; i<cdata->nblocks; i++)
            if(cdata->fds[i] >= 0) {
                sprintf(path, "%s/%s", dir, sxfs_file->fdata->ha[cdata->blocks[i]]);
                if(close(cdata->fds[i]))
                    SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
                if(unlink(path)) {
                    if(errno != ENOENT)
                        SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
                } else {
                    sxfs->cache->used -= sxfs_file->fdata->blocksize;
                }
            }
            free(cdata->dir);
            free(cdata);
        }
    if(cache_locked)
        pthread_mutex_unlock(&sxfs->cache->mutex);
    free(path);
} /* cache_read_background */

ssize_t sxfs_cache_read (sxfs_state_t *sxfs, sxfs_file_t *sxfs_file, void *buff, size_t length, off_t offset) {
    int fd = -1, cache_locked = 0, download = 0;
    unsigned int block, nblocks = 0;
    ssize_t ret;
    char *path;
    const char *dir = "foo"; /* shut up warnings */
    sxfs_cache_t *cache;
    sxi_sxfs_data_t *fdata;

    if(!sxfs || !sxfs->cache || !sxfs_file || !buff) {
        if(sxfs)
            SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    cache = sxfs->cache;
    fdata = sxfs_file->fdata;
    if(sxfs->need_file) {
        download = 1;
    } else if(fdata) { /* file opened by create() doesn't have fdata but always has write_fd */
        switch(fdata->blocksize) {
            case SX_BS_SMALL:
                download = 1;
                break;
            case SX_BS_MEDIUM:
                dir = cache->dir_medium;
                nblocks = SXFS_BS_MEDIUM_AMOUNT;
                break;
            case SX_BS_LARGE:
                dir = cache->dir_large;
                nblocks = SXFS_BS_LARGE_AMOUNT;
                break;
            default:
                SXFS_ERROR("Unknown block size");
                return -EINVAL;
        }
    }
    if(download && sxfs_file->write_fd < 0 && (ret = sxfs_get_file(sxfs, sxfs_file))) {
        SXFS_ERROR("Cannot get '%s' file", sxfs_file->remote_path);
        return ret;
    }
    if(sxfs_file->write_fd >= 0) {
        SXFS_VERBOSE("Using file descriptor: %d", sxfs_file->write_fd);
        if((ret = pread(sxfs_file->write_fd, buff, length, offset)) < 0) {
            ret = -errno;
            SXFS_ERROR("Cannot read from '%s' file: %s", sxfs_file->write_path, strerror(errno));
        }
        return ret;
    }
    if(!fdata) {
        SXFS_ERROR("No file data nor file descriptor available");
        return -EINVAL;
    }
    block = offset / fdata->blocksize;
    if(block >= fdata->nhashes) {
        SXFS_VERBOSE("Reading after EOF");
        return 0;
    }
    SXFS_VERBOSE("Offset: %lld, block number: %llu", (long long int)offset, (unsigned long long int)block);
    path = (char*)malloc(strlen(dir) + 1 + strlen(fdata->ha[block]) + 1);
    if(!path) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    sprintf(path, "%s/%s", dir, fdata->ha[block]);
    cache_read_background(sxfs, sxfs_file, dir, block+1, nblocks);
    fd = open(path, O_RDONLY);
    if(fd < 0) {
        if(errno == ENOENT) {
            if((ret = cache_download(sxfs, fdata, block, path, &fd)))
                goto sxfs_cache_read_err;
        } else {
            ret = -errno;
            SXFS_ERROR("Cannot open '%s' file: %s", path, strerror(errno)); 
            goto sxfs_cache_read_err;
        }
    } else {
        struct stat st;

        if(fstat(fd, &st)) {
            ret = -errno;
            SXFS_ERROR("Cannot fstat '%s' file: %s", path, strerror(errno));
            goto sxfs_cache_read_err;
        }
        if(st.st_size != fdata->blocksize) {
            int status;
            block_state_t *state;

            pthread_mutex_lock(&cache->mutex);
            cache_locked = 1;
            if(stat(path, &st)) { /* protection against race condition */
                if(errno == ENOENT) {
                    close(fd);
                    fd = -1;
                    if((ret = cache_download(sxfs, fdata, block, path, &fd)))
                        goto sxfs_cache_read_err;
                    st.st_size = fdata->blocksize; /* to not enter next if() */
                } else {
                    ret = -errno;
                    SXFS_ERROR("Cannot stat '%s' file: %s", path, strerror(errno));
                    goto sxfs_cache_read_err;
                }
            }
            if(st.st_size != fdata->blocksize) {
                if(sxi_ht_get(cache->blocks, fdata->ha[block], strlen(fdata->ha[block]), (void**)&state)) {
                    state = (block_state_t*)malloc(sizeof(block_state_t));
                    if(!state) {
                        SXFS_ERROR("Out of memory");
                        ret = -ENOMEM;
                        goto sxfs_cache_read_err;
                    }
                    state->waiting = 1;
                    state->status = BLOCK_STATUS_BUSY;
                    if(sxi_ht_add(cache->blocks, fdata->ha[block], strlen(fdata->ha[block]), state)) {
                        SXFS_ERROR("Out of memory");
                        ret = -ENOMEM;
                        goto sxfs_cache_read_err;
                    }
                } else {
                    state->waiting++;
                }
                while(state->status == BLOCK_STATUS_BUSY) {
                    pthread_mutex_unlock(&cache->mutex);
                    usleep(SXFS_THREAD_WAIT);
                    pthread_mutex_lock(&cache->mutex);
                }
                state->waiting--;
                status = state->status;
                if(state->waiting == 0) {
                    free(state);
                    sxi_ht_del(cache->blocks, fdata->ha[block], strlen(fdata->ha[block]));
                }
                if(status == BLOCK_STATUS_FAILED) {
                    SXFS_ERROR("Failed to download the block");
                    ret = -EAGAIN;
                    goto sxfs_cache_read_err;
                }
            }
            pthread_mutex_unlock(&cache->mutex);
            cache_locked = 0;
        }
    }

    if((ret = pread(fd, buff, length, offset % fdata->blocksize)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot read from '%s' file: %s", path, strerror(errno));
    }
    if(utime(path, NULL) && errno != ENOENT)
        SXFS_ERROR("Cannot update mtime of '%s' file: %s", path, strerror(errno));
sxfs_cache_read_err:
    if(cache_locked)
        pthread_mutex_unlock(&cache->mutex);
    if(fd >= 0 && close(fd))
        SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
    free(path);
    return ret;
} /* sxfs_cache_read */

void sxfs_cache_free (sxfs_state_t *sxfs) {
    if(!sxfs || !sxfs->cache)
        return;
    if(sxi_rmdirs(sxfs->cache->dir_medium))
        SXFS_ERROR("Cannot remove '%s' directory: %s", sxfs->cache->dir_medium, strerror(errno));
    if(sxi_rmdirs(sxfs->cache->dir_large))
        SXFS_ERROR("Cannot remove '%s' directory: %s", sxfs->cache->dir_large, strerror(errno));
    cache_free(sxfs, sxfs->cache);
} /* sxfs_cache_free */

