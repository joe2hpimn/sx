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

#include "cache.h"
#include "common.h"

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <utime.h>
#include <limits.h>
#include <errno.h>

#define BLOCK_STATUS_BUSY 1
#define BLOCK_STATUS_DONE 2
#define BLOCK_STATUS_FAILED 3

#define MIN_FREE_SIZE (3 * 1024 * 1024) /* 3 MB */

#define CACHE_INDEX_SMALL 0
#define CACHE_INDEX_MEDIUM 1
#define CACHE_INDEX_LARGE 2

#define LFU_SORTED_NONE 0
#define LFU_SORTED_BY_NAME 1
#define LFU_SORTED_BY_USAGE 2

struct _block_state_t {
    int waiting, status;
};
typedef struct _block_state_t block_state_t;

struct _sxfs_cache_lfu_t {
    char *name;
    size_t times_used;
    time_t add_time;
};
typedef struct _sxfs_cache_lfu_t sxfs_cache_lfu_t;

static int lfu_sort_cmp_usage (const void *ptr1, const void *ptr2) {
    ssize_t diff;
    const sxfs_cache_lfu_t *block1, *block2;

    block1 = (const sxfs_cache_lfu_t*)ptr1;
    block2 = (const sxfs_cache_lfu_t*)ptr2;
    diff = (ssize_t)block2->times_used - (ssize_t)block1->times_used;
    if(!diff)
        return block1->add_time - block2->add_time;
    return diff;
} /* lfu_sort_cmp_usage */

static int lfu_sort_cmp_name (const void *ptr1, const void *ptr2) {
    return strcmp(((const sxfs_cache_lfu_t*)ptr1)->name, ((const sxfs_cache_lfu_t*)ptr2)->name);
} /* lfu_sort_cmp_name */

static int lfu_entry_cmp_name (const void **table, size_t index, const char *name) {
    const sxfs_cache_lfu_t *lfu = (const sxfs_cache_lfu_t*)table;
    return strcmp(lfu[index].name, name);
} /* lfu_entry_cmp_name */

struct _sxfs_cache_t {
    int lfu_sorted[3];
    size_t lfu_entries[3], lfu_max;
    ssize_t used, size; /* can be negative due to race conditions with small size */
    char *tempdir, *dir_small, *dir_medium, *dir_large, *dir_lfu_small, *dir_lfu_medium, *dir_lfu_large;
    pthread_mutex_t mutex, lfu_mutex;
    sxi_ht *blocks, *lru;
    sxfs_cache_lfu_t *lfu[3];
};

static void cache_free (sxfs_state_t *sxfs, sxfs_cache_t *cache) {
    int err;
    unsigned int i, j;

    if(!sxfs || !cache)
        return;
    if(cache->dir_small && sxi_rmdirs(cache->dir_small) && errno != ENOENT)
        SXFS_ERROR("Cannot remove '%s' directory: %s", cache->dir_small, strerror(errno));
    if(cache->dir_medium && sxi_rmdirs(cache->dir_medium) && errno != ENOENT)
        SXFS_ERROR("Cannot remove '%s' directory: %s", cache->dir_medium, strerror(errno));
    if(cache->dir_large && sxi_rmdirs(cache->dir_large) && errno != ENOENT)
        SXFS_ERROR("Cannot remove '%s' directory: %s", cache->dir_large, strerror(errno));
    if(cache->dir_lfu_small && cache->tempdir) {
        sprintf(cache->dir_lfu_small, "%s/lfu", cache->tempdir); /* no need to drop every subdirectory separately */
        if(sxi_rmdirs(cache->dir_lfu_small) && errno != ENOENT)
            SXFS_ERROR("Cannot remove '%s' directory: %s", cache->dir_lfu_small, strerror(errno));
    }
    free(cache->tempdir);
    free(cache->dir_small);
    free(cache->dir_medium);
    free(cache->dir_large);
    free(cache->dir_lfu_small);
    free(cache->dir_lfu_medium);
    free(cache->dir_lfu_large);
    for(i=0; i<sizeof(cache->lfu)/sizeof(cache->lfu[0]); i++) {
        if(cache->lfu[i]) {
            for(j=0; j<cache->lfu_entries[i]; j++)
                free(cache->lfu[i][j].name);
            free(cache->lfu[i]);
        }
    }
    sxi_ht_free(cache->lru);
    sxi_ht_free(cache->blocks);
    if((err = pthread_mutex_destroy(&cache->mutex)))
        SXFS_ERROR("Cannot destroy cache mutex: %s", strerror(err));
    if((err = pthread_mutex_destroy(&cache->lfu_mutex)))
        SXFS_ERROR("Cannot destroy LFU cache mutex: %s", strerror(err));
    free(cache);
} /* cache_free */

int sxfs_cache_init (sxc_client_t *sx, sxfs_state_t *sxfs, size_t size, const char *path) {
    int ret = -1, err;
    unsigned int i;
    sxfs_cache_t *cache;

    if(!sxfs)
        return ret;
    if(!sx || !path) {
        fprintf(stderr, "ERROR: NULL argument in cache initialization\n");
        return ret;
    }
    if(sxfs->need_file)
        return 0;
    if(size < 64 * SX_BS_LARGE) {
        fprintf(stderr, "ERROR: Cache size must be at least %d\n", 64 * SX_BS_LARGE);
        return ret;
    }

    cache = (sxfs_cache_t*)calloc(1, sizeof(sxfs_cache_t));
    if(!cache) {
        fprintf(stderr, "ERROR: Out of memory\n");
        return ret;
    }
    cache->size = size / 2;
    cache->lfu_max = size / (SX_BS_SMALL + SX_BS_MEDIUM + SX_BS_LARGE);
    if((err = pthread_mutex_init(&cache->mutex, NULL))) {
        fprintf(stderr, "ERROR: Cannot create cache mutex: %s\n", strerror(err));
        ret = -err;
        free(cache);
        return ret;
    }
    if((err = pthread_mutex_init(&cache->lfu_mutex, NULL))) {
        fprintf(stderr, "ERROR: Cannot create LFU cache mutex: %s\n", strerror(err));
        ret = -err;
        if((err = pthread_mutex_destroy(&cache->mutex)))
            fprintf(stderr, "ERROR: Cannot destroy cache mutex: %s\n", strerror(err));
        free(cache);
        return ret;
    }
    cache->blocks = sxi_ht_new(sx, 10000); /* more than 128 * 64 for ht efficiency */
    if(!cache->blocks) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }
    /* using default cache we can have up to: 65536 small, 16384 medium or 256 large blocks */
    cache->lru = sxi_ht_new(sx, 1000);
    if(!cache->lru) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }
    cache->tempdir = strdup(path);
    if(!cache->tempdir) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }

    memset(cache->lfu, 0, 3 * sizeof(sxfs_cache_lfu_t*));
    for(i=0; i<sizeof(cache->lfu)/sizeof(cache->lfu[0]); i++) {
        cache->lfu[i] = (sxfs_cache_lfu_t*)malloc(cache->lfu_max * sizeof(sxfs_cache_lfu_t));
        if(!cache->lfu[i]) {
            fprintf(stderr, "ERROR: Out of memory\n");
            goto sxfs_cache_init_err;
        }
    }

    cache->dir_small = (char*)malloc(strlen(path) + 1 + lenof("small") + 1);
    if(!cache->dir_small) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }
    cache->dir_medium = (char*)malloc(strlen(path) + 1 + lenof("medium") + 1);
    if(!cache->dir_medium) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }
    cache->dir_large = (char*)malloc(strlen(path) + 1 + lenof("large") + 1);
    if(!cache->dir_large) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }
    cache->dir_lfu_small = (char*)malloc(strlen(path) + 1 + lenof("small") + 1 + lenof("lfu") + 1);
    if(!cache->dir_lfu_small) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }
    cache->dir_lfu_medium = (char*)malloc(strlen(path) + 1 + lenof("medium") + 1 + lenof("lfu") + 1);
    if(!cache->dir_lfu_medium) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }
    cache->dir_lfu_large = (char*)malloc(strlen(path) + 1 + + lenof("large") + 1 + lenof("lfu") + 1);
    if(!cache->dir_lfu_large) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }

    sprintf(cache->dir_lfu_small, "%s/lfu", path);
    if(mkdir(cache->dir_lfu_small, 0700)) {
        fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", cache->dir_lfu_small, strerror(errno));
        goto sxfs_cache_init_err;
    }

    sprintf(cache->dir_small, "%s/small", path);
    sprintf(cache->dir_medium, "%s/medium", path);
    sprintf(cache->dir_large, "%s/large", path);
    sprintf(cache->dir_lfu_small, "%s/lfu/small", path);
    sprintf(cache->dir_lfu_medium, "%s/lfu/medium", path);
    sprintf(cache->dir_lfu_large, "%s/lfu/large", path);

    if(mkdir(cache->dir_small, 0700)) {
        fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", cache->dir_small, strerror(errno));
        goto sxfs_cache_init_err;
    }
    if(mkdir(cache->dir_medium, 0700)) {
        fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", cache->dir_medium, strerror(errno));
        goto sxfs_cache_init_err;
    }
    if(mkdir(cache->dir_large, 0700)) {
        fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", cache->dir_large, strerror(errno));
        goto sxfs_cache_init_err;
    }
    if(mkdir(cache->dir_lfu_small, 0700)) {
        fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", cache->dir_lfu_small, strerror(errno));
        goto sxfs_cache_init_err;
    }
    if(mkdir(cache->dir_lfu_medium, 0700)) {
        fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", cache->dir_lfu_medium, strerror(errno));
        goto sxfs_cache_init_err;
    }
    if(mkdir(cache->dir_lfu_large, 0700)) {
        fprintf(stderr, "ERROR: Cannot create '%s' directory: %s\n", cache->dir_lfu_large, strerror(errno));
        goto sxfs_cache_init_err;
    }

    sxfs->cache = cache;
    cache = NULL;
    ret = 0;
sxfs_cache_init_err:
    cache_free(sxfs, cache);
    return ret;
} /* sxfs_cache_init */

void sxfs_cache_free (sxfs_state_t *sxfs) {
    cache_free(sxfs, sxfs->cache);
} /* sxfs_cache_free */

static void ENOSPC_handler (sxfs_state_t *sxfs) {
    pthread_mutex_lock(&sxfs->limits_mutex);
    if(!sxfs->need_file) {
        SXFS_ERROR("Disabling the block cache, restart SXFS (possibly with a different cache dir) to re-enable the cache");
        sxfs->need_file = 1;
        sxi_rmdirs(sxfs->cache->dir_small);
        sxi_rmdirs(sxfs->cache->dir_medium);
        sxi_rmdirs(sxfs->cache->dir_large);
    }
    pthread_mutex_unlock(&sxfs->limits_mutex);
} /* ENOSPC_handler */

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
    int ret, *block_counter;
    unsigned int blocksize;
    char path[PATH_MAX];
    size_t i_s = 0, i_m = 0, i_l = 0, removed = 0;
    size_t nfiles_small = 0, nfiles_medium = 0, nfiles_large = 0;
    blockfile_t *list_small = NULL, *list_medium = NULL, *list_large = NULL;

    if(sxfs->cache->used + size > sxfs->cache->size) {
        if(size < MIN_FREE_SIZE)
            size = MIN_FREE_SIZE;
        if((ret = load_files(sxfs, sxfs->cache->dir_small, &list_small, &nfiles_small)))
            goto cache_make_space_err;
        if((ret = load_files(sxfs, sxfs->cache->dir_medium, &list_medium, &nfiles_medium)))
            goto cache_make_space_err;
        if((ret = load_files(sxfs, sxfs->cache->dir_large, &list_large, &nfiles_large)))
            goto cache_make_space_err;

        while(sxfs->cache->used + size > sxfs->cache->size) {
	    int have_l = (i_l < nfiles_large);
	    int have_m = (i_m < nfiles_medium);
	    int have_s = (i_s < nfiles_small);
	    time_t mtime_l = have_l ? list_large[i_l].mtime : -1;
	    time_t mtime_m = have_m ? list_medium[i_m].mtime : -1;
	    time_t mtime_s = have_s ? list_small[i_s].mtime : -1;

	    if(have_l &&
	       (!have_m || mtime_l <= mtime_m) &&
	       (!have_s || mtime_l <= mtime_s)) {
                snprintf(path, sizeof(path), "%s/%s", sxfs->cache->dir_large, list_large[i_l].name);
                if(!sxi_ht_get(sxfs->cache->lru, list_large[i_l].name, strlen(list_large[i_l].name), (void**)&block_counter)) {
                    free(block_counter);
                    sxi_ht_del(sxfs->cache->lru, list_large[i_l].name, strlen(list_large[i_l].name));
                }
                i_l++;
                blocksize = SX_BS_LARGE;
	    } else if(have_m &&
		      (!have_l || mtime_m <= mtime_l) &&
		      (!have_s || mtime_m <= mtime_s)) {
                snprintf(path, sizeof(path), "%s/%s", sxfs->cache->dir_medium, list_medium[i_m].name);
                if(!sxi_ht_get(sxfs->cache->lru, list_medium[i_m].name, strlen(list_medium[i_m].name), (void**)&block_counter)) {
                    free(block_counter);
                    sxi_ht_del(sxfs->cache->lru, list_medium[i_m].name, strlen(list_medium[i_m].name));
                }
                i_m++;
                blocksize = SX_BS_MEDIUM;
	    } else if(have_s &&
		      (!have_l || mtime_s <= mtime_l) &&
		      (!have_m || mtime_s <= mtime_m)) {
		snprintf(path, sizeof(path), "%s/%s", sxfs->cache->dir_small, list_small[i_s].name);
                if(!sxi_ht_get(sxfs->cache->lru, list_small[i_s].name, strlen(list_small[i_s].name), (void**)&block_counter)) {
                    free(block_counter);
                    sxi_ht_del(sxfs->cache->lru, list_small[i_s].name, strlen(list_small[i_s].name));
                }
                i_s++;
                blocksize = SX_BS_SMALL;
	    } else {
                SXFS_ERROR("Cache inconsistency error");
                ret = -ENOMSG;
                goto cache_make_space_err;
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
    if(list_small) {
        for(i_s = 0; i_s<nfiles_small; i_s++)
            free(list_small[i_s].name);
        free(list_small);
    }
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
    int ret, fd, tmp_fd = -1, mutex_locked = 1, used_added = 0, *block_counter = NULL;
    ssize_t bytes;
    char *tmp_path = NULL, buff[SX_BS_LARGE];
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *dest = NULL;
    block_state_t *state;

    block_counter = (int*)calloc(1, sizeof(int));
    if(!block_counter) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    pthread_mutex_lock(&sxfs->cache->mutex);
    fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if(fd < 0) {
        if(errno != EEXIST) {
            ret = -errno;
            SXFS_ERROR("Cannot create '%s' file: %s", path, strerror(errno));
            if(ret == -ENOSPC)
                ENOSPC_handler(sxfs);
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
        free(block_counter); /* 'ret' needs to be true for 'block_counter' to be freed */
        goto cache_download_err; /* this is not a failure */
    }
    if((ret = cache_make_space(sxfs, fdata->blocksize)))
        goto cache_download_err;
    sxfs->cache->used += fdata->blocksize;
    if(sxi_ht_add(sxfs->cache->lru, fdata->ha[block], strlen(fdata->ha[block]), block_counter)) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto cache_download_err;
    }
    pthread_mutex_unlock(&sxfs->cache->mutex);
    mutex_locked = 0;
    used_added = 1;
    tmp_path = (char*)malloc(strlen(sxfs->cache->tempdir) + 1 + lenof("cache_XXXXXX") + 1);
    if(!tmp_path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto cache_download_err;
    }
    sprintf(tmp_path, "%s/cache_XXXXXX", sxfs->cache->tempdir);
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
        if(ret == -ENOSPC)
            ENOSPC_handler(sxfs);
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
    if(tmp_fd >= 0) {
        if(close(tmp_fd))
            SXFS_ERROR("Cannot close '%s' file: %s", tmp_path, strerror(errno));
        if(unlink(tmp_path))
            SXFS_ERROR("Cannot remove '%s' file: %s", tmp_path, strerror(errno));
    }
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
    if(ret) {
        free(block_counter);
        sxi_ht_del(sxfs->cache->lru, fdata->ha[block], strlen(fdata->ha[block]));
    }
    pthread_mutex_unlock(&sxfs->cache->mutex);
    free(tmp_path);
    sxc_file_free(dest);
    return ret;
} /* cache_download */

#define MAXBLOCKS MAX(MAX(SXFS_BS_SMALL_AMOUNT, SXFS_BS_MEDIUM_AMOUNT), SXFS_BS_LARGE_AMOUNT)
struct _cache_thread_data_t {
    int fds[MAXBLOCKS];
    unsigned int nblocks, blocks[MAXBLOCKS];
    char *dir;
    sxfs_state_t *sxfs;
    sxfs_file_t *sxfs_file;
};
typedef struct _cache_thread_data_t cache_thread_data_t;

static void* cache_download_thread (void *ptr) {
    int err, fd = -1, *block_counter = NULL;
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
        err = ENOMEM;
        goto cache_download_thread_err;
    }
    for(i=0; i<cdata->nblocks; i++) {
        fdata2.ha[i] = strdup(fdata->ha[cdata->blocks[i]]);
        if(!fdata2.ha[i]) {
            SXFS_ERROR("Out of memory");
            err = ENOMEM;
            goto cache_download_thread_err;
        }
    }
    fdata2.nhashes = cdata->nblocks;
    snprintf(path, sizeof(path), "%s/cache_XXXXXX", sxfs->cache->tempdir);
    fd = mkstemp(path);
    if(fd < 0) {
        err = errno;
        SXFS_ERROR("Cannot create unique temporary file: %s", strerror(errno));
        goto cache_download_thread_err;
    }
    if((err = sxfs_get_sx_data(sxfs, &sx, &cluster))) {
        SXFS_ERROR("Cannot get SX data");
        goto cache_download_thread_err;
    }
    file = sxc_file_local(sx, path);
    if(!file) {
        SXFS_ERROR("Cannot create local file object: %s", sxc_geterrmsg(sx));
        err = sxfs_sx_err(sx);
        goto cache_download_thread_err;
    }
    if(sxi_sxfs_download_run(&fdata2, cluster, file, 0, cdata->nblocks * fdata->blocksize)) { /* 0 offset - fdata2.ha is 'hacked' */
        SXFS_ERROR("Cannot download the part of '%s' file: %s", cdata->sxfs_file->remote_path, sxc_geterrmsg(sx));
        err = sxfs_sx_err(sx);
        goto cache_download_thread_err;
    }
    for(i=0; i<cdata->nblocks; i++) {
        if((bytes = read(fd, buff, fdata->blocksize)) < 0) {
            err = errno;
            SXFS_ERROR("Cannot read from '%s' file: %s", path, strerror(errno));
            goto cache_download_thread_err;
        }
        if(bytes < fdata->blocksize) {
            SXFS_ERROR("Read less data than expected (%lu != %u)", (unsigned long int)bytes, fdata->blocksize);
            err = EINVAL;
            goto cache_download_thread_err;
        }
        if((bytes = write(cdata->fds[i], buff, fdata->blocksize)) < 0) {
            err = errno;
            SXFS_ERROR("Cannot write to %d (%s) file descriptor: %s", cdata->fds[i], fdata->ha[cdata->blocks[i]], strerror(errno));
            if(err == ENOSPC)
                ENOSPC_handler(sxfs);
            goto cache_download_thread_err;
        }
        if(bytes < fdata->blocksize) {
            SXFS_ERROR("Wrote less data than expected (%lu != %u)", (unsigned long int)bytes, fdata->blocksize);
            err = EINVAL;
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

    err = 0;
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
        if(err && !sxi_ht_get(sxfs->cache->lru, fdata->ha[cdata->blocks[i]], strlen(fdata->ha[cdata->blocks[i]]), (void**)&block_counter)) {
            free(block_counter);
            sxi_ht_del(sxfs->cache->lru, fdata->ha[cdata->blocks[i]], strlen(fdata->ha[cdata->blocks[i]]));
        }
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
    pthread_exit(NULL);
} /* cache_download_thread */

static void cache_read_background (sxfs_state_t *sxfs, sxfs_file_t *sxfs_file, unsigned int block, unsigned int nblocks) {
    int err, end_reached = 0, duplicate, cache_locked = 0, *block_counter = NULL;
    unsigned int i, j;
    char *path;
    const char *dir = "foo"; /* shut up warnings */
    cache_thread_data_t *cdata = NULL;
    pthread_t thread;

    if(block >= sxfs_file->fdata->nhashes)
        return;
    if(block + nblocks > sxfs_file->fdata->nhashes)
        nblocks = sxfs_file->fdata->nhashes - block;
    if(!nblocks)
        return;
    switch(sxfs_file->fdata->blocksize) {
        case SX_BS_SMALL:
            dir = "small";
            break;
        case SX_BS_MEDIUM:
            dir = "medium";
            break;
        case SX_BS_LARGE:
            dir = "large";
            break;
        default:
            SXFS_ERROR("Unknown block size");
            return;
    }
    path = (char*)malloc(strlen(sxfs->cache->tempdir) + 1 + lenof("lfu") + 1 + strlen(dir) + 1 + SXI_SHA1_TEXT_LEN + 1);
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
    cdata->dir = (char*)malloc(strlen(sxfs->cache->tempdir) + 1 + strlen(dir) + 1);
    if(!cdata->dir) {
        SXFS_ERROR("Out of memory");
        goto cache_read_background_err;
    }
    sprintf(cdata->dir, "%s/%s", sxfs->cache->tempdir, dir);
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
            sprintf(path, "%s/%s/%s", sxfs->cache->tempdir, dir, sxfs_file->fdata->ha[block+i]);
            if(access(path, F_OK)) {
                if(errno == ENOENT) {
                    sprintf(path, "%s/lfu/%s/%s", sxfs->cache->tempdir, dir, sxfs_file->fdata->ha[block+i]);
                    if(access(path, F_OK)) {
                        if(errno == ENOENT) {
                            cdata->fds[cdata->nblocks] = -1;
                            cdata->blocks[cdata->nblocks] = block + i;
                            cdata->nblocks++;
                        } else {
                            SXFS_ERROR("Cannot access '%s' file: %s", path, strerror(errno));
                            goto cache_read_background_err;
                        }
                    }
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
            block_counter = (int*)calloc(1, sizeof(int));
            if(!block_counter) {
                SXFS_ERROR("Out of memory");
                goto cache_read_background_err;
            }
            if(sxi_ht_add(sxfs->cache->lru, sxfs_file->fdata->ha[cdata->blocks[i]], strlen(sxfs_file->fdata->ha[cdata->blocks[i]]), block_counter)) {
                SXFS_ERROR("Out of memory");
                free(block_counter);
            }
            block_counter = NULL;
            sprintf(path, "%s/%s/%s", sxfs->cache->tempdir, dir, sxfs_file->fdata->ha[cdata->blocks[i]]);
            cdata->fds[i] = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
            if(cdata->fds[i] < 0) {
                err = errno;
                SXFS_ERROR("Cannot create '%s' file: %s", path, strerror(errno));
                if(err == ENOSPC)
                    ENOSPC_handler(sxfs);
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
        for(i=0; i<cdata->nblocks; i++) {
            if(!sxi_ht_get(sxfs->cache->lru, sxfs_file->fdata->ha[cdata->blocks[i]], strlen(sxfs_file->fdata->ha[cdata->blocks[i]]), (void**)&block_counter)) {
                free(block_counter);
                sxi_ht_del(sxfs->cache->lru, sxfs_file->fdata->ha[cdata->blocks[i]], strlen(sxfs_file->fdata->ha[cdata->blocks[i]]));
            }
            if(cdata->fds[i] >= 0) {
                sprintf(path, "%s/%s/%s", sxfs->cache->tempdir, dir, sxfs_file->fdata->ha[cdata->blocks[i]]);
                if(close(cdata->fds[i]))
                    SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
                if(unlink(path)) {
                    if(errno != ENOENT)
                        SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
                } else {
                    sxfs->cache->used -= sxfs_file->fdata->blocksize;
                }
            }
        }
        free(cdata->dir);
        free(cdata);
    }
    if(cache_locked)
        pthread_mutex_unlock(&sxfs->cache->mutex);
    free(path);
} /* cache_read_background */

static int wait_for_block (sxfs_state_t *sxfs, sxfs_cache_t *cache, sxi_sxfs_data_t *fdata, unsigned int block) {
    int status;
    block_state_t *state;

    if(sxi_ht_get(cache->blocks, fdata->ha[block], strlen(fdata->ha[block]), (void**)&state)) {
        state = (block_state_t*)malloc(sizeof(block_state_t));
        if(!state) {
            SXFS_ERROR("Out of memory");
            return -ENOMEM;
        }
        state->waiting = 1;
        state->status = BLOCK_STATUS_BUSY;
        if(sxi_ht_add(cache->blocks, fdata->ha[block], strlen(fdata->ha[block]), state)) {
            SXFS_ERROR("Out of memory");
            return -ENOMEM;
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
    if(status == BLOCK_STATUS_FAILED)
        return -EAGAIN;
    return 0;
} /* wait_for_block */

static char* calculate_block_name (sxfs_state_t *sxfs, void *buff, size_t size) {
    char *ret;
    const char *uuid;
    unsigned char sha_hash[SXI_SHA1_BIN_LEN];
    sxc_client_t *sx;
    sxc_cluster_t *cluster;

    ret = (char*)malloc(SXI_SHA1_TEXT_LEN + 1);
    if(!ret)
        return NULL;
    if(sxfs_get_sx_data(sxfs, &sx, &cluster)) {
        SXFS_ERROR("Cannot get SX data");
        free(ret);
        return NULL;
    }
    uuid = sxc_cluster_get_uuid(cluster);
    if(!uuid) {
        SXFS_ERROR("Cannot get cluster UUID");
        free(ret);
        return NULL;
    }
    if(sxi_sha1_calc(uuid, strlen(uuid), buff, size, sha_hash)) {
        SXFS_ERROR("Cannot calculate checksum");
        free(ret);
        return NULL;
    }
    sxi_bin2hex(sha_hash, SXI_SHA1_BIN_LEN, ret);
    ret[SXI_SHA1_TEXT_LEN] = '\0';
    return ret;
} /* calculate_block_name */

static ssize_t validate_block (sxfs_state_t *sxfs, sxi_sxfs_data_t *fdata, unsigned int block, void *buff, size_t length, off_t offset) {
    int fd = -1, cache_locked = 0, lfu_accessed = 0, *block_counter = NULL, *lfu_sorted;
    size_t *lfu_n;
    ssize_t ret, index;
    time_t add_time;
    char *path = NULL, *calc_name = NULL, local_buff[SX_BS_LARGE];
    const char *block_name = fdata->ha[block], *dir = "foo"; /* shut up warnings */
    struct stat st;
    sxfs_cache_t *cache = sxfs->cache;
    sxfs_cache_lfu_t *lfu;

    switch(fdata->blocksize) {
        case SX_BS_SMALL:
            dir = "small";
            lfu = cache->lfu[CACHE_INDEX_SMALL];
            lfu_n = &cache->lfu_entries[CACHE_INDEX_SMALL];
            lfu_sorted = &cache->lfu_sorted[CACHE_INDEX_SMALL];
            break;
        case SX_BS_MEDIUM:
            dir = "medium";
            lfu = cache->lfu[CACHE_INDEX_MEDIUM];
            lfu_n = &cache->lfu_entries[CACHE_INDEX_MEDIUM];
            lfu_sorted = &cache->lfu_sorted[CACHE_INDEX_MEDIUM];
            break;
        case SX_BS_LARGE:
            dir = "large";
            lfu = cache->lfu[CACHE_INDEX_LARGE];
            lfu_n = &cache->lfu_entries[CACHE_INDEX_LARGE];
            lfu_sorted = &cache->lfu_sorted[CACHE_INDEX_LARGE];
            break;
        default:
            SXFS_ERROR("Unknown block size");
            return -EINVAL;
    }
    if((add_time = time(NULL)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
        goto validate_block_err;
    }
    path = (char*)malloc(strlen(cache->tempdir) + 1 + lenof("lfu") + 1 + strlen(dir) + 1 + strlen(block_name) + 1);
    if(!path) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    sprintf(path, "%s/%s/%s", cache->tempdir, dir, block_name);
    fd = open(path, O_RDONLY);
    if(fd < 0) {
        if(errno == ENOENT) {
            sprintf(path, "%s/lfu/%s/%s", cache->tempdir, dir, block_name);
            pthread_mutex_lock(&cache->lfu_mutex);
            fd = open(path, O_RDONLY);
            if(fd < 0) {
                pthread_mutex_unlock(&cache->lfu_mutex);
                sprintf(path, "%s/%s/%s", cache->tempdir, dir, block_name);
                if((ret = cache_download(sxfs, fdata, block, path, &fd))) {
                    goto validate_block_err;
                }
            } else {
                lfu_accessed = 1;
                if(*lfu_n && *lfu_sorted != LFU_SORTED_BY_NAME) {
                    qsort(lfu, *lfu_n, sizeof(sxfs_cache_lfu_t), lfu_sort_cmp_name);
                    *lfu_sorted = LFU_SORTED_BY_NAME;
                }
                if((index = sxfs_find_entry((const void**)lfu, *lfu_n, block_name, lfu_entry_cmp_name)) >= 0) {
                    lfu[index].times_used++;
                    lfu[index].add_time = add_time;
                } else { /* this means that unlink has failed, but why not make use of this block? */
                    if(unlink(path))
                        SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
                }
                pthread_mutex_unlock(&cache->lfu_mutex);
            }
        } else {
            ret = -errno;
            SXFS_ERROR("Cannot open '%s' file: %s", path, strerror(errno));
            goto validate_block_err;
        }
    } else {
        char *block_name_dup = strdup(block_name), *path2;

        if(!block_name_dup) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            goto validate_block_err;
        }
        path2 = (char*)malloc(strlen(cache->tempdir) + 1 + lenof("lfu") + 1 + strlen(dir) + 1 + strlen(block_name) + 1);
        if(!path2) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            free(block_name_dup);
            goto validate_block_err;
        }
        sprintf(path2, "%s/lfu/%s/%s", cache->tempdir, dir, block_name);
        pthread_mutex_lock(&cache->mutex);
        if(sxi_ht_get(cache->lru, block_name, strlen(block_name), (void**)&block_counter)) {
            SXFS_DEBUG("'%s' block counter not found in LRU (possible race condition)", block_name);
            /* do not fail whole function - there can be a race condition with block removal */
        }
	block_counter = NULL;
        if(block_counter && *block_counter) {
            if(rename(path, path2)) {
                if(errno != ENOENT) /* very racy stuff */
                    SXFS_ERROR("Cannot insert block into LFU cache: %s", strerror(errno));
                pthread_mutex_unlock(&cache->mutex);
            } else {
                char *tmp_str = path;
                path = path2;
                path2 = tmp_str;

                cache->used -= fdata->blocksize;
                free(block_counter);
                block_counter = NULL;
                sxi_ht_del(cache->lru, block_name, strlen(block_name));
                lfu_accessed = 1;
                pthread_mutex_unlock(&cache->mutex);
                pthread_mutex_lock(&cache->lfu_mutex);
                if(*lfu_sorted == LFU_SORTED_BY_NAME && (index = sxfs_find_entry((const void**)lfu, *lfu_n, block_name, lfu_entry_cmp_name)) >= 0) {
                    /* This error does not seem to be critical due to EAGAIN being returned. It can be triggered by
                     * regular read operations, especially for large files. */
                    SXFS_DEBUG("'%s' block already in LFU cache", block_name);
                    free(block_name_dup);
                    free(path2);
                    ret = -EAGAIN;
                    pthread_mutex_unlock(&cache->lfu_mutex);
                    goto validate_block_err;
                }
                if(*lfu_n == cache->lfu_max) {
                    if(*lfu_sorted != LFU_SORTED_BY_USAGE) {
                        qsort(lfu, *lfu_n, sizeof(sxfs_cache_lfu_t), lfu_sort_cmp_usage);
                        *lfu_sorted = LFU_SORTED_BY_USAGE;
                    }
                    index = 0;
                    sprintf(path2, "%s/lfu/%s/%s", cache->tempdir, dir, lfu[index].name); /* all block names have equal lenght */
                    if(unlink(path2))
                        SXFS_ERROR("Cannot remove '%s' file: %s", path2, strerror(errno));
                    free(lfu[index].name);
                } else {
                    index = *lfu_n;
                }
                lfu[index].name = block_name_dup;
                block_name_dup = NULL;
                lfu[index].times_used = 2;
                lfu[index].add_time = add_time;
                if(*lfu_n != cache->lfu_max) {
                    (*lfu_n)++;
                    /* put new entry in correct position only if array is sorted */
                    if(*lfu_sorted == LFU_SORTED_BY_NAME) {
                        while(index > 0 && strcmp(lfu[index].name, lfu[index-1].name) < 0) {
                            sxfs_cache_lfu_t tmp = lfu[index-1];
                            lfu[index-1] = lfu[index];
                            lfu[index] = tmp;
                            index--;
                        }
                    } else {
                        *lfu_sorted = LFU_SORTED_NONE;
                    }
                }
                pthread_mutex_unlock(&cache->lfu_mutex);
            }
        } else
            pthread_mutex_unlock(&cache->mutex);
        free(block_name_dup);
        free(path2);
    }
    if(!offset && !lfu_accessed) {
        pthread_mutex_lock(&cache->mutex);
        if(!block_counter && sxi_ht_get(cache->lru, block_name, strlen(block_name), (void**)&block_counter)) {
            SXFS_DEBUG("'%s' block counter not found in LRU (possible race condition)", block_name);
            /* do not fail whole function - there can be a race condition with block removal */
        } else {
            (*block_counter)++;
        }
        pthread_mutex_unlock(&cache->mutex);
    }
    if(fstat(fd, &st)) { /* try to avoid locking the mutex for better performance */
        ret = -errno;
        SXFS_ERROR("Cannot fstat '%s' file: %s", path, strerror(errno));
        goto validate_block_err;
    }
    if(st.st_size != fdata->blocksize) {
        pthread_mutex_lock(&cache->mutex);
        cache_locked = 1;
        if(fstat(fd, &st)) { /* file can be filled between those fstats which can lead to deadlock */
            ret = -errno;
            SXFS_ERROR("Cannot fstat '%s' file: %s", path, strerror(errno));
            goto validate_block_err;
        }
        if(st.st_size != fdata->blocksize) {
            if(wait_for_block(sxfs, cache, fdata, block)) {
                SXFS_DEBUG("Background thread failed to download the block, trying again");
                if((ret = cache_download(sxfs, fdata, block, path, &fd))) /* try to download the block again anyway */
                    goto validate_block_err;
            }
        }
        pthread_mutex_unlock(&cache->mutex);
        cache_locked = 0;
    }
    if((ret = pread(fd, local_buff, fdata->blocksize, 0)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot read from '%s' file: %s", path, strerror(errno));
        goto validate_block_err;
    }
    if(ret != fdata->blocksize) {
        SXFS_ERROR("Read less than expected (%lld != %u)", (long long int)ret, fdata->blocksize);
        ret = -EINVAL;
        goto validate_block_err;
    }
    calc_name = calculate_block_name(sxfs, local_buff, fdata->blocksize);
    if(!calc_name) {
        SXFS_ERROR("Failed to compute the block name");
        ret = -ENOMEM;
        goto validate_block_err;
    }
    if(memcmp(calc_name, fdata->ha[block], SXI_SHA1_TEXT_LEN)) {
        SXFS_ERROR("Invalid content of '%s' block. Calculated name: %s", fdata->ha[block], calc_name);
        pthread_mutex_lock(&cache->mutex);
        if(unlink(path))
            SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
        else
            cache->used -= fdata->blocksize;
        pthread_mutex_unlock(&cache->mutex);
        ret = -EAGAIN;
        goto validate_block_err;
    }
    if(utime(path, NULL) && errno != ENOENT)
        SXFS_ERROR("Cannot update mtime of '%s' file: %s", path, strerror(errno));

    if(length + offset > fdata->blocksize)
        length = fdata->blocksize - offset; /* don't try to read more than available */
    memcpy(buff, local_buff + offset, length);
    ret = length;
validate_block_err:
    if(cache_locked)
        pthread_mutex_unlock(&cache->mutex);
    if(fd >= 0 && close(fd))
        SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
    free(path);
    free(calc_name);
    return ret;
} /* validate_block */

ssize_t sxfs_cache_read (sxfs_state_t *sxfs, sxfs_file_t *sxfs_file, void *buff, size_t length, off_t offset) {
    unsigned int block, nblocks = 0;
    ssize_t ret;
    sxfs_cache_t *cache;
    sxi_sxfs_data_t *fdata;

    if(!sxfs || !sxfs_file || !buff) {
        if(sxfs)
            SXFS_ERROR("NULL argument");
        return -EINVAL;
    }
    cache = sxfs->cache;
    fdata = sxfs_file->fdata;
    if(!sxfs->need_file) {
        if(!cache) { /* sxfs->cache can be NULL when sxfs->need_file is true */
            SXFS_ERROR("NULL argument");
            return -EINVAL;
        }
        if(fdata) { /* file opened by create() doesn't have fdata but always has write_fd */
            switch(fdata->blocksize) {
                case SX_BS_SMALL:
                    nblocks = SXFS_BS_SMALL_AMOUNT;
                    break;
                case SX_BS_MEDIUM:
                    nblocks = SXFS_BS_MEDIUM_AMOUNT;
                    break;
                case SX_BS_LARGE:
                    nblocks = SXFS_BS_LARGE_AMOUNT;
                    break;
                default:
                    SXFS_ERROR("Unknown block size");
                    return -EINVAL;
            }
        }
    } else if(sxfs_file->write_fd < 0 && (ret = sxfs_get_file(sxfs, sxfs_file))) {
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
    if(!sxfs->args->fuse_single_threaded_given) /* SXFS sets *_flag to 1 on OS X */
        cache_read_background(sxfs, sxfs_file, block+1, nblocks);

    /* reading the block is inside so sxfs can use the data it needs to read anyway */
    return validate_block(sxfs, fdata, block, buff, length, offset % fdata->blocksize);
} /* sxfs_cache_read */

