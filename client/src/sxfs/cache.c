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

#define CACHE_MIN_SIZE 256 /* in MB */
#define MIN_FREE_SIZE (3 * 1024 * 1024) /* 3 MB */
#define CACHE_LFU_THRESHOLD 2

#define CACHE_INDEX_SMALL 0
#define CACHE_INDEX_MEDIUM 1
#define CACHE_INDEX_LARGE 2

#define CACHE_MUTEX (1<<0)
#define CACHE_LRU_MUTEX (1<<1)
#define CACHE_LFU_MUTEX (1<<2)

struct _block_state_t {
    unsigned int times_used, waiting;
    int status;
};
typedef struct _block_state_t block_state_t;

struct _sxfs_cache_t {
    size_t nthreads, lfu_entries[3], lfu_max[3];
    ssize_t used, lru_size; /* can be negative due to race conditions with small size */
    char *tempdir, *dir_small, *dir_medium, *dir_large, *dir_lfu_small, *dir_lfu_medium, *dir_lfu_large;
    pthread_mutex_t mutex, lru_mutex, lfu_mutex;
    sxi_ht *blocks_lru, *blocks_lfu[3];
};

static void cache_free (sxfs_state_t *sxfs, sxfs_cache_t *cache) {
    int err;
    unsigned int i, key_len;
    const void *key;
    block_state_t *block_state;

    if(!sxfs || !cache)
        return;
    pthread_mutex_lock(&cache->mutex);
    while(cache->nthreads) {
        pthread_mutex_unlock(&cache->mutex);
        usleep(SXFS_THREAD_WAIT);
        pthread_mutex_lock(&cache->mutex);
    }
    pthread_mutex_unlock(&cache->mutex);
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
    sxi_ht_enum_reset(cache->blocks_lru);
    while(!sxi_ht_enum_getnext(cache->blocks_lru, &key, &key_len, NULL)) {
        if(sxi_ht_get(cache->blocks_lru, key, key_len, (void**)&block_state)) {
            SXFS_ERROR("Cannot get LRU block state");
        } else {
            free(block_state);
        }
    }
    sxi_ht_free(cache->blocks_lru);
    for(i=0; i<sizeof(cache->blocks_lfu)/sizeof(cache->blocks_lfu[0]); i++) {
        sxi_ht_enum_reset(cache->blocks_lfu[i]);
        while(!sxi_ht_enum_getnext(cache->blocks_lfu[i], &key, &key_len, NULL)) {
            if(sxi_ht_get(cache->blocks_lfu[i], key, key_len, (void**)&block_state)) {
                SXFS_ERROR("Cannot get LFU block state");
            } else {
                free(block_state);
            }
        }
        sxi_ht_free(cache->blocks_lfu[i]);
    }
    if((err = pthread_mutex_destroy(&cache->mutex)))
        SXFS_ERROR("Cannot destroy cache mutex: %s", strerror(err));
    if((err = pthread_mutex_destroy(&cache->lru_mutex)))
        SXFS_ERROR("Cannot destroy LRU cache mutex: %s", strerror(err));
    if((err = pthread_mutex_destroy(&cache->lfu_mutex)))
        SXFS_ERROR("Cannot destroy LFU cache mutex: %s", strerror(err));
    free(cache);
} /* cache_free */

int sxfs_cache_init (sxc_client_t *sx, sxfs_state_t *sxfs, size_t size, const char *path) {
    int ret = -1, err;
    unsigned int i;
    size_t lfu_medium_size, lfu_large_size;
    sxfs_cache_t *cache;

    if(!sxfs)
        return ret;
    if(!sx || !path) {
        fprintf(stderr, "ERROR: NULL argument in cache initialization\n");
        return ret;
    }
    if(sxfs->need_file)
        return 0;
    if(size < CACHE_MIN_SIZE * 1024UL * 1024UL) {
        fprintf(stderr, "ERROR: Cache size must be at least %lu\n", CACHE_MIN_SIZE * 1024UL * 1024UL);
        return ret;
    }

    cache = (sxfs_cache_t*)calloc(1, sizeof(sxfs_cache_t));
    if(!cache) {
        fprintf(stderr, "ERROR: Out of memory\n");
        return ret;
    }
    size /= 2;
    cache->lru_size = size; /* LFU is half of cache in size (and so LFU is) */
    lfu_large_size = size / 2; /* 50% of LFU size */
    lfu_medium_size = (size * 35) / 100; /* 35% of LFU */
    cache->lfu_max[CACHE_INDEX_LARGE] = lfu_large_size / SX_BS_LARGE;
    cache->lfu_max[CACHE_INDEX_MEDIUM] = lfu_medium_size / SX_BS_MEDIUM;
    cache->lfu_max[CACHE_INDEX_SMALL] = (size - lfu_medium_size - lfu_large_size) / SX_BS_SMALL; /* 15% of LFU (which is the rest) */
    SXFS_DEBUG("LFU blocks number limits: small: %lu, medium: %lu, large: %lu", (long unsigned int)cache->lfu_max[CACHE_INDEX_SMALL], (long unsigned int)cache->lfu_max[CACHE_INDEX_MEDIUM], (long unsigned int)cache->lfu_max[CACHE_INDEX_LARGE]);
    if((err = pthread_mutex_init(&cache->mutex, NULL))) {
        fprintf(stderr, "ERROR: Cannot create cache mutex: %s\n", strerror(err));
        ret = -err;
        free(cache);
        return ret;
    }
    if((err = pthread_mutex_init(&cache->lru_mutex, NULL))) {
        fprintf(stderr, "ERROR: Cannot create LRU cache mutex: %s\n", strerror(err));
        ret = -err;
        if((err = pthread_mutex_destroy(&cache->mutex)))
            fprintf(stderr, "ERROR: Cannot destroy cache mutex: %s\n", strerror(err));
        free(cache);
        return ret;
    }
    if((err = pthread_mutex_init(&cache->lfu_mutex, NULL))) {
        fprintf(stderr, "ERROR: Cannot create LFU cache mutex: %s\n", strerror(err));
        ret = -err;
        if((err = pthread_mutex_destroy(&cache->mutex)))
            fprintf(stderr, "ERROR: Cannot destroy cache mutex: %s\n", strerror(err));
        if((err = pthread_mutex_destroy(&cache->lru_mutex)))
            fprintf(stderr, "ERROR: Cannot destroy LRU cache mutex: %s\n", strerror(err));
        free(cache);
        return ret;
    }
    cache->blocks_lru = sxi_ht_new(sx, (size / 4096) + 100); /* number of SX_BS_SMALL blocks available to fit in the LRU +100 (see below) */
    if(!cache->blocks_lru) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }
    for(i=0; i<sizeof(cache->blocks_lfu)/sizeof(cache->blocks_lfu[0]); i++) {
        if(i >= sizeof(cache->lfu_max)/sizeof(cache->lfu_max[0])) {
            fprintf(stderr, "ERROR: Internal cache incosistency\n");
            goto sxfs_cache_init_err;
        }
        cache->blocks_lfu[i] = sxi_ht_new(sx, cache->lfu_max[i] + 100); /* +100 is a buffer for moving blocks between LRU and LFU */
        if(!cache->blocks_lfu[i]) {
            fprintf(stderr, "ERROR: Out of memory\n");
            goto sxfs_cache_init_err;
        }
    }
    cache->tempdir = strdup(path);
    if(!cache->tempdir) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
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
    int ret;
    unsigned int blocksize;
    char *block_name, path[PATH_MAX];
    size_t i_s = 0, i_m = 0, i_l = 0, removed = 0;
    size_t nfiles_small = 0, nfiles_medium = 0, nfiles_large = 0;
    blockfile_t *list_small = NULL, *list_medium = NULL, *list_large = NULL;
    block_state_t *block_state;

    if(sxfs->cache->used + size > sxfs->cache->lru_size) {
        if(size < MIN_FREE_SIZE)
            size = MIN_FREE_SIZE;
        if((ret = load_files(sxfs, sxfs->cache->dir_small, &list_small, &nfiles_small)))
            goto cache_make_space_err;
        if((ret = load_files(sxfs, sxfs->cache->dir_medium, &list_medium, &nfiles_medium)))
            goto cache_make_space_err;
        if((ret = load_files(sxfs, sxfs->cache->dir_large, &list_large, &nfiles_large)))
            goto cache_make_space_err;

        while(sxfs->cache->used + size > sxfs->cache->lru_size) {
	    int have_l = (i_l < nfiles_large);
	    int have_m = (i_m < nfiles_medium);
	    int have_s = (i_s < nfiles_small);
	    time_t mtime_l = have_l ? list_large[i_l].mtime : -1;
	    time_t mtime_m = have_m ? list_medium[i_m].mtime : -1;
	    time_t mtime_s = have_s ? list_small[i_s].mtime : -1;

	    if(have_l &&
	       (!have_m || mtime_l <= mtime_m) &&
	       (!have_s || mtime_l <= mtime_s)) {
                block_name = list_large[i_l].name;
                snprintf(path, sizeof(path), "%s/%s", sxfs->cache->dir_large, list_large[i_l].name);
                i_l++;
                blocksize = SX_BS_LARGE;
	    } else if(have_m &&
		      (!have_l || mtime_m <= mtime_l) &&
		      (!have_s || mtime_m <= mtime_s)) {
                block_name = list_medium[i_m].name;
                snprintf(path, sizeof(path), "%s/%s", sxfs->cache->dir_medium, list_medium[i_m].name);
                i_m++;
                blocksize = SX_BS_MEDIUM;
	    } else if(have_s &&
		      (!have_l || mtime_s <= mtime_l) &&
		      (!have_m || mtime_s <= mtime_m)) {
                block_name = list_small[i_s].name;
		snprintf(path, sizeof(path), "%s/%s", sxfs->cache->dir_small, list_small[i_s].name);
                i_s++;
                blocksize = SX_BS_SMALL;
	    } else {
                SXFS_ERROR("Cache inconsistency error");
                ret = -ENOMSG;
                goto cache_make_space_err;
	    }
            if(sxi_ht_get(sxfs->cache->blocks_lru, block_name, strlen(block_name), (void**)&block_state)) {
                SXFS_ERROR("Cannot get LRU block state: %s", block_name);
            } else if(block_state->status == BLOCK_STATUS_DONE && !block_state->waiting) {
                sxi_ht_del(sxfs->cache->blocks_lru, block_name, strlen(block_name));
                free(block_state);
                if(unlink(path)) {
                    ret = -errno;
                    SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
                    goto cache_make_space_err;
                }
                removed++;
                sxfs->cache->used -= blocksize;
            }
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

static int wait_for_block (sxfs_state_t *sxfs, int fd, const char *block_name, unsigned int blocksize) {
    int ret;
    struct stat st;
    sxfs_cache_t *cache = sxfs->cache;
    block_state_t *block_state, *new_block_state;
        
    if(fstat(fd, &st)) { /* try to avoid locking the mutex for better performance */
        ret = -errno;
        SXFS_ERROR("Cannot fstat file: %s", strerror(errno));
        return ret;
    }
    if(st.st_size != blocksize) {
        if(sxi_ht_get(cache->blocks_lru, block_name, strlen(block_name), (void**)&block_state)) {
            SXFS_ERROR("Cannot get LRU block state: %s", block_name);
            return -EAGAIN;
        } else {
            block_state->waiting++;
        }
        /* wait for the block to be correctly downloaded */
        while(block_state->status == BLOCK_STATUS_BUSY) {
            pthread_mutex_unlock(&cache->lru_mutex);
            usleep(SXFS_THREAD_WAIT);
            pthread_mutex_lock(&cache->lru_mutex);
        }
        block_state->waiting--;
        if(block_state->status == BLOCK_STATUS_FAILED) {
            /* wait for the block to be removed from hashtable */
            while(!sxi_ht_get(cache->blocks_lru, block_name, strlen(block_name), (void**)&new_block_state) && block_state == new_block_state) { /* block_state pointer can already be freed and replaced but here it's all about the pointer address */
                pthread_mutex_unlock(&cache->lru_mutex);
                usleep(SXFS_THREAD_WAIT);
                pthread_mutex_lock(&cache->lru_mutex);
            }
            /* try to download the block again */
            return -EAGAIN;
        }
    }
    return 0;
} /* wait_for_block */

static int move_block_to_lfu (sxfs_state_t *sxfs, sxi_sxfs_data_t *fdata, char **block_path, const char *block_name, block_state_t *block_state) { /* block_state contains data about block in LRU */
    int ret, lfu_locked = 0, lfu_index, file_over_limit = 0;
    unsigned int key_len, times_used = UINT_MAX;
    const void *key;
    size_t *lfu_n, *lfu_max;
    char *lfu_file_path = NULL, *lfu_file_path2 = NULL, *lru_file_path2 = NULL, *lfu_block_name = NULL;
    const char *dir = "foo"; /* shut up warnings */
    block_state_t *lfu_block_state = NULL;
    const block_state_t *tmp_block_state;
    sxfs_cache_t *cache = sxfs->cache;

    /* NOOP if another thread already moved this block */
    if(access(*block_path, F_OK)) {
        if(errno != ENOENT) {
            ret = -errno;
            SXFS_ERROR("Cannot check '%s' file existence: %s", *block_path, strerror(errno));
            return ret;
        }
        return 0;
    }
    /* lru_mutex is already locked in cache_read_block() */
    pthread_mutex_lock(&cache->lfu_mutex);
    lfu_locked = 1;
    /* this is done under both locks to avoid race condition in accessing block_state->times_used */
    if(block_state->times_used < CACHE_LFU_THRESHOLD) {
        pthread_mutex_unlock(&cache->lfu_mutex);
        return 0;
    }
    switch(fdata->blocksize) {
        case SX_BS_SMALL:
            dir = "small";
            lfu_index = CACHE_INDEX_SMALL;
            break;
        case SX_BS_MEDIUM:
            dir = "medium";
            lfu_index = CACHE_INDEX_MEDIUM;
            break;
        case SX_BS_LARGE:
            dir = "large";
            lfu_index = CACHE_INDEX_LARGE;
            break;
        default:
            SXFS_ERROR("Unknown block size");
            ret = -EINVAL;
            goto move_block_to_lfu_err;
    }

    lfu_file_path = (char*)malloc(strlen(cache->tempdir) + 1 + lenof("lfu") + 1 + strlen(dir) + 1 + strlen(block_name) + 1);
    if(!lfu_file_path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto move_block_to_lfu_err;
    }
    sprintf(lfu_file_path, "%s/lfu/%s/%s", cache->tempdir, dir, block_name);

    /* moving block back to LRU will not be triggered only for relatively small amount of blocks at the beginning of run 
     * so I can always prepare for this as I will not lost much performance at the beginning */
    /* *_file_path2 are used to bring block back from LFU to LRU */
    lru_file_path2 = (char*)malloc(strlen(cache->tempdir) + 1 + strlen(dir) + 1 + strlen(block_name) + 1); /* all block names have equal length */
    if(!lru_file_path2) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto move_block_to_lfu_err;
    }
    lfu_file_path2 = (char*)malloc(strlen(cache->tempdir) + 1 + lenof("lfu") + 1 + strlen(dir) + 1 + strlen(block_name) + 1); /* all block names have equal length */
    if(!lfu_file_path2) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto move_block_to_lfu_err;
    }
    lfu_block_name = strdup(block_name); /* all block names have equal length */
    if(!lfu_block_name) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto move_block_to_lfu_err;
    }

    lfu_n = &cache->lfu_entries[lfu_index];
    lfu_max = &cache->lfu_max[lfu_index];

    /* find less frequently used block, different than just inserted one */
    sxi_ht_enum_reset(cache->blocks_lfu[lfu_index]);
    while(!sxi_ht_enum_getnext(cache->blocks_lfu[lfu_index], &key, &key_len, (const void**)&tmp_block_state)) {
        if(times_used > tmp_block_state->times_used) { /* new block is not yet in LFU so no need to check whether we are moving same block back */
            times_used = tmp_block_state->times_used;
            memcpy(lfu_block_name, key, key_len);
            lfu_block_name[key_len] = '\0';
        }
    }
    sprintf(lru_file_path2, "%s/%s/%s", cache->tempdir, dir, lfu_block_name);
    sprintf(lfu_file_path2, "%s/lfu/%s/%s", cache->tempdir, dir, lfu_block_name); /* all block names have equal length */

    /* main logic begins */
    /* store block_state in both hashtables, sxi_ht_del always work */
    if(sxi_ht_add(cache->blocks_lfu[lfu_index], block_name, strlen(block_name), block_state)) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto move_block_to_lfu_err;
    }

    if(rename(*block_path, lfu_file_path)) { /* moving block from LRU to LFU */
        ret = -errno;
        SXFS_ERROR("Cannot insert block into LFU cache: %s", strerror(errno));
        sxi_ht_del(cache->blocks_lfu[lfu_index], block_name, strlen(block_name));
        goto move_block_to_lfu_err;
    } else {
        char *tmp_str = *block_path;
        *block_path = lfu_file_path;
        lfu_file_path = tmp_str;

        (*lfu_n)++; /* block added to LFU */
        cache->used -= fdata->blocksize; /* one block has been taken from LRU to LFU */
        sxi_ht_del(cache->blocks_lru, block_name, strlen(block_name));

        if(*lfu_n > *lfu_max) {
            file_over_limit = 1; /* we have too many files in LFU now */
            /* try to move the block from LFU back to LRU */
            if(sxi_ht_get(cache->blocks_lfu[lfu_index], lfu_block_name, strlen(lfu_block_name), (void**)&lfu_block_state)) {
                SXFS_ERROR("Cannot get LFU block state: %s", lfu_block_name);
                sxi_ht_del(cache->blocks_lfu[lfu_index], lfu_block_name, strlen(lfu_block_name)); /* we do not want this block in LFU anyway */
                (*lfu_n)--;
                ret = -ENOMSG;
                goto move_block_to_lfu_err;
            }
            sxi_ht_del(cache->blocks_lfu[lfu_index], lfu_block_name, strlen(lfu_block_name)); /* we do not want this block in LFU anyway */
            (*lfu_n)--;
            if(sxi_ht_add(cache->blocks_lru, lfu_block_name, strlen(lfu_block_name), lfu_block_state)) {
                SXFS_ERROR("Out of memory");
                ret = -ENOMEM;
                goto move_block_to_lfu_err;
            }
            if(rename(lfu_file_path2, lru_file_path2)) {
                ret = -errno;
                SXFS_ERROR("%s -> %s", lfu_file_path2, lru_file_path2);
                SXFS_ERROR("Cannot move '%s' block from LFU to LRU: %s", lfu_block_name, strerror(errno));
                sxi_ht_del(cache->blocks_lru, lfu_block_name, strlen(lfu_block_name));
                goto move_block_to_lfu_err;
            } else {
                file_over_limit = 0; /* no longer too many files in LFU */
                lfu_block_state->times_used = 0;
                cache->used += fdata->blocksize; /* moving block back to LRU */
            }
        }
    }

    ret = 0;
move_block_to_lfu_err:
    if(file_over_limit && unlink(lfu_file_path2)) /* we do not want this file in LFU */
        SXFS_ERROR("Cannot remove '%s' file: %s", lfu_file_path2, strerror(errno));
    if(lfu_locked)
        pthread_mutex_unlock(&cache->lfu_mutex);
    free(lfu_file_path);
    free(lfu_file_path2);
    free(lru_file_path2);
    free(lfu_block_name);
    return ret;
} /* move_block_to_lfu */

static int cache_download (sxfs_state_t *sxfs, sxi_sxfs_data_t *fdata, unsigned int block, char **path, int *file_fd, off_t offset) {
    int ret, fd = -1, tmp_fd = -1, mutex_locked = 0, got_sem = 0, used_added = 0, block_state_added = 0;
    ssize_t bytes;
    char *tmp_path = NULL, *buff = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *dest = NULL;
    sxfs_cache_t *cache = sxfs->cache;
    block_state_t *block_state = NULL;

    if(!file_fd) {
        SXFS_ERROR("NULL file descriptor pointer");
        return -EINVAL;
    }
    if(sem_wait(&sxfs->download_sem)) {
        ret = -errno;
        SXFS_ERROR("Failed to wait for semaphore: %s", strerror(errno));
        goto cache_download_err;
    }
    got_sem = 1;
    pthread_mutex_lock(&cache->lru_mutex);
    mutex_locked = 1;
    if(*file_fd < 0) {
        fd = open(*path, O_RDWR | O_CREAT | O_EXCL, 0600);
        if(fd < 0) {
            if(errno != EEXIST) {
                ret = -errno;
                SXFS_ERROR("Cannot create '%s' file: %s", *path, strerror(errno));
                if(ret == -ENOSPC)
                    ENOSPC_handler(sxfs);
                goto cache_download_err;
            }
            if(sem_post(&sxfs->download_sem)) {
                ret = -errno;
                SXFS_ERROR("Failed to post the semaphore: %s", strerror(errno));
                goto cache_download_err;
            }
            /* handle race condition */
            fd = open(*path, O_RDWR);
            if(fd < 0) {
                ret = -errno;
                SXFS_ERROR("Cannot open '%s' file: %s", *path, strerror(errno));
                pthread_mutex_unlock(&cache->lru_mutex);
                return ret;
            }
            if(sxi_ht_get(cache->blocks_lru, fdata->ha[block], strlen(fdata->ha[block]), (void**)&block_state)) {
                SXFS_ERROR("Cannot get LRU block state: %s [%u]", fdata->ha[block], block);
                if(close(fd))
                    SXFS_ERROR("Cannot close '%s' file: %s", *path, strerror(errno));
                pthread_mutex_unlock(&cache->lru_mutex);
                return -EAGAIN;
            }
            if(!offset)
                block_state->times_used++;
            /* do not exit before the block is correctly downloaded */
            if((ret = wait_for_block(sxfs, fd, fdata->ha[block], fdata->blocksize))) {
                SXFS_DEBUG("Another thread failed to download the block, trying again");
                if(close(fd))
                    SXFS_ERROR("Cannot close '%s' file: %s", *path, strerror(errno));
                pthread_mutex_unlock(&cache->lru_mutex);
                return ret;
            }
            if((ret = move_block_to_lfu(sxfs, fdata, path, fdata->ha[block], block_state))) {
                if(close(fd))
                    SXFS_ERROR("Cannot close '%s' file: %s", *path, strerror(errno));
                pthread_mutex_unlock(&cache->lru_mutex);
                return ret;
            }
            *file_fd = fd;
            pthread_mutex_unlock(&cache->lru_mutex);
            return 0;
        }
    } else {
        fd = *file_fd;
    }
    buff = (char*)malloc(SX_BS_LARGE);
    if(!buff) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto cache_download_err;
    }
    /* there should be no block_state in cache->blocks_lru if there was no file */
    block_state = (block_state_t*)calloc(1, sizeof(block_state_t));
    if(!block_state) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto cache_download_err;
    }
    block_state->status = BLOCK_STATUS_BUSY;
    if(!offset)
        block_state->times_used = 1;
    if(sxi_ht_add(cache->blocks_lru, fdata->ha[block], strlen(fdata->ha[block]), block_state)) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto cache_download_err;
    }
    block_state_added = 1;
    if((ret = cache_make_space(sxfs, fdata->blocksize)))
        goto cache_download_err;
    cache->used += fdata->blocksize;
    pthread_mutex_unlock(&cache->lru_mutex);
    mutex_locked = 0;
    used_added = 1;
    tmp_path = (char*)malloc(strlen(cache->tempdir) + 1 + lenof("cache_XXXXXX") + 1);
    if(!tmp_path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto cache_download_err;
    }
    sprintf(tmp_path, "%s/cache_XXXXXX", cache->tempdir);
    tmp_fd = mkstemp(tmp_path); /* different fd to be sure that sxfs_cache_read() works on the file *file_fd is possibly pointing to */ /* TODO: create sxc_file_t using file descriptor */
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
    if((bytes = sxi_read_hard(tmp_fd, buff, fdata->blocksize)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot read from '%s' file: %s", tmp_path, strerror(errno));
        goto cache_download_err;
    }
    if(bytes != fdata->blocksize) {
        SXFS_ERROR("Read less than expected (%lld != %u)", (long long int)bytes, fdata->blocksize);
        ret = -EINVAL;
        goto cache_download_err;
    }
    if((bytes = sxi_write_hard(fd, buff, fdata->blocksize)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot write to '%s' file: %s", *path, strerror(errno));
        if(ret == -ENOSPC)
            ENOSPC_handler(sxfs);
        goto cache_download_err;
    }
    if(bytes != fdata->blocksize) {
        SXFS_ERROR("Wrote less than expected (%lld != %u)", (long long int)bytes, fdata->blocksize);
        ret = -EINVAL;
        goto cache_download_err;
    }
    if(*file_fd < 0) {
        *file_fd = fd;
        fd = -1;
    }

    ret = 0;
cache_download_err:
    if(fd >= 0 && close(fd))
        SXFS_ERROR("Cannot close '%s' file: %s", *path, strerror(errno));
    if(tmp_fd >= 0) {
        if(close(tmp_fd))
            SXFS_ERROR("Cannot close '%s' file: %s", tmp_path, strerror(errno));
        if(unlink(tmp_path))
            SXFS_ERROR("Cannot remove '%s' file: %s", tmp_path, strerror(errno));
    }
    if(!mutex_locked)
        pthread_mutex_lock(&cache->lru_mutex);
    if(ret) {
        if(block_state) {
            /* set block status as failed and wait for another threads to not access this block_state */
            block_state->status = BLOCK_STATUS_FAILED;
            while(block_state->waiting) {
                pthread_mutex_unlock(&cache->lru_mutex);
                usleep(SXFS_THREAD_WAIT);
                pthread_mutex_lock(&cache->lru_mutex);
            }
            sxi_ht_del(cache->blocks_lru, fdata->ha[block], strlen(fdata->ha[block])); /* ENOENT -> NOOP */
            free(block_state);
        }
        if(fd >= 0 && unlink(*path))
            SXFS_ERROR("Cannot remove '%s' file: %s", *path, strerror(errno));
        if(used_added)
            cache->used -= fdata->blocksize;
    } else if(block_state_added) {
        block_state->status = BLOCK_STATUS_DONE;
    }
    if(got_sem && sem_post(&sxfs->download_sem))
        SXFS_ERROR("Failed to post the semaphore: %s", strerror(errno));
    pthread_mutex_unlock(&cache->lru_mutex);
    free(buff);
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
    int err, fd = -1;
    unsigned int i;
    ssize_t bytes;
    char path[PATH_MAX], *buff = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *file = NULL;
    sxfs_state_t *sxfs;
    sxfs_cache_t *cache;
    cache_thread_data_t *cdata = (cache_thread_data_t*)ptr;
    block_state_t *block_state;
    sxi_sxfs_data_t *fdata, fdata2;

    sxfs = cdata->sxfs;
    cache = sxfs->cache;
    fdata = cdata->sxfs_file->fdata;
    memset(&fdata2, 0, sizeof(fdata2));
    buff = (char*)malloc(fdata->blocksize);
    if(!buff) {
        SXFS_ERROR("Out of memory");
        goto cache_download_thread_err;
    }
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
    snprintf(path, sizeof(path), "%s/cache_XXXXXX", cache->tempdir);
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
    /* download all blocks to one file and then move the data into correct files */
    if(sxi_sxfs_download_run(&fdata2, cluster, file, 0, cdata->nblocks * fdata->blocksize)) { /* 0 offset - fdata2.ha is 'hacked' */
        SXFS_ERROR("Cannot download the part of '%s' file: %s", cdata->sxfs_file->remote_path, sxc_geterrmsg(sx));
        goto cache_download_thread_err;
    }
    for(i=0; i<cdata->nblocks; i++) {
        if((bytes = sxi_read_hard(fd, buff, fdata->blocksize)) < 0) {
            SXFS_ERROR("Cannot read from '%s' file: %s", path, strerror(errno));
            goto cache_download_thread_err;
        }
        if(bytes < fdata->blocksize) {
            SXFS_ERROR("Read less data than expected (%lu != %u)", (unsigned long int)bytes, fdata->blocksize);
            goto cache_download_thread_err;
        }
        if((bytes = sxi_write_hard(cdata->fds[i], buff, fdata->blocksize)) < 0) {
            err = errno;
            SXFS_ERROR("Cannot write to %d (%s) file descriptor: %s", cdata->fds[i], fdata->ha[cdata->blocks[i]], strerror(errno));
            if(err == ENOSPC)
                ENOSPC_handler(sxfs);
            goto cache_download_thread_err;
        }
        if(bytes < fdata->blocksize) {
            SXFS_ERROR("Wrote less data than expected (%lu != %u)", (unsigned long int)bytes, fdata->blocksize);
            goto cache_download_thread_err;
        }
        if(close(cdata->fds[i]))
            SXFS_ERROR("Cannot close %d file descriptor: %s", cdata->fds[i], strerror(errno));
        cdata->fds[i] = -1;
        pthread_mutex_lock(&cache->lru_mutex);
        if(sxi_ht_get(cache->blocks_lru, fdata2.ha[i], strlen(fdata2.ha[i]), (void**)&block_state)) {
            SXFS_ERROR("Cannot get LRU block state: %s [%u]", fdata2.ha[i], cdata->blocks[i]);
        } else {
            block_state->status = BLOCK_STATUS_DONE;
        }
        pthread_mutex_unlock(&cache->lru_mutex);
    }

cache_download_thread_err:
    if(fd >= 0) {
        if(close(fd))
            SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
        if(unlink(path))
            SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
    }
    pthread_mutex_lock(&cache->lru_mutex);
    for(i=0; i<cdata->nblocks; i++) {
        if(fdata2.ha)
            free(fdata2.ha[i]);
        if(sxi_ht_get(cache->blocks_lru, fdata->ha[cdata->blocks[i]], strlen(fdata->ha[cdata->blocks[i]]), (void**)&block_state)) {
            SXFS_ERROR("Cannot get LRU block state: %s [%u]", fdata->ha[cdata->blocks[i]], cdata->blocks[i]);
        } else if(block_state->status == BLOCK_STATUS_BUSY) { /* all blocks with status different than DONE are failed (cache_read_background has already set status to BUSY) */
            /* set block status as failed and wait for another threads to not access this block_state */
            block_state->status = BLOCK_STATUS_FAILED;
            while(block_state->waiting) {
                pthread_mutex_unlock(&cache->lru_mutex);
                usleep(SXFS_THREAD_WAIT);
                pthread_mutex_lock(&cache->lru_mutex);
            }
            sxi_ht_del(cache->blocks_lru, fdata->ha[cdata->blocks[i]], strlen(fdata->ha[cdata->blocks[i]]));
            free(block_state);
            if(cdata->fds[i] >= 0) { /* the block has not been fully processed so SXFS has to remove the tempfile */
                snprintf(path, sizeof(path), "%s/%s", cdata->dir, fdata->ha[cdata->blocks[i]]);
                if(close(cdata->fds[i]))
                    SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
                if(unlink(path)) {
                    if(errno != ENOENT)
                        SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
                } else {
                    cache->used -= fdata->blocksize;
                }
            }
        }
    }
    pthread_mutex_unlock(&cache->lru_mutex);
    free(buff);
    free(fdata2.ha);
    free(cdata->dir);
    sxc_file_free(file);
    if(sem_post(&sxfs->download_sem))
        SXFS_ERROR("Failed to post the semaphore: %s", strerror(errno));
    pthread_mutex_lock(&sxfs->limits_mutex);
    sxfs->threads_num--;
    cdata->sxfs_file->threads_num--;
    pthread_mutex_unlock(&sxfs->limits_mutex);
    free(cdata);
    pthread_mutex_lock(&cache->mutex);
    cache->nthreads--;
    pthread_mutex_unlock(&cache->mutex);
    pthread_exit(NULL);
} /* cache_download_thread */

static void cache_read_background (sxfs_state_t *sxfs, sxfs_file_t *sxfs_file, unsigned int block) {
    int err, end_reached = 0, duplicate, cache_locked = 0, got_sem = 0;
    unsigned int i, j, nblocks, tmp_nblocks = 0;
    char *path;
    const char *dir = "foo"; /* shut up warnings */
    sxfs_cache_t *cache = sxfs->cache;
    cache_thread_data_t *cdata = NULL;
    block_state_t *block_state = NULL;
    sxi_sxfs_data_t *fdata = sxfs_file->fdata;
    pthread_t thread;

    if(block >= fdata->nhashes)
        return;
    switch(fdata->blocksize) {
        case SX_BS_SMALL:
            dir = "small";
            nblocks = SXFS_BS_SMALL_AMOUNT;
            break;
        case SX_BS_MEDIUM:
            dir = "medium";
            nblocks = SXFS_BS_MEDIUM_AMOUNT;
            break;
        case SX_BS_LARGE:
            dir = "large";
            nblocks = SXFS_BS_LARGE_AMOUNT;
            break;
        default:
            SXFS_ERROR("Unknown block size");
            return;
    }
    if(block + nblocks > fdata->nhashes)
        nblocks = fdata->nhashes - block;
    path = (char*)malloc(strlen(cache->tempdir) + 1 + lenof("lfu") + 1 + strlen(dir) + 1 + SXI_SHA1_TEXT_LEN + 1);
    if(!path) {
        SXFS_ERROR("Out of memory");
        return;
    }
    cdata = (cache_thread_data_t*)calloc(1, sizeof(cache_thread_data_t));
    if(!cdata) {
        SXFS_ERROR("Out of memory");
        err = -ENOMEM;
        goto cache_read_background_err;
    }
    cdata->sxfs = sxfs;
    cdata->sxfs_file = sxfs_file;
    cdata->dir = (char*)malloc(strlen(cache->tempdir) + 1 + strlen(dir) + 1);
    if(!cdata->dir) {
        SXFS_ERROR("Out of memory");
        err = -ENOMEM;
        goto cache_read_background_err;
    }
    sprintf(cdata->dir, "%s/%s", cache->tempdir, dir);
    if(sem_trywait(&sxfs->download_sem)) {
        err = -errno;
        if(errno == EAGAIN) { /* the decrement cannot be immediately performed */
            SXFS_VERBOSE("Download operations limit reached");
        } else {
            SXFS_ERROR("Failed to wait for semaphore: %s", strerror(errno));
        }
        goto cache_read_background_err;
    }
    got_sem = 1;
    pthread_mutex_lock(&cache->lru_mutex);
    cache_locked = 1;
    for(i=0; cdata->nblocks < nblocks; i++) {
        if(block + i == fdata->nhashes) {
            end_reached = 1;
            break;
        }
        if(i > 2 * nblocks) /* do not try to read too far from given block */
            break;
        duplicate = 0;
        for(j=0; j<cdata->nblocks; j++)
            if(!strcmp(fdata->ha[block+i], fdata->ha[cdata->blocks[j]])) {
                duplicate = 1;
                break;
            }
        if(!duplicate) {
            sprintf(path, "%s/%s/%s", cache->tempdir, dir, fdata->ha[block+i]);
            if(access(path, F_OK)) {
                if(errno == ENOENT) {
                    sprintf(path, "%s/lfu/%s/%s", cache->tempdir, dir, fdata->ha[block+i]);
                    if(access(path, F_OK)) {
                        if(errno == ENOENT) {
                            if(sxi_ht_get(cache->blocks_lru, fdata->ha[block+i], strlen(fdata->ha[block+i]), NULL)) {
                                cdata->fds[cdata->nblocks] = -1;
                                cdata->blocks[cdata->nblocks] = block + i;
                                cdata->nblocks++;
                            }
                        } else {
                            err = -errno;
                            SXFS_ERROR("Cannot access '%s' file: %s", path, strerror(errno));
                            goto cache_read_background_err;
                        }
                    }
                } else {
                    err = -errno;
                    SXFS_ERROR("Cannot access '%s' file: %s", path, strerror(errno));
                    goto cache_read_background_err;
                }
            } else if(utime(path, NULL)) /* this can be the least recently used file - avoid removing it */
                SXFS_ERROR("Cannot update mtime of '%s' file: %s", path, strerror(errno));
        }
    }
    if(cdata->nblocks && (end_reached || 2 * (cdata->blocks[0] - block) < nblocks || cdata->nblocks == nblocks)) { /* near to EOF  OR  filling holes  OR  limit reached */
        if(cache_make_space(sxfs, cdata->nblocks * fdata->blocksize)) {
            err = -ENOMSG;
            goto cache_read_background_err;
        }
        for(i=0; i<cdata->nblocks; i++) {
            block_state = (block_state_t*)calloc(1, sizeof(block_state_t));
            if(!block_state) {
                SXFS_ERROR("Out of memory");
                err = -ENOMEM;
                goto cache_read_background_err;
            }
            block_state->status = BLOCK_STATUS_BUSY;
            if(sxi_ht_add(cache->blocks_lru, fdata->ha[cdata->blocks[i]], strlen(fdata->ha[cdata->blocks[i]]), block_state)) {
                SXFS_ERROR("Out of memory");
                err = -ENOMEM;
                goto cache_read_background_err;
            }
            block_state = NULL;
            tmp_nblocks++;
            sprintf(path, "%s/%s/%s", cache->tempdir, dir, fdata->ha[cdata->blocks[i]]);
            cdata->fds[i] = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
            if(cdata->fds[i] < 0) {
                err = errno;
                SXFS_ERROR("Cannot create '%s' file: %s", path, strerror(errno));
                if(err == ENOSPC)
                    ENOSPC_handler(sxfs);
                err = -err;
                goto cache_read_background_err;
            }
            cache->used += fdata->blocksize;
        }
        pthread_mutex_unlock(&cache->lru_mutex);
        cache_locked = 0;
        pthread_mutex_lock(&sxfs->limits_mutex);
        sxfs_file->threads_num++;
        pthread_mutex_unlock(&sxfs->limits_mutex);
        pthread_mutex_lock(&cache->mutex);
        cache->nthreads++;
        pthread_mutex_unlock(&cache->mutex);
        if((err = sxfs_thread_create(sxfs, &thread, cache_download_thread, (void*)cdata))) {
            pthread_mutex_lock(&sxfs->limits_mutex);
            sxfs_file->threads_num--;
            pthread_mutex_unlock(&sxfs->limits_mutex);
            pthread_mutex_lock(&cache->mutex);
            cache->nthreads--;
            pthread_mutex_unlock(&cache->mutex);
            SXFS_ERROR("Cannot start new thread");
            goto cache_read_background_err;
        }
        if((err = pthread_detach(thread)))
            SXFS_ERROR("Cannot detach the thread: %s", strerror(err));
        cdata = NULL;
        got_sem = 0; /* it will be post in download thread */
    }

    err = 0;
cache_read_background_err:
    free(block_state);
    if(!cache_locked)
        pthread_mutex_lock(&cache->lru_mutex);
    if(err && cdata) {
        for(i=0; i<cdata->nblocks; i++) {
            if(i < tmp_nblocks) {
                if(sxi_ht_get(cache->blocks_lru, fdata->ha[cdata->blocks[i]], strlen(fdata->ha[cdata->blocks[i]]), (void**)&block_state)) {
                    SXFS_ERROR("Cannot get LRU block state: %s [%u]", fdata->ha[cdata->blocks[i]], cdata->blocks[i]);
                } else {
                    /* set block status as failed and wait for another threads to not access this block_state */
                    block_state->status = BLOCK_STATUS_FAILED;
                    while(block_state->waiting) {
                        pthread_mutex_unlock(&cache->lru_mutex);
                        usleep(SXFS_THREAD_WAIT);
                        pthread_mutex_lock(&cache->lru_mutex);
                    }
                    sxi_ht_del(cache->blocks_lru, fdata->ha[cdata->blocks[i]], strlen(fdata->ha[cdata->blocks[i]]));
                    free(block_state);
                } /* no handling for BLOCK_STATUS_DONE because new thread is for this */
                /* if this cleanup has been reached then all blocks are currently BUSY */
                if(cdata->fds[i] >= 0) {
                    sprintf(path, "%s/%s/%s", cache->tempdir, dir, fdata->ha[cdata->blocks[i]]);
                    if(close(cdata->fds[i]))
                        SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
                    if(unlink(path)) {
                        if(errno != ENOENT)
                            SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
                    } else {
                        cache->used -= fdata->blocksize;
                    }
                }
            }
        }
    }
    if(got_sem && sem_post(&sxfs->download_sem))
        SXFS_ERROR("Failed to post the semaphore: %s", strerror(errno));
    pthread_mutex_unlock(&cache->lru_mutex);
    if(cdata) {
        free(cdata->dir);
        free(cdata);
    }
    free(path);
} /* cache_read_background */

static char* calculate_block_name (sxfs_state_t *sxfs, const void *buff, size_t size) {
    char *ret;
    unsigned char sha_hash[SXI_SHA1_BIN_LEN];

    ret = (char*)malloc(SXI_SHA1_TEXT_LEN + 1);
    if(!ret)
        return NULL;
    if(sxi_sha1_calc(sxfs->cluster_uuid, strlen(sxfs->cluster_uuid), buff, size, sha_hash)) {
        SXFS_ERROR("Cannot calculate checksum");
        free(ret);
        return NULL;
    }
    sxi_bin2hex(sha_hash, SXI_SHA1_BIN_LEN, ret);
    ret[SXI_SHA1_TEXT_LEN] = '\0';
    return ret;
} /* calculate_block_name */

static int validate_block (sxfs_state_t *sxfs, const char *block_name, const char *buff, unsigned int blocksize) {
    char *calc_name = calculate_block_name(sxfs, buff, blocksize);
    if(!calc_name) {
        SXFS_ERROR("Failed to compute the block name");
        return -ENOMEM;
    }
    if(memcmp(calc_name, block_name, SXI_SHA1_TEXT_LEN)) {
        SXFS_ERROR("Invalid content of '%s' block. Calculated name: %s", block_name, calc_name);
        free(calc_name);
        return -EAGAIN;
    }
    free(calc_name);
    return 0;
} /* validate_block */

static ssize_t cache_read_block (sxfs_state_t *sxfs, sxi_sxfs_data_t *fdata, unsigned int block, void *buff, size_t length, off_t offset) {
    int fd = -1, lfu_index, locked = 0;
    ssize_t ret;
    char *path = NULL, *local_buff = NULL;
    const char *block_name = fdata->ha[block], *dir = "foo"; /* shut up warnings */
    block_state_t *block_state = NULL;
    sxfs_cache_t *cache = sxfs->cache;

    local_buff = (char*)malloc(fdata->blocksize);
    if(!local_buff) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    switch(fdata->blocksize) {
        case SX_BS_SMALL:
            dir = "small";
            lfu_index = CACHE_INDEX_SMALL;
            break;
        case SX_BS_MEDIUM:
            dir = "medium";
            lfu_index = CACHE_INDEX_MEDIUM;
            break;
        case SX_BS_LARGE:
            dir = "large";
            lfu_index = CACHE_INDEX_LARGE;
            break;
        default:
            SXFS_ERROR("Unknown block size");
            ret = -EINVAL;
            goto cache_read_block_err;
    }
    path = (char*)malloc(strlen(cache->tempdir) + 1 + lenof("lfu") + 1 + strlen(dir) + 1 + strlen(block_name) + 1);
    if(!path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto cache_read_block_err;
    }
    sprintf(path, "%s/%s/%s", cache->tempdir, dir, block_name);
    pthread_mutex_lock(&cache->lru_mutex);
    locked |= CACHE_LRU_MUTEX;
    /* try to open file in LRU */
    fd = open(path, O_RDONLY);
    if(fd < 0) {
        pthread_mutex_unlock(&cache->lru_mutex);
        locked &= ~CACHE_LRU_MUTEX;
        if(errno == ENOENT) {
            sprintf(path, "%s/lfu/%s/%s", cache->tempdir, dir, block_name);
            pthread_mutex_lock(&cache->lfu_mutex);
            locked |= CACHE_LFU_MUTEX;
            /* try to open file in LFU */
            fd = open(path, O_RDONLY);
            if(fd < 0) {
                pthread_mutex_unlock(&cache->lfu_mutex);
                locked &= ~CACHE_LFU_MUTEX;
            } else {
                /* block is in LFU */
                if(!offset) {
                    if(sxi_ht_get(cache->blocks_lfu[lfu_index], block_name, strlen(block_name), (void**)&block_state)) {
                        SXFS_ERROR("Cannot get LFU block state: %s [%u]", block_name, block);
                        ret = -EAGAIN;
                        goto cache_read_block_err;
                    }
                    block_state->times_used++;
                }
                pthread_mutex_unlock(&cache->lfu_mutex);
                locked &= ~CACHE_LFU_MUTEX;
            }
        } else {
            ret = -errno;
            SXFS_ERROR("Cannot open '%s' file: %s", path, strerror(errno));
            goto cache_read_block_err;
        }
    } else {
        /* block is in LRU */
        if(!offset) {
            if(sxi_ht_get(cache->blocks_lru, block_name, strlen(block_name), (void**)&block_state)) {
                SXFS_DEBUG("Cannot get LRU block state: %s [%u]", block_name, block);
                ret = -EAGAIN;
                goto cache_read_block_err;
            }
            block_state->times_used++;
        }
        /* do it inside the lock to avoid races */
        if((ret = wait_for_block(sxfs, fd, block_name, fdata->blocksize))) {
            if(ret == -EAGAIN) {
                SXFS_DEBUG("Another thread failed to download the block, trying again");
                if(close(fd))
                    SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
                fd = -1;
            } else {
                goto cache_read_block_err;
            }
        }
        /* possible race condition here since wait_for_block() can unlock the mutex for a while */
        if(block_state && (ret = move_block_to_lfu(sxfs, fdata, &path, block_name, block_state)))
            goto cache_read_block_err;
        pthread_mutex_unlock(&cache->lru_mutex);
        locked &= ~CACHE_LRU_MUTEX;
    }
    if(fd < 0) { /* file does not exist or block failed to download in another thread */
        sprintf(path, "%s/%s/%s", cache->tempdir, dir, block_name);
        if((ret = cache_download(sxfs, fdata, block, &path, &fd, offset))) {
            goto cache_read_block_err;
        }
    }
    if((ret = sxi_pread_hard(fd, local_buff, fdata->blocksize, 0)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot read from '%s' file: %s", path, strerror(errno));
        goto cache_read_block_err;
    }
    if(ret != fdata->blocksize) {
        SXFS_ERROR("Read less than expected (%lld != %u)", (long long int)ret, fdata->blocksize);
        ret = -EINVAL;
        goto cache_read_block_err;
    }
    if((ret = validate_block(sxfs, fdata->ha[block], local_buff, fdata->blocksize))) {
        int block_in_LRU = !strstr(path, "/lfu/");
        SXFS_ERROR("Invalid '%s' block content!", fdata->ha[block]);
        pthread_mutex_lock(block_in_LRU ? &cache->lru_mutex : &cache->lfu_mutex);
        sxi_ht_del(block_in_LRU ? cache->blocks_lru : cache->blocks_lfu[lfu_index], block_name, strlen(block_name));
        if(unlink(path)) {
            SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
        } else if(block_in_LRU) {
            cache->used -= fdata->blocksize;
        } else {
            cache->lfu_entries[lfu_index]--;
        }
        pthread_mutex_unlock(block_in_LRU ? &cache->lru_mutex : &cache->lfu_mutex);
        goto cache_read_block_err;
    }
    if(utime(path, NULL) && errno != ENOENT)
        SXFS_ERROR("Cannot update mtime of '%s' file: %s", path, strerror(errno));

    if(length + offset > fdata->blocksize)
        length = fdata->blocksize - offset; /* don't try to read more than available */
    memcpy(buff, local_buff + offset, length);
    ret = length;
cache_read_block_err:
    if(locked & CACHE_LRU_MUTEX)
        pthread_mutex_unlock(&cache->lru_mutex);
    if(locked & CACHE_LFU_MUTEX)
        pthread_mutex_unlock(&cache->lfu_mutex);
    if(fd >= 0 && close(fd))
        SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
    free(path);
    free(local_buff);
    return ret;
} /* cache_read_block */

ssize_t sxfs_cache_read (sxfs_state_t *sxfs, sxfs_file_t *sxfs_file, void *buff, size_t length, off_t offset) {
    unsigned int block;
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
        if(!cache) { /* cache can be NULL when sxfs->need_file is true */
            SXFS_ERROR("NULL argument");
            return -EINVAL;
        }
    } else if(sxfs_file->write_fd < 0 && (ret = sxfs_get_file(sxfs, sxfs_file))) {
        SXFS_ERROR("Cannot get '%s' file", sxfs_file->remote_path);
        return ret;
    }
    if(sxfs_file->write_fd >= 0) {
        SXFS_VERBOSE("Using file descriptor: %d", sxfs_file->write_fd);
        if((ret = sxi_pread_hard(sxfs_file->write_fd, buff, length, offset)) < 0) {
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
        cache_read_background(sxfs, sxfs_file, block+1);

    /* reading the block is inside so sxfs can use the data it needs to read anyway */
    /* TODO: made it in loop to read all requested data */
    return cache_read_block(sxfs, fdata, block, buff, length, offset % fdata->blocksize);
} /* sxfs_cache_read */

