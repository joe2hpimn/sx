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

#define CACHE_INDEX_SMALL 0
#define CACHE_INDEX_MEDIUM 1
#define CACHE_INDEX_LARGE 2

#define LFU_SORTED_NONE 0
#define LFU_SORTED_BY_NAME 1
#define LFU_SORTED_BY_USAGE 2

struct _block_state_t {
    unsigned int times_used, waiting;
    int status;
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
    size_t lfu_entries[3], lfu_max[3];
    ssize_t used, lru_size; /* can be negative due to race conditions with small size */
    char *tempdir, *dir_small, *dir_medium, *dir_large, *dir_lfu_small, *dir_lfu_medium, *dir_lfu_large;
    pthread_mutex_t mutex, lfu_mutex;
    sxi_ht *blocks;
    sxfs_cache_lfu_t *lfu[3];
};

static void cache_free (sxfs_state_t *sxfs, sxfs_cache_t *cache) {
    int err;
    unsigned int i, j, key_len;
    const void *key;
    block_state_t *block_state;

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
    sxi_ht_enum_reset(cache->blocks);
    while(!sxi_ht_enum_getnext(cache->blocks, &key, &key_len, NULL)) { /* FIXME: iterate through and wait for background jobs to be done */
        if(sxi_ht_get(cache->blocks, key, key_len, (void**)&block_state)) {
            SXFS_ERROR("Cannot get block state");
        } else {
            free(block_state);
        }
    }
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
        fprintf(stderr, "ERROR: Cache size must be at least %d\n", CACHE_MIN_SIZE * SX_BS_LARGE);
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
    cache->tempdir = strdup(path);
    if(!cache->tempdir) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto sxfs_cache_init_err;
    }

    memset(cache->lfu, 0, 3 * sizeof(sxfs_cache_lfu_t*));
    for(i=0; i<sizeof(cache->lfu)/sizeof(cache->lfu[0]); i++) {
        cache->lfu[i] = (sxfs_cache_lfu_t*)malloc(cache->lfu_max[i] * sizeof(sxfs_cache_lfu_t));
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

static int wait_for_block (sxfs_state_t *sxfs, char *block_name) {
    block_state_t *block_state, *new_block_state;

    if(sxi_ht_get(sxfs->cache->blocks, block_name, strlen(block_name), (void**)&block_state)) {
        return 0; /* no such block being downloaded */
    } else {
        block_state->waiting++;
    }
    while(block_state->status == BLOCK_STATUS_BUSY) {
        pthread_mutex_unlock(&sxfs->cache->mutex);
        usleep(SXFS_THREAD_WAIT);
        pthread_mutex_lock(&sxfs->cache->mutex);
    }
    block_state->waiting--;
    if(block_state->status == BLOCK_STATUS_FAILED) {
        /* wait for another thread to remove the block from hashtable */
        while(!sxi_ht_get(sxfs->cache->blocks, block_name, strlen(block_name), (void**)&new_block_state) && block_state == new_block_state) { /* block_state pointer can already be freed and replaced but here it's all about the address */
            pthread_mutex_unlock(&sxfs->cache->mutex);
            usleep(SXFS_THREAD_WAIT);
            pthread_mutex_lock(&sxfs->cache->mutex);
        }
        return -EAGAIN;
    }
    return 0;
} /* wait_for_block */

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
            if(sxi_ht_get(sxfs->cache->blocks, block_name, strlen(block_name), (void**)&block_state)) {
                SXFS_ERROR("Cannot get block state: %s", block_name);
            } else if(block_state->status == BLOCK_STATUS_DONE && !block_state->waiting) {
                sxi_ht_del(sxfs->cache->blocks, block_name, strlen(block_name));
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

static int cache_download (sxfs_state_t *sxfs, sxi_sxfs_data_t *fdata, unsigned int block, const char *path, int *file_fd) {
    int ret, fd = -1, tmp_fd = -1, mutex_locked = 0, used_added = 0, block_state_added = 0;
    ssize_t bytes;
    char *tmp_path = NULL, *buff = NULL;
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxc_file_t *dest = NULL;
    block_state_t *block_state = NULL;

    buff = (char*)malloc(SX_BS_LARGE);
    if(!buff) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    pthread_mutex_lock(&sxfs->cache->mutex);
    mutex_locked = 1;
    if(!file_fd || *file_fd < 0) {
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
            goto cache_download_err; /* this is not a failure */
        }
    } else {
        fd = *file_fd;
    }
    /* there should be no block_state in cache->blocks if there was no file */
    block_state = (block_state_t*)calloc(1, sizeof(block_state_t));
    if(!block_state) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto cache_download_err;
    }
    block_state->status = BLOCK_STATUS_BUSY;
    if(sxi_ht_add(sxfs->cache->blocks, fdata->ha[block], strlen(fdata->ha[block]), block_state)) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto cache_download_err;
    }
    block_state_added = 1;
    if((ret = cache_make_space(sxfs, fdata->blocksize)))
        goto cache_download_err;
    sxfs->cache->used += fdata->blocksize;
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
    if(file_fd && *file_fd < 0) {
        *file_fd = fd;
        fd = -1;
    }

    ret = 0;
cache_download_err:
    if(fd >= 0 && close(fd))
        SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
    if(tmp_fd >= 0) {
        if(close(tmp_fd))
            SXFS_ERROR("Cannot close '%s' file: %s", tmp_path, strerror(errno));
        if(unlink(tmp_path))
            SXFS_ERROR("Cannot remove '%s' file: %s", tmp_path, strerror(errno));
    }
    if(!mutex_locked)
        pthread_mutex_lock(&sxfs->cache->mutex);
    if(ret) {
        if(block_state) {
            block_state->status = BLOCK_STATUS_FAILED;
            while(block_state->waiting) {
                pthread_mutex_unlock(&sxfs->cache->mutex);
                usleep(SXFS_THREAD_WAIT);
                pthread_mutex_lock(&sxfs->cache->mutex);
            }
            sxi_ht_del(sxfs->cache->blocks, fdata->ha[block], strlen(fdata->ha[block])); /* ENOENT -> NOOP */
            free(block_state);
        }
        if(fd >= 0 && unlink(path))
            SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
        if(used_added)
            sxfs->cache->used -= fdata->blocksize;
    } else if(block_state_added) {
        block_state->status = BLOCK_STATUS_DONE;
    }
    pthread_mutex_unlock(&sxfs->cache->mutex);
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
    cache_thread_data_t *cdata = (cache_thread_data_t*)ptr;
    block_state_t *block_state;
    sxi_sxfs_data_t *fdata, fdata2;

    sxfs = cdata->sxfs;
    fdata = cdata->sxfs_file->fdata;
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
    snprintf(path, sizeof(path), "%s/cache_XXXXXX", sxfs->cache->tempdir);
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
        pthread_mutex_lock(&sxfs->cache->mutex);
        if(sxi_ht_get(sxfs->cache->blocks, fdata2.ha[i], strlen(fdata2.ha[i]), (void**)&block_state)) {
            SXFS_ERROR("Cannot get block state: %s [%u]", fdata->ha[cdata->blocks[i]], cdata->blocks[i]); /* fdata2 contains only a part of hashes from fdata */
        } else {
            block_state->status = BLOCK_STATUS_DONE;
        }
        pthread_mutex_unlock(&sxfs->cache->mutex);
    }

cache_download_thread_err:
    if(fd >= 0) {
        if(close(fd))
            SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
        if(unlink(path))
            SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
    }
    pthread_mutex_lock(&sxfs->cache->mutex);
    for(i=0; i<cdata->nblocks; i++) {
        if(fdata2.ha)
            free(fdata2.ha[i]);
        if(sxi_ht_get(sxfs->cache->blocks, fdata->ha[cdata->blocks[i]], strlen(fdata->ha[cdata->blocks[i]]), (void**)&block_state)) {
            SXFS_ERROR("Cannot get block state: %s [%u]", fdata->ha[cdata->blocks[i]], cdata->blocks[i]);
        } else if(block_state->status == BLOCK_STATUS_BUSY) {
            block_state->status = BLOCK_STATUS_FAILED;
            while(block_state->waiting) {
                pthread_mutex_unlock(&sxfs->cache->mutex);
                usleep(SXFS_THREAD_WAIT);
                pthread_mutex_lock(&sxfs->cache->mutex);
            }
            sxi_ht_del(sxfs->cache->blocks, fdata->ha[cdata->blocks[i]], strlen(fdata->ha[cdata->blocks[i]]));
            free(block_state);
            if(cdata->fds[i] >= 0) { /* it means the block has not been fully processed so SXFS has to remove the tempfile */
                snprintf(path, sizeof(path), "%s/%s", cdata->dir, fdata->ha[cdata->blocks[i]]);
                if(close(cdata->fds[i]))
                    SXFS_ERROR("Cannot close '%s' file: %s", path, strerror(errno));
                if(unlink(path)) {
                    if(errno != ENOENT)
                        SXFS_ERROR("Cannot remove '%s' file: %s", path, strerror(errno));
                } else {
                    sxfs->cache->used -= fdata->blocksize;
                }
            }
        }
    }
    pthread_mutex_unlock(&sxfs->cache->mutex);
    free(buff);
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
    int err, end_reached = 0, duplicate, cache_locked = 0;
    unsigned int i, j, tmp_nblocks = 0;
    char *path;
    const char *dir = "foo"; /* shut up warnings */
    cache_thread_data_t *cdata = NULL;
    block_state_t *block_state = NULL;
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
        err = -ENOMEM;
        goto cache_read_background_err;
    }
    cdata->sxfs = sxfs;
    cdata->sxfs_file = sxfs_file;
    cdata->dir = (char*)malloc(strlen(sxfs->cache->tempdir) + 1 + strlen(dir) + 1);
    if(!cdata->dir) {
        SXFS_ERROR("Out of memory");
        err = -ENOMEM;
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
                            if(sxi_ht_get(sxfs->cache->blocks, sxfs_file->fdata->ha[block+i], strlen(sxfs_file->fdata->ha[block+i]), NULL)) {
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
    if(cdata->nblocks && ((end_reached || 2 * (cdata->blocks[0] - block) < nblocks) || cdata->nblocks == nblocks)) { /* near to EOF  OR  filling holes  OR  limit reached */
        if(cache_make_space(sxfs, cdata->nblocks * sxfs_file->fdata->blocksize)) {
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
            if(sxi_ht_add(sxfs->cache->blocks, sxfs_file->fdata->ha[cdata->blocks[i]], strlen(sxfs_file->fdata->ha[cdata->blocks[i]]), block_state)) {
                SXFS_ERROR("Out of memory");
                err = -ENOMEM;
                goto cache_read_background_err;
            }
            block_state = NULL;
            tmp_nblocks++;
            sprintf(path, "%s/%s/%s", sxfs->cache->tempdir, dir, sxfs_file->fdata->ha[cdata->blocks[i]]);
            cdata->fds[i] = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
            if(cdata->fds[i] < 0) {
                err = errno;
                SXFS_ERROR("Cannot create '%s' file: %s", path, strerror(errno));
                if(err == ENOSPC)
                    ENOSPC_handler(sxfs);
                err = -err;
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

    err = 0;
cache_read_background_err:
    free(block_state);
    if(err) {
        if(!cache_locked) {
            pthread_mutex_lock(&sxfs->cache->mutex);
            cache_locked = 1;
        }
        for(i=0; i<cdata->nblocks; i++) {
            if(i < tmp_nblocks) {
                if(sxi_ht_get(sxfs->cache->blocks, sxfs_file->fdata->ha[cdata->blocks[i]], strlen(sxfs_file->fdata->ha[cdata->blocks[i]]), (void**)&block_state)) {
                    SXFS_ERROR("Cannot get block state: %s [%u]", sxfs_file->fdata->ha[cdata->blocks[i]], cdata->blocks[i]);
                } else {
                    block_state->status = BLOCK_STATUS_FAILED;
                    while(block_state->waiting) {
                        pthread_mutex_unlock(&sxfs->cache->mutex);
                        usleep(SXFS_THREAD_WAIT);
                        pthread_mutex_lock(&sxfs->cache->mutex);
                    }
                    sxi_ht_del(sxfs->cache->blocks, sxfs_file->fdata->ha[cdata->blocks[i]], strlen(sxfs_file->fdata->ha[cdata->blocks[i]]));
                    free(block_state);
                } /* no handling for BLOCK_STATUS_DONE because new thread is for this */
                /* if error path cleanup has been reached then all blocks are currently BUSY */
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
        }
    }
    if(cdata) {
        free(cdata->dir);
        free(cdata);
    }
    if(cache_locked)
        pthread_mutex_unlock(&sxfs->cache->mutex);
    free(path);
} /* cache_read_background */

static char* calculate_block_name (sxfs_state_t *sxfs, void *buff, size_t size) {
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

static ssize_t validate_block (sxfs_state_t *sxfs, sxi_sxfs_data_t *fdata, unsigned int block, void *buff, size_t length, off_t offset) {
    int fd = -1, cache_locked = 0, lfu_accessed = 0, *lfu_sorted;
    size_t *lfu_n, *lfu_max;
    ssize_t ret, index;
    time_t add_time;
    char *path = NULL, *calc_name = NULL, *block_name_dup = NULL, *lfu_file_path = NULL, *local_buff = NULL;
    const char *block_name = fdata->ha[block], *dir = "foo"; /* shut up warnings */
    struct stat st;
    block_state_t *block_state = NULL;
    sxfs_cache_t *cache = sxfs->cache;
    sxfs_cache_lfu_t *lfu;

    local_buff = (char*)malloc(fdata->blocksize);
    if(!local_buff) {
        SXFS_ERROR("Out of memory");
        return -ENOMEM;
    }
    switch(fdata->blocksize) {
        case SX_BS_SMALL:
            dir = "small";
            lfu = cache->lfu[CACHE_INDEX_SMALL];
            lfu_n = &cache->lfu_entries[CACHE_INDEX_SMALL];
            lfu_max = &cache->lfu_max[CACHE_INDEX_SMALL];
            lfu_sorted = &cache->lfu_sorted[CACHE_INDEX_SMALL];
            break;
        case SX_BS_MEDIUM:
            dir = "medium";
            lfu = cache->lfu[CACHE_INDEX_MEDIUM];
            lfu_n = &cache->lfu_entries[CACHE_INDEX_MEDIUM];
            lfu_max = &cache->lfu_max[CACHE_INDEX_MEDIUM];
            lfu_sorted = &cache->lfu_sorted[CACHE_INDEX_MEDIUM];
            break;
        case SX_BS_LARGE:
            dir = "large";
            lfu = cache->lfu[CACHE_INDEX_LARGE];
            lfu_n = &cache->lfu_entries[CACHE_INDEX_LARGE];
            lfu_max = &cache->lfu_max[CACHE_INDEX_LARGE];
            lfu_sorted = &cache->lfu_sorted[CACHE_INDEX_LARGE];
            break;
        default:
            SXFS_ERROR("Unknown block size");
            ret = -EINVAL;
            goto validate_block_err;
    }
    if((add_time = time(NULL)) < 0) {
        ret = -errno;
        SXFS_ERROR("Cannot get current time: %s", strerror(errno));
        goto validate_block_err;
    }
    path = (char*)malloc(strlen(cache->tempdir) + 1 + lenof("lfu") + 1 + strlen(dir) + 1 + strlen(block_name) + 1);
    if(!path) {
        SXFS_ERROR("Out of memory");
        ret = -ENOMEM;
        goto validate_block_err;
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
                } else { /* this means that previous unlink has failed, but why not make use of this block? */
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
        block_name_dup = strdup(block_name);
        if(!block_name_dup) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            goto validate_block_err;
        }
        lfu_file_path = (char*)malloc(strlen(cache->tempdir) + 1 + lenof("lfu") + 1 + strlen(dir) + 1 + strlen(block_name) + 1);
        if(!lfu_file_path) {
            SXFS_ERROR("Out of memory");
            ret = -ENOMEM;
            goto validate_block_err;
        }
        sprintf(lfu_file_path, "%s/lfu/%s/%s", cache->tempdir, dir, block_name);
        pthread_mutex_lock(&cache->mutex);
        cache_locked = 1;
        if(sxi_ht_get(cache->blocks, block_name, strlen(block_name), (void**)&block_state)) {
            SXFS_DEBUG("Cannot get block state: %s [%u]", block_name, block);
            /* do not fail whole function - there can be a race condition with block removal */
        }
        if(block_state && block_state->times_used && !offset) {
            if(rename(path, lfu_file_path)) { /* getting one block from LRU */
                if(errno != ENOENT) /* very racy stuff */
                    SXFS_ERROR("Cannot insert block into LFU cache: %s", strerror(errno));
            } else {
                char *tmp_str = path;
                path = lfu_file_path;
                lfu_file_path = tmp_str;

                cache->used -= fdata->blocksize; /* one block has been taken from LRU to LFU */
                block_state->times_used = 0; /* reset the counter in case block will came back from LFU */
                lfu_accessed = 1;
                pthread_mutex_lock(&cache->lfu_mutex);
                if(*lfu_sorted == LFU_SORTED_BY_NAME && (index = sxfs_find_entry((const void**)lfu, *lfu_n, block_name, lfu_entry_cmp_name)) >= 0) {
                    /* This error does not seem to be critical due to EAGAIN being returned. It can be triggered by
                     * regular read operations, especially for large files. */
                    SXFS_DEBUG("'%s' block already in LFU cache", block_name);
                    ret = -EAGAIN;
                    pthread_mutex_unlock(&cache->lfu_mutex);
                    goto validate_block_err;
                }
                if(*lfu_n == *lfu_max) {
                    char *lru_file_path = (char*)malloc(strlen(cache->tempdir) + 1 + strlen(dir) + 1 + strlen(block_name) + 1); /* all block names have equal length */

                    if(!lru_file_path) {
                        SXFS_ERROR("Out of memory");
                        free(lru_file_path);
                        pthread_mutex_unlock(&cache->lfu_mutex);
                        ret = -ENOMEM;
                        goto validate_block_err;
                    }
                    if(*lfu_sorted != LFU_SORTED_BY_USAGE) {
                        qsort(lfu, *lfu_n, sizeof(sxfs_cache_lfu_t), lfu_sort_cmp_usage);
                        *lfu_sorted = LFU_SORTED_BY_USAGE;
                    }
                    index = 0;
                    sprintf(lru_file_path, "%s/%s/%s", cache->tempdir, dir, lfu[index].name);
                    sprintf(lfu_file_path, "%s/lfu/%s/%s", cache->tempdir, dir, lfu[index].name); /* all block names have equal lenght */
                    if(rename(lfu_file_path, lru_file_path) && errno != ENOENT) { /* racy stuff */
                        ret = -errno;
                        SXFS_ERROR("Cannot move '%s' block from LFU to LRU: %s", lfu[index].name, strerror(errno));
                        free(lru_file_path);
                        pthread_mutex_unlock(&cache->lfu_mutex);
                        if(unlink(lfu_file_path)) /* try to avoid going over the limit of files */
                            SXFS_ERROR("Cannot remove '%s' file: %s", lfu_file_path, strerror(errno));
                        goto validate_block_err;
                    } else {
                        cache->used += fdata->blocksize; /* one block has been put back from LFU to LRU */
                    }
                    /* block counter is already reseted */
                    free(lfu[index].name);
                    free(lru_file_path);
                } else {
                    index = *lfu_n;
                }
                lfu[index].name = block_name_dup;
                block_name_dup = NULL;
                lfu[index].times_used = 2;
                lfu[index].add_time = add_time;
                if(*lfu_n != *lfu_max) {
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
        }
        pthread_mutex_unlock(&cache->mutex);
        cache_locked = 0;
    }
    if(!offset && !lfu_accessed) {
        pthread_mutex_lock(&cache->mutex);
        if(!block_state && sxi_ht_get(cache->blocks, block_name, strlen(block_name), (void**)&block_state)) {
            SXFS_DEBUG("Cannot get block state: %s", block_name);
            /* do not fail whole function - there can be a race condition with block removal */
        } else {
            block_state->times_used++;
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
            if(wait_for_block(sxfs, fdata->ha[block])) {
                SXFS_DEBUG("Background thread failed to download the block, trying again");
                pthread_mutex_unlock(&cache->mutex); /* cache_dowload() locks this mutex */
                cache_locked = 0;
                if((ret = cache_download(sxfs, fdata, block, path, &fd))) /* try to download the block again anyway */
                    goto validate_block_err;
            }
        }
        if(cache_locked) { /* FIXME */
            pthread_mutex_unlock(&cache->mutex);
            cache_locked = 0;
        }
    }
    if((ret = sxi_pread_hard(fd, local_buff, fdata->blocksize, 0)) < 0) {
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
    free(block_name_dup);
    free(lfu_file_path);
    free(local_buff);
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
        cache_read_background(sxfs, sxfs_file, block+1, nblocks);

    /* reading the block is inside so sxfs can use the data it needs to read anyway */
    return validate_block(sxfs, fdata, block, buff, length, offset % fdata->blocksize);
} /* sxfs_cache_read */

