/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <utime.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "sx.h"
#include "libsx/src/clustcfg.h"
#include "libsx/src/volops.h"
#include "version.h"
#include "rgen.h"
#include "client-test-cmdline.h"

#define _BSD_SOURCE
#define VOLSIZE 2*args.replica_arg*1024LL*1024LL*1024LL /* TODO: bigger precision */
#define VOLNAME "vol" /* There will be 6 random characters suffix added. There CANNOT be '..' inside! */
#define LOCAL_DIR "/tmp/.test" /* There will be 6 random characters suffix added. */
#define REMOTE_DIR ".test"
#define EMPTY_FILE_NAME "file_empty"
#define UD_FILE_NAME "file_ud"
#define REV_FILE_NAME "file_rev" /* There will be added numbers as suffixes for revision versions */
#define ATTRIBS_COUNT 10 /* Up to 100 (or you will have no enough space for it) */
#define ATTRIBS_FILE_NAME "file_attrib"
#define TRASH_NAME "/.Trash"
#define UNDELETE_FILE_NAME "file_undelete"
#define QUOTA_FILE_NAME "file_quota"
#define QUOTA_VOL_SIZE 1
#define QUOTA_FILE_SIZE 5 /* Must be more then QUOTA_VOL_SIZE */

int64_t bytes; /* FIXME: small change in libsx to avoid this to be global */

float to_human (long long int n) {
    float h = (float)n;
    while(h>=1024)
        h/=1024;
    return h;
}

char to_human_suffix (long long int n) {
    int count = 0;
    char suf[] = {'B', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'};
    while(n>1023) {
        n/=1024;
        count++;
    }
    return count<sizeof(suf)?suf[count]:suf[sizeof(suf)-1];
}

int test_input_fn(sxc_client_t *sx, sxc_input_t type, const char *prompt, const char *def, char *in, unsigned int insize, void *ctx) {
    if(!sx || !prompt || !in || !insize) {
        if(sx)
            fprintf(stderr, "test_input_fn: ERROR: NULL argument.\n");
        return -1;
    }
    switch(type) {
        case SXC_INPUT_SENSITIVE:
            snprintf(in, insize, "yacWetheas9");
            break;
        default:
            return -1;
    }
    return 0;
}

static int test_callback(const sxc_xfer_stat_t *xfer_stat) {
    if(!xfer_stat) {
        fprintf(stderr, "callback\n");
        return SXE_NOERROR;
    }
    if(xfer_stat->status == SXC_XFER_STATUS_PART_FINISHED || xfer_stat->status == SXC_XFER_STATUS_WAITING)
        *((int64_t*)xfer_stat->ctx) = xfer_stat->current_xfer.sent;
    return SXE_NOERROR;
}

int create_volume(sxc_client_t *sx, sxc_cluster_t *cluster, const char *volname, const char *filter_dir, const char *filter_name, const char *filter_cfg, struct gengetopt_args_info args, int max_revisions) {
    void *cfgdata = NULL;
    int i, fcount, filter_idx, ret = 1;
    unsigned int cfgdata_len = 0;
    char uuidcfg[41];
    uint8_t uuid[16];
    char *voldir = NULL;
    const char *confdir;
    sxc_meta_t *meta = NULL;
    const sxc_filter_t *filter = NULL;
    const sxf_handle_t *filters = NULL;
    
    if(filter_name) {
        sxc_filter_loadall(sx, filter_dir);
        confdir = sxi_cluster_get_confdir(cluster);
        voldir = (char*)malloc(strlen(confdir) + strlen("/volumes/") + strlen(volname) + 1);
        if(!voldir) {
            fprintf(stderr, "create_volume: ERROR: Cannot allocate memory for voldir.\n");
            goto create_volume_err;
        }
        sprintf(voldir, "%s/volumes/%s", confdir, volname);
        /* Wipe existing local config */
        /* There is no check for '..' in the path since the path is fully based on the code, not on arguments. */
        if(!access(voldir, F_OK) && sxi_rmdirs(voldir)) {
            fprintf(stderr, "create_volume: ERROR: Cannot wipe old volume configuration directory %s\n", voldir);
            goto create_volume_err;
        }
        filters = sxc_filter_list(sx, &fcount);
        if(!filters) {
            fprintf(stderr, "create_volume: ERROR: Cannot use filter '%s' - no filters available\n", filter_name);
            goto create_volume_err;
        }
        meta = sxc_meta_new(sx);
        if(!meta) {
            fprintf(stderr, "create_volume: ERROR: Cannot initialize meta.\n");
            goto create_volume_err;
        }
        for(i=0; i<fcount; i++) {
            const sxc_filter_t *f = sxc_get_filter(&filters[i]);
            if(!strcmp(f->shortname, filter_name))
                if(!filter || (f->version[0] > filter->version[0]) || (f->version[0] == filter->version[0] && f->version[1] > filter->version[1])) {
                    filter = f;
                    filter_idx = i;
                }
        }
        if(!filter) {
            fprintf(stderr, "create_volume: ERROR: Filter '%s' not found.\n", filter_name);
            goto create_volume_err;
        }
        sxi_uuid_parse(filter->uuid, uuid);
        if(sxc_meta_setval(meta, "filterActive", uuid, 16)) {
            fprintf(stderr, "create_volume: ERROR: Cannot use filter '%s' - metadata error.\n", filter_name);
            goto create_volume_err;
        }
        snprintf(uuidcfg, sizeof(uuidcfg), "%s-cfg", filter->uuid);
        if(filter->configure) {
            char *fdir = NULL;
            if(confdir) {
                fdir = (char*)malloc(strlen(voldir) + 1 + strlen(filter->uuid) + 1); /* The 1 inside is for '/' character. */
                if(!fdir) {
                    fprintf(stderr, "create_volume: ERROR: Cannot allocate memory for fdir.\n");
                    goto create_volume_err;
                }
                if(access(voldir, F_OK))
                    mkdir(voldir, 0700);
                sprintf(fdir, "%s/%s", voldir, filter->uuid);
                if(access(fdir, F_OK))
                    if(mkdir(fdir, 0700) == -1) {
                        fprintf(stderr, "create_volume: ERROR: Cannot create filter configuration directory '%s'.\n", fdir);
                        free(fdir);
                        goto create_volume_err;
                    }
            }
            if(filter->configure(&filters[filter_idx], filter_cfg, fdir, &cfgdata, &cfgdata_len)) {
                fprintf(stderr, "create_volume: ERROR: Cannot configure filter '%s'.\n", filter_name);
                free(fdir);
                goto create_volume_err;
            }
            free(fdir);
            if(cfgdata && sxc_meta_setval(meta, uuidcfg, cfgdata, cfgdata_len)) {
                fprintf(stderr, "create_volume: ERROR: Cannot store configuration for filter '%s' - metadata error.\n", filter_name);
                goto create_volume_err;
            }
        }
    }
    if(sxc_volume_add(cluster, volname, VOLSIZE, args.replica_arg, max_revisions, meta, args.owner_arg)) {
        fprintf(stderr, "create_volume: ERROR: %s\n", sxc_geterrmsg(sx));
        goto create_volume_err;
    }
    if(sxi_volume_cfg_store(sx, cluster, volname, filter ? filter->uuid : NULL, cfgdata, cfgdata_len)) {
        fprintf(stderr, "create_volume: ERROR: Configuration problem: %s\n", sxc_geterrmsg(sx));
        goto create_volume_err;
    }
    if(args.human_flag)
        printf("create_volume: Volume '%s' (replica: %d, size: %0.f%c) created.\n", volname, args.replica_arg, to_human(VOLSIZE), to_human_suffix(VOLSIZE));
    else
        printf("create_volume: Volume '%s' (replica: %d, size: %lld) created.\n", volname, args.replica_arg, (long long int)VOLSIZE);

    ret = 0;
create_volume_err:
    free(voldir);
    free(cfgdata);
    sxc_meta_free(meta);
    return ret;
} /* create_volume */

int remove_volume(sxc_client_t *sx, sxc_cluster_t *cluster, const char *volname) {
    int ret = 1;
    char*voldir = NULL;
    const char *confdir;

    if(sxc_volume_remove(cluster, volname)) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        return ret;
    }
    printf("remove_volume: Volume '%s' removed.\n", volname);
    confdir = sxi_cluster_get_confdir(cluster);
    voldir = (char*)malloc(strlen(confdir) + strlen("/volumes/") + strlen(volname) + 1);
    if(!voldir) {
        fprintf(stderr, "remove_volume: ERROR: Cannot allocate memory for voldir.\n");
        return ret;
    }
    sprintf(voldir, "%s/volumes/%s", confdir, volname);
    if(!access(voldir, F_OK) && sxi_rmdirs(voldir)) {
        fprintf(stderr, "remove_volume: ERROR: Cannot wipe old volume configuration directory %s\n", voldir);
        goto remove_volume_err;
    }
    
    ret = 0;
remove_volume_err:
    free(voldir);
    return ret;
} /* remove_volume */

int upload_file(sxc_client_t *sx, sxc_cluster_t *cluster, char *local_file_path, char *remote_file_path) {
    int ret = 1;
    sxc_file_t *src, *dest = NULL;
    sxc_uri_t *uri;
     
    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
        fprintf(stderr, "upload_file: ERROR: Bad uri '%s': %s\n", remote_file_path, sxc_geterrmsg(sx));
        return ret;
    }
    src = sxc_file_local(sx, local_file_path);
    if(!src) {
        fprintf(stderr, "upload_file: ERROR: Cannot open '%s' file: %s\n", local_file_path, sxc_geterrmsg(sx));
        goto upload_file_err;
    }
    dest = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!dest) {
        fprintf(stderr, "upload_file: ERROR: Cannot open destination directory.\n");
        goto upload_file_err;
    }
    if(sxc_copy(src, dest, local_file_path[strlen(local_file_path) - 1] == '/', 0)) {
        fprintf(stderr, "upload_file: ERROR: Cannot upload file: %s\n", sxc_geterrmsg(sx));
        goto upload_file_err;
    }

    ret = 0;
upload_file_err:
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* upload_file */

/* This function gives you an opened file. Remember to fclose() it. */
FILE* download_file(sxc_client_t *sx, sxc_cluster_t *cluster, char *local_file_path, char *remote_file_path, int revision) {
    char *rev_char = NULL;
    FILE *ret = NULL;
    sxc_file_t *src, *dest = NULL;
    sxc_uri_t *uri;
    sxc_revlist_t *revs = NULL;
     
    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
        fprintf(stderr, "download_file: ERROR: Bad uri %s: %s\n", remote_file_path, sxc_geterrmsg(sx));
        return ret;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        fprintf(stderr, "download_file: ERROR: Cannot open remote file.\n");
        goto download_file_err;
    }
    dest = sxc_file_local(sx, local_file_path);
    if(!dest) {
        fprintf(stderr, "download_file: ERROR: Cannot open '%s' file: %s\n", local_file_path, sxc_geterrmsg(sx));
        goto download_file_err;
    }
    if(revision>0) {
        revs = sxc_revisions(src);
        if(!revs) {
            fprintf(stderr, "download_file: ERROR: Failed to retrieve file revisions: %s\n", sxc_geterrmsg(sx));
            goto download_file_err;
        }
        if(revision>revs->count) {
            fprintf(stderr, "download_file: ERROR: No such a revision number.\n");
            goto download_file_err;
        }
        rev_char = revs->revisions[revision-1]->revision;
        sxc_file_free(src);
        src = sxc_file_remote(cluster, uri->volume, uri->path, rev_char);
        if(!src) {
            fprintf(stderr, "download_file: ERROR: Cannot open remote file version: %s\n", rev_char);
            goto download_file_err;
        }
        if(sxc_copy_sxfile(src, dest)) {
            fprintf(stderr, "download_file: ERROR: Cannot download file: %s\n", sxc_geterrmsg(sx));
            goto download_file_err;
        }
    } else {
        if(sxc_copy(src, dest, 0, 0)) {
            fprintf(stderr, "download_file: ERROR: Cannot download file: %s\n", sxc_geterrmsg(sx));
            goto download_file_err;
        }
    }
    ret = fopen(local_file_path, "r");
    if(!ret) {
        fprintf(stderr, "download_file: ERROR: Cannot open '%s' file: %s\n", local_file_path, strerror(errno));
        goto download_file_err;
    }

download_file_err:
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    sxc_revisions_free(revs);
    return ret;
} /* download_file */

int download_files(sxc_client_t *sx, sxc_cluster_t *cluster, char *local_dir_path, char *remote_dir_path) {
    int ret = 1;
    sxc_file_t *src, *dest = NULL;
    sxc_uri_t *uri;
     
    uri = sxc_parse_uri(sx, remote_dir_path);
    if(!uri) {
        fprintf(stderr, "download_file: ERROR: Bad uri %s: %s\n", remote_dir_path, sxc_geterrmsg(sx));
        return ret;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        fprintf(stderr, "download_file: ERROR: Cannot open remote directory.\n");
        goto download_files_err;
    }
    dest = sxc_file_local(sx, local_dir_path);
    if(!dest) {
        fprintf(stderr, "download_file: ERROR: Cannot open '%s' directory: %s\n", local_dir_path, sxc_geterrmsg(sx));
        goto download_files_err;
    }
    if(sxc_copy(src, dest, 1, 0)) {
        fprintf(stderr, "download_file: ERROR: Cannot download files: %s\n", sxc_geterrmsg(sx));
        goto download_files_err;
    }

    ret = 0;
download_files_err:
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* download_files */

int delete_file(sxc_client_t *sx, sxc_cluster_t *cluster, char *remote_file_path) {
    int ret = 1;
    sxc_file_t *file;
    sxc_file_list_t *lst = NULL;
    sxc_uri_t *uri;

    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
        fprintf(stderr, "delete_file: ERROR: Bad uri %s: %s\n", remote_file_path, sxc_geterrmsg(sx));
        return ret;
    }
    file = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!file) {
        fprintf(stderr, "delete_file: ERROR: Cannot open destination directory.\n");
        goto delete_file_err;
    }
    lst = sxc_file_list_new(sx, 0);
    if(!lst) {
        fprintf(stderr, "delete_file: ERROR: Failed to create new file list.\n");
        sxc_file_free(file);
        goto delete_file_err;
    }
    if(sxc_file_list_add(lst, file, 0)) {
        fprintf(stderr, "delete_file: ERROR: Cannot add file list entry '%s': %s\n", remote_file_path, sxc_geterrmsg(sx));
        sxc_file_free(file);
        goto delete_file_err;
    }
    if(sxc_rm(lst)) {
        fprintf(stderr, "delete_file: ERROR: Failed to remove file list: %s\n", sxc_geterrmsg(sx));
        goto delete_file_err;
    }

    ret = 0;
delete_file_err:
    sxc_free_uri(uri);
    sxc_file_list_free(lst);
    return ret;
} /* delete_file */

int delete_files(sxc_client_t *sx, sxc_cluster_t *cluster, char *remote_dir_path) {
    int ret = 1, n;
    char *file_name;
    sxc_file_t *file = NULL;
    sxc_file_list_t *lst = NULL;
    sxc_cluster_lf_t *file_list;
    sxc_uri_t *uri;

    uri = sxc_parse_uri(sx, remote_dir_path);
    if(!uri) {
        fprintf(stderr, "delete_files: ERROR: Bad uri %s: %s\n", remote_dir_path, sxc_geterrmsg(sx));
        return ret;
    }
    file_list = sxc_cluster_listfiles(cluster, uri->volume, uri->path, 0, NULL, NULL, NULL, NULL, 0);
    if(!file_list) {
        fprintf(stderr, "delete_files: ERROR: Cannot get volume files list.\n");
        goto delete_files_err;
    }
    lst = sxc_file_list_new(sx, 0);
    if(!lst) {
        fprintf(stderr, "delete_files: ERROR: Failed to create new file list.\n");
        sxc_file_free(file);
        goto delete_files_err;
    }
    while(1) {
        n = sxc_cluster_listfiles_next(file_list, &file_name, NULL, NULL, NULL);
        if(n <= 0) {
            if(n) {
                fprintf(stderr, "find_file: ERROR: Failed to retrieve file name for '%s' directory.\n", remote_dir_path);
                goto delete_files_err;
            }
            break;
        }
        if(!file_name) {
            fprintf(stderr, "find_file: ERROR: NULL file name pointer received.\n");
            goto delete_files_err;
        }
        file = sxc_file_remote(cluster, uri->volume, file_name, NULL);
        if(!file) {
            fprintf(stderr, "delete_files: ERROR: Cannot process file: %s\n", file_name);
            free(file_name);
            goto delete_files_err;
        }
        if(sxc_file_list_add(lst, file, 0)) {
            fprintf(stderr, "delete_files: ERROR: Cannot add file list entry '%s': %s\n", file_name, sxc_geterrmsg(sx));
            sxc_file_free(file);
            free(file_name);
            goto delete_files_err;
        }
        free(file_name);
    }
    if(sxc_rm(lst)) {
        fprintf(stderr, "delete_files: ERROR: Failed to remove file list: %s\n", sxc_geterrmsg(sx));
        goto delete_files_err;
    }

    ret = 0;
delete_files_err:
    sxc_free_uri(uri);
    sxc_file_list_free(lst);
    sxc_cluster_listfiles_free(file_list);
    return ret;
} /* delete_files */

/* -1 - error
 *  0 - file not found
 *  1 - file found*/
int find_file(sxc_client_t *sx, sxc_cluster_t *cluster, char *remote_dir_path, char *remote_file_path) {
    int ret = -1, n;
    char *file_name;
    sxc_file_list_t *lst = NULL;
    sxc_uri_t *uri;
    sxc_cluster_lf_t *file_list;

    uri = sxc_parse_uri(sx, remote_dir_path);
    if(!uri) {
        fprintf(stderr, "find_file: ERROR: Bad uri %s: %s\n", remote_dir_path, sxc_geterrmsg(sx));
        return ret;
    }
    file_list = sxc_cluster_listfiles(cluster, uri->volume, uri->path, 0, NULL, NULL, NULL, NULL, 0);
    if(!file_list) {
        fprintf(stderr, "find_file: ERROR: Cannot get volume files list.\n");
        goto find_file_err;
    }
    while(1) {
        n = sxc_cluster_listfiles_next(file_list, &file_name, NULL, NULL, NULL);
        if(n <= 0) {
            if(n) {
                fprintf(stderr, "find_file: ERROR: Failed to retrieve file name for '%s' directory.\n", remote_dir_path);
                goto find_file_err;
            }
            break;
        }
        if(!file_name) {
            fprintf(stderr, "find_file: ERROR: NULL file name pointer received.\n");
            goto find_file_err;
        }
        if(!strncmp( remote_file_path, file_name, MIN(strlen(remote_file_path),strlen(file_name)) )) {
            ret = 1;
            free(file_name);
            goto find_file_err;
        }
        free(file_name);
    }

    ret = 0;
find_file_err:
    sxc_free_uri(uri);
    sxc_file_list_free(lst);
    sxc_cluster_listfiles_free(file_list);
    return ret;
} /* find file */

int test_empty_file(sxc_client_t *sx, sxc_cluster_t *cluster, char *local_dir_path, char *remote_dir_path) {
    int ret = 1;
    char *local_file_path, *remote_file_path = NULL;
    FILE *file = NULL;
    sxc_uri_t *uri;

    printf("test_empty_file: Started\n");
    uri = sxc_parse_uri(sx, remote_dir_path);
    if(!uri) {
        fprintf(stderr, "test_empty_file: ERROR: Bad uri %s: %s\n", remote_dir_path, sxc_geterrmsg(sx));
        return ret;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(EMPTY_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_empty_file: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_empty_file_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, EMPTY_FILE_NAME);
    file = fopen(local_file_path,"w");
    if(!file) {
        fprintf(stderr, "test_empty_file: ERROR: Cannot create '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_empty_file_err;
    }
    if(fclose(file) == EOF) {
        fprintf(stderr, "test_empty_file: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_empty_file_err;
    }
    if(upload_file(sx, cluster, local_file_path, remote_dir_path)) {
        fprintf(stderr, "test_empty_file: ERROR: Uploading '%s' file failed: %s\n", local_file_path, sxc_geterrmsg(sx));
        goto test_empty_file_err;
    }
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(EMPTY_FILE_NAME) + 1);
    if(!remote_file_path) {
        fprintf(stderr, "test_empty_file: ERROR: Cannot allocate memory for remote_file_path.\n");
        goto test_empty_file_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, EMPTY_FILE_NAME);
    if(delete_file(sx,cluster,remote_file_path)) {
        fprintf(stderr, "test_empty_file: ERROR: Error while deleting a file.\n");
        goto test_empty_file_err;
    }

    ret = 0;
    printf("test_empty_file: Succeeded\n");
test_empty_file_err:
    if(file && unlink(local_file_path)) {
        fprintf(stderr, "test_empty_file: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        ret = 1;
    }
    free(remote_file_path);
    free(local_file_path);
    sxc_free_uri(uri);
    return ret;
} /* test_empty_file */

void create_block(rnd_state_t *state, unsigned char *block, uint64_t block_size)
{
    uint64_t i;
    for(i=0; i<block_size; i++)
        block[i] = rand_2cmres(state);
} /* create_block */

int test_upload_and_download(sxc_client_t *sx, sxc_cluster_t *cluster, char *local_dir_path, char *remote_dir_path, uint64_t block_size, uint64_t count, int human, int size_flag) {
    int i, tmp, ret = 1;
    uint64_t seed;
    rnd_state_t state;
    char *local_file_path = NULL, *remote_file_path = NULL;
    unsigned char *block = NULL, *hash1 = NULL, *hash2 = NULL;
    FILE *file = NULL;
    SHA_CTX ctx;
    
    printf("test_upload_and_download: Started\n");
    if(sxc_cluster_set_progress_cb(sx, cluster, test_callback, (void*)&bytes)) {
        fprintf(stderr, "test_upload_and_download: ERROR: Cannot set callback.\n");
        return ret;
    }
    block = (unsigned char*)malloc(block_size * sizeof(unsigned char));
    if(!block) {
        fprintf(stderr, "test_upload_and_download: ERROR: Cannot allocate memory for block.\n");
        goto test_upload_and_download_err;
    }
    hash1 = (unsigned char*)malloc((SHA_DIGEST_LENGTH) * sizeof(unsigned char));
    if(!hash1) {
        fprintf(stderr, "test_upload_and_download: ERROR: Cannot allocate memory for hash1.\n");
        goto test_upload_and_download_err;
    }
    hash2 = (unsigned char*)malloc((SHA_DIGEST_LENGTH) * sizeof(unsigned char));
    if(!hash2) {
        fprintf(stderr, "test_upload_and_download: ERROR: Cannot allocate memory for hash2.\n");
        goto test_upload_and_download_err;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(UD_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_upload_and_download: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_upload_and_download_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, UD_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(UD_FILE_NAME) + 1);
    if(!remote_file_path) {
        fprintf(stderr, "test_upload_and_download: ERROR: Cannot allocate memory for remote_file_path.\n");
        goto test_upload_and_download_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, UD_FILE_NAME);
    seed = make_seed();
    printf("test_upload_and_download: Seed: %012lx\n", seed);
    rnd_seed(&state,seed);
    if(human)
        printf("test_upload_and_download: Creating file of size: %.2f%c (%" PRIu64 "*%.0f%c)\n", to_human(block_size*count), to_human_suffix(block_size*count), count, to_human(block_size), to_human_suffix(block_size));
    else
        printf("test_upload_and_download: Creating file of size: %" PRIu64 " (%" PRIu64 "*%" PRIu64 ")\n", block_size*count, count, block_size);
    switch(block_size) {
        case SX_BS_SMALL:
            if(count>31)
                fprintf(stderr, "test_upload_and_download: WARNING: File size out of set block size bounds.\n");
            break;
        case SX_BS_MEDIUM:
            if(count<32 || count>8192)
                fprintf(stderr, "test_upload_and_download: WARNING: File size out of set block size bounds.\n");
            break;
        case SX_BS_LARGE:
            if(count<129)
                fprintf(stderr, "test_upload_and_download: WARNING: File size out of set block size bounds.\n");
            break;
        default:
            fprintf(stderr, "test_upload_and_download: ERROR: Unknown block size.\n");
            goto test_upload_and_download_err;
    }
    create_block(&state, block, block_size);
    file = fopen(local_file_path, "wb");
    if(!file) {
        fprintf(stderr, "test_upload_and_download: ERROR: Cannot create '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_upload_and_download_err;
    }
    if(!SHA1_Init(&ctx)) {
        fprintf(stderr, "test_upload_and_download: ERROR: SHA1_Init() failure.\n");
        goto test_upload_and_download_err;
    }
    for(i=0; i<count; i++) {
        if(fwrite(block, sizeof(unsigned char), block_size, file) != block_size) {
            fprintf(stderr, "test_upload_and_download: ERROR: Error while writing to '%s' file. (%d)\n", local_file_path, i);
            goto test_upload_and_download_err;
        }
        if(!SHA1_Update(&ctx, block, block_size)) {
            fprintf(stderr, "test_upload_and_download: ERROR: SHA1_Update() failure. (%d).\n", i);
            goto test_upload_and_download_err;
        }
    }
    if(!SHA1_Final(hash1, &ctx)) {
        fprintf(stderr, "test_upload_and_download: ERROR: SHA1_Final() failure.\n");
        goto test_upload_and_download_err;
    }
    if(fclose(file) == EOF) {
        fprintf(stderr, "test_upload_and_download: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        if(unlink(local_file_path))
            fprintf(stderr, "test_upload_and_download: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        file = NULL;
        goto test_upload_and_download_err;
    }
    file = NULL;
    printf("test_upload_and_download: Uploading\n");
    if(upload_file(sx,cluster, local_file_path, remote_dir_path)) {
        fprintf(stderr, "test_upload_and_download: ERROR: Uploading '%s' file failed: %s\n",local_file_path, sxc_geterrmsg(sx));
        if(unlink(local_file_path))
            fprintf(stderr, "test_upload_and_download: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_upload_and_download_err;
    }
    if(unlink(local_file_path)) {
        fprintf(stderr, "test_upload_and_download: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_upload_and_download_err;
    }
    if(size_flag && (uint64_t)block_size != bytes) {
        fprintf(stderr, "test_upload_and_download: ERROR: Uploaded more data than necessary.\n");
        goto test_upload_and_download_err;
    }
    printf("test_upload_and_download: Downloading\n");
    file = download_file(sx, cluster, local_file_path, remote_file_path, 0);
    if(!file) {
        fprintf(stderr, "test_upload_and_download: ERROR: Downloading a file failed.\n");
        goto test_upload_and_download_err;
    }
    if(!SHA1_Init(&ctx)) {
        fprintf(stderr, "test_upload_and_download: ERROR: SHA1_Init() failure.\n");
        goto test_upload_and_download_err;
    }
    while((tmp = fread(block, sizeof(unsigned char), block_size, file))) {
        if(!SHA1_Update(&ctx, block, tmp)) {
            fprintf(stderr, "test_upload_and_download: ERROR: SHA1_Update() failure.\n");
            goto test_upload_and_download_err;
        }
        if(tmp < block_size) {
            fprintf(stderr, "test_upload_and_download: ERROR: Downloaded only a part of file.\n");
            goto test_upload_and_download_err;
        }
    }
    if(!SHA1_Final(hash2, &ctx)) {
        fprintf(stderr, "test_upload_and_download: ERROR: SHA1_Final() failure.\n");
        goto test_upload_and_download_err;
    }
    if(memcmp(hash1, hash2, SHA_DIGEST_LENGTH)) {
        fprintf(stderr, "test_upload_and_download: ERROR: Uploaded and downloaded file differs.\n");
        goto test_upload_and_download_err;
    }
    if(delete_file(sx, cluster, remote_file_path)) {
        fprintf(stderr, "test_upload_and_download: ERROR: Deleting '%s' file failed.\n", remote_file_path);
        goto test_upload_and_download_err;
    }
    switch(find_file(sx, cluster, remote_dir_path, UD_FILE_NAME)) {
        case -1:
            fprintf(stderr, "test_upload_and_download: ERROR: Looking for '%s' file in %s failed.\n", UD_FILE_NAME, remote_file_path);
            goto test_upload_and_download_err;
        case 0: break;
        case 1:
            fprintf(stderr, "test_upload_and_download: ERROR: '%s' file has not been deleted correctly.\n", UD_FILE_NAME);
            goto test_upload_and_download_err;
    }
    
    ret = 0;
    printf("test_upload_and_download: Succeeded\n");
test_upload_and_download_err:
    free(hash1);
    free(hash2);
    free(block);
    if(file) {
        if(fclose(file) == EOF) {
            fprintf(stderr, "test_upload_and_download: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
            ret = 1;
        } else if(unlink(local_file_path)) {
            fprintf(stderr, "test_upload_and_download: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
            ret = 1;
        }
    }
    free(local_file_path);
    free(remote_file_path);
    return ret;
} /* test_upload_and_download */

int test_revision(sxc_client_t *sx, sxc_cluster_t *cluster, char *local_dir_path, char *remote_dir_path, uint64_t block_size, uint64_t count, int human, int max_revisions) {
    int i, j, tmp, ret = 1;
    uint64_t seed;
    rnd_state_t state;
    char *local_file_path = NULL, *remote_file_path = NULL;
    unsigned char *block, *hash = NULL, **hashes = NULL;
    FILE *file = NULL;
    SHA_CTX ctx;

    printf("test_revision: Started (revision: %d)\n", max_revisions);
    block = (unsigned char*)malloc(block_size * sizeof(unsigned char));
    if(!block) {
        fprintf(stderr, "test_revision: ERROR: Cannot allocate memory for block.\n");
        return ret;
    }
    hash = (unsigned char*)malloc((SHA_DIGEST_LENGTH + 1) * sizeof(unsigned char));
    if(!hash) {
        fprintf(stderr, "test_revision: ERROR: Cannot allocate memory for hash.\n");
        goto test_revision_err;
    }
    hashes = (unsigned char**)calloc(max_revisions, sizeof(unsigned char*));
    if(!hashes) {
        fprintf(stderr, "test_revision: ERROR: Cannot allocate memory for hashes.\n");
        goto test_revision_err;
    }
    for(i=0; i<max_revisions; i++) {
        hashes[i] = (unsigned char*)malloc((SHA_DIGEST_LENGTH + 1) * sizeof(unsigned char));
        if(!hashes[i]) {
            fprintf(stderr, "test_revision: ERROR: Cannot allocate memory for hashes[%d].)\n", i);
            goto test_revision_err;
        }
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(REV_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_revision: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_revision_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, REV_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(REV_FILE_NAME) + 1);
    if(!remote_file_path) {
        fprintf(stderr, "test_revision: ERROR: Cannot allocate memory for remote_file_path.\n");
        goto test_revision_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, REV_FILE_NAME);
    seed = make_seed();
    printf("test_revision: Seed: %012lx\n", seed);
    rnd_seed(&state,seed);
    if(human)
        printf("test_revision: Creating and uploading files of size: %.2f%c (%" PRIu64 "*%.0f%c)\n", to_human(block_size*count), to_human_suffix(block_size*count), count, to_human(block_size), to_human_suffix(block_size));
    else
        printf("test_revision: Creating and uploading files of size: %" PRIu64 " (%" PRIu64 "*%" PRIu64 ")\n", block_size*count, count, block_size);
    switch(block_size) {
        case SX_BS_SMALL:
            if(count>31)
                fprintf(stderr, "test_revision: WARNING: File size out of set block size bounds.\n");
            break;
        case SX_BS_MEDIUM:
            if(count<32 || count>8192)
                fprintf(stderr, "test_revision: WARNING: File size out of set block size bounds.\n");
            break;
        case SX_BS_LARGE:
            if(count<129)
                fprintf(stderr, "test_revision: WARNING: File size out of set block size bounds.\n");
            break;
        default:
            fprintf(stderr, "test_revsion: ERROR: Unknown block size.\n");
            goto test_revision_err;
    }
    file = fopen(local_file_path, "wb");
    if(!file) {
        fprintf(stderr, "test_revision: ERROR: Cannot create '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_revision_err;
    }
    for(i=0; i<max_revisions; i++) {
        if(truncate(local_file_path, 0)) {
            fprintf(stderr, "test_revision: ERROR: Cannot truncate '%s' file: %s\n", local_file_path, strerror(errno));
            goto test_revision_err;
        }
        rewind(file);
        create_block(&state, block, block_size);
        if(!SHA1_Init(&ctx)) {
            fprintf(stderr, "test_revision: ERROR: SHA1_Init() failure while creating file. (%d).\n", i);
            goto test_revision_err;
        }
        for(j=0; j<count; j++) {
            if(fwrite(block, sizeof(unsigned char), block_size, file) != block_size) {
                fprintf(stderr, "test_revision: ERROR: Writting to '%s' file failed. (%d)\n", local_file_path, j);
                goto test_revision_err;
            }
            if(!SHA1_Update(&ctx, block, block_size)) {
                fprintf(stderr, "test_revision: ERROR: SHA1_Update() failure while creating file. (%d:%d).\n", i, j);
                goto test_revision_err;
            }
        }
        if(!SHA1_Final(hashes[max_revisions-1-i], &ctx)) {
            fprintf(stderr, "test_revision: ERROR: SHA1_Final() failure while creating file. (%d).\n", i);
            goto test_revision_err;
        }
        if(fflush(file)==EOF) {
            fprintf(stderr, "test_revision: ERROR: Cannot flush '%s' file: %s (%d)\n", local_file_path, strerror(errno), i);
            goto test_revision_err;
        }
        if(upload_file(sx, cluster, local_file_path, remote_dir_path)) {
            fprintf(stderr, "test_revision: ERROR: Uploading '%s' file failed: %s\n", local_file_path, sxc_geterrmsg(sx));
            goto test_revision_err;
        }
    }
    printf("test_revision: Downloading and checking file versions.\n");
    for(i=0; i<max_revisions; i++) {
        if(fclose(file) == EOF) {
            fprintf(stderr, "test_revision: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
            if(unlink(local_file_path))
                fprintf(stderr, "test_revision: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
            file = NULL;
            goto test_revision_err;
        }
        if(unlink(local_file_path)) {
            fprintf(stderr, "test_revision: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
            file = NULL;
            goto test_revision_err;
        }
        file = download_file(sx, cluster, local_file_path, remote_file_path, i+1);
        if(!file) {
            fprintf(stderr, "test_revision: ERROR: Downloading '%s' file failed: %s\n", remote_file_path, sxc_geterrmsg(sx));
            goto test_revision_err;
        }
        if(!SHA1_Init(&ctx)) {
            fprintf(stderr, "test_revision: ERROR: SHA1_Init() failure while downloading file. (%d)\n", i);
            goto test_revision_err;
        }
        while((tmp = fread(block, sizeof(unsigned char), block_size, file))) {
            if(!SHA1_Update(&ctx, block, tmp)) {
                fprintf(stderr, "test_revision: ERROR: SHA1_Update() failure while downloading file. (%d)\n", i);
                goto test_revision_err;
            }
            if(tmp < block_size) {
                fprintf(stderr, "test_revision: ERROR: Downloaded only a part of file.\n");
                goto test_revision_err;
            }
        }
        if(!SHA1_Final(hash, &ctx)) {
            fprintf(stderr, "test_revision: ERROR: SHA1_Final() failure while downloading file. (%d)\n", i);
            goto test_revision_err;
        }
        if(memcmp(hash, hashes[i], SHA_DIGEST_LENGTH)) {
            fprintf(stderr, "test_revision: ERROR: Uploaded and downloaded file differs. (%d)\n", i);
            goto test_revision_err;
        }
    }
    if(delete_file(sx, cluster, remote_file_path)) {
        fprintf(stderr, "test_revision: ERROR: Deleting '%s' file failed.\n", remote_file_path);
        goto test_revision_err;
    }
    switch(find_file(sx, cluster, remote_dir_path, REV_FILE_NAME)) {
        case -1:
            fprintf(stderr, "test_revision: ERROR: Looking for '%s' file in %s failed.\n", REV_FILE_NAME, remote_file_path);
            goto test_revision_err;
        case 0: break;
        case 1:
            fprintf(stderr, "test_revision: ERROR: '%s' file has not been deleted correctly.\n", REV_FILE_NAME);
            goto test_revision_err;
    }

    ret = 0;
    printf("test_revision: Succeeded\n");
test_revision_err:
    if(file) {
        if(fclose(file) == EOF) {
            fprintf(stderr, "test_revision: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
            ret = 1;
        } else if(unlink(local_file_path)) {
            fprintf(stderr, "test_revision: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
            ret = 1;
        }
    }
    free(local_file_path);
    free(remote_file_path);
    if(hashes)
        for(i=0; i<max_revisions; i++)
            free(hashes[i]);
    free(hashes);
    free(hash);
    free(block);
    return ret;
} /* test_revision */

/* For test_upload_and_download:
 *       Block size | Available number of blocks
 *    SX_BS_SMALL   |  0 - 31
 *    SX_BS_MEDIUM  |  8 - 8192
 *    SX_BS_LARGE   |  129+
 * REMEMBER TO CHECK WHETHER THE VOLUME SIZE IS BIG ENOUGH!! */
int run_tests(sxc_client_t *sx, sxc_cluster_t *cluster, char *local_dir_path, char *remote_dir_path, struct gengetopt_args_info args, int max_revisions, int size_flag) {
    if(test_empty_file(sx, cluster, local_dir_path, remote_dir_path)) {
        fprintf(stderr, "run_tests: ERROR: test_empty_file() failed.\n");
        return 1;
    }
    if(test_upload_and_download(sx, cluster, local_dir_path, remote_dir_path, SX_BS_SMALL, 26, args.human_flag, size_flag)) {
        fprintf(stderr, "run_tests: ERROR: test_upload_and_download failed.\n");
        return 1;
    }
    if(test_upload_and_download(sx, cluster, local_dir_path, remote_dir_path, SX_BS_MEDIUM, 2314, args.human_flag, size_flag)) {
        fprintf(stderr, "run_tests: ERROR: test_upload_and_download failed.\n");
        return 1;
    }
    if(args.all_flag && test_upload_and_download(sx, cluster, local_dir_path, remote_dir_path, SX_BS_LARGE, 285, args.human_flag, size_flag)) {
        fprintf(stderr, "run_tests: ERROR: test_upload_and_download failed.\n");
        return 1;
    }
    if(test_revision(sx, cluster, local_dir_path, remote_dir_path, SX_BS_SMALL, 29, args.human_flag, max_revisions)) {
        fprintf(stderr, "run_tests: ERROR: test_revision failed.\n");
        return 1;
    }
    if(test_revision(sx, cluster, local_dir_path, remote_dir_path, SX_BS_MEDIUM, 649, args.human_flag, max_revisions)) {
        fprintf(stderr, "run_tests: ERROR: test_revision failed.\n");
        return 1;
    }
    if(args.all_flag && test_revision(sx, cluster, local_dir_path, remote_dir_path, SX_BS_LARGE, 131, args.human_flag, max_revisions)) {
        fprintf(stderr, "run_tests: ERROR: test_revision failed.\n");
        return 1;
    }
    return 0;
} /* run_tests */

int test_attribs(sxc_client_t *sx, sxc_cluster_t *cluster, char *local_dir_path, char *remote_dir_path) {
    int i, ret = 1, owner, group, other;
    long int tmp_time;
    char *local_files_paths[ATTRIBS_COUNT], *remote_files_paths[ATTRIBS_COUNT];
    uint64_t seed;
    mode_t attribs;
    rnd_state_t state;
    struct utimbuf time;
    struct timeval tv;
    struct stat st, t_st[ATTRIBS_COUNT];
    FILE *files[ATTRIBS_COUNT];

    printf("test_attribs: Started\n");
    memset(files, 0, sizeof(files));
    memset(local_files_paths, 0, sizeof(local_files_paths));
    memset(remote_files_paths, 0, sizeof(remote_files_paths));
    seed = make_seed();
    printf("test_attribs: Seed: %012lx\n", seed);
    rnd_seed(&state,seed);
    for(i=0; i<ATTRIBS_COUNT; i++) {
        local_files_paths[i] = (char*)malloc(strlen(local_dir_path) + strlen(ATTRIBS_FILE_NAME) + 2 + 1);
        if(!local_files_paths[i]) {
            fprintf(stderr, "test_attribs: ERROR: Cannot allocate memory for local_files_paths[%d].\n", i);
            goto test_attribs_err;
        }
        sprintf(local_files_paths[i], "%s%s%d", local_dir_path, ATTRIBS_FILE_NAME, i);
        remote_files_paths[i] = (char*)malloc(strlen(remote_dir_path) + strlen(ATTRIBS_FILE_NAME) + 2 + 1);
        if(!remote_files_paths[i]) {
            fprintf(stderr, "test_attribs: ERROR: Cannot allocate memory for remote_files_paths[%d].\n", i);
            goto test_attribs_err;
        }
        sprintf(remote_files_paths[i], "%s%s%d", remote_dir_path, ATTRIBS_FILE_NAME, i);
        files[i] = fopen(local_files_paths[i], "w");
        if(!files[i]) {
            fprintf(stderr, "test_attribs: ERROR: Cannot open '%s' file: %s\n", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
        }
        if(fclose(files[i]) == EOF) {
            fprintf(stderr, "test_attribs: ERROR: Cannot close '%s' file: %s\n", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
        }
        owner = (rand_2cmres(&state)%8)|4;
        group = rand_2cmres(&state)%8;
        other = rand_2cmres(&state)%8;
        printf("test_attribs: rights being tested: %c%c%c%c%c%c%c%c%c\n", owner&4?'r':'-', owner&2?'w':'-', owner&1?'x':'-', group&4?'r':'-', group&2?'w':'-', group&1?'x':'-', other&4?'r':'-', other&2?'w':'-', other&1?'x':'-');
        attribs = (owner<<6) | (group<<3) | other;
        if(chmod(local_files_paths[i], attribs)) {
            fprintf(stderr, "test_attribs: ERROR: Cannot set attributes for '%s' file: %s\n", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
        }
        if(gettimeofday(&tv, NULL)) {
            fprintf(stderr, "test_attribs: ERROR: Cannot get current time: %s\n", strerror(errno));
            goto test_attribs_err;
        }
        tmp_time = (long int)rand_2cmres(&state)%100000000;
        if((owner + group + other)&1)
            tmp_time *= -1;
        time.actime = 0;
        time.modtime = tv.tv_sec + tmp_time;
        if(utime(local_files_paths[i], &time)) {
            fprintf(stderr, "test_attribs: ERROR: Cannot set modification time for '%s' file: %s\n", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
        }
        stat(local_files_paths[i], &t_st[i]);
    }
    if(upload_file(sx, cluster, local_dir_path, remote_dir_path)) {
        fprintf(stderr, "test_attribs: ERROR: Uploading files from %s failed: %s\n", local_dir_path, sxc_geterrmsg(sx));
        goto test_attribs_err;
    }
    for(i=0; i<ATTRIBS_COUNT; i++) {
       files[i] = NULL;
       if(unlink(local_files_paths[i])) {
            fprintf(stderr, "test_attribs: ERROR: Cannot remove '%s' file: %s\n", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
       }
    }
    if(download_files(sx, cluster, local_dir_path, remote_dir_path)) {
        fprintf(stderr, "test_attribs: ERROR: Cannot download files: %s\n", sxc_geterrmsg(sx));
        goto test_attribs_err;
    }
    memset(files, 1, sizeof(files));
    for(i=0; i<ATTRIBS_COUNT; i++) {
        stat(local_files_paths[i], &st);
        if(st.st_mode != t_st[i].st_mode) {
            fprintf(stderr, "test_attribs: ERROR: File attributes difer.\n");
            goto test_attribs_err;
        }
        if(st.st_mtime != t_st[i].st_mtime) {
            fprintf(stderr, "test_attribs: ERROR: File modification time difers.\n");
            goto test_attribs_err;
        }
    }
    if(delete_files(sx, cluster, remote_dir_path)) {
        fprintf(stderr, "test_attribs: ERROR: Cannot remove files from %s\n", remote_dir_path);
        goto test_attribs_err;
    }

    printf("test_attribs: Succeeded\n");
    ret = 0;
test_attribs_err:
    for(i=0; i<ATTRIBS_COUNT; i++) {
        if(local_files_paths[i]) {
            unlink(local_files_paths[i]);
            free(local_files_paths[i]);
        }
        free(remote_files_paths[i]);
    }
    return ret;
} /* test_attribs */

int test_undelete(sxc_client_t *sx, sxc_cluster_t *cluster, char *local_dir_path, char *remote_dir_path) {
    int ret = 1;
    char *local_file_path, *remote_file_path = NULL;
    sxc_uri_t *uri;
    FILE *file = NULL;

    printf("test_undelete: Started\n");
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(UNDELETE_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_undelete: ERROR: Cannot allocate memory for local_file_path.\n");
        return ret;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, UNDELETE_FILE_NAME);
    uri = sxc_parse_uri(sx, remote_dir_path);
    if(!uri) {
        fprintf(stderr, "test_undelete: ERROR: Bad uri %s: %s\n", remote_dir_path, sxc_geterrmsg(sx));
        goto test_undelete_err;
    }
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(UNDELETE_FILE_NAME) + strlen(TRASH_NAME) + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_file_path) {
        fprintf(stderr, "test_undelete: ERROR: Cannot allocate memory for remote_file_path.\n");
        goto test_undelete_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, UNDELETE_FILE_NAME);
    file = fopen(local_file_path, "w");
    if(!file) {
        fprintf(stderr, "test_undelete: ERROR: Cannot open '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_undelete_err;
    }
    if(fclose(file) == EOF) {
        fprintf(stderr, "test_undelete: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_undelete_err;
    }
    if(upload_file(sx, cluster, local_file_path, remote_file_path)) {
        fprintf(stderr, "test_undelete: ERROR: Uploading '%s' file failed: %s\n", local_file_path, sxc_geterrmsg(sx));
        goto test_undelete_err;
    }
    if(delete_file(sx, cluster, remote_file_path)) {
        fprintf(stderr, "test_undelete: ERROR: Cannot remove '%s' file: %s\n", remote_file_path, sxc_geterrmsg(sx));
        goto test_undelete_err;
    }
    sprintf(remote_file_path, "sx://%s@%s/%s%s/%s/", uri->profile, uri->host, uri->volume, TRASH_NAME, REMOTE_DIR);
    switch(find_file(sx, cluster, remote_file_path, UNDELETE_FILE_NAME)) {
        case -1:
            fprintf(stderr, "test_undelete: ERROR: Looking for '%s' file in %s failed.\n", UNDELETE_FILE_NAME, remote_file_path);
            goto test_undelete_err;
        case 0: break;
        case 1:
            fprintf(stderr, "test_undelete: ERROR: '%s' file has not been deleted correctly.\n", UNDELETE_FILE_NAME);
            goto test_undelete_err;
    }
    if(delete_files(sx, cluster, remote_file_path)) {
        fprintf(stderr, "test_undelete: ERROR: Cannot remove files from '%s': %s\n", remote_file_path, sxc_geterrmsg(sx));
        goto test_undelete_err;
    }

    printf("test_undelete: Succeeded\n");
    ret = 0;
test_undelete_err:
    if(file && unlink(local_file_path)) {
        fprintf(stderr, "test_undelete: ERROR: Cannot remove '%s' file: %s\n", local_file_path, strerror(errno));
        ret = 1;
    }
    free(local_file_path);
    free(remote_file_path);
    sxc_free_uri(uri);
    return ret;
} /* test_undelete */

int volume_test(sxc_client_t *sx, sxc_cluster_t *cluster, char *volname, char *filter_dir, char *filter_name, char *filter_cfg, char *local_dir_path, char *remote_dir_path, struct gengetopt_args_info args, int max_revisions) {
    int size_flag;
    if(filter_name && (!strcmp(filter_name, "zcomp") || !strcmp(filter_name, "aes256")))
        size_flag = 0;
    else
        size_flag = 1;
    printf("\nVolume test - filter: %s; filter configuration: %s\n", filter_name?filter_name:"<no filter>", filter_cfg?filter_cfg:"<none>");
    if(create_volume(sx, cluster, volname, filter_dir, filter_name, filter_cfg, args, max_revisions)) {
        fprintf(stderr, "volume_test: ERROR: Cannot create new volume.\n");
        return 1;
    }
    if(run_tests(sx, cluster, local_dir_path, remote_dir_path, args, max_revisions, size_flag))
        return 1;
    if(filter_name) {
        if(!strcmp(filter_name, "attribs") && test_attribs(sx, cluster, local_dir_path, remote_dir_path)) {
            fprintf(stderr, "volume_test: ERROR: Attributs test failed.\n");
            return 1;
        }
        /* This has to be executed at the very end because it removes all the files from trash. */
        if(!strcmp(filter_name, "undelete") && test_undelete(sx, cluster, local_dir_path, remote_dir_path)) {
            fprintf(stderr, "volume_test: ERROR: Undelete test failed.\n");
            return 1;
        }
    }
    if(remove_volume(sx, cluster, volname)) {
        fprintf(stderr, "volume_test: ERROR: Cannot remove '%s' volume: %s\n", volname, sxc_geterrmsg(sx));
        return 1;
    }
    return 0;
} /* volume_test */

int test_quota(sxc_client_t *sx, sxc_cluster_t *cluster, char *local_dir_path, char *remote_dir_path, struct gengetopt_args_info args) {
    int i, fd, ret = 1;
    uint64_t seed;
    char *volname = NULL, *local_file_path = NULL, *remote_path = NULL;
    unsigned char *block = NULL;
    FILE *file = NULL;
    sxc_file_t *src = NULL, *dest = NULL;
    rnd_state_t state;

    printf("test_quota: Started\n");
    volname = (char*)malloc(strlen(VOLNAME) + strlen("XXXXXX") + 1);
    if(!volname) {
        fprintf(stderr, "test_quota: ERROR: Cannot allocate memory for volname.\n");
        goto test_quota_err;
    }
    sprintf(volname, "%sXXXXXX", VOLNAME);
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(QUOTA_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_quota: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_quota_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, QUOTA_FILE_NAME);
    remote_path = (char*)malloc(strlen(volname) + 1 + strlen(QUOTA_FILE_NAME) + 1);
    if(!remote_path) {
        fprintf(stderr, "test_quota: ERROR: Cannot allocate memory for remote_path.\n");
        goto test_quota_err;
    }
    sprintf(remote_path, "%s/%s", volname, QUOTA_FILE_NAME);
    block = (unsigned char*)malloc(SX_BS_LARGE * sizeof(unsigned char));
    if(!block) {
        fprintf(stderr, "test_quota: ERROR: Cannot allocate memory for block.\n");
        goto test_quota_err;
    }
    seed = make_seed();
    printf("test_quota: Seed: %012lx\n", seed);
    rnd_seed(&state,seed);
    create_block(&state, block, SX_BS_LARGE);
    fd = mkstemp(volname);
    if(fd < 0) {
        fprintf(stderr, "test_quota: ERROR: Cannot generate temporary directory name.\n");
        goto test_quota_err;
    }
    if(close(fd)) {
        fprintf(stderr, "test_quota: ERROR: Cannot close file descriptor: %s\n", strerror(errno));
        goto test_quota_err;
    }
    if(unlink(volname)) {
        fprintf(stderr, "test_quota: ERROR: Cannot delete '%s' file: %s\n", volname, strerror(errno));
        goto test_quota_err;
    }
    if(sxc_volume_add(cluster, volname, QUOTA_VOL_SIZE*1024*1024, 1, 1, NULL, args.owner_arg)) {
        fprintf(stderr, "test_quota: ERROR: Cannot create new volume: %s\n", sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    if(args.human_flag) {
        printf("test_quota: Volume '%s' (replica: 1, size: %dM) created.\n", volname, QUOTA_VOL_SIZE);
        printf("test_quota: Creating file of size: %dM\n", QUOTA_FILE_SIZE);
    } else {
        printf("test_quota: Volume '%s' (replica: 1, size: %lld) created.\n", volname, QUOTA_VOL_SIZE*1024LL*1024LL);
        printf("test_quota: Creating file of size: %" PRIu64 "\n", (uint64_t)QUOTA_FILE_SIZE*1024*1024);
    }
    file = fopen(local_file_path, "wb");
    if(!file) {
        fprintf(stderr, "test_quota: ERROR: Cannot create '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_quota_err;
    }
    for(i=0; i<QUOTA_FILE_SIZE; i++)
        if(fwrite(block, sizeof(unsigned char), SX_BS_LARGE, file) != SX_BS_LARGE) {
            fprintf(stderr, "test_quota: ERROR: Error while writing to '%s' file. (%d)\n", local_file_path, i);
            if(fclose(file) == EOF)
                fprintf(stderr, "test_quota: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
            goto test_quota_err;
        }
    if(fclose(file) == EOF) {
        fprintf(stderr, "test_quota: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_quota_err;
    }
    src = sxc_file_local(sx, local_file_path);
    if(!src) {
        fprintf(stderr, "test_quota: ERROR: Cannot open '%s' file: %s\n", local_file_path, sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    dest = sxc_file_remote(cluster, volname, remote_path, NULL);
    if(!dest) {
        fprintf(stderr, "test_quota: ERROR: Cannot open destination directory.\n");
        goto test_quota_err;
    }
    switch(sxc_copy(src, dest, local_file_path[strlen(local_file_path) - 1] == '/', 0)) {
        case 0:
            fprintf(stderr, "test_quota: ERROR: Volume size limit not enforced.\n");
            goto test_quota_err;
        case 413:
            printf("test_quota: Volume size limit enforced correctly.\n");
            break;
        default:
            fprintf(stderr, "test_quota: ERROR: Cannot upload file: %s\n", sxc_geterrmsg(sx));
            goto test_quota_err;
    }
    if(remove_volume(sx, cluster, volname)) {
        fprintf(stderr, "test_quota: ERROR: Cannot remove '%s' volume: %s\n", volname, sxc_geterrmsg(sx));
        goto test_quota_err;
    }

    printf("test_quota: Succeeded\n");
    ret = 0;
test_quota_err:
    if(file && unlink(local_file_path)) {
        fprintf(stderr, "test_quota: ERROR: Cannot remove '%s' file: %s\n", local_file_path, strerror(errno));
        ret = 1;
    }
    free(block);
    free(volname);
    free(local_file_path);
    free(remote_path);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* test_quota */

int main(int argc, char **argv) {
    int i, fd, ret = 1;
    char *local_dir_path = NULL, *remote_dir_path = NULL, *volname = NULL, *filter_dir = NULL;
    sxc_client_t *sx = NULL;
    sxc_logger_t log;
    sxc_cluster_t *cluster = NULL;
    sxc_uri_t *uri = NULL;
    struct gengetopt_args_info args;

    if(cmdline_parser(argc, argv, &args)) {
        cmdline_parser_print_help();
        printf("\n");
        return ret;
    }
    if(!args.inputs_num) {
        cmdline_parser_print_help();
        printf("\n");
        fprintf(stderr, "main: ERROR: Wrong number of arguments.\n");
        goto main_err;
    }
    sx = sxc_init(SRC_VERSION, sxc_default_logger(&log,argv[0]), test_input_fn, NULL);
    if(!sx) {
        fprintf(stderr, "main: ERROR: Cannot initiate SX.\n");
        goto main_err;
    }
    if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
        fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
        goto main_err;
    }
    sxc_set_debug(sx, args.debug_flag);
    for(i=0; i<args.inputs_num; i++) {
        uri = sxc_parse_uri(sx, args.inputs[i]);
        if(!uri)
            fprintf(stderr, "main: ERROR: Cannot parse uri %s: %s\n", args.inputs[i], sxc_geterrmsg(sx));
        else
            break;
    }
    if(!uri) {
        fprintf(stderr, "main: ERROR: Cluster uri not specified.\n");
        goto main_err;
    }
    if(uri->volume) {
        fprintf(stderr, "main: ERROR: Volume name not expected.\n");
        goto main_err;
    }
    cluster = sxc_cluster_load_and_update(sx, uri->host, uri->profile);
    if(!cluster) {
        fprintf(stderr, "main: ERROR: Cannot load the cluster: %s\n", sxc_geterrmsg(sx));
        goto main_err;
    }
    volname = (char*)malloc(strlen(VOLNAME) + strlen("XXXXXX") + 1);
    if(!volname) {
        fprintf(stderr, "main: ERROR: Cannot allocate memory for volname.\n");
        goto main_err;
    }
    sprintf(volname, "%sXXXXXX", VOLNAME);
    fd = mkstemp(volname);
    if(fd < 0) {
        fprintf(stderr, "main: ERROR: Cannot generate temporary directory name.\n");
        goto main_err;
    }
    if(close(fd)) {
        fprintf(stderr, "main: ERROR: Cannot close file descriptor: %s\n", strerror(errno));
        goto main_err;
    }
    if(unlink(volname)) {
        fprintf(stderr, "main: ERROR: Cannot delete '%s' file: %s\n", volname, strerror(errno));
        goto main_err;
    }
    remote_dir_path = (char*)malloc(strlen("sx://") + strlen(args.owner_arg) + 1 + strlen(uri->host) + 1 + strlen(volname) + 1 + strlen(REMOTE_DIR) + 1 + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_dir_path) {
        fprintf(stderr, "main: ERROR: Cannot allocate memory for remote_dir_path.\n");
        goto main_err;
    }
    sprintf(remote_dir_path, "sx://%s@%s/%s/%s/", args.owner_arg, uri->host, volname, REMOTE_DIR);
    sxc_free_uri(uri);
    uri = sxc_parse_uri(sx, remote_dir_path);
    if(!uri) {
        fprintf(stderr, "main: ERROR: Bad uri (after manipulations) %s: %s\n", remote_dir_path, sxc_geterrmsg(sx));
        goto main_err;
    }
    local_dir_path = (char*)malloc(strlen(LOCAL_DIR) + 6 + 1 + 1); /* There is 6 X's suffix for mkdtemp() and '/' character at the end */
    if(!local_dir_path) {
        fprintf(stderr, "main: ERROR: Cannot allocate memory for local_dir_path.\n");
        goto main_err;
    }
    sprintf(local_dir_path, "%sXXXXXX", LOCAL_DIR);
    if(!mkdtemp(local_dir_path)) {
        fprintf(stderr, "main: ERROR: Cannot create new temporary directory: %s\n", local_dir_path);
        goto main_err;
    }
    strcat(local_dir_path,"/");

    if(args.filter_dir_given) {
        filter_dir = strdup(args.filter_dir_arg);
    } else {
        const char *pt = getenv("SX_FILTER_DIR");
        if(pt)
            filter_dir = strdup(pt);
    }
    if(!filter_dir) {
        fprintf(stderr, "main: ERROR: Cannot get filter directory. Use --filter-dir or 'export SX_FILTER_DIR=<src_dir>/client/src/filters/'\n");
        goto main_err;
    }
    if(!filter_dir) {
        fprintf(stderr, "main: ERROR: Failed to set filter directory.\n");
        goto main_err;
    }
    
    /* The beginning of tests */
    if(volume_test(sx, cluster, volname, filter_dir, NULL, NULL, local_dir_path, remote_dir_path, args, 1))
        goto main_err;
    if(volume_test(sx, cluster, volname, filter_dir, "aes256", NULL, local_dir_path, remote_dir_path, args, 2))
        goto main_err;
    if(volume_test(sx, cluster, volname, filter_dir, "zcomp", "level:1", local_dir_path, remote_dir_path, args, 3))
        goto main_err;
    if(volume_test(sx, cluster, volname, filter_dir, "attribs", NULL, local_dir_path, remote_dir_path, args, 4))
        goto main_err;
    if(volume_test(sx, cluster, volname, filter_dir, "undelete", TRASH_NAME, local_dir_path, remote_dir_path, args, 5))
        goto main_err;
    if(test_quota(sx, cluster, local_dir_path, remote_dir_path, args))
        goto main_err;
    /* The end of tests */

    ret = 0;
    printf("\nmain: All tests succeeded.\n");
main_err:
    if(local_dir_path && rmdir(local_dir_path)) {
        fprintf(stderr, "main: ERROR: Cannot delete '%s' directory: %s\n", local_dir_path, strerror(errno));
        ret = 1;
    }
    free(local_dir_path);
    free(remote_dir_path);
    free(volname);
    free(filter_dir);
    sxc_cluster_free(cluster);
    sxc_free_uri(uri);
    sxc_shutdown(sx,0);
    cmdline_parser_free(&args);
    return ret;
} /* main */

