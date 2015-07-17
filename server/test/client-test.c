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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <unistd.h>

#include "sx.h"
#include "libsxclient/src/clustcfg.h"
#include "libsxclient/src/volops.h"
#include "libsxclient/src/misc.h"
#include "version.h"
#include "rgen.h"
#include "client-test-cmdline.h"

#define VOLSIZE (replica*1024LL*1024LL*1024LL)
#define VOLNAME "vol" /* There will be 6 random characters suffix added. There CANNOT be '..' inside! */
#define LOCAL_DIR "/tmp/.test" /* There will be 6 random characters suffix added. */
#define REMOTE_DIR ".test"
#define EMPTY_FILE_NAME "file_empty"
#define UD_FILE_NAME "file_ud"
#define REV_FILE_NAME "file_rev" /* There will be added numbers as suffixes for revision versions */
#define ATTRIBS_COUNT 10 /* Up to 100 (there is malloc'ed space for 2 digits in file path) */
#define ATTRIBS_FILE_NAME "file_attrib"
#define TRASH_NAME "/.Trash"
#define UNDELETE_FILE_NAME "file_undelete"
#define QUOTA_FILE_NAME "file_quota"
#define QUOTA_VOL_SIZE 1
#define QUOTA_FILE_SIZE 5 /* Must be more then QUOTA_VOL_SIZE */
#define COPY_FILE_NAME "file_copy"
#define ACL_USER1 "user1" /* There will be 6 random characters suffix added. */
#define ACL_USER2 "user2" /* There will be 6 random characters suffix added. */
#define ACL_USER3 "user3" /* There will be 6 random characters suffix added. */
#define MAX_USERNAME_LEN 128
#define ACL_VOLNAME1 "vol1" /* There will be 6 random characters suffix added. */
#define ACL_VOLNAME2 "vol2" /* There will be 6 random characters suffix added. */
#define MAX_VOLNAME_LEN 128
#define ACL_FILE_NAME "file_acl"
#define ACL_KEY_FILE_NAME "file_acl_key"
#define CAT_FILE_NAME_IN "file_cat_in"
#define CAT_FILE_NAME_OUT "file_cat_out"
#define CAT_FILE_SIZE 1
#define ERRORS_FILE_NAME "file_err"

typedef struct {
    const int for_volume, no_filter, dedicated, additional;
    const uint64_t block_size, block_count;
    const char *name, *filter1_name, *filter1_cfg, *filter2_name, *filter2_cfg;

    int (*fun)(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, const uint64_t block_size, const uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size);
} client_test_t;

static int run_test(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size, const client_test_t *test) {
    if(!test->fun)
        return -1;
    return test->fun(sx, cluster, local_dir_path, remote_dir_path, profile_name, cluster_name, filter_dir, test->filter1_name, test->filter1_cfg, test->filter2_name, test->filter2_cfg, test->block_size, test->block_count, args, max_revisions, check_data_size);
}

int64_t bytes; /* FIXME: small change in libsxclient to avoid this to be global */
client_test_t tests[];

static float to_human (long long int n) {
    float h = (float)n;
    while(h >= 1024)
        h /= 1024;
    return h;
}

static char to_human_suffix (long long int n) {
    unsigned int count = 0;
    char suf[] = {'B', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'};
    while(n > 1023) {
        n /= 1024;
        count++;
    }
    return count < sizeof(suf) ? suf[count] : suf[sizeof(suf)-1];
}

static void failed_test_msg(const char *progname, const struct gengetopt_args_info *args, const client_test_t *test) {
    unsigned int i;
    fprintf(stderr, "\nFailed to run '%s' test.", test->name);
    if(!args->run_test_given) {
        fprintf(stderr, " Use:\n%s", progname);
        for(i=0; i<args->inputs_num; i++)
            fprintf(stderr, " %s", args->inputs[i]);
        if(args->owner_given)
            fprintf(stderr, " --owner=%s", args->owner_arg);
        if(args->replica_given)
            fprintf(stderr, " --replica=%d", args->replica_arg);
        if(args->all_given && args->all_flag)
            fprintf(stderr, " --all");
        if(args->human_given && args->human_flag)
            fprintf(stderr, " --human");
        if(args->config_dir_given)
            fprintf(stderr, " --config-dir=%s", args->config_dir_arg);
        if(args->filter_dir_given)
            fprintf(stderr, " --filter-dir=%s", args->filter_dir_arg);
        if(args->debug_given && args->debug_flag)
            fprintf(stderr, " --debug");
        fprintf(stderr, " --run-test=%s\n", test->name);
        fprintf(stderr, "To run only this test again.");
    }
    fprintf(stderr, "\n");
}

static int test_input_fn(sxc_client_t *sx, sxc_input_t type, const char *prompt, const char *def, char *in, unsigned int insize, void *ctx) {
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
        fprintf(stderr, "Callback failure.\n");
        return SXE_NOERROR;
    }
    if(xfer_stat->status == SXC_XFER_STATUS_PART_FINISHED || xfer_stat->status == SXC_XFER_STATUS_WAITING)
        *((int64_t*)xfer_stat->ctx) = xfer_stat->current_xfer.sent;
    return SXE_NOERROR;
}

static int randomize_name(char *name) {
    int fd;
    mode_t mask = umask(0);
    umask(077); /* shut up warnings */
    fd = mkstemp(name);
    umask(mask);
    if(fd < 0) {
        fprintf(stderr, "randomize_name: ERROR: Cannot generate temporary name.\n");
        return 1;
    }
    if(close(fd)) {
        fprintf(stderr, "randomize_name: ERROR: Cannot close '%s' file descriptor: %s\n", name, strerror(errno));
        if(unlink(name))
            fprintf(stderr, "randomize_name: ERROR: Cannot delete '%s' file: %s\n", name, strerror(errno));
        return 1;
    }
    if(unlink(name)) {
        fprintf(stderr, "randomize_name: ERROR: Cannot delete '%s' file: %s\n", name, strerror(errno));
        return 1;
    }
    return 0;
}

static int create_volume(sxc_client_t *sx, sxc_cluster_t *cluster, const char *volname, const char *owner, const char *filter_dir, const char *filter_name, const char *filter_cfg, int replica, const unsigned int max_revisions, int human_readable, const int hide_errors) {
    void *cfgdata = NULL;
    int i, fcount, filter_idx, ret = 1;
    uint8_t uuid[16];
    char *voldir = NULL, uuidcfg[41];
    unsigned int cfgdata_len = 0;
    const char *confdir;
    const sxc_filter_t *filter = NULL;
    const sxf_handle_t *filters = NULL;
    sxc_meta_t *meta = NULL, *custom_meta = NULL;

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
            fprintf(stderr, "create_volume: ERROR: Cannot wipe old volume configuration directory: %s\n", voldir);
            goto create_volume_err;
        }
        filters = sxc_filter_list(sx, &fcount);
        if(!filters) {
            fprintf(stderr, "create_volume: ERROR: No filters available.\n");
            goto create_volume_err;
        }
        meta = sxc_meta_new(sx);
        custom_meta = sxc_meta_new(sx);
        if(!meta || !custom_meta) {
            fprintf(stderr, "create_volume: ERROR: Cannot initiate meta.\n");
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
            fprintf(stderr, "create_volume: ERROR: Filter not found.\n");
            goto create_volume_err;
        }
        sxi_uuid_parse(filter->uuid, uuid);
        if(sxc_meta_setval(meta, "filterActive", uuid, 16)) {
            fprintf(stderr, "create_volume: ERROR: Metadata error.\n");
            goto create_volume_err;
        }
        snprintf(uuidcfg, sizeof(uuidcfg), "%s-cfg", filter->uuid);
        if(filter->configure) {
            char *fdir;
	    int rc = 0;
            fdir = (char*)malloc(strlen(voldir) + 1 + strlen(filter->uuid) + 1); /* The 1 inside is for '/' character. */
            if(!fdir) {
                fprintf(stderr, "create_volume: ERROR: Cannot allocate memory for fdir.\n");
                goto create_volume_err;
            }
            if(access(voldir, F_OK))
                rc = mkdir(voldir, 0700);
            sprintf(fdir, "%s/%s", voldir, filter->uuid);
            if(access(fdir, F_OK)) {
                if(rc == -1 || mkdir(fdir, 0700) == -1) {
                    fprintf(stderr, "create_volume: ERROR: Cannot create filter configuration directory: %s\n", fdir);
                    free(fdir);
                    goto create_volume_err;
                }
	    }
	    if(filter->configure(&filters[filter_idx], filter_cfg, fdir, &cfgdata, &cfgdata_len, custom_meta)) {
                fprintf(stderr, "create_volume: ERROR: Cannot configure filter.\n");
		free(fdir);
		goto create_volume_err;
	    }
	    free(fdir);
	    if(cfgdata && sxc_meta_setval(meta, uuidcfg, cfgdata, cfgdata_len)) {
                fprintf(stderr, "create_volume: ERROR: Cannot store filter configuration.\n");
		goto create_volume_err;
	    }
	}
    }
    if(sxc_volume_add(cluster, volname, VOLSIZE, replica, max_revisions, meta, owner)) {
        if(!hide_errors)
            fprintf(stderr, "create_volume: ERROR: %s\n", sxc_geterrmsg(sx));
        goto create_volume_err;
    }
    if(sxc_meta_count(custom_meta) && sxc_volume_modify(cluster, volname, NULL, -1, -1, custom_meta)) {
        fprintf(stderr, "volume_modify: ERROR: %s\n", sxc_geterrmsg(sx));
        goto create_volume_err;
    }
    if(sxi_volume_cfg_store(sx, cluster, volname, filter ? filter->uuid : NULL, cfgdata, cfgdata_len)) {
        fprintf(stderr, "create_volume: ERROR: %s\n", sxc_geterrmsg(sx));
        goto create_volume_err;
    }
    if(human_readable)
        printf("create_volume: Volume '%s' (replica: %d, size: %0.f%c) created.\n", volname, replica, to_human(VOLSIZE), to_human_suffix(VOLSIZE));
    else
        printf("create_volume: Volume '%s' (replica: %d, size: %lld) created.\n", volname, replica, (long long int)VOLSIZE);

    ret = 0;
create_volume_err:
    free(voldir);
    free(cfgdata);
    sxc_meta_free(meta);
    sxc_meta_free(custom_meta);
    return ret;
} /* create_volume */

static int remove_volume(sxc_client_t *sx, sxc_cluster_t *cluster, const char *volname, const int hide_errors) {
    int ret = 1;
    char *voldir = NULL;
    const char *confdir;

    if(sxc_volume_remove(cluster, volname)) {
        if(!hide_errors)
            fprintf(stderr, "remove_volume: ERROR: %s\n", sxc_geterrmsg(sx));
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
        fprintf(stderr, "remove_volume: ERROR: Cannot wipe volume configuration directory: %s\n", voldir);
        goto remove_volume_err;
    }

    ret = 0;
remove_volume_err:
    free(voldir);
    return ret;
} /* remove_volume */

static int upload_file(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_path, const char *remote_path, const int hide_errors) {
    int ret = 1;
    sxc_uri_t *uri;
    sxc_file_t *src, *dest = NULL;

    uri = sxc_parse_uri(sx, remote_path);
    if(!uri) {
        fprintf(stderr, "upload_file: ERROR: %s\n", sxc_geterrmsg(sx));
        return ret;
    }
    src = sxc_file_local(sx, local_path);
    if(!src) {
        fprintf(stderr, "upload_file: ERROR: Cannot open '%s': %s\n", local_path, sxc_geterrmsg(sx));
        goto upload_file_err;
    }
    dest = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!dest) {
        fprintf(stderr, "upload_file: ERROR: Cannot open '%s': %s\n", remote_path, sxc_geterrmsg(sx));
        goto upload_file_err;
    }
    if(sxc_copy(src, dest, local_path[strlen(local_path) - 1] == '/', 0, 0, NULL, 1)) {
        if(!hide_errors)
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
static FILE* download_file(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_file_path, const char *remote_file_path) {
    FILE *ret = NULL;
    sxc_uri_t *uri;
    sxc_file_t *src, *dest = NULL;
    sxc_revlist_t *revs = NULL;

    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
        fprintf(stderr, "download_file: ERROR: %s\n", sxc_geterrmsg(sx));
        return ret;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        fprintf(stderr, "download_file: ERROR: Cannot open '%s' file: %s\n", remote_file_path, sxc_geterrmsg(sx));
        goto download_file_err;
    }
    dest = sxc_file_local(sx, local_file_path);
    if(!dest) {
        fprintf(stderr, "download_file: ERROR: Cannot open '%s': %s\n", local_file_path, sxc_geterrmsg(sx));
        goto download_file_err;
    }
    if(sxc_copy(src, dest, 0, 0, 0, NULL, 1)) {
        fprintf(stderr, "download_file: ERROR: Cannot download file: %s\n", sxc_geterrmsg(sx));
        goto download_file_err;
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

static int download_files(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path) {
    int ret = 1;
    sxc_uri_t *uri;
    sxc_file_t *src, *dest = NULL;

    uri = sxc_parse_uri(sx, remote_dir_path);
    if(!uri) {
        fprintf(stderr, "download_files: ERROR: %s\n", sxc_geterrmsg(sx));
        return ret;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        fprintf(stderr, "download_files: ERROR: Cannot open '%s' directory: %s\n", remote_dir_path, sxc_geterrmsg(sx));
        goto download_files_err;
    }
    dest = sxc_file_local(sx, local_dir_path);
    if(!dest) {
        fprintf(stderr, "download_files: ERROR: Cannot open '%s' directory: %s\n", local_dir_path, sxc_geterrmsg(sx));
        goto download_files_err;
    }
    if(sxc_copy(src, dest, 1, 0, 0, NULL, 1)) {
        fprintf(stderr, "download_files: ERROR: Cannot download files: %s\n", sxc_geterrmsg(sx));
        goto download_files_err;
    }

    ret = 0;
download_files_err:
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* download_files */

static int delete_files(sxc_client_t *sx, sxc_cluster_t *cluster, const char *remote_path, const int recursive, const int hide_errors) {
    int ret = 1, n;
    char *file_name;
    sxc_uri_t *uri;
    sxc_file_t *file = NULL;
    sxc_file_list_t *lst;
    sxc_cluster_lf_t *file_list = NULL;

    uri = sxc_parse_uri(sx, remote_path);
    if(!uri) {
        fprintf(stderr, "delete_files: ERROR: %s\n", sxc_geterrmsg(sx));
        return ret;
    }
    lst = sxc_file_list_new(sx, recursive);
    if(!lst) {
        fprintf(stderr, "delete_files: ERROR: %s\n", sxc_geterrmsg(sx));
        sxc_file_free(file);
        goto delete_files_err;
    }
    if(remote_path[strlen(remote_path) - 1] == '/') {
        file_list = sxc_cluster_listfiles(cluster, uri->volume, uri->path, 0, NULL, NULL, NULL, NULL, 0);
        if(!file_list) {
            if(!hide_errors)
                fprintf(stderr, "delete_files: ERROR: Cannot get volume files list: %s\n", sxc_geterrmsg(sx));
            goto delete_files_err;
        }
        while(1) {
            n = sxc_cluster_listfiles_next(file_list, &file_name, NULL, NULL, NULL);
            if(n <= 0) {
                if(n) {
                    fprintf(stderr, "delete_files: ERROR: %s\n", sxc_geterrmsg(sx));
                    goto delete_files_err;
                }
                break;
            }
            if(!file_name) {
                fprintf(stderr, "delete_files: ERROR: NULL file name pointer received.\n");
                goto delete_files_err;
            }
            file = sxc_file_remote(cluster, uri->volume, file_name, NULL);
            if(!file) {
                fprintf(stderr, "delete_files: ERROR: Cannot open '%s%s' file: %s\n", remote_path, file_name, sxc_geterrmsg(sx));
                free(file_name);
                goto delete_files_err;
            }
            if(sxc_file_list_add(lst, file, recursive)) {
                fprintf(stderr, "delete_files: ERROR: Cannot add file list entry '%s': %s\n", file_name, sxc_geterrmsg(sx));
                sxc_file_free(file);
                free(file_name);
                goto delete_files_err;
            }
            free(file_name);
        }
    } else {
        file = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
        if(!file) {
            fprintf(stderr, "delete_files: ERROR: Cannot open '%s' directory: %s\n", remote_path, sxc_geterrmsg(sx));
            goto delete_files_err;
        }
        if(sxc_file_list_add(lst, file, recursive)) {
            fprintf(stderr, "delete_files: ERROR: Cannot add file list entry '%s': %s\n", remote_path, sxc_geterrmsg(sx));
            sxc_file_free(file);
            goto delete_files_err;
        }
    }
    if(sxc_rm(lst, 0, 0)) {
        if(!hide_errors)
            fprintf(stderr, "delete_files: ERROR: Failed to remove file list: %s\n", sxc_geterrmsg(sx));
        goto delete_files_err;
    }
    
    ret = 0;
delete_files_err:
    sxc_free_uri(uri);
/*  sxc_file_free(file); */         /* done in sx_file_list_free(lst); */
    sxc_file_list_free(lst);
    sxc_cluster_listfiles_free(file_list);
    return ret;
} /* delete_files */

/* -1 - error
 *  0 - file not found
 *  1 - file found */
static int find_file(sxc_client_t *sx, sxc_cluster_t *cluster, const char *remote_file_path, const int hide_errors) {
    int ret = -1, n;
    char *file_name = NULL;
    sxc_uri_t *uri;
    sxc_file_list_t *lst = NULL;
    sxc_cluster_lf_t *file_list;

    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
        fprintf(stderr, "find_file: ERROR: %s\n", sxc_geterrmsg(sx));
        return ret;
    }
    file_list = sxc_cluster_listfiles(cluster, uri->volume, uri->path, 0, NULL, NULL, NULL, NULL, 0);
    if(!file_list) {
        if(!hide_errors)
            fprintf(stderr, "find_file: ERROR: Cannot get volume files list: %s\n", sxc_geterrmsg(sx));
        goto find_file_err;
    }
    n = sxc_cluster_listfiles_next(file_list, &file_name, NULL, NULL, NULL);
    if(n < 0) {
        fprintf(stderr, "find_file: ERROR: %s\n", sxc_geterrmsg(sx));
        goto find_file_err;
    }
    if(n > 0 && !file_name) {
        fprintf(stderr, "find_file: ERROR: NULL file name pointer received.\n");
        goto find_file_err;
    }

    ret = n ? 1 : 0;
find_file_err:
    free(file_name);
    sxc_free_uri(uri);
    sxc_file_list_free(lst);
    sxc_cluster_listfiles_free(file_list);
    return ret;
} /* find_file */

static void create_block(rnd_state_t *state, unsigned char *block, const uint64_t block_size)
{
    uint64_t i;
    for(i=0; i<block_size; i++)
        block[i] = rand_2cmres(state);
} /* create_block */

static int create_file(const char* local_file_path, uint64_t block_size, uint64_t block_count, unsigned char sha_hash[SHA_DIGEST_LENGTH], const int force_size) {
    int ret = 1;
    uint64_t seed, i;
    unsigned char *block;
    FILE *file = NULL;
    rnd_state_t state;
    SHA_CTX ctx;

    block = (unsigned char*)malloc(block_size);
    if(!block) {
        fprintf(stderr, "create_file: ERROR: Cannot allocate memory for block.\n");
        return ret;
    }
    seed = make_seed();
    printf("create_file: Seed: %012lx\n", seed);
    rnd_seed(&state, seed);
    if(!force_size)
        switch(block_size) {
            case SX_BS_SMALL:
                if(block_count > 31)
                    fprintf(stderr, "create_file: WARNING: File size out of set block size bounds.\n");
                break;
            case SX_BS_MEDIUM:
                if(block_count < 32 || block_count > 8192)
                    fprintf(stderr, "create_file: WARNING: File size out of set block size bounds.\n");
                break;
            case SX_BS_LARGE:
                if(block_count < 129)
                    fprintf(stderr, "create_file: WARNING: File size out of set block size bounds.\n");
                break;
            default:
                fprintf(stderr, "create_file: ERROR: Unknown block size.\n");
                goto create_file_err;
        }
    create_block(&state, block, block_size);
    file = fopen(local_file_path, "wb");
    if(!file) {
        fprintf(stderr, "create_file: ERROR: Cannot create '%s' file: %s\n", local_file_path, strerror(errno));
        goto create_file_err;
    }
    if(sha_hash && !SHA1_Init(&ctx)) {
        fprintf(stderr, "create_file: ERROR: SHA1_Init() failure.\n");
        goto create_file_err;
    }
    for(i=0; i<block_count; i++) {
        if(fwrite(block, sizeof(unsigned char), block_size, file) != block_size) {
            fprintf(stderr, "create_file: ERROR: Error while writing to '%s' file. (%llu)\n", local_file_path, (unsigned long long)i);
            goto create_file_err;
        }
        if(sha_hash && !SHA1_Update(&ctx, block, block_size)) {
            fprintf(stderr, "create_file: ERROR: SHA1_Update() failure. (%llu)\n", (unsigned long long)i);
            goto create_file_err;
        }
    }
    if(sha_hash && !SHA1_Final(sha_hash, &ctx)) {
        fprintf(stderr, "create_file: ERROR: SHA1_Final() failure.\n");
        goto create_file_err;
    }
    if(fclose(file) == EOF) {
        fprintf(stderr, "create_file: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        if(unlink(local_file_path))
            fprintf(stderr, "create_file: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        file = NULL;
        goto create_file_err;
    }

    ret = 0;
create_file_err:
    free(block);
    if(ret && file) {
        if(fclose(file) == EOF)
            fprintf(stderr, "create_file: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        if(unlink(local_file_path))
            fprintf(stderr, "create_file: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
    }
    return ret;
} /* create_file */

static int test_empty_file(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int ret = 1;
    char *local_file_path, *remote_file_path = NULL;
    FILE *file = NULL;
    sxc_uri_t *uri;

    printf("test_empty_file: Started\n");
    uri = sxc_parse_uri(sx, remote_dir_path);
    if(!uri) {
        fprintf(stderr, "test_empty_file: ERROR: %s\n", sxc_geterrmsg(sx));
        return ret;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(EMPTY_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_empty_file: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_empty_file_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, EMPTY_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(EMPTY_FILE_NAME) + 1);
    if(!remote_file_path) {
        fprintf(stderr, "test_empty_file: ERROR: Cannot allocate memory for remote_file_path.\n");
        goto test_empty_file_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, EMPTY_FILE_NAME);
    file = fopen(local_file_path, "w");
    if(!file) {
        fprintf(stderr, "test_empty_file: ERROR: Cannot create '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_empty_file_err;
    }
    if(fclose(file) == EOF) {
        fprintf(stderr, "test_empty_file: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_empty_file_err;
    }
    if(upload_file(sx, cluster, local_file_path, remote_dir_path, 0)) {
        fprintf(stderr, "test_empty_file: ERROR: Cannot upload '%s' file.\n", local_file_path);
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

static int test_transfer(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int ret = 1;
    char *local_file_path = NULL, *remote_file_path = NULL;
    unsigned char *block = NULL, hash1[SHA_DIGEST_LENGTH], hash2[SHA_DIGEST_LENGTH];
    FILE *file = NULL;
    SHA_CTX ctx;
    size_t tmp;

    printf("test_transfer: Started\n");
    if(sxc_cluster_set_progress_cb(sx, cluster, test_callback, (void*)&bytes)) {
        fprintf(stderr, "test_transfer: ERROR: Cannot set callback.\n");
        return ret;
    }
    block = (unsigned char*)malloc(block_size);
    if(!block) {
        fprintf(stderr, "test_transfer: ERROR: Cannot allocate memory for block.\n");
        goto test_transfer_err;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(UD_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_transfer: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_transfer_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, UD_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(UD_FILE_NAME) + 1);
    if(!remote_file_path) {
        fprintf(stderr, "test_transfer: ERROR: Cannot allocate memory for remote_file_path.\n");
        goto test_transfer_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, UD_FILE_NAME);
    if(args->human_flag)
        printf("test_transfer: Creating file of size: %.2f%c (%llu*%.0f%c)\n", to_human(block_size*block_count), to_human_suffix(block_size*block_count), (unsigned long long)block_count, to_human(block_size), to_human_suffix(block_size));
    else
        printf("test_transfer: Creating file of size: %llu (%llu*%llu)\n", (unsigned long long)block_size*block_count, (unsigned long long)block_count, (unsigned long long)block_size);
    if(create_file(local_file_path, block_size, block_count, hash1, 0)) {
        fprintf(stderr, "test_transfer: ERROR: Cannot create '%s' file.\n", local_file_path);
        goto test_transfer_err;
    }
    printf("test_transfer: Uploading\n");
    if(upload_file(sx, cluster, local_file_path, remote_dir_path, 0)) {
        fprintf(stderr, "test_transfer: ERROR: Cannot upload '%s' file.\n", local_file_path);
        if(unlink(local_file_path))
            fprintf(stderr, "test_transfer: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_transfer_err;
    }
    if(unlink(local_file_path)) {
        fprintf(stderr, "test_transfer: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_transfer_err;
    }
    if(check_data_size && (int64_t)block_size != bytes) {
        fprintf(stderr, "test_transfer: ERROR: Uploaded wrong number of data.\n");
        goto test_transfer_err;
    }
    printf("test_transfer: Downloading\n");
    file = download_file(sx, cluster, local_file_path, remote_file_path);
    if(!file) {
        fprintf(stderr, "test_transfer: ERROR: Cannot download '%s' file.\n", remote_file_path);
        goto test_transfer_err;
    }
    if(!SHA1_Init(&ctx)) {
        fprintf(stderr, "test_transfer: ERROR: SHA1_Init() failure.\n");
        goto test_transfer_err;
    }
    while((tmp = fread(block, sizeof(unsigned char), block_size, file))) {
        if(!SHA1_Update(&ctx, block, tmp)) {
            fprintf(stderr, "test_transfer: ERROR: SHA1_Update() failure.\n");
            goto test_transfer_err;
        }
        if(tmp < block_size) {
            fprintf(stderr, "test_transfer: ERROR: Downloaded only a part of file.\n");
            goto test_transfer_err;
        }
    }
    if(!SHA1_Final(hash2, &ctx)) {
        fprintf(stderr, "test_transfer: ERROR: SHA1_Final() failure.\n");
        goto test_transfer_err;
    }
    if(memcmp(hash1, hash2, SHA_DIGEST_LENGTH)) {
        fprintf(stderr, "test_transfer: ERROR: Uploaded and downloaded file differs.\n");
        goto test_transfer_err;
    }
    
    ret = 0;
    printf("test_transfer: Succeeded\n");
test_transfer_err:
    free(block);
    if(file) {
        if(fclose(file) == EOF) {
            fprintf(stderr, "test_transfer: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
            ret = 1;
        } else if(unlink(local_file_path)) {
            fprintf(stderr, "test_transfer: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
            ret = 1;
        }
    }
    free(local_file_path);
    free(remote_file_path);
    return ret;
} /* test_transfer */

static int test_revision(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int ret = 1;
    char *local_file_path = NULL, *remote_file_path = NULL;
    unsigned char *block, hash[SHA_DIGEST_LENGTH], **hashes;
    FILE *file = NULL;
    SHA_CTX ctx;
    sxc_uri_t *uri = NULL;
    sxc_file_t *src = NULL, *dest = NULL;
    sxc_revlist_t *revs = NULL;
    unsigned int i;
    size_t tmp;

    printf("test_revision: Started (revision: %d)\n", max_revisions);
    block = (unsigned char*)malloc(block_size);
    if(!block) {
        fprintf(stderr, "test_revision: ERROR: Cannot allocate memory for block.\n");
        return ret;
    }
    hashes = (unsigned char**)calloc(max_revisions, sizeof(unsigned char*));
    if(!hashes) {
        fprintf(stderr, "test_revision: ERROR: Cannot allocate memory for hashes.\n");
        goto test_revision_err;
    }
    for(i=0; i<max_revisions; i++) {
        hashes[i] = (unsigned char*)malloc(SHA_DIGEST_LENGTH);
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
    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
        fprintf(stderr, "test_revision: ERROR: %s\n", sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(args->human_flag)
        printf("test_revision: Creating and uploading files of size: %.2f%c (%llu*%.0f%c)\n", to_human(block_size*block_count), to_human_suffix(block_size*block_count), (unsigned long long)block_count, to_human(block_size), to_human_suffix(block_size));
    else
        printf("test_revision: Creating and uploading files of size: %llu (%llu*%llu)\n", (unsigned long long)block_size*block_count, (unsigned long long)block_count, (unsigned long long)block_size);
    src = sxc_file_local(sx, local_file_path);
    if(!src) {
        fprintf(stderr, "test_revision: ERROR: Cannot open '%s': %s\n", local_file_path, sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    dest = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!dest) {
        fprintf(stderr, "test_revision: ERROR: Cannot open '%s' file: %s\n", remote_file_path, sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    for(i=0; i<max_revisions; i++) {
        if(create_file(local_file_path, block_size, block_count, hashes[max_revisions-1-i], !i)) {
            fprintf(stderr, "test_revision: ERROR: Cannot create '%s' file.\n", local_file_path);
            goto test_revision_err;
        }
        if(sxc_copy(src, dest, 0, 0, 0, NULL, 1)) {
            fprintf(stderr, "test_revision: ERROR: Cannot upload file: %s\n", sxc_geterrmsg(sx));
            goto test_revision_err;
        }
        if(unlink(local_file_path)) {
            fprintf(stderr, "test_revision: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
            goto test_revision_err;
        }
        file = NULL;
    }
    sxc_file_free(src);
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        fprintf(stderr, "test_revision: ERROR: Cannot open '%s' file: %s\n", remote_file_path, sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    revs = sxc_revisions(src);
    if(!revs) {
        fprintf(stderr, "test_revision: ERROR: %s\n", sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(max_revisions > revs->count) {
        fprintf(stderr, "test_revision: ERROR: Not enough revisions.\n");
        goto test_revision_err;
    } else if(max_revisions < revs->count) {
        fprintf(stderr, "test_revision: ERROR: Too many revisions.\n");
        goto test_revision_err;
    }
    printf("test_revision: Downloading and checking file versions.\n");
    for(i=0; i<max_revisions; i++) {
        sxc_file_free(src);
        src = sxc_file_remote(cluster, uri->volume, uri->path, revs->revisions[i]->revision);
        if(!src) {
            fprintf(stderr, "test_revision: ERROR: Cannot open '%s' (%s) file: %s\n", remote_file_path, revs->revisions[i]->revision, sxc_geterrmsg(sx));
            goto test_revision_err;
        }
        sxc_file_free(dest);
        dest = sxc_file_local(sx, local_file_path);
        if(!dest) {
            fprintf(stderr, "test_revision: ERROR: Cannot open '%s': %s\n", local_file_path, sxc_geterrmsg(sx));
            goto test_revision_err;
        }
        if(sxc_copy_sxfile(src, dest, 1)) {
            fprintf(stderr, "test_revision: ERROR: Cannot download '%s' file: %s\n", remote_file_path, sxc_geterrmsg(sx));
            goto test_revision_err;
        }
        file = fopen(local_file_path, "rb");
        if(!file) {
            fprintf(stderr, "test_revision: ERROR: Cannot open '%s' file.\n", remote_file_path);
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
        file = NULL;
        if(!SHA1_Final(hash, &ctx)) {
            fprintf(stderr, "test_revision: ERROR: SHA1_Final() failure while downloading file. (%d)\n", i);
            goto test_revision_err;
        }
        if(memcmp(hash, hashes[i], SHA_DIGEST_LENGTH)) {
            fprintf(stderr, "test_revision: ERROR: Uploaded and downloaded file differs. (%d)\n", i);
            goto test_revision_err;
        }
    }
    sxc_file_free(src);
    src = sxc_file_remote(cluster, uri->volume, uri->path, revs->revisions[max_revisions/2]->revision);
    if(!src) {
        fprintf(stderr, "test_revision: ERROR: Cannot open '%s' (%s) file: %s\n", remote_file_path, revs->revisions[i]->revision, sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(sxc_remove_sxfile(src)) {
        fprintf(stderr, "test_revision: ERROR: Cannot remove '%s' (%s) file: %s\n", remote_file_path, revs->revisions[max_revisions/2]->revision, sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(sxc_copy_sxfile(src, dest, 1)) {
        if(sxc_geterrnum(sx) == SXE_ECOMM)
            printf("test_revision: File revision removed correctly.\n");
        else {
            fprintf(stderr, "test_revision: ERROR: Cannot download '%s' file: %s\n", remote_file_path, sxc_geterrmsg(sx));
            goto test_revision_err;
        }
    } else {
        fprintf(stderr, "test_revision: ERROR: Nonexistent file revision has been downloaded.\n");
        goto test_revision_err;
    }
    if(delete_files(sx, cluster, remote_file_path, 0, 0)) {
        fprintf(stderr, "test_revision: ERROR: Cannot delete '%s' file.\n", remote_file_path);
        goto test_revision_err;
    }
    switch(find_file(sx, cluster, remote_file_path, 0)) {
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
    free(block);
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    sxc_revisions_free(revs);
    return ret;
} /* test_revision */

static int test_cat(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int fd = 0, ret = 1, tmp;
    char *local_file_path = NULL, *cat_file_path = NULL, *remote_file_path = NULL;
    unsigned char *block = NULL, hash_in[SHA_DIGEST_LENGTH], hash_out[SHA_DIGEST_LENGTH];
    FILE *file = NULL;
    sxc_uri_t *uri = NULL;
    sxc_file_t *src = NULL;
    SHA_CTX ctx;

    printf("test_cat: Started\n");
    block = (unsigned char*)malloc(SX_BS_LARGE);
    if(!block) {
        fprintf(stderr, "test_cat: ERROR: Cannot allocate memory for block.\n");
        return ret;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(CAT_FILE_NAME_IN) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_cat: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_cat_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, CAT_FILE_NAME_IN);
    cat_file_path = (char*)malloc(strlen(local_dir_path) + strlen(CAT_FILE_NAME_OUT) + 1);
    if(!cat_file_path) {
        fprintf(stderr, "test_cat: ERROR: Cannot allocate memory for cat_file_path.\n");
        goto test_cat_err;
    }
    sprintf(cat_file_path, "%s%s", local_dir_path, CAT_FILE_NAME_OUT);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(CAT_FILE_NAME_IN) + 1);
    if(!remote_file_path) {
        fprintf(stderr, "test_cat: ERROR: Cannot allocate memory for remote_file_path.\n");
        goto test_cat_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, CAT_FILE_NAME_IN);
    if(create_file(local_file_path, SX_BS_LARGE, CAT_FILE_SIZE, hash_in, 1)) {
        fprintf(stderr, "test_cat: ERROR: Cannot create new file.\n");
        goto test_cat_err;
    }
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 0)) {
        fprintf(stderr, "test_cat: ERROR: Cannot upload '%s' file.\n", local_file_path);
        if(unlink(local_file_path))
            fprintf(stderr, "test_cat: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_cat_err;
    }
    if(unlink(local_file_path)) {
        fprintf(stderr, "test_cat: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_cat_err;
    }
    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
	fprintf(stderr, "test_cat: ERROR: %s\n", sxc_geterrmsg(sx));
        goto test_cat_err;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        fprintf(stderr, "test_cat: ERROR: Cannot open '%s' file: %s\n", remote_file_path, sxc_geterrmsg(sx));
        goto test_cat_err;
    }
    fd = open(cat_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(fd < 0) {
        fprintf(stderr, "test_cat: ERROR: Cannot create new file.\n");
        goto test_cat_err;
    }
    printf("test_cat: Processing the file.\n"); /* It shows (on stdout) that program works */
    if(sxc_cat(src, fd)) {
        fprintf(stderr, "test_cat: ERROR: %s\n", sxc_geterrmsg(sx));
        goto test_cat_err;
    }
    file = fopen(cat_file_path, "rb");
    if(!file) {
        fprintf(stderr, "test_cat: ERROR: Cannot open '%s' file: %s\n", cat_file_path, strerror(errno));
        goto test_cat_err;
    }
    if(!SHA1_Init(&ctx)) {
        fprintf(stderr, "test_cat: ERROR: SHA1_Init() failure.\n");
        if(fclose(file))
            fprintf(stderr, "test_cat: ERROR: Cannot close '%s' file: %s\n", cat_file_path, strerror(errno));
        goto test_cat_err;
    }
    while((tmp = fread(block, sizeof(unsigned char), SX_BS_LARGE, file))) {
        if(!SHA1_Update(&ctx, block, tmp)) {
            fprintf(stderr, "test_cat: ERROR: SHA1_Update() failure.\n");
            if(fclose(file))
                fprintf(stderr, "test_cat: ERROR: Cannot close '%s' file: %s\n", cat_file_path, strerror(errno));
            goto test_cat_err;
        }
        if(tmp < SX_BS_LARGE) {
            if(fclose(file))
                fprintf(stderr, "test_cat: ERROR: Cannot close '%s' file: %s\n", cat_file_path, strerror(errno));
            fclose(file);
            goto test_cat_err;
        }
    }
    if(fclose(file))
        fprintf(stderr, "test_cat: ERROR: Cannot close '%s' file: %s\n", cat_file_path, strerror(errno));
    if(!SHA1_Final(hash_out, &ctx)) {
        fprintf(stderr, "test_cat_file: ERROR: SHA1_Final() failure.\n");
        goto test_cat_err;
    }
    if(memcmp(hash_in, hash_out, SHA_DIGEST_LENGTH)) {
        fprintf(stderr, "test_cat: ERROR: File from cat differs.\n");
        goto test_cat_err;
    }
    printf("test_cat: Succeeded\n");

    ret = 0;
test_cat_err:
    if(fd && close(fd)) {
        fprintf(stderr, "test_cat: ERROR: Cannot close '%s' file: %s\n", cat_file_path, strerror(errno));
        ret = 1;
    }
    if(file && unlink(cat_file_path)) {
        fprintf(stderr, "test_cat: ERROR: Cannot delete '%s' file: %s\n", cat_file_path, strerror(errno));
        ret = 1;
    }
    free(block);
    free(local_file_path);
    free(cat_file_path);
    free(remote_file_path);
    sxc_free_uri(uri);
    sxc_file_free(src);
    return ret;
} /* test_cat */

static int test_errors(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int ret = 1;
    char *local_file_path, *remote_file_path = NULL, *wrong_name = NULL, revision[]="2014-13-32 25:61:69.460:ac6ed3c7a371107a763da500c165c37c"; /* Revision is made of impossible date + md5sum of /dev/urandom */
    FILE *file = NULL;
    sxc_uri_t *uri = NULL;
    sxc_file_t *src = NULL, *dest = NULL;
    sxc_cluster_t *cl_tmp;

    printf("test_errors: Started\n");
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(ERRORS_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_errors: ERROR: Cannot allocate memory for local_file_path.\n");
        return ret;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, ERRORS_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + 1 + strlen(ERRORS_FILE_NAME) + 6 + 1); /* The 1's inside are for '@' and '/' characters + "XXXXXX" part */
    if(!remote_file_path) {
        fprintf(stderr, "test_errors: ERROR: Cannot allocate memory for remote_file_path.\n");
        goto test_errors_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, ERRORS_FILE_NAME);
    file = fopen(local_file_path, "w");
    if(!file) {
        fprintf(stderr, "test_errors: ERROR: Cannot create '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_errors_err;
    }
    if(fclose(file) == EOF) {
        fprintf(stderr, "test_errors: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_errors_err;
    }
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 0)) {
        fprintf(stderr, "test_errors: ERROR: Cannot upload '%s' file.\n", local_file_path);
        goto test_errors_err;
    }
    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
	fprintf(stderr, "test_errors: ERROR: %s\n", sxc_geterrmsg(sx));
        goto test_errors_err;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, revision);
    if(!src) {
        fprintf(stderr, "test_errors: ERROR: Cannot open '%s' file: %s\n", remote_file_path, sxc_geterrmsg(sx));
        goto test_errors_err;
    }
    dest = sxc_file_local(sx, local_file_path);
    if(!dest) {
        fprintf(stderr, "test_errors: ERROR: Cannot open '%s' file: %s.\n", local_file_path, sxc_geterrmsg(sx));
        goto test_errors_err;
    }
    if(sxc_copy_sxfile(src, dest, 1)) {
        if(sxc_geterrnum(sx) == SXE_ECOMM)
            printf("test_errors: 'Failed to download file content hashes' enforced correctly.\n");
        else {
            fprintf(stderr, "test_errors: ERROR: Cannot download '%s' file: %s\n", remote_file_path, sxc_geterrmsg(sx));
            goto test_errors_err;
        }
    } else {
        fprintf(stderr, "test_errors: ERROR: Nonexistent file revision has been downloaded.\n");
        goto test_errors_err;
    }
    if(delete_files(sx, cluster, remote_file_path, 0, 0)) {
        fprintf(stderr, "test_errors: ERROR: Cannot delete '%s' file.\n", remote_file_path);
        goto test_errors_err;
    }
    sxc_file_free(src);
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        fprintf(stderr, "test_errors: ERROR: Cannot open '%s' file: %s\n", remote_file_path, sxc_geterrmsg(sx));
        goto test_errors_err;
    }
    if(sxc_cat(src, STDOUT_FILENO)) {
        if(sxc_geterrnum(sx) == SXE_ECOMM)
            printf("test_errors: 'Failed to locate volume' enforced correctly.\n");
        else {
            fprintf(stderr, "test_errors: ERROR: %s\n", sxc_geterrmsg(sx));
            goto test_errors_err;
        }
    } else {
        fprintf(stderr, "test_errors: ERROR: File has been shown from nonexistent volume.\n");
        goto test_errors_err;
    }
    wrong_name = (char*)malloc(strlen(uri->host) + strlen(uri->volume) + strlen("XXXXXX") + 1);
    if(!wrong_name) {
        fprintf(stderr, "test_errors: ERROR: Cannot allocate memory for wrong_name.\n");
        goto test_errors_err;
    }
    sprintf(wrong_name, "%sXXXXXXX", uri->host);
    if(randomize_name(wrong_name))
        goto test_errors_err;
    cl_tmp = sxc_cluster_load_and_update(sx, wrong_name, NULL);
    if(!cl_tmp) {
        if(sxc_geterrnum(sx) == SXE_ECFG)
            printf("test_errors: 'Cannot stat configuration directory' enforced correctly.\n");
        else {
            fprintf(stderr, "test_errors: ERROR: Cannot load cluster: %s\n", sxc_geterrmsg(sx));
            goto test_errors_err;
        }
    } else {
        fprintf(stderr, "test_errors: ERROR: Loaded nonexistent cluster.\n");
        sxc_cluster_free(cl_tmp);
        goto test_errors_err;
    }
    sprintf(wrong_name, "%sXXXXXXX", uri->volume);
    if(randomize_name(wrong_name))
        goto test_errors_err;
    sprintf(remote_file_path, "sx://%s%s%s/%s/", uri->profile ? uri->profile : "", uri->profile ? "@" : "", uri->host, wrong_name);
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 1)) {
        if(sxc_geterrnum(sx) == SXE_ECOMM)
            printf("test_errors: 'No such volume' enforced correctly.\n");
        else {
            fprintf(stderr, "test_errors: ERROR: Cannot upload '%s' file.\n", local_file_path);
            goto test_errors_err;
        }
    } else {
        fprintf(stderr, "test_errors: ERROR: File has been copied to nonexistent volume.\n");
        goto test_errors_err;
    }
    if(unlink(local_file_path)) {
        fprintf(stderr, "test_errors: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        file = NULL;
        goto test_errors_err;
    }
    file = NULL;
    sprintf(remote_file_path, "%s%s", remote_dir_path, ERRORS_FILE_NAME);
    if(upload_file(sx, cluster, local_file_path, remote_dir_path, 1)) {
        if(sxc_geterrnum(sx) == SXE_EREAD)
            printf("test_errors: 'No such file or directory' enforced correctly.\n");
        else {
            fprintf(stderr, "test_errors: ERROR: Cannot upload '%s' file.\n", local_file_path);
            goto test_errors_err;
        }
    } else {
        fprintf(stderr, "test_errors: ERROR: Copied nonexistent file.\n");
        goto test_errors_err;
    }
    if(sxc_volume_remove(cluster, wrong_name)) {
        if(sxc_geterrnum(sx) == SXE_ECOMM)
            printf("test_errors: 'Failed to locate volume' enforced correctly.\n");
        else {
            fprintf(stderr, "test_errors: ERROR: %s\n", sxc_geterrmsg(sx));
            goto test_errors_err;
        }
    } else {
        fprintf(stderr, "test_errors: ERROR: Nonexistent volume has been removed.\n");
        goto test_errors_err;
    }

    printf("test_errors: Succeeded\n");
    ret = 0;
test_errors_err:
    if(file && unlink(local_file_path)) {
        fprintf(stderr, "test_errors: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        ret = 1;
    }
    free(wrong_name);
    free(local_file_path);
    free(remote_file_path);
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* test_errors */

static int test_attribs(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
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
    rnd_seed(&state, seed);
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
        owner = (rand_2cmres(&state)%8) | 4;
        group = rand_2cmres(&state)%8;
        other = rand_2cmres(&state)%8;
        printf("test_attribs: rights being tested: %c%c%c%c%c%c%c%c%c\n", owner&4 ? 'r' : '-', owner&2 ? 'w' : '-', owner&1 ? 'x' : '-', group&4 ? 'r' : '-', group&2 ? 'w' : '-', group&1 ? 'x' : '-', other&4 ? 'r' : '-', other&2 ? 'w':'-', other&1 ? 'x' : '-');
        attribs = (owner<<6) | (group<<3) | other;
        if(chmod(local_files_paths[i], attribs)) {
            fprintf(stderr, "test_attribs: ERROR: Cannot set attributes for '%s' file: %s\n", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
        }
        if(gettimeofday(&tv, NULL)) {
            fprintf(stderr, "test_attribs: ERROR: Cannot get current time: %s\n", strerror(errno));
            goto test_attribs_err;
        }
        tmp_time = (long int)rand_2cmres(&state) % 100000000;
        if((owner + group + other)&1)
            tmp_time *= -1;
        time.actime = 0;
        time.modtime = tv.tv_sec + tmp_time;
        if(utime(local_files_paths[i], &time)) {
            fprintf(stderr, "test_attribs: ERROR: Cannot set modification time for '%s' file: %s\n", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
        }
        if(stat(local_files_paths[i], &t_st[i]) == -1) {
            fprintf(stderr, "test_attribs: ERROR: stat() failed for '%s': %s\n", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
	}
    }
    if(upload_file(sx, cluster, local_dir_path, remote_dir_path, 0)) {
        fprintf(stderr, "test_attribs: ERROR: Cannot upload files from '%s'.\n", local_dir_path);
        goto test_attribs_err;
    }
    for(i=0; i<ATTRIBS_COUNT; i++) {
       files[i] = NULL;
       if(unlink(local_files_paths[i])) {
            fprintf(stderr, "test_attribs: ERROR: Cannot delete '%s' file: %s\n", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
       }
    }
    if(download_files(sx, cluster, local_dir_path, remote_dir_path)) {
        fprintf(stderr, "test_attribs: ERROR: Cannot download files from '%s'.\n", remote_dir_path);
        goto test_attribs_err;
    }
    memset(files, 1, sizeof(files));
    for(i=0; i<ATTRIBS_COUNT; i++) {
        if(stat(local_files_paths[i], &st) == -1) {
            fprintf(stderr, "test_attribs: ERROR: stat() failed for '%s': %s\n", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
	}
        if(st.st_mode != t_st[i].st_mode) {
            fprintf(stderr, "test_attribs: ERROR: File attributes differ.\n");
            goto test_attribs_err;
        }
        if(st.st_mtime != t_st[i].st_mtime) {
            fprintf(stderr, "test_attribs: ERROR: File modification time differs.\n");
            goto test_attribs_err;
        }
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

static int test_undelete(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int ret = 1;
    char *local_file_path, *remote_file_path = NULL;
    FILE *file = NULL;
    sxc_uri_t *uri;

    printf("test_undelete: Started\n");
    uri = sxc_parse_uri(sx, remote_dir_path);
    if(!uri) {
        fprintf(stderr, "test_undelete: ERROR: %s\n", sxc_geterrmsg(sx));
        return ret;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(UNDELETE_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_undelete: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_undelete_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, UNDELETE_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(TRASH_NAME) + strlen(UNDELETE_FILE_NAME) + 1);
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
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 0)) {
        fprintf(stderr, "test_undelete: ERROR: Cannot upload '%s' file.\n", local_file_path);
        goto test_undelete_err;
    }
    if(delete_files(sx, cluster, remote_file_path, 0, 0)) {
        fprintf(stderr, "test_undelete: ERROR: Cannot delete '%s' file.\n", remote_file_path);
        goto test_undelete_err;
    }
    sprintf(remote_file_path, "sx://%s%s%s/%s%s/%s/%s", uri->profile ? uri->profile : "", uri->profile ? "@" : "", uri->host, uri->volume, TRASH_NAME, REMOTE_DIR, UNDELETE_FILE_NAME);
    switch(find_file(sx, cluster, remote_file_path, 0)) {
        case -1:
            fprintf(stderr, "test_undelete: ERROR: Looking for '%s' file in %s failed.\n", UNDELETE_FILE_NAME, remote_file_path);
            goto test_undelete_err;
        case 0:
            fprintf(stderr, "test_undelete: ERROR: '%s' file has not been deleted correctly.\n", UNDELETE_FILE_NAME);
            goto test_undelete_err;
        case 1: break;
    }

    printf("test_undelete: Succeeded\n");
    ret = 0;
test_undelete_err:
    if(file && unlink(local_file_path)) {
        fprintf(stderr, "test_undelete: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        ret = 1;
    }
    free(local_file_path);
    free(remote_file_path);
    sxc_free_uri(uri);
    return ret;
} /* test_undelete */

static int volume_test(const char *progname, sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const sxc_uri_t *uri, const char *filter_dir, const struct gengetopt_args_info *args, const char *filter_name, const char *filter_cfg, const int max_revisions) {
    int i, ret = 1, test = 0, check_data_size;
    char *volname, *remote_dir_path = NULL;

    volname = (char*)malloc(sizeof(VOLNAME) + 1 + (filter_name ? strlen(filter_name) : strlen("NonFilter")) + 1 + strlen("XXXXXX") + 1);
    if(!volname) {
        fprintf(stderr, "volume_test: ERROR: Cannot allocate memory for volname.\n");
        return 1;
    }
    sprintf(volname, "%s_%s_XXXXXX", VOLNAME, filter_name ? filter_name : "NonFilter");
    if(randomize_name(volname))
        goto volume_test_err;
    remote_dir_path = (char*)malloc(strlen("sx://") + (uri->profile ? strlen(uri->profile) + 1 : 0) + strlen(uri->host) + 1 + strlen(volname) + 1 + strlen(REMOTE_DIR) + 1 + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_dir_path) {
        fprintf(stderr, "volume_test: ERROR: Cannot allocate memory for remote_dir_path.\n");
        goto volume_test_err;
    }
    sprintf(remote_dir_path, "sx://%s%s%s/%s/%s/", uri->profile ? uri->profile : "", uri->profile ? "@" : "", uri->host, volname, REMOTE_DIR);
    for(i=0; tests[i].name; i++) {
        if(tests[i].for_volume && (args->run_test_given ? !strcmp(args->run_test_arg, tests[i].name) : (tests[i].additional ? args->all_flag : 1))) {
            if(tests[i].dedicated) {
                if(filter_name && !strcmp(filter_name, tests[i].name))
                    test = 1;
            } else {
                if(!tests[i].no_filter || !filter_name)
                    test = 1;
            }
        }
    }
    if(!test) {
        ret = 0;
        goto volume_test_err;
    }
    if(filter_name && (!strcmp(filter_name, "zcomp") || !strcmp(filter_name, "aes256")))
        check_data_size = 0;
    else
        check_data_size = 1;
    printf("\nVolume test - filter: %s; filter configuration: %s\n", filter_name ? filter_name : "<no filter>", filter_cfg ? filter_cfg : "<none>");
    if(create_volume(sx, cluster, volname, args->owner_arg, filter_dir, filter_name, filter_cfg, args->replica_arg, max_revisions, args->human_flag, 0)) {
        fprintf(stderr, "volume_test: ERROR: Cannot create new volume.\n");
        goto volume_test_err;
    }
    for(i=0; tests[i].name; i++) {
        if(tests[i].for_volume && (args->run_test_given ? !strcmp(args->run_test_arg, tests[i].name) : (tests[i].additional ? args->all_flag : 1))) {
            if(tests[i].dedicated) {
                if(filter_name && !strcmp(filter_name, tests[i].name) && run_test(sx, cluster, local_dir_path, remote_dir_path, uri->profile, uri->host, filter_dir, args, max_revisions, check_data_size, &tests[i])) {
                    failed_test_msg(progname, args, &tests[i]);
                    goto volume_test_err;
                }
            } else if((!tests[i].no_filter || !filter_name) && run_test(sx, cluster, local_dir_path, remote_dir_path, uri->profile, uri->host, filter_dir, args, max_revisions, check_data_size, &tests[i])) {
                failed_test_msg(progname, args, &tests[i]);
                goto volume_test_err;
            }
        }
    }
    if(delete_files(sx, cluster, remote_dir_path, 1, 0)) {
        fprintf(stderr, "volume_test: ERROR: Cannot delete files from '%s'.\n", remote_dir_path);
        goto volume_test_err;
    }
    if(filter_name && !strcmp(filter_name, "undelete")) {
        char *trash_path;
        trash_path = (char*)malloc(strlen(remote_dir_path) + strlen(filter_cfg) + 1 + 1);
        if(!trash_path) {
            fprintf(stderr, "volume_test: ERROR: Cannot allocate memory for trash_path.\n");
            goto volume_test_err;
        }
        sprintf(trash_path, "sx://%s%s%s/%s%s/%s/", uri->profile ? uri->profile : "", uri->profile ? "@" : "", uri->host, volname, filter_cfg, REMOTE_DIR);
        if(delete_files(sx, cluster, trash_path, 0, 0)) {
            fprintf(stderr, "volume_test: ERROR: Cannot delete files from '%s'.\n", trash_path);
            free(trash_path);
            goto volume_test_err;
        }
        free(trash_path);
    }
    if(remove_volume(sx, cluster, volname, 0)) {
        fprintf(stderr, "volume_test: ERROR: Cannot remove '%s' volume.\n", volname);
        goto volume_test_err;
    }

    ret = 0;
volume_test_err:
    free(volname);
    free(remote_dir_path);
    return ret;
} /* volume_test */

struct user_data {
    char username[MAX_USERNAME_LEN+1];
    int admin;
    char *key;
};

static void user_data_free(struct user_data *udata) {
    if(!udata)
        return;
    free(udata->key);
    udata->key = NULL;
    *udata->username = '\0';
}

/* Prepare users for testing */
static int prepare_users(const char *test_name, sxc_client_t *sx, sxc_cluster_t *cluster, struct user_data *udata, unsigned int count) {
    int ret = -1;
    unsigned int i;
    if(!sx || !cluster || !test_name || !udata || !count) {
        fprintf(stderr, "%s: ERROR: Cannot prepare test: Invalid argument.\n", test_name);
        return ret;
    }

    for(i = 0; i < count; i++) {
        /* Create first user */
        sprintf(udata[i].username, "user_XXXXXX");
        if(randomize_name(udata[i].username))
            goto prepare_users_err;
        udata[i].key = sxc_user_add(cluster, udata[i].username, NULL, udata[i].admin, NULL, NULL, 1, 0);
        if(!udata[i].key) {
            fprintf(stderr, "%s: ERROR: Cannot create '%s' user: %s\n", test_name, udata[i].username, sxc_geterrmsg(sx));
            goto prepare_users_err;
        }
        if(sxc_cluster_add_access(cluster, udata[i].username, udata[i].key)) {
            fprintf(stderr, "%s: ERROR: Failed to add '%s' profile authentication: %s\n", test_name, udata[i].username, sxc_geterrmsg(sx));
            goto prepare_users_err;
        }
    }

    ret = 0;
prepare_users_err:
    if(ret) {
        for(; i < count; i++)
            user_data_free(&udata[i]);
    }
    return ret;
}

/* Cleanup users created using prepare_users() */
static void cleanup_users(const char *test_name, sxc_client_t *sx, sxc_cluster_t *cluster, struct user_data *udata, unsigned int count) {
    unsigned int i;
    if(!test_name || !sx || !cluster || !udata || !count) {
        fprintf(stderr, "%s: ERROR: Failed to cleanup users: Invalid argument\n", test_name);
        return;
    }

    for(i = 0; i < count; i++) {
        /* Delete user */
        if(*udata[i].username && sxc_user_remove(cluster, udata[i].username, 0))
            fprintf(stderr, "%s: WARNING: Failed to cleanup user %s\n", test_name, udata[i].username);
        user_data_free(&udata[i]);
    }
}

struct vol_data {
    char name[MAX_VOLNAME_LEN+1];
    const char *owner;
    unsigned int replica;
    unsigned int revisons;
    const char *filter_name;
};

/* Prepare volumes for testing */
static int prepare_volumes(const char *test_name, sxc_client_t *sx, sxc_cluster_t *cluster, struct vol_data *vdata, unsigned int count, const char *filter_dir, const char *filter_cfg, int human_readable, int hide_errors) {
    int ret = -1;
    unsigned int i;

    if(!sx || !cluster || !test_name || !vdata || !count) {
        fprintf(stderr, "%s: ERROR: Cannot prepare test: Invalid argument.\n", test_name);
        return ret;
    }

    for(i = 0; i < count; i++) {
        sprintf(vdata[i].name, "%s_NonFilter_XXXXXX", VOLNAME);
        if(randomize_name(vdata[i].name))
            goto prepare_volumes_err;
        if(create_volume(sx, cluster, vdata[i].name, vdata[i].owner ? vdata[i].owner : "admin", filter_dir, vdata[i].filter_name, filter_cfg, vdata[i].replica ? vdata[i].replica : 1, vdata[i].revisons ? vdata[i].revisons : 1, human_readable, hide_errors)) {
            fprintf(stderr, "%s: ERROR: Cannot create volume %s: %s\n", test_name, vdata[i].name, sxc_geterrmsg(sx));
            goto prepare_volumes_err;
        }
    }

    ret = 0;
prepare_volumes_err:
    if(ret) {
        for(; i < count; i++)
            *vdata[i].name = '\0';
    }
    return ret;
}

/* Cleanup volumes created with prepare_volumes() */
static void cleanup_volumes(const char *test_name, sxc_client_t *sx, sxc_cluster_t *cluster, struct vol_data *vdata, unsigned int count) {
    unsigned int i;

    for(i = 0; i < count; i++) {
        if(*vdata[i].name && remove_volume(sx, cluster, vdata[i].name, 1))
            fprintf(stderr, "%s: WARNING: Failed to cleanup volume %s: %s\n", test_name, vdata[i].name, sxc_geterrmsg(sx));
    }
}

/* Compare meta data, return 0 if they are the same, 1 if different, -1 on error */
static int cmp_meta(const char *test_name, sxc_client_t *sx, sxc_meta_t *a, sxc_meta_t *b, int hide_errors) {
    unsigned int i, count;
    if(!test_name || !sx || !a || !b) {
        fprintf(stderr, "%s: ERROR: Invalid argument\n", test_name);
        return -1;
    }
    count = sxc_meta_count(a);

    /* Compare sizes first */
    if(count != sxc_meta_count(b)) {
        if(!hide_errors)
            fprintf(stderr, "%s: ERROR: Different meta sizes: %d != %d\n", test_name, count, sxc_meta_count(b));
        return 1;
    }

    for(i = 0; i < count; i++) {
        const char *metakey;
        const void *metavalue1, *metavalue2;
        unsigned int metavalue1_len, metavalue2_len;

        /* Get the first entry */
        if(sxc_meta_getkeyval(a, i, &metakey, &metavalue1, &metavalue1_len)) {
            if(!hide_errors)
                fprintf(stderr, "%s: ERROR: Failed to read meta entry\n", test_name);
            return 1;
        }

        if(!metakey) {
            if(!hide_errors)
                fprintf(stderr, "%s: ERROR: Invalid meta key\n", test_name);
            return 1;
        }

        if(sxc_meta_getval(b, metakey, &metavalue2, &metavalue2_len)) {
            if(!hide_errors)
                fprintf(stderr, "%s: ERROR: Failed to get meta key from reference meta\n", test_name);
            return 1;
        }

        /* Check if the entry is the same as expected */
        if(!metavalue1 || !metavalue2 || metavalue1_len != metavalue2_len || memcmp(metavalue1, metavalue2, metavalue1_len)) {
            if(!hide_errors)
                fprintf(stderr, "%s: ERROR: Different meta values for meta key '%s'\n", test_name, metakey);
            return 1;
        }
    }

    return 0;
}

static int test_volmeta(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int ret = -1;
    sxc_meta_t *custom_meta = NULL, *custom_meta_remote = NULL;
    sxc_file_t *file = NULL;
    struct user_data udata[3];
    struct vol_data vdata[1];

    memset(udata, 0, sizeof(udata));
    memset(vdata, 0, sizeof(vdata));
    udata[2].admin = 1;

    /* Create 1 user */
    if(prepare_users(__FUNCTION__, sx, cluster, udata, sizeof(udata) / sizeof(*udata))) {
        fprintf(stderr, "%s: ERROR: Failed to prepare users\n", __FUNCTION__);
        goto test_volmeta_err;
    }

    vdata[0].owner = udata[0].username;
    /* Create 1 volume owned by user1 */
    if(prepare_volumes(__FUNCTION__, sx, cluster, vdata, sizeof(vdata) / sizeof(*vdata), NULL, NULL, 0, 1)) {
        fprintf(stderr, "%s: ERROR: Failed to prepare volumes\n", __FUNCTION__);
        goto test_volmeta_err;
    }

    /* Actual test begins here */

    /* Create remote file structure instance to pass it to sxc_custom_volumemeta_new() */
    file = sxc_file_remote(cluster, vdata[0].name, NULL, NULL);
    if(!file) {
        fprintf(stderr, "%s: ERROR: Failed to initialize remote file structure\n", __FUNCTION__);
        goto test_volmeta_err;
    }

    /* Create custom meta buffer */
    custom_meta = sxc_meta_new(sx);
    if(!custom_meta) {
        fprintf(stderr, "%s: ERROR: Failed to create volume %s custom meta: %s\n", __FUNCTION__, vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    custom_meta_remote = sxc_custom_volumemeta_new(file);
    if(!custom_meta_remote) {
        fprintf(stderr, "%s: ERROR: Failed to get volume %s custom meta: %s\n", __FUNCTION__, vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Compare local and remote meta */
    if(cmp_meta(__FUNCTION__, sx, custom_meta, custom_meta_remote, 0))
        goto test_volmeta_err;

    /* Add new custom meta value */
    if(sxc_meta_setval(custom_meta, "1", "123", 3)) {
        fprintf(stderr, "%s: ERROR: Failed to modify meta\n", __FUNCTION__);
        goto test_volmeta_err;
    }

    /* Modify the volume */
    if(sxc_volume_modify(cluster, vdata[0].name, NULL, -1, -1, custom_meta)) {
        fprintf(stderr, "%s: ERROR: Failed to modify meta\n", __FUNCTION__);
        goto test_volmeta_err;
    }

    /* Get custom meta again */
    sxc_meta_free(custom_meta_remote);
    custom_meta_remote = sxc_custom_volumemeta_new(file);
    if(!custom_meta_remote) {
        fprintf(stderr, "%s: ERROR: Failed to get volume %s custom meta: %s\n", __FUNCTION__, vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Compare local and remote meta */
    if(cmp_meta(__FUNCTION__, sx, custom_meta, custom_meta_remote, 0))
        goto test_volmeta_err;

    /* Switch to the volume owner account */
    if(sxc_cluster_set_access(cluster, udata[0].username)) {
        fprintf(stderr, "%s: ERROR: Failed to set '%s' profile authentication: %s\n", __FUNCTION__, udata[0].username, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Add new custom meta value */
    if(sxc_meta_setval(custom_meta, "2", "22222222", 8)) {
        fprintf(stderr, "%s: ERROR: Failed to modify meta\n", __FUNCTION__);
        goto test_volmeta_err;
    }

    /* Modify the volume as a volume owner */
    if(sxc_volume_modify(cluster, vdata[0].name, NULL, -1, -1, custom_meta)) {
        fprintf(stderr, "%s: ERROR: Failed to modify meta\n", __FUNCTION__);
        goto test_volmeta_err;
    }

    /* Get remote custom meta */
    sxc_meta_free(custom_meta_remote);
    custom_meta_remote = sxc_custom_volumemeta_new(file);
    if(!custom_meta_remote) {
        fprintf(stderr, "%s: ERROR: Failed to get volume %s custom meta: %s\n", __FUNCTION__, vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Compare local and remote meta */
    if(cmp_meta(__FUNCTION__, sx, custom_meta, custom_meta_remote, 0))
        goto test_volmeta_err;

    /* Switch to the second user account */
    if(sxc_cluster_set_access(cluster, udata[1].username)) {
        fprintf(stderr, "%s: ERROR: Failed to set '%s' profile authentication: %s\n", __FUNCTION__, udata[1].username, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Add new custom meta value */
    if(sxc_meta_setval(custom_meta, "3", "A", 1)) {
        fprintf(stderr, "%s: ERROR: Failed to modify meta\n", __FUNCTION__);
        goto test_volmeta_err;
    }

    /* Try to modify the volume as a non-authorised user - should fail */
    if(!sxc_volume_modify(cluster, vdata[0].name, NULL, -1, -1, custom_meta)) {
        fprintf(stderr, "%s: ERROR: Successfully changed volume %s meta as a non-authorised user '%s'\n", __FUNCTION__, vdata[0].name, udata[1].username);
        goto test_volmeta_err;
    }

    /* Switch to the admin user account */
    if(sxc_cluster_set_access(cluster, udata[2].username)) {
        fprintf(stderr, "%s: ERROR: Failed to set '%s' profile authentication: '%s'\n", __FUNCTION__, udata[1].username, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Get remote custom meta */
    sxc_meta_free(custom_meta_remote);
    custom_meta_remote = sxc_custom_volumemeta_new(file);
    if(!custom_meta_remote) {
        fprintf(stderr, "%s: ERROR: Failed to get volume %s custom meta: %s\n", __FUNCTION__, vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Compare local and remote meta - should not be changed */
    if(!cmp_meta(__FUNCTION__, sx, custom_meta, custom_meta_remote, 1))
        goto test_volmeta_err;

    /* Modify the volume as an admin user */
    if(sxc_volume_modify(cluster, vdata[0].name, NULL, -1, -1, custom_meta)) {
        fprintf(stderr, "%s: ERROR: Failed to modify volume %s meta as the admin user '%s'\n", __FUNCTION__, vdata[0].name, udata[2].username);
        goto test_volmeta_err;
    }

    /* Get remote custom meta */
    sxc_meta_free(custom_meta_remote);
    custom_meta_remote = sxc_custom_volumemeta_new(file);
    if(!custom_meta_remote) {
        fprintf(stderr, "%s: ERROR: Failed to get volume %s custom meta: %s\n", __FUNCTION__, vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Compare local and remote meta */
    if(cmp_meta(__FUNCTION__, sx, custom_meta, custom_meta_remote, 0))
        goto test_volmeta_err;

    ret = 0;
test_volmeta_err:
    if(sxc_cluster_set_access(cluster, profile_name))
        fprintf(stderr, "%s: WARNING: Failed to set '%s' profile authentication: %s\n", __FUNCTION__, udata[0].username, sxc_geterrmsg(sx));

    cleanup_volumes(__FUNCTION__, sx, cluster, vdata, sizeof(vdata) / sizeof(*vdata));
    cleanup_users(__FUNCTION__, sx, cluster, udata, sizeof(udata) / sizeof(*udata));
    sxc_file_free(file);
    sxc_meta_free(custom_meta);
    sxc_meta_free(custom_meta_remote);
    return ret;
}

static int test_user_quota(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int ret = -1, file_created = 0;
    sxc_meta_t *custom_meta = NULL, *custom_meta_remote = NULL;
    sxc_file_t *src = NULL, *dest = NULL;
    struct user_data udata[2];
    struct vol_data vdata[2];
    char *local_file_path = NULL, *remote_path = NULL;

    memset(udata, 0, sizeof(udata));
    memset(vdata, 0, sizeof(vdata));
    udata[1].admin = 1;

    /* Create 1 user */
    if(prepare_users(__FUNCTION__, sx, cluster, udata, sizeof(udata) / sizeof(*udata))) {
        fprintf(stderr, "%s: ERROR: Failed to prepare users\n", __FUNCTION__);
        goto test_user_quota_err;
    }

    vdata[0].owner = udata[0].username;
    vdata[1].owner = udata[0].username;
    /* Create 1 volume owned by user1 */
    if(prepare_volumes(__FUNCTION__, sx, cluster, vdata, sizeof(vdata) / sizeof(*vdata), NULL, NULL, 0, 1)) {
        fprintf(stderr, "%s: ERROR: Failed to prepare volumes\n", __FUNCTION__);
        goto test_user_quota_err;
    }

    local_file_path = malloc(strlen(local_dir_path) + lenof(QUOTA_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "%s: ERROR: Cannot allocate memory for local_file_path.\n", __FUNCTION__);
        goto test_user_quota_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, QUOTA_FILE_NAME);
    remote_path = malloc(lenof("sx://") + strlen(args->owner_arg) + 1 + strlen(cluster_name) + 1 + strlen(vdata[0].name) + 1 + lenof(REMOTE_DIR) + 1 + lenof(QUOTA_FILE_NAME) + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_path) {
        fprintf(stderr, "%s: ERROR: Cannot allocate memory for remote_path.\n", __FUNCTION__);
        goto test_user_quota_err;
    }
    sprintf(remote_path, "%s/%s", REMOTE_DIR, QUOTA_FILE_NAME);
    src = sxc_file_local(sx, local_file_path);
    if(!src) {
        fprintf(stderr, "%s: ERROR: Cannot open '%s' file: %s\n", __FUNCTION__, local_file_path, sxc_geterrmsg(sx));
        goto test_user_quota_err;
    }
    dest = sxc_file_remote(cluster, vdata[0].name, remote_path, NULL);
    if(!dest) {
        fprintf(stderr, "%s: ERROR: Cannot open '%s' directory: %s\n", __FUNCTION__, remote_path, sxc_geterrmsg(sx));
        goto test_user_quota_err;
    }

    /* Actual test begins here */

    /* Create test file: its size on local disk will be exactly one SX_BS_LARGE bytes */
    if(create_file(local_file_path, SX_BS_LARGE, 1, NULL, 1)) {
        fprintf(stderr, "%s: ERROR: Cannot create '%s' file.\n", __FUNCTION__, local_file_path);
        goto test_user_quota_err;
    }
    file_created = 1;

    /* Modify the first user quota, set it to be the same as raw file data - 1 byte */
    if(sxc_user_modify(cluster, udata[0].username, SX_BS_LARGE + lenof(REMOTE_DIR) + 1 + lenof(QUOTA_FILE_NAME) - 1, NULL)) {
        fprintf(stderr, "%s: ERROR: Failed to modify user '%s' quota\n", __FUNCTION__, udata[0].username);
        goto test_user_quota_err;
    }

    /* Switch to the volume owner account */
    if(sxc_cluster_set_access(cluster, udata[0].username)) {
        fprintf(stderr, "%s: ERROR: Failed to set '%s' profile authentication: %s\n", __FUNCTION__, udata[0].username, sxc_geterrmsg(sx));
        goto test_user_quota_err;
    }

    switch(sxc_copy(src, dest, 0, 0, 0, NULL, 1)) {
        case 0:
            fprintf(stderr, "%s: ERROR: User '%s' quota not enforced.\n", __FUNCTION__, udata[0].username);
            goto test_user_quota_err;
        case 413:
            printf("%s: User '%s' quota enforced correctly (file upload).\n", __FUNCTION__, udata[0].username);
            break;
        default:
            fprintf(stderr, "%s: ERROR: Cannot upload '%s' file: %s\n", __FUNCTION__, local_file_path, sxc_geterrmsg(sx));
            goto test_user_quota_err;
    }
    sxc_clearerr(sx);

    /* Switch to the admin account */
    if(sxc_cluster_set_access(cluster, udata[1].username)) {
        fprintf(stderr, "%s: ERROR: Failed to set '%s' profile authentication: %s\n", __FUNCTION__, udata[0].username, sxc_geterrmsg(sx));
        goto test_user_quota_err;
    }

    /* Modify the first user quota, set it to be the same as raw file data */
    if(sxc_user_modify(cluster, udata[0].username, SX_BS_LARGE + lenof(REMOTE_DIR) + 1 + lenof(QUOTA_FILE_NAME), NULL)) {
        fprintf(stderr, "%s: ERROR: Failed to modify user '%s' quota\n", __FUNCTION__, udata[0].username);
        goto test_user_quota_err;
    }

    /* Now file should exactly fit into user quota */
    if(sxc_copy(src, dest, 0, 0, 0, NULL, 1)) {
        fprintf(stderr, "%s: ERROR: Cannot upload '%s' file: %s\n", __FUNCTION__, local_file_path, sxc_geterrmsg(sx));
        goto test_user_quota_err;
    }

    ret = 0;
test_user_quota_err:
    if(sxc_cluster_set_access(cluster, profile_name))
        fprintf(stderr, "%s: WARNING: Failed to set '%s' profile authentication: %s\n", __FUNCTION__, udata[0].username, sxc_geterrmsg(sx));

    if(remote_path) {
        sprintf(remote_path, "sx://%s@%s/%s/%s/%s", args->owner_arg, cluster_name, vdata[0].name, REMOTE_DIR, QUOTA_FILE_NAME);
        if(delete_files(sx, cluster, remote_path, 0, 0))
            fprintf(stderr, "%s: WARNING: Cannot delete '%s' file.\n", __FUNCTION__, remote_path);
    }

    cleanup_volumes(__FUNCTION__, sx, cluster, vdata, sizeof(vdata) / sizeof(*vdata));
    cleanup_users(__FUNCTION__, sx, cluster, udata, sizeof(udata) / sizeof(*udata));
    sxc_meta_free(custom_meta);
    sxc_meta_free(custom_meta_remote);
    if(file_created && unlink(local_file_path))
        fprintf(stderr, "%s: WARNING: Cannot delete '%s' file: %s\n", __FUNCTION__, local_file_path, strerror(errno));
    free(local_file_path);
    free(remote_path);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
}

static int test_volume_quota(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int ret = 1, file = 0;
    char *volname, *local_file_path = NULL, *remote_path = NULL;
    sxc_file_t *src = NULL, *dest = NULL;

    printf("\ntest_quota: Started\n");
    volname = (char*)malloc(sizeof(VOLNAME) + 1 + strlen("NonFilter_XXXXXX") + 1);
    if(!volname) {
        fprintf(stderr, "test_quota: ERROR: Cannot allocate memory for volname.\n");
        return ret;
    }
    sprintf(volname, "%s_NonFilter_XXXXXX", VOLNAME);
    if(randomize_name(volname))
        goto test_quota_err;
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(QUOTA_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_quota: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_quota_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, QUOTA_FILE_NAME);
    remote_path = (char*)malloc(strlen("sx://") + strlen(args->owner_arg) + 1 + strlen(cluster_name) + 1 + strlen(volname) + 1 + strlen(REMOTE_DIR) + 1 + strlen(QUOTA_FILE_NAME) + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_path) {
        fprintf(stderr, "test_quota: ERROR: Cannot allocate memory for remote_path.\n");
        goto test_quota_err;
    }
    sprintf(remote_path, "%s/%s", REMOTE_DIR, QUOTA_FILE_NAME);
    if(sxc_volume_add(cluster, volname, QUOTA_VOL_SIZE*SX_BS_LARGE, 1, 1, NULL, args->owner_arg)) {
        fprintf(stderr, "test_quota: ERROR: Cannot create '%s' volume: %s\n", volname, sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    if(args->human_flag) {
        printf("test_quota: Volume '%s' (replica: 1, size: %dM) created.\n", volname, QUOTA_VOL_SIZE);
        printf("test_quota: Creating file of size: %dM\n", QUOTA_FILE_SIZE);
    } else {
        printf("test_quota: Volume '%s' (replica: 1, size: %lld) created.\n", volname, QUOTA_VOL_SIZE*1024LL*1024LL);
        printf("test_quota: Creating file of size: %llu\n", (unsigned long long)QUOTA_FILE_SIZE*1024*1024);
    }
    src = sxc_file_local(sx, local_file_path);
    if(!src) {
        fprintf(stderr, "test_quota: ERROR: Cannot open '%s' file: %s\n", local_file_path, sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    dest = sxc_file_remote(cluster, volname, remote_path, NULL);
    if(!dest) {
        fprintf(stderr, "test_quota: ERROR: Cannot open '%s' directory: %s\n", remote_path, sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    if(create_file(local_file_path, SX_BS_LARGE, QUOTA_FILE_SIZE, NULL, 1)) {
        fprintf(stderr, "test_quota: ERROR: Cannot create '%s' file.\n", local_file_path);
        goto test_quota_err;
    }
    file = 1;
    switch(sxc_copy(src, dest, 0, 0, 0, NULL, 1)) {
        case 0:
            fprintf(stderr, "test_quota: ERROR: Volume size limit not enforced.\n");
            goto test_quota_err;
        case 413:
            printf("test_quota: Volume size limit enforced correctly.\n");
            break;
        default:
            fprintf(stderr, "test_quota: ERROR: Cannot upload '%s' file: %s\n", local_file_path, sxc_geterrmsg(sx));
            goto test_quota_err;
    }
    if(sxc_volume_modify(cluster, volname, NULL, 2 * QUOTA_FILE_SIZE * SX_BS_LARGE, -1, NULL)) {
        fprintf(stderr, "test_quota: ERROR: Cannot change volume size: %s\n", sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    if(sxc_copy(src, dest, 0, 0, 0, NULL, 1)) {
        fprintf(stderr, "test_quota: ERROR: Cannot upload '%s' file: %s\n", local_file_path, sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    printf("test_quota: Volume size changed correctly.\n");
    sprintf(remote_path, "sx://%s@%s/%s/%s/%s", args->owner_arg, cluster_name, volname, REMOTE_DIR, QUOTA_FILE_NAME);
    if(delete_files(sx, cluster, remote_path, 0, 0)) {
        fprintf(stderr, "test_quota: ERROR: Cannot delete '%s' file.\n", remote_path);
        goto test_quota_err;
    }
    if(remove_volume(sx, cluster, volname, 0)) {
        fprintf(stderr, "test_quota: ERROR: Cannot remove '%s' volume.\n", volname);
        goto test_quota_err;
    }

    printf("test_quota: Succeeded\n");
    ret = 0;
test_quota_err:
    if(file && unlink(local_file_path))
        fprintf(stderr, "test_quota: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
    free(volname);
    free(local_file_path);
    free(remote_path);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* test_quota */

static int test_copy(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int ret = 1, tmp;
    char *volname1, *volname2 = NULL, *local_file_path = NULL, *remote_file1_path = NULL, *remote_file2_path = NULL;
    unsigned char block[SX_BS_MEDIUM], hash1[SHA_DIGEST_LENGTH], hash2[SHA_DIGEST_LENGTH];
    FILE *file = NULL;
    sxc_uri_t *uri = NULL;
    sxc_file_t *src = NULL, *dest = NULL;
    SHA_CTX ctx;

    printf("\ntest_copy: Started\n");
    volname1 = (char*)malloc(sizeof(VOLNAME) + 2 + (filter1_name ? strlen(filter1_name) : strlen("NonFilter")) + 1 + strlen("XXXXXX") + 1);
    if(!volname1) {
        fprintf(stderr, "test_copy: ERROR: Cannot allocate memory for volname1.\n");
        return ret;
    }
    sprintf(volname1, "%s1_%s_XXXXXX", VOLNAME, filter1_name ? filter1_name : "NonFilter");
    if(randomize_name(volname1))
        goto test_copy_err;
    volname2 = (char*)malloc(sizeof(VOLNAME) + 2 + (filter2_name ? strlen(filter2_name) : strlen("NonFilter")) + 1 + strlen("XXXXXX") + 1);
    if(!volname2) {
        fprintf(stderr, "test_copy: ERROR: Cannot allocate memory for volname2.\n");
        goto test_copy_err;
    }
    sprintf(volname2, "%s2_%s_XXXXXX", VOLNAME, filter2_name ? filter2_name : "NonFilter");
    if(randomize_name(volname2))
        goto test_copy_err;
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(COPY_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_copy: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_copy_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, COPY_FILE_NAME);
    remote_file1_path = (char*)malloc(strlen("sx://") + (profile_name ? strlen(profile_name) + 1 : 0) + strlen(cluster_name) + 1 + strlen(volname1) + 1 + strlen(REMOTE_DIR) + 1 + strlen(COPY_FILE_NAME) + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_file1_path) {
        fprintf(stderr, "test_copy: ERROR: Cannot allocate memory for remote_file1_path.\n");
        goto test_copy_err;
    }
    sprintf(remote_file1_path, "sx://%s%s%s/%s/%s/%s", profile_name ? profile_name : "", profile_name ? "@" : "", cluster_name, volname1, REMOTE_DIR, COPY_FILE_NAME);
    remote_file2_path = (char*)malloc(strlen("sx://") + (profile_name ? strlen(profile_name) + 1 : 0) + strlen(cluster_name) + 1 + strlen(volname2) + 1 + strlen(REMOTE_DIR) + 1 + strlen(COPY_FILE_NAME) + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_file2_path) {
        fprintf(stderr, "test_copy: ERROR: Cannot allocate memory for remote_file2_path.\n");
        goto test_copy_err;
    }
    sprintf(remote_file2_path, "sx://%s%s%s/%s/%s/%s", profile_name ? profile_name : "", profile_name ? "@" : "", cluster_name, volname2, REMOTE_DIR, COPY_FILE_NAME);
    printf("test_copy: Filters: %s (%s) and %s (%s).\n", filter1_name, filter1_cfg, filter2_name, filter2_cfg);
    if(create_volume(sx, cluster, volname1, args->owner_arg, filter_dir, filter1_name, filter1_cfg, args->replica_arg, 1, args->human_flag, 0)) {
        fprintf(stderr, "test_copy: ERROR: Cannot create new volume.\n");
        goto test_copy_err;
    }
    if(create_volume(sx, cluster, volname2, args->owner_arg, filter_dir, filter2_name, filter2_cfg, args->replica_arg, 1, args->human_flag, 0)) {
        fprintf(stderr, "test_copy: ERROR: Cannot create new volume.\n");
        goto test_copy_err;
    }
    if(create_file(local_file_path, SX_BS_MEDIUM, 10, hash1, 1)) {
        fprintf(stderr, "test_copy: ERROR: Cannot create '%s' file.\n", local_file_path);
        goto test_copy_err;
    }
    printf("test_copy: Uploading file.\n");
    if(upload_file(sx, cluster, local_file_path, remote_file1_path, 0)) {
        fprintf(stderr, "test_copy: ERROR: Cannot upload '%s' file.\n", local_file_path);
        if(unlink(local_file_path))
            fprintf(stderr, "test_copy: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_copy_err;
    }
    if(unlink(local_file_path)) {
        fprintf(stderr, "test_copy: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_copy_err;
    }
    uri = sxc_parse_uri(sx, remote_file1_path);
    if(!uri) {
        fprintf(stderr, "test_copy: ERROR: %s\n", sxc_geterrmsg(sx));
        goto test_copy_err;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        fprintf(stderr, "test_copy: ERROR: Cannot open '%s' file: %s\n", remote_file1_path, sxc_geterrmsg(sx));
        sxc_free_uri(uri);
        uri = NULL;
        goto test_copy_err;
    }
    sxc_free_uri(uri);
    printf("test_copy: Copying file between volumes.\n");
    uri = sxc_parse_uri(sx, remote_file2_path);
    if(!uri) {
        fprintf(stderr, "test_copy: ERROR: %s\n", sxc_geterrmsg(sx));
        goto test_copy_err;
    }
    dest = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!dest) {
        fprintf(stderr, "test_copy: ERROR: Cannot open '%s' file: %s\n", remote_file2_path, sxc_geterrmsg(sx));
        goto test_copy_err;
    }
    if(sxc_copy(src, dest, 0, 0, 0, NULL, 1)) {
        fprintf(stderr, "test_copy: ERROR: Cannot upload '%s' file: %s\n", remote_file2_path, sxc_geterrmsg(sx));
        goto test_copy_err;
    }
    printf("test_copy: Downloading file.\n");
    file = download_file(sx, cluster, local_file_path, remote_file2_path);
    if(!file) {
        fprintf(stderr, "test_copy: ERROR: Cannot download '%s' file.\n", remote_file2_path);
        goto test_copy_err;
    }
    if(!SHA1_Init(&ctx)) {
        fprintf(stderr, "test_copy: ERROR: SHA1_Init() failure.\n");
        goto test_copy_err;
    }
    while((tmp = fread(block, sizeof(unsigned char), SX_BS_MEDIUM, file))) {
        if(!SHA1_Update(&ctx, block, tmp)) {
            fprintf(stderr, "test_copy: ERROR: SHA1_Update() failure.\n");
            goto test_copy_err;
        }
        if(tmp < SX_BS_MEDIUM) {
            fprintf(stderr, "test_copy: ERROR: Downloaded only a part of file.\n");
            goto test_copy_err;
        }
    }
    if(!SHA1_Final(hash2, &ctx)) {
        fprintf(stderr, "test_copy: ERROR: SHA1_Final() failure.\n");
        goto test_copy_err;
    }
    if(memcmp(hash1, hash2, SHA_DIGEST_LENGTH)) {
        fprintf(stderr, "test_copy: ERROR: Uploaded and downloaded file differs.\n");
        goto test_copy_err;
    }
    if(delete_files(sx, cluster, remote_file1_path, 0, 0)) {
        fprintf(stderr, "test_copy: ERROR: Cannot delete '%s' file.\n", remote_file1_path);
        goto test_copy_err;
    }
    if(delete_files(sx, cluster, remote_file2_path, 0, 0)) {
        fprintf(stderr, "test_copy: ERROR: Cannot delete '%s' file.\n", remote_file2_path);
        goto test_copy_err;
    }
    if(remove_volume(sx, cluster, volname1, 0)) {
        fprintf(stderr, "test_copy: ERROR: Cannot remove '%s' volume.\n", volname1);
        goto test_copy_err;
    }
    if(remove_volume(sx, cluster, volname2, 0)) {
        fprintf(stderr, "test_copy: ERROR: Cannot remove '%s' volume.\n", volname2);
        goto test_copy_err;
    }
    
    printf("test_copy: Succeeded\n");
    ret = 0;
test_copy_err:
    if(file) {
        if(fclose(file) == EOF) {
            fprintf(stderr, "test_copy: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
            goto test_copy_err;
        }
        if(unlink(local_file_path)) {
            fprintf(stderr, "test_copy: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
            ret = 1;
        }
    }
    free(volname1);
    free(volname2);
    free(local_file_path);
    free(remote_file1_path);
    free(remote_file2_path);
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* test_copy */

/* Both users without 'read' permission.
 * Path to already existing file. 
 *  -1 - error
 *   0 - files not uploaded (permissions forced)
 *   1 - files uploaded */
static int cross_copy(sxc_client_t *sx, sxc_cluster_t *cluster, const char *cluster_name, const char *volname1, const char* volname2, const char *user1, const char *user2, const char *profile_name, const char *local_file_path) {
    int ret = -1;
    char *remote_file_path;

    remote_file_path = (char*)malloc(strlen("sx://") + strlen(user1) + strlen(user2) + 1 + strlen(cluster_name) + 1 + strlen(volname1) + strlen(volname2) + 2); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_file_path) {
        fprintf(stderr, "cross_copy: ERROR: Cannot allocate memory for remote_file_path.\n");
        return ret;
    }
    if(sxc_cluster_set_access(cluster, user1)) {
        fprintf(stderr, "cross_copy: ERROR: Failed to set '%s' profile authentication: %s\n", user1, sxc_geterrmsg(sx));
        goto cross_copy_err;
    }
    sprintf(remote_file_path, "sx://%s@%s/%s/", user1, cluster_name, volname2);
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 1)) {
        if(sxc_geterrnum(sx) != SXE_EAUTH) {
            fprintf(stderr, "cross_copy: ERROR: Cannot upload '%s' file.\n", local_file_path);
            goto cross_copy_err;
        }
    } else {
        fprintf(stderr, "cross_copy: ERROR: File upload succeeded without permission.\n");
        ret = 1;
        goto cross_copy_err;
    }
    if(sxc_cluster_set_access(cluster, user2)) {
        fprintf(stderr, "cross_copy: ERROR: Failed to set '%s' profile authentication: %s\n", user2, sxc_geterrmsg(sx));
        goto cross_copy_err;
    }
    sprintf(remote_file_path, "sx://%s@%s/%s/", user2, cluster_name, volname1);
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 1)) {
        if(sxc_geterrnum(sx) != SXE_EAUTH) {
            fprintf(stderr, "cross_copy: ERROR: Cannot upload '%s' file.\n", local_file_path);
            goto cross_copy_err;
        }
    } else {
        fprintf(stderr, "cross_copy: ERROR: File upload succeeded without permission.\n");
        ret = 1;
        goto cross_copy_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        fprintf(stderr, "cross_copy: ERROR: Failed to set default profile: %s\n", sxc_geterrmsg(sx));
        goto cross_copy_err;
    }

    ret = 0;
cross_copy_err:
    free(remote_file_path); 
    return ret;
} /* cross_copy */

/* -1 - error
 *  0 - users list is the same as given in arguments
 *  1 - different users list */
static int check_users(sxc_cluster_t *cluster, const char **users, const int users_num) {
    int i, ret = -1, is_admin, next = 1, num = 0;
    char *user = NULL, *desc = NULL;
    int64_t quota, quota_used;
    sxc_cluster_lu_t *lstu;

    lstu = sxc_cluster_listusers(cluster);
    if(!lstu)
        return ret;
    while(next > 0) {
        next = sxc_cluster_listusers_next(lstu, &user, &is_admin, &desc, &quota, &quota_used);
        free(desc);
        switch(next) {
            case -1:
                if(user)
                    free(user);
                goto check_users_err;
            case 0: break;
            case 1:
                for(i=0; i<users_num; i++)
                    if(users[i] && !strcmp(users[i], user)) {
                        users[i] = NULL;
                        break;
                    }
                free(user);
                user = NULL;
                num++;
                break;
        }
    }
    if(num - 1 != users_num) { /* There is always admin profile */
        ret = 1;
        goto check_users_err;
    }
    for(i=0; i<users_num; i++)
        if(users[i]) {
            ret = 2;
            goto check_users_err;
        }

    ret = 0;
check_users_err:
    sxc_cluster_listusers_free(lstu);
    return ret;
} /* check_users */

/* -1 - error
 *  0 - user has the same rights as given in arguments
 *  1 - different user rights */
static int check_user(sxc_cluster_t *cluster, const char *volname, const char *user, int rights) {
    int ret = -1, next = 1, acl;
    char *get_user = NULL;
    sxc_cluster_la_t *lstu;

    lstu = sxc_cluster_listaclusers(cluster, volname);
    if(!lstu)
        return ret;
    while(next > 0) {
        next = sxc_cluster_listaclusers_next(lstu, &get_user, &acl);
        switch(next) {
            case -1:
                if(get_user)
                    free(get_user);
                goto check_user_err;
            case 0: break;
            case 1:
                if(!strcmp(user, get_user)) {
                    free(get_user);
                    if(rights != acl) {
                        ret = 1;
                        fprintf(stderr, "rights: %x, acl: %x\n", rights, acl);
                        goto check_user_err;
                    }
                    next = 0;
                    break;
                }
                free(get_user);
                get_user = NULL;
                break;
        }
    }

    ret = 0;
check_user_err:
    sxc_cluster_listaclusers_free(lstu);
    return ret;
} /* check_user */

/* -1 - error
 *  0 - current user in the cluster is not an admin
 *  1 - current user in the cluster is an admin */
static int check_admin(sxc_cluster_t *cluster) {
    int ret = -1, is_admin, next = 1;
    char *get_user = NULL;
    char *user = NULL, *desc, *role = NULL;
    int64_t quota, quota_used;
    sxc_cluster_lu_t *lstu;

    lstu = sxc_cluster_listusers(cluster);
    if(!lstu)
        return ret;

    if(sxc_cluster_whoami(cluster, &user, &role, NULL, &quota, &quota_used))
	goto check_admin_err;

    if(!role || strcmp(role, "admin"))
        goto check_admin_err;
    if(quota != 0 || quota_used != 0)
        goto check_admin_err;
    while(next > 0) {
        next = sxc_cluster_listusers_next(lstu, &get_user, &is_admin, &desc, &quota, &quota_used);
        free(desc);
        switch(next) {
            case -1:
                if(get_user)
                    free(get_user);
                goto check_admin_err;
            case 0: break;
            case 1:
                if(!strcmp(user, get_user))
                    next = 0;
                free(get_user);
                get_user = NULL;
                break;
        }
    }

    /* Admin should not have quota assigned */
    if(quota || quota_used)
        goto check_admin_err;

    ret = is_admin;
check_admin_err:
    sxc_cluster_listusers_free(lstu);
    free(user);
    free(role);
    return ret;
} /* check_admin */

static int test_acl(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *filter_dir, const char *filter1_name, const char *filter1_cfg, const char *filter2_name, const char *filter2_cfg, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, const unsigned int max_revisions, const int check_data_size) {
    int ret = 1;
    char *user1, *user2 = NULL, *user3 = NULL, *key1 = NULL, *key2 = NULL, *key3 = NULL, key_tmp[AUTHTOK_ASCII_LEN], *volname1 = NULL, *volname2 = NULL, *local_file_path = NULL, *remote_file_path = NULL;
    const char *list[3];
    FILE *file = NULL;
    int64_t quota, quota_used;

    printf("\ntest_acl: Started\n");
    switch(check_admin(cluster)) {
        case -1:
            fprintf(stderr, "test_acl: ERROR: %s\n", sxc_geterrmsg(sx));
            return ret;
        case 0:
            fprintf(stderr, "test_acl: ERROR: Current user is not an admin.\n");
            return ret;
    }
    switch(check_users(cluster, (const char**)list, 0)) {
        case -1:
            fprintf(stderr, "test_acl: ERROR: %s\n", sxc_geterrmsg(sx));
            return ret;
        case 0: break;
        case 1: 
            fprintf(stderr, "test_acl: ERROR: Wrong number of users.\n");
            return ret;
        case 2:
            fprintf(stderr, "test_acl: ERROR: Different user list.\n");
            return ret;
    }
    user1 = (char*)malloc(strlen(ACL_USER1) + strlen("XXXXXX") + 1);
    if(!user1) {
        fprintf(stderr, "test_acl: ERROR: Cannot allocate memory for user1.\n");
        return ret;
    }
    sprintf(user1, "%sXXXXXX", ACL_USER1);
    if(randomize_name(user1))
        goto test_acl_err;
    key1 = sxc_user_add(cluster, user1, NULL, 0, NULL, NULL, 1, 0);
    if(!key1) {
        fprintf(stderr, "test_acl: ERROR: Cannot create '%s' user: %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_add_access(cluster, user1, key1)) {
        fprintf(stderr, "test_acl: ERROR: Failed to add '%s' profile authentication: %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    user2 = (char*)malloc(strlen(ACL_USER2) + strlen("XXXXXX") + 1);
    if(!user2) {
        fprintf(stderr, "test_acl: ERROR: Cannot allocate memory for user2.\n");
        goto test_acl_err;
    }
    sprintf(user2, "%sXXXXXX", ACL_USER2);
    if(randomize_name(user2))
        goto test_acl_err;
    key2 = sxc_user_add(cluster, user2, NULL, 0, NULL, NULL, 1, 0);
    if(!key2) {
        fprintf(stderr, "test_acl: ERROR: Cannot create '%s' user: %s", user2, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_add_access(cluster, user2, key2)) {
        fprintf(stderr, "test_acl: ERROR: Failed to add '%s' profile authentication: %s\n", user2, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    volname1 = (char*)malloc(sizeof(VOLNAME) + 1 + strlen("NonFilter_XXXXXX") + 1);
    if(!volname1) {
        fprintf(stderr, "test_acl: ERROR: Cannot allocate memory for volname1.\n");
        goto test_acl_err;
    }
    sprintf(volname1, "%s_NonFilter_XXXXXX", VOLNAME);
    if(randomize_name(volname1))
        goto test_acl_err;
    volname2 = (char*)malloc(sizeof(VOLNAME) + 1 + strlen("NonFilter_XXXXXX") + 1);
    if(!volname2) {
        fprintf(stderr, "test_acl: ERROR: Cannot allocate memory for volname2.\n");
        goto test_acl_err;
    }
    sprintf(volname2, "%s_NonFilter_XXXXXX", VOLNAME);
    if(randomize_name(volname2))
        goto test_acl_err;
    remote_file_path = (char*)malloc(strlen("sx://") + strlen(user1) + strlen(user2) + 1 + strlen(cluster_name) + 1 + strlen(volname1) + strlen(volname2) + 2); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_file_path) {
        fprintf(stderr, "test_acl: ERROR: Cannot allocate memory for remote_file_path.\n");
        goto test_acl_err;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(ACL_FILE_NAME) + strlen(ACL_KEY_FILE_NAME) + 1);
    if(!local_file_path) {
        fprintf(stderr, "test_acl: ERROR: Cannot allocate memory for local_file_path.\n");
        goto test_acl_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, ACL_FILE_NAME);
    file = fopen(local_file_path, "w");
    if(!file) {
        fprintf(stderr, "test_acl: ERROR: Cannot create '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(fclose(file) == EOF) {
        fprintf(stderr, "test_acl: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, user1)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set '%s' profile authentication: %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(create_volume(sx, cluster, volname1, user1, NULL, NULL, NULL, args->replica_arg, 1, args->human_flag, 1)) {
        if(sxc_geterrnum(sx) == SXE_EAUTH)
            printf("test_acl: Volume creation permission enforced correctly.\n");
        else {
            fprintf(stderr, "test_acl: ERROR: Cannot create new volume.\n");
            goto test_acl_err;
        }
    } else {
        fprintf(stderr, "test_acl: ERROR: Volume created without permission.\n");
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set default profile: %s\n", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(create_volume(sx, cluster, volname1, user1, NULL, NULL, NULL, args->replica_arg, 1, args->human_flag, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot create new volume.\n");
        goto test_acl_err;
    }
    if(create_volume(sx, cluster, volname2, user2, NULL, NULL, NULL, args->replica_arg, 1, args->human_flag, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot create new volume.\n");
        goto test_acl_err;
    }
    switch(check_user(cluster, volname1, user1, SX_ACL_FULL)) { /* read + write + manager + owner */
        case -1:
            fprintf(stderr, "test_acl: ERROR: %s\n", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 1:
            fprintf(stderr, "test_acl: ERROR: '%s' has diferent rights on '%s'.\n", user1, volname1);
            goto test_acl_err;
    }
    switch(check_user(cluster, volname1, user2, 0)) { /* no rights yet */
        case -1:
            fprintf(stderr, "test_acl: ERROR: %s\n", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 1:
            fprintf(stderr, "test_acl: ERROR: '%s' has diferent rights on '%s'.\n", user2, volname1);
            goto test_acl_err;
    }
    switch(cross_copy(sx, cluster, cluster_name, volname1, volname2, user1, user2, profile_name, local_file_path)) {
        case -1:
            fprintf(stderr, "test_acl: ERROR: Files uploading failure.\n");
            goto test_acl_err;
        case 0:
            printf("test_acl: Users permissions enforced correctly.\n");
            break;
        case 1:
            fprintf(stderr, "test_acl: ERROR: Files uploaded without permission.\n");
            goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, user2)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set '%s' profile authentication: %s\n", user2, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    sprintf(remote_file_path, "sx://%s@%s/%s/%s", user1, cluster_name, volname2, ACL_FILE_NAME);
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 0)) { /* user1 in remote_file_path have no impact here */
        fprintf(stderr, "test_acl: ERROR: Cannot upload '%s' file.\n", local_file_path);
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, volname2, user1, SX_ACL_READ, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot add 'read' permission to '%s': %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, user1)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set '%s' profile authentication: %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    switch(find_file(sx, cluster, remote_file_path, 0)) {
        case -1:
            fprintf(stderr, "test_acl: ERROR: Looking for '%s' file failed.\n", remote_file_path);
            goto test_acl_err;
        case 0:
            fprintf(stderr, "test_acl: ERROR: '%s' file not found.\n", remote_file_path);
            goto test_acl_err;
        case 1:
            printf("test_acl: 'read' permission granted correctly.\n");
            break;
    }
    switch(check_user(cluster, volname2, user1, SX_ACL_READ)) { /* read */
        case -1:
            fprintf(stderr, "test_acl: ERROR: %s\n", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 1:
            fprintf(stderr, "test_acl: ERROR: '%s' has diferent rights on '%s'.\n", user1, volname2);
            goto test_acl_err;
    }
    if(delete_files(sx, cluster, remote_file_path, 0, 1)) {
        if(sxc_geterrnum(sx) == SXE_EAUTH)
            printf("test_acl: 'write' permission enforced correctly.\n");
        else {
            fprintf(stderr, "test_acl: ERROR: Cannot delete '%s' file.\n", remote_file_path);
            goto test_acl_err;
        }
    } else {
        fprintf(stderr, "test_acl: ERROR: File has been deleted without permission.\n");
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, volname1, user2, SX_ACL_WRITE, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot add 'write' permission to '%s': %s\n", user2, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, user2)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set '%s' profile authentication: %s\n", user2, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(delete_files(sx, cluster, remote_file_path, 0, 1)) {
        fprintf(stderr, "test_acl: ERROR: Cannot delete '%s' file.\n", remote_file_path);
        goto test_acl_err;
    }
    sprintf(remote_file_path, "sx://%s@%s/%s/%s", user2, cluster_name, volname1, ACL_FILE_NAME);
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 1)) {
        fprintf(stderr, "test_acl: ERROR: Cannot upload '%s' file.\n", local_file_path);
        goto test_acl_err;
    } else
        printf("test_acl: 'write' permission granted correctly.\n");
    if(find_file(sx, cluster, remote_file_path, 1) == -1) {
        if(sxc_geterrnum(sx) == SXE_EAUTH)
            printf("test_acl: 'read' permission enforced correctly.\n");
        else {
            fprintf(stderr, "test_acl: ERROR: Looking for '%s' file in %s failed.\n", ACL_FILE_NAME, remote_file_path);
            goto test_acl_err;
        }
    } else {
        fprintf(stderr, "test_acl: ERROR: Searching for a file done without permission.\n");
        goto test_acl_err;
    }
    if(delete_files(sx, cluster, remote_file_path, 0, 1)) {
        fprintf(stderr, "test_acl: ERROR: Cannot delete '%s' file.\n", remote_file_path);
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, volname2, user1, 0, SX_ACL_READ)) {
        fprintf(stderr, "test_acl: ERROR: Cannot revoke 'read' permission from '%s': %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, user1)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set '%s' profile authentication: %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, volname1, user2, 0, SX_ACL_WRITE)) {
        fprintf(stderr, "test_acl: ERROR: Cannot revoke 'write' permission from '%s': %s\n", user2, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    switch(cross_copy(sx, cluster, cluster_name, volname1, volname2, user1, user2, profile_name, local_file_path)) {
        case -1:
            fprintf(stderr, "test_acl: ERROR: Cannot upload file.\n");
            goto test_acl_err;
        case 0:
            printf("test_acl: User permissions revoked correctly.\n");
            break;
        case 1:
            fprintf(stderr, "test_acl: ERROR: File uploaded without permission.\n");
            goto test_acl_err;
    }
    user3 = (char*)malloc(strlen(ACL_USER3) + strlen("XXXXXX") + 1);
    if(!user3) {
        fprintf(stderr, "test_acl: ERROR: Cannot allocate memory for user3.\n");
        goto test_acl_err;
    }
    sprintf(user3, "%sXXXXXX", ACL_USER1);
    if(randomize_name(user3))
        goto test_acl_err;
    key3 = sxc_user_add(cluster, user3, NULL, 0, NULL, NULL, 1, 0);
    if(!key3) {
        fprintf(stderr, "test_acl: ERROR: Cannot create '%s' user: %s\n", user3, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_add_access(cluster, user3, key3)) {
        fprintf(stderr, "test_acl: ERROR: Failed to add '%s' profile authentication: %s\n", user3, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    list[0] = user1;
    list[1] = user2;
    list[2] = user3;
    switch(check_users(cluster, (const char**)list, 3)) {
        case -1:
            goto test_acl_err;
        case 0: break;
        case 1: 
            fprintf(stderr, "test_acl: ERROR: Wrong number of users.\n");
            goto test_acl_err;
        case 2:
            fprintf(stderr, "test_acl: ERROR: Different user list.\n");
            goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, volname1, user3, SX_ACL_RW, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot add 'read,write' permission to %s: %s\n", user3, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, user3)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set '%s' profile authentication: %s\n", user3, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, volname1, user2, SX_ACL_READ, 0)) {
        if(sxc_geterrnum(sx) == SXE_EAUTH)
            printf("test_acl: User permissions enforced correctly.\n");
        else {
            fprintf(stderr, "test_acl: ERROR: Cannot add 'read' permission to '%s': %s\n", user3, sxc_geterrmsg(sx));
            goto test_acl_err;
        }
    } else {
        fprintf(stderr, "test_acl: ERROR: Permissions granted without permission.\n");
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set default profile: %s\n", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, volname1, user3, 0, SX_ACL_RW)) {
        fprintf(stderr, "test_acl: ERROR: Cannot revoke 'read,write' permission from '%s': %s\n", user3, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_volume_modify(cluster, volname1, user3, 0, -1, NULL)) {
        fprintf(stderr, "test_quota: ERROR: Cannot change volume owner: %s\n", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, user3)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set '%s' profile authentication: %s\n", user3, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    switch(check_user(cluster, volname1, user1, SX_ACL_RW)) { /* read + write */
        case -1:
            fprintf(stderr, "test_acl: ERROR: %s\n", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 1:
            fprintf(stderr, "test_acl: ERROR: '%s' has diferent rights on '%s'.\n", user1, volname1);
            goto test_acl_err;
    }
    switch(check_user(cluster, volname1, user3, SX_ACL_FULL)) { /* read + write + manager + owner */
        case -1:
            fprintf(stderr, "test_acl: ERROR: %s\n", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 1:
            fprintf(stderr, "test_acl: ERROR: '%s' has diferent rights on '%s'.\n", user1, volname1);
            goto test_acl_err;
    }
    if(remove_volume(sx, cluster, volname1, 1)) {
        if(sxc_geterrnum(sx) == SXE_EAUTH)
            printf("test_acl: Volume removal permission enforced correctly.\n");
        else {
            fprintf(stderr, "test_acl: ERROR: Cannot remove '%s' volume.\n", volname1);
            goto test_acl_err;
        }
    } else {
        fprintf(stderr, "test_acl: ERROR: Volume removed without permission.\n");
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set default profile: %s\n", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(unlink(local_file_path)) {
        fprintf(stderr, "test_acl: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        file = NULL;
        goto test_acl_err;
    }
    sprintf(local_file_path, "%s/%s", local_dir_path, ACL_KEY_FILE_NAME);
    file = fopen(local_file_path, "w+");
    if(!file) {
        fprintf(stderr, "test_acl: ERROR: Cannot open '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(sxc_user_getinfo(cluster, user1, file, NULL, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot get '%s' key: %s\n", user1, sxc_geterrmsg(sx));
        if(fclose(file) == EOF)
            fprintf(stderr, "test_acl: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(fflush(file) == EOF) {
        fprintf(stderr, "test_acl: ERROR: Cannot flush '%s' file: %s\n", local_file_path, strerror(errno));
        if(fclose(file) == EOF)
            fprintf(stderr, "test_acl: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    rewind(file);
    if(ftell(file) == -1) {
        fprintf(stderr, "test_acl: ERROR: Cannot rewind '%s' file: %s\n", local_file_path, strerror(errno));
        if(fclose(file) == EOF)
            fprintf(stderr, "test_acl: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(fread(key_tmp, 1, AUTHTOK_ASCII_LEN, file) != AUTHTOK_ASCII_LEN) {
        fprintf(stderr, "test_acl: ERROR: Cannot get '%s' key.\n", user1);
        if(fclose(file) == EOF)
            fprintf(stderr, "test_acl: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(fclose(file) == EOF) {
        fprintf(stderr, "test_acl: ERROR: Cannot close '%s' file: %s\n", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(memcmp(key1, key_tmp, AUTHTOK_ASCII_LEN)) {
        fprintf(stderr, "test_acl: ERROR: User keys differs.\n");
        goto test_acl_err;
    }
    free(key2);
    key2 = sxc_user_newkey(cluster, user1, NULL, NULL, 1);
    if(!key2) {
        fprintf(stderr, "test_acl: ERROR: Cannot generate new key for '%s': %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, user1)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set '%s' profile authentication: %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    free(key3);
    if(sxc_cluster_whoami(cluster, &key3, NULL, NULL, NULL, NULL)) {
        if(sxc_geterrnum(sx) == 7) {
            printf("test_acl: User permissions after key change enforced correctly.\n");
        } else {
            fprintf(stderr, "test_acl: ERROR: %s\n", sxc_geterrmsg(sx));
            goto test_acl_err;
        }
    } else {
        fprintf(stderr, "test_acl: ERROR: Name checked without permission.\n");
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        fprintf(stderr, "cross_copy: ERROR: Failed to set default profile: %s\n", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_add_access(cluster, user1, key2)) {
        fprintf(stderr, "test_acl: ERROR: Failed to add '%s' profile authentication: %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, user1)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set '%s' profile authentication: %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    free(key3);
    if(sxc_cluster_whoami(cluster, &key3, NULL, NULL, &quota, &quota_used)) {
        fprintf(stderr, "test_acl: ERROR: %s\n", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(quota || quota_used) {
        fprintf(stderr, "test_acl: ERROR: Got non-zero quota and quota usage\n");
        goto test_acl_err;
    }
    if(strcmp(user1, key3)) {
        fprintf(stderr, "test_acl: ERROR: Got wrong user name.\n");
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        fprintf(stderr, "test_acl: ERROR: Failed to set default profile: %s\n", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_user_remove(cluster, user1, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot remove '%s' user: %s\n", user1, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_user_remove(cluster, user2, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot remove '%s' user: %s\n", user2, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_user_remove(cluster, user3, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot remove '%s' user: %s\n", user3, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(remove_volume(sx, cluster, volname1, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot remove '%s' volume.\n", volname1);
        goto test_acl_err;
    }
    if(remove_volume(sx, cluster, volname2, 0)) {
        fprintf(stderr, "test_acl: ERROR: Cannot remove '%s' volume.\n", volname2);
        goto test_acl_err;
    }
    
    printf("test_acl: Succeeded\n");
    ret = 0;
test_acl_err:
    if(file && unlink(local_file_path)) {
        fprintf(stderr, "test_acl: ERROR: Cannot delete '%s' file: %s\n", local_file_path, strerror(errno));
        if(!ret)
            ret = -1;
    }
    free(user1);
    free(user2);
    free(user3);
    free(key1);
    free(key2);
    free(key3);
    free(volname1);
    free(volname2);
    free(local_file_path);
    free(remote_file_path);
    return ret;
} /* test_acl */

/* For test_transfer:
 *       Block size | Available number of blocks
 *    SX_BS_SMALL   |  0 - 31
 *    SX_BS_MEDIUM  |  8 - 8192
 *    SX_BS_LARGE   |  129+
 * REMEMBER TO CHECK WHETHER THE VOLUME SIZE IS BIG ENOUGH!!
 */
client_test_t tests[] = {
    {1, 1, 0, 0, 0, 0, "empty_file", NULL, NULL, NULL, NULL, test_empty_file},
    {1, 0, 0, 0, SX_BS_SMALL, 26, "transfer:small", NULL, NULL, NULL, NULL, test_transfer},
    {1, 0, 0, 0, SX_BS_MEDIUM, 2314, "transfer:medium", NULL, NULL, NULL, NULL, test_transfer},
    {1, 0, 0, 1, SX_BS_LARGE, 285, "transfer:large", NULL, NULL, NULL, NULL, test_transfer},
    {1, 1, 0, 0, SX_BS_SMALL, 29, "revision:small", NULL, NULL, NULL, NULL, test_revision},
    {1, 1, 0, 0, SX_BS_MEDIUM, 649, "revision:medium", NULL, NULL, NULL, NULL, test_revision},
    {1, 1, 0, 1, SX_BS_LARGE, 131, "revision:large", NULL, NULL, NULL, NULL, test_revision},
    {1, 1, 0, 0, 0, 0, "cat", NULL, NULL, NULL, NULL, test_cat},
    {1, 1, 0, 0, 0, 0, "errors", NULL, NULL, NULL, NULL, test_errors},
    {1, 0, 1, 0, 0, 0, "attribs", NULL, NULL, NULL, NULL, test_attribs},
    {1, 0, 1, 0, 0, 0, "undelete", NULL, NULL, NULL, NULL, test_undelete},
    {0, 0, 0, 0, 0, 0, "volume_meta", NULL, NULL, NULL, NULL, test_volmeta},
    {0, 0, 0, 0, 0, 0, "quota:user", NULL, NULL, NULL, NULL, test_user_quota},
    {0, 0, 0, 0, 0, 0, "quota:volume", NULL, NULL, NULL, NULL, test_volume_quota},
    {0, 0, 0, 0, 0, 0, "copy", NULL, NULL, NULL, NULL, test_copy},
    {0, 0, 0, 0, 0, 0, "copy:filters", "aes256", NULL, "zcomp", "level:1", test_copy},
    {0, 0, 0, 0, 0, 0, "acl", NULL, NULL, NULL, NULL, test_acl},
    {-1, -1, -1, -1, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL}
};

int main(int argc, char **argv) {
    int i, ret = 1;
    char *local_dir_path = NULL, *filter_dir = NULL;
    sxc_client_t *sx = NULL;
    sxc_logger_t log;
    sxc_cluster_t *cluster = NULL;
    sxc_uri_t *uri = NULL;
    struct gengetopt_args_info args;

    if(QUOTA_FILE_SIZE <= QUOTA_VOL_SIZE) {
        fprintf(stderr, "ERROR: File size to test quota is smaller than volume size.\nPlease contact with software developer.\n");
        return ret;
    }
    if(cmdline_parser(argc, argv, &args)) {
        cmdline_parser_print_help();
        printf("\n");
        return ret;
    }
    if(args.list_tests_given) {
        printf("Available tests:\n");
        for(i=0; tests[i].name; i++)
            printf("   %s\n", tests[i].name);
        printf("\n");
    } else {
        if(args.inputs_num != 1) {
            cmdline_parser_print_help();
            printf("\n");
            fprintf(stderr, "main: ERROR: Wrong number of arguments.\n");
            goto main_err;
        }
        sx = sxc_init(SRC_VERSION, sxc_file_logger(&log, argv[0], "/dev/null", 0), test_input_fn, NULL);
        if(!sx) {
            fprintf(stderr, "main: ERROR: Cannot initiate SX.\n");
            goto main_err;
        }
        if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
            fprintf(stderr, "main: ERROR: Could not set configuration directory to '%s': %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
            goto main_err;
        }
        sxc_set_debug(sx, args.debug_flag);
        uri = sxc_parse_uri(sx, args.inputs[0]);
        if(!uri) {
            fprintf(stderr, "main: ERROR: %s\n", sxc_geterrmsg(sx));
            goto main_err;
        }
        if(uri->volume) {
            fprintf(stderr, "main: ERROR: Volume name not expected.\n");
            goto main_err;
        }
        cluster = sxc_cluster_load_and_update(sx, uri->host, uri->profile);
        if(!cluster) {
            fprintf(stderr, "main: ERROR: Cannot load cluster: %s\n", sxc_geterrmsg(sx));
            goto main_err;
        }
        local_dir_path = (char*)malloc(strlen(LOCAL_DIR) + strlen("XXXXXX") + 1 + 1); /* There is '/' character at the end */
        if(!local_dir_path) {
            fprintf(stderr, "main: ERROR: Cannot allocate memory for local_dir_path.\n");
            goto main_err;
        }
        sprintf(local_dir_path, "%sXXXXXX", LOCAL_DIR);
        if(!mkdtemp(local_dir_path)) {
            fprintf(stderr, "main: ERROR: Cannot create '%s' temporary directory: %s\n", local_dir_path, strerror(errno));
            goto main_err;
        }
        strcat(local_dir_path, "/");
        if(args.filter_dir_given) {
            filter_dir = strdup(args.filter_dir_arg);
        } else {
            const char *pt = sxi_getenv("SX_FILTER_DIR");
            if(pt)
                filter_dir = strdup(pt);
        }
        if(!filter_dir) {
            fprintf(stderr, "main: ERROR: Cannot get filter directory. Use --filter-dir or 'export SX_FILTER_DIR=<src_dir>/client/src/filters/'\n");
            goto main_err;
        }

        /* If particular test has been specified, check if it exists */
        if(args.run_test_given) {
            for(i=0; tests[i].name; i++) {
                if(!strcmp(args.run_test_arg, tests[i].name))
                    break;
            }

            if(!tests[i].name) {
                /* The given test has not been found, bail out with error message */
                fprintf(stderr, "main: ERROR: Cannot find test '%s'. Use --list-tests option to get the list of available tests.\n", args.run_test_arg);
                goto main_err;
            }
        }

        /* The beginning of tests */
        if(volume_test(argv[0], sx, cluster, local_dir_path, uri, filter_dir, &args, NULL, NULL, 3))
            goto main_err;
        if(volume_test(argv[0], sx, cluster, local_dir_path, uri, filter_dir, &args, "aes256", NULL, 1))
            goto main_err;
        if(volume_test(argv[0], sx, cluster, local_dir_path, uri, filter_dir, &args, "zcomp", "level:1", 1))
            goto main_err;
        if(volume_test(argv[0], sx, cluster, local_dir_path, uri, filter_dir, &args, "attribs", NULL, 1))
            goto main_err;
        if(volume_test(argv[0], sx, cluster, local_dir_path, uri, filter_dir, &args, "undelete", TRASH_NAME, 1))
            goto main_err;
        for(i=0; tests[i].name; i++)
            if(!tests[i].for_volume && (args.run_test_given ? !strcmp(args.run_test_arg, tests[i].name) : 1) && run_test(sx, cluster, local_dir_path, NULL, uri->profile, uri->host, filter_dir, &args, 1, 1, &tests[i])) {
                failed_test_msg(argv[0], &args, &tests[i]);
                goto main_err;
            }
        /* The end of tests */
        printf("\nmain: All tests succeeded.\n");
    }

    ret = 0;
main_err:
    if(local_dir_path && rmdir(local_dir_path)) {
        fprintf(stderr, "main: ERROR: Cannot delete '%s' directory: %s\n", local_dir_path, strerror(errno));
        ret = 1;
    }
    free(local_dir_path);
    free(filter_dir);
    sxc_cluster_free(cluster);
    sxc_free_uri(uri);
    sxc_shutdown(sx, 0);
    cmdline_parser_free(&args);
    return ret;
} /* main */

