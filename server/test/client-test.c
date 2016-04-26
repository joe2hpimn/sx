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
#include <unistd.h>

#include "sx.h"
#include "libsxclient/src/clustcfg.h"
#include "libsxclient/src/volops.h"
#include "libsxclient/src/misc.h"
#include "libsxclient/src/vcrypto.h"
#include "server/src/common/sxlimits.h"
#include "version.h"
#include "rgen.h"
#include "client-test-cmdline.h"
#include "libsxclient/src/fileops.h"

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
#define ZCOMP_LEVEL "level:1"
#define RENAME_FILE_NAME "file_rename"
#define UNDELETE_FILE_NAME "file_undelete"
#define QUOTA_FILE_NAME "file_quota"
#define QUOTA_VOL_SIZE 1
#define QUOTA_FILE_SIZE 2 /* Must be more then QUOTA_VOL_SIZE */
#define COPY_FILE_NAME "file_copy"
#define ACL_USER1 "user1" /* There will be 6 random characters suffix added. */
#define ACL_USER2 "user2" /* There will be 6 random characters suffix added. */
#define ACL_USER3 "user3" /* There will be 6 random characters suffix added. */
#define ACL_VOLNAME1 "vol1" /* There will be 6 random characters suffix added. */
#define ACL_VOLNAME2 "vol2" /* There will be 6 random characters suffix added. */
#define ACL_FILE_NAME "file_acl"
#define ACL_KEY_FILE_NAME "file_acl_key"
#define CAT_FILE_NAME_IN "file_cat_in"
#define CAT_FILE_NAME_OUT "file_cat_out"
#define CAT_FILE_SIZE 1
#define ERRORS_FILE_NAME "file_err"

#define PRINT(...) print_msg(__func__, "", __VA_ARGS__)
#define WARNING(...) print_msg(__func__, "WARNING", __VA_ARGS__)
#define ERROR(...) print_msg(__func__, "ERROR", __VA_ARGS__)

static void print_msg (const char *fn, const char *level, const char *format_string, ...) {
    va_list vl;

    fprintf(stderr, "[%-17s] %s: ", strcmp(fn, "main") ? fn : "client-test", level);
    va_start(vl, format_string);
    vfprintf(stderr, format_string, vl);
    va_end(vl);
    fprintf(stderr, "\n");
} /* print_msg */

typedef struct {
    int for_volume, no_filter, dedicated, additional, rand_filters;
    uint64_t block_size, block_count;
    const char *name;

    int (*fun)(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size);
} client_test_t;

static int run_test(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, const sxf_handle_t *filters, int fcount, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size, const client_test_t *test) {
    if(!test->fun)
        return -1;
    return test->fun(sx, cluster, local_dir_path, remote_dir_path, profile_name, cluster_name, vol_filter, test->rand_filters, filters, fcount, test->block_size, test->block_count, args, max_revisions, check_data_size);
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

static void failed_test_msg(const struct gengetopt_args_info *args, const client_test_t *test) {
    unsigned int i;
    fprintf(stderr, "\nFailed to run '%s' test.", test->name);
    if(!args->run_test_given) {
        fprintf(stderr, " Use:\nclient-test");
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
            ERROR("NULL argument");
        return -1;
    }
    switch(type) {
        case SXC_INPUT_YN:
            *in = 'y';
            break;
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
        ERROR("NULL argument");
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
        ERROR("Cannot generate temporary name: %s", strerror(errno));
        return 1;
    }
    if(close(fd)) {
        ERROR("Cannot close '%s' file descriptor: %s", name, strerror(errno));
        if(unlink(name))
            ERROR("Cannot delete '%s' file: %s", name, strerror(errno));
        return 1;
    }
    if(unlink(name)) {
        ERROR("Cannot delete '%s' file: %s", name, strerror(errno));
        return 1;
    }
    return 0;
}

static int create_volume(sxc_client_t *sx, sxc_cluster_t *cluster, const char *volname, const char *owner, int64_t size, const sxf_handle_t *filter, const char *filter_cfg, int replica, unsigned int max_revisions, int human_readable, int hide_errors) {
    void *cfgdata = NULL;
    int ret = 1;
    uint8_t uuid[16];
    char uuidcfg[41], *voldir = NULL;
    const char *confdir;
    unsigned int cfgdata_len = 0;
    sxc_meta_t *meta = NULL, *custom_meta = NULL;
    const sxc_filter_t *f = sxc_get_filter(filter);

    if(f) {
        meta = sxc_meta_new(sx);
        custom_meta = sxc_meta_new(sx);
        if(!meta || !custom_meta) {
            ERROR("Cannot initiate meta");
            goto create_volume_err;
        }
        sxi_uuid_parse(f->uuid, uuid);
        if(sxc_meta_setval(meta, "filterActive", uuid, 16)) {
            ERROR("Metadata error");
            goto create_volume_err;
        }
        snprintf(uuidcfg, sizeof(uuidcfg), "%s-cfg", f->uuid);
        confdir = sxi_cluster_get_confdir(cluster);
        voldir = (char*)malloc(strlen(confdir) + strlen("/volumes/") + strlen(volname) + 1);
        if(!voldir) {
            ERROR("Cannot allocate memory for volume configuration directory");
            goto create_volume_err;
        }
        sprintf(voldir, "%s/volumes/%s", confdir, volname);
        /* Wipe existing local config */
        /* There is no check for '..' in the path since the path is fully based on the code, not on arguments. */
        if(sxi_rmdirs(voldir) && errno != ENOENT) {
            ERROR("Cannot wipe '%s' volume configuration directory: %s", voldir, strerror(errno));
            goto create_volume_err;
        }
        if(f->configure) {
            char *fdir;
	    int rc = 0;
            fdir = (char*)malloc(strlen(voldir) + 1 + strlen(f->uuid) + 1); /* The 1 inside is for '/' character. */
            if(!fdir) {
                ERROR("Cannot allocate memory for filter configuration dir");
                goto create_volume_err;
            }
            if(mkdir(voldir, 0700) == -1 && errno != EEXIST)
                rc = -1;
            sprintf(fdir, "%s/%s", voldir, f->uuid);
            if(access(fdir, F_OK)) {
                if(rc == -1 || (mkdir(fdir, 0700) == -1 && errno != EEXIST)) {
                    ERROR("Cannot create '%s' filter configuration directory: %s", fdir, strerror(errno));
                    free(fdir);
                    goto create_volume_err;
                }
	    }
	    if(f->configure(filter, filter_cfg, fdir, &cfgdata, &cfgdata_len, custom_meta)) {
                ERROR("Cannot configure filter");
		free(fdir);
		goto create_volume_err;
	    }
	    free(fdir);
	    if(cfgdata && sxc_meta_setval(meta, uuidcfg, cfgdata, cfgdata_len)) {
                ERROR("Cannot store filter configuration");
		goto create_volume_err;
	    }
	}
    }
    if(sxc_volume_add(cluster, volname, size ? size : VOLSIZE, replica, max_revisions, meta, owner)) {
        if(!hide_errors)
            ERROR("%s", sxc_geterrmsg(sx));
        goto create_volume_err;
    }
    if(sxc_meta_count(custom_meta) && sxc_volume_modify(cluster, volname, NULL, NULL, -1, -1, custom_meta)) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto create_volume_err;
    }
    if(sxi_volume_cfg_store(sx, cluster, volname, f ? f->uuid : NULL, cfgdata, cfgdata_len)) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto create_volume_err;
    }
    if(human_readable)
        PRINT("Volume '%s' (replica: %d, size: %0.f%c) created", volname, replica, to_human(size ? size : VOLSIZE), to_human_suffix(size ? size : VOLSIZE));
    else
        PRINT("Volume '%s' (replica: %d, size: %lld) created", volname, replica, (long long int)(size ? size : VOLSIZE));

    ret = 0;
create_volume_err:
    free(voldir);
    free(cfgdata);
    sxc_meta_free(meta);
    sxc_meta_free(custom_meta);
    return ret;
} /* create_volume */

static int delete_files(sxc_client_t *sx, sxc_cluster_t *cluster, const char *volname, const char *remote_path, int hide_errors) {
    int ret = 1, n;
    sxc_uri_t *uri = NULL;
    sxc_file_t *file = NULL;
    sxc_file_list_t *lst;
    sxc_cluster_lf_t *file_list = NULL; /* to be able to clean .Trash directory in undelete filter */

    if(!volname) {
        uri = sxc_parse_uri(sx, remote_path);
        if(!uri) {
            ERROR("%s", sxc_geterrmsg(sx));
            return ret;
        }
    }
    lst = sxc_file_list_new(sx, 0, 0);
    if(!lst) {
        ERROR("%s", sxc_geterrmsg(sx));
        sxc_file_free(file);
        goto delete_files_err;
    }
    if(remote_path[strlen(remote_path)-1] == '/') {
        file_list = sxc_cluster_listfiles(cluster, volname ? volname : uri->volume, volname ? remote_path : uri->path, 1, NULL, 0);
        if(!file_list) {
            if(!hide_errors)
                ERROR("Cannot get files list: %s", sxc_geterrmsg(sx));
            goto delete_files_err;
        }
        while(1) {
            const char *file_name;

            file = NULL;
            n = sxc_cluster_listfiles_next(cluster, volname ? volname : uri->volume, file_list, &file);
            if(n <= 0) {
                if(n) {
                    ERROR("%s", sxc_geterrmsg(sx));
                    goto delete_files_err;
                }
                break;
            }
            if(!file) {
                ERROR("NULL file name pointer received");
                goto delete_files_err;
            }
            file_name = sxc_file_get_path(file);
            if(sxc_file_list_add(lst, file, 0)) {
                ERROR("Cannot add '%s' into file list: %s", file_name, sxc_geterrmsg(sx));
                sxc_file_free(file);
                goto delete_files_err;
            }
        }
    } else {
        file = sxc_file_remote(cluster, volname ? volname : uri->volume, volname ? remote_path : uri->path, NULL);
        if(!file) {
            ERROR("Cannot open '%s' directory: %s", remote_path, sxc_geterrmsg(sx));
            goto delete_files_err;
        }
        if(sxc_file_list_add(lst, file, 0)) {
            ERROR("Cannot add '%s' into file list: %s", remote_path, sxc_geterrmsg(sx));
            sxc_file_free(file);
            goto delete_files_err;
        }
    }
    if(sxc_rm(lst, 0)) {
        if(!hide_errors)
            ERROR("Failed to remove file list: %s", sxc_geterrmsg(sx));
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

static int remove_volume(sxc_client_t *sx, sxc_cluster_t *cluster, const char *volname, int hide_errors) {
    int ret = 1;
    char *voldir = NULL;
    const char *confdir;

    if(delete_files(sx, cluster, volname, "/", hide_errors) && sxc_geterrnum(sx) != SXE_ECOMM) {
        ERROR("Cannot clear '%s' volume: %s", volname, sxc_geterrmsg(sx));
        return ret;
    }
    if(strstr(volname, "undelete") && delete_files(sx, cluster, volname, "/", hide_errors) && sxc_geterrnum(sx) != SXE_ECOMM) { /* wipe the trash */
        ERROR("Cannot clear '%s' volume's trash: %s", volname, sxc_geterrmsg(sx));
        return ret;
    }
    if(sxc_volume_remove(cluster, volname)) {
        if(!hide_errors)
            ERROR("%s", sxc_geterrmsg(sx));
        return ret;
    }
    PRINT("Volume '%s' removed", volname);
    confdir = sxi_cluster_get_confdir(cluster);
    voldir = (char*)malloc(strlen(confdir) + strlen("/volumes/") + strlen(volname) + 1);
    if(!voldir) {
        ERROR("Cannot allocate memory for volume configuration directory");
        return ret;
    }
    sprintf(voldir, "%s/volumes/%s", confdir, volname);
    if(!access(voldir, F_OK) && sxi_rmdirs(voldir)) {
        ERROR("Cannot wipe '%s' volume configuration directory: %s", voldir, strerror(errno));
        goto remove_volume_err;
    }

    ret = 0;
remove_volume_err:
    free(voldir);
    return ret;
} /* remove_volume */

struct user_data {
    char username[SXLIMIT_MAX_USERNAME_LEN+1];
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
static int prepare_users(sxc_client_t *sx, sxc_cluster_t *cluster, struct user_data *udata, unsigned int count) {
    int ret = -1;
    unsigned int i;
    if(!sx || !cluster || !udata || !count) {
        ERROR("NULL argument");
        return ret;
    }

    for(i = 0; i < count; i++) {
        /* Create first user */
        sprintf(udata[i].username, "user_XXXXXX");
        if(randomize_name(udata[i].username))
            goto prepare_users_err;
        udata[i].key = sxc_user_add(cluster, udata[i].username, NULL, udata[i].admin, NULL, NULL, 1, 0);
        if(!udata[i].key) {
            ERROR("Cannot create '%s' user: %s", udata[i].username, sxc_geterrmsg(sx));
            goto prepare_users_err;
        }
        if(sxc_cluster_add_access(cluster, udata[i].username, udata[i].key)) {
            ERROR("Failed to add '%s' profile authentication: %s", udata[i].username, sxc_geterrmsg(sx));
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
static void cleanup_users(sxc_client_t *sx, sxc_cluster_t *cluster, struct user_data *udata, unsigned int count) {
    unsigned int i;
    if(!sx || !cluster || !udata || !count) {
        ERROR("NULL argument");
        return;
    }

    for(i = 0; i < count; i++) {
        /* Delete user */
        if(*udata[i].username && sxc_user_remove(cluster, udata[i].username, 0))
            WARNING("Failed to cleanup user %s", udata[i].username);
        user_data_free(&udata[i]);
    }
}

struct vol_data {
    char name[SXLIMIT_MAX_VOLNAME_LEN+1];
    const char *owner;
    unsigned int replica;
    unsigned int revisions;
    int64_t size;
    const char *filter_name;
    const char *filter_cfg;
};

const char *filters_name[] = {"undelete", "zcomp", "aes256", "attribs", NULL};
const char *filters_cfg[] = {TRASH_NAME, ZCOMP_LEVEL, NULL, NULL, NULL};

/* Get configuration assigned to the filter */
static const char* get_filter_cfg (const sxf_handle_t *filter) {
    int i;
    const sxc_filter_t *f;
    if(!filter)
        return NULL;
    f = sxc_get_filter(filter);
    for(i=0; filters_name[i]; i++)
        if(!strcmp(filters_name[i], f->shortname))
            return filters_cfg[i];
    return NULL;
} /* get_filter_cfg */

static int get_filters (const sxf_handle_t *filters, int fcount, struct vol_data *vdata, int n, int rand_filters, const struct gengetopt_args_info *args) {
    int i, j, ret = -1, done;
    uint64_t seed, r;
    char *use_filter = NULL, *filter_name = NULL, *ptr = NULL;
    rnd_state_t state;
    const sxc_filter_t *filter;

    if(rand_filters) { /* Use filters */
        if(fcount < n) {
            ERROR("Not enough filters");
            return -2; /* TODO: is it a failure or not? */
        } else if(fcount == n) {
            for(i=0; i<fcount; i++) {
                filter = sxc_get_filter(&filters[i]);
                if(!strcmp(filter->uuid, "35a5404d-1513-4009-904c-6ee5b0cd8634")) { /* We have 'n' filters, cannot use one of them, not enough left */
                    ERROR("Not enough filters");
                    return -2; /* TODO: is it a failure or not? */
                }
            }
        }
        seed = make_seed();
        rnd_seed(&state, seed);
        if(args->use_filter_given) {
            use_filter = strdup(args->use_filter_arg);
            if(!use_filter) {
                ERROR("Out of memory");
                return ret;
            }
            ptr = use_filter;
        }
        for(i=0; i<n; i++) {
            if(ptr) {
                filter_name = ptr;
                ptr = strchr(filter_name, ':');
                if(ptr) {
                    *ptr = '\0';
                    ptr++;
                    if(!*ptr)
                        ptr = NULL;
                }
            }
            if(vdata[i].filter_name || filter_name) { /* Use specified filter (the one in the data structure has higher priority) */
                filter = NULL;
                for(j=0; j<fcount; j++) {
                    filter = sxc_get_filter(&filters[j]);
                    if(!strcmp(filter->shortname, vdata[i].filter_name ? vdata[i].filter_name : filter_name))
                        break;
                    filter = NULL;
                }
                if(!filter) {
                    ERROR("'%s' filter not found", vdata[i].filter_name ? vdata[i].filter_name : filter_name);
                    goto get_filters_err;
                }
            } else { /* Take random filter */
                while(1) {
                    r = rand_2cmres(&state) % (uint64_t)fcount;
                    filter = sxc_get_filter(&filters[r]);
                    if(!filter) {
                        ERROR("Cannot randomize the filter to use");
                        goto get_filters_err;
                    }
                    done = 1;
                    if(!strcmp(filter->uuid, "35a5404d-1513-4009-904c-6ee5b0cd8634")) { /* Don't use old aes filter */
                        done = 0;
                    } else {
                        for(j=0; j<i; j++)
                            if(!strcmp(filter->shortname, vdata[j].filter_name)) {
                                done = 0;
                                break;
                            }
                    }
                    if(done)
                        break;
                }
                j = (int)r; /* There should not be more filters than INT_MAX */
            }
            vdata[i].filter_name = filter->shortname;
            vdata[i].filter_cfg = get_filter_cfg(&filters[j]);
        }
    } else { /* Do not use filters */
        for(i=0; i<n; i++)
            vdata[i].filter_name = vdata[i].filter_cfg = NULL;
    }

    ret = 0;
get_filters_err:
    free(use_filter);
    return ret;
} /* get_filters */

/* Prepare volumes for testing */
static int prepare_volumes(sxc_client_t *sx, sxc_cluster_t *cluster, const sxf_handle_t *filters, int fcount, struct vol_data *vdata, unsigned int count, int human_readable, int hide_errors) {
    int j, ret = -1;
    unsigned int i;

    if(!sx || !cluster || !vdata || !count) {
        ERROR("NULL argument");
        return ret;
    }

    for(i = 0; i < count; i++) {
        snprintf(vdata[i].name, sizeof(vdata[i].name), "%s%u_%s_XXXXXX", VOLNAME, i + 1, vdata[i].filter_name ? vdata[i].filter_name : "NonFilter");
        if(randomize_name(vdata[i].name))
            goto prepare_volumes_err;
        j = fcount;
        if(vdata[i].filter_name) {
            for(j=0; j<fcount; j++) {
                const sxc_filter_t *f = sxc_get_filter(&filters[j]);
                if(!strcmp(vdata[i].filter_name, f->shortname))
                    break;
            }
            if(j == fcount) {
                ERROR("'%s' filter not loaded", vdata[i].filter_name);
                goto prepare_volumes_err;
            }
        }
        if(create_volume(sx, cluster, vdata[i].name, vdata[i].owner ? vdata[i].owner : "admin", vdata[i].size, j == fcount ? NULL : &filters[j], vdata[i].filter_cfg, vdata[i].replica ? vdata[i].replica : 1, vdata[i].revisions ? vdata[i].revisions : 1, human_readable, hide_errors))
            goto prepare_volumes_err;
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
static void cleanup_volumes(sxc_client_t *sx, sxc_cluster_t *cluster, struct vol_data *vdata, unsigned int count) {
    unsigned int i;

    for(i = 0; i < count; i++) {
        if(*vdata[i].name && remove_volume(sx, cluster, vdata[i].name, 1))
            WARNING("Failed to cleanup volume %s: %s", vdata[i].name, sxc_geterrmsg(sx));
    }
}

static int upload_file(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_path, const char *remote_path, int hide_errors) {
    int ret = 1;
    sxc_uri_t *uri;
    sxc_file_t *src, *dest = NULL;

    uri = sxc_parse_uri(sx, remote_path);
    if(!uri) {
        ERROR("%s", sxc_geterrmsg(sx));
        return ret;
    }
    src = sxc_file_local(sx, local_path);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", local_path, sxc_geterrmsg(sx));
        goto upload_file_err;
    }
    dest = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!dest) {
        ERROR("Cannot open '%s' file: %s", remote_path, sxc_geterrmsg(sx));
        goto upload_file_err;
    }
    if(sxc_copy_single(src, dest, local_path[strlen(local_path) - 1] == '/', 0, 0, NULL, 1)) {
        if(!hide_errors)
            ERROR("Cannot upload '%s' file: %s", local_path, sxc_geterrmsg(sx));
        goto upload_file_err;
    }

    ret = 0;
upload_file_err:
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* upload_file */

static int download_file(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_path, const char *remote_path) {
    int ret = 1;
    sxc_uri_t *uri;
    sxc_file_t *src, *dest = NULL;

    uri = sxc_parse_uri(sx, remote_path);
    if(!uri) {
        ERROR("%s", sxc_geterrmsg(sx));
        return ret;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        ERROR("Cannot open '%s': %s", remote_path, sxc_geterrmsg(sx));
        goto download_file_err;
    }
    dest = sxc_file_local(sx, local_path);
    if(!dest) {
        ERROR("Cannot open '%s': %s", local_path, sxc_geterrmsg(sx));
        goto download_file_err;
    }
    if(sxc_copy_single(src, dest, remote_path[strlen(remote_path)-1] == '/', 0, 0, NULL, 1)) {
        ERROR("Cannot download files from '%s': %s", remote_path, sxc_geterrmsg(sx));
        goto download_file_err;
    }

    ret = 0;
download_file_err:
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* download_file */

/* -1 - error
 *  0 - file not found
 *  1 - file found */
static int find_file(sxc_client_t *sx, sxc_cluster_t *cluster, const char *remote_file_path, int hide_errors) {
    int ret = -1, n;
    sxc_uri_t *uri;
    sxc_cluster_lf_t *file_list;
    sxc_file_t *file = NULL;

    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
        ERROR("%s", sxc_geterrmsg(sx));
        return ret;
    }
    file_list = sxc_cluster_listfiles(cluster, uri->volume, uri->path, 0, NULL, 0);
    if(!file_list) {
        if(!hide_errors)
            ERROR("Cannot get volume files list: %s", sxc_geterrmsg(sx));
        goto find_file_err;
    }
    n = sxc_cluster_listfiles_next(cluster, uri->volume, file_list, &file);
    if(n < 0) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto find_file_err;
    }
    if(n > 0 && (!file || !sxc_file_get_path(file))) {
        ERROR("NULL file name pointer received");
        goto find_file_err;
    }

    ret = n ? 1 : 0;
find_file_err:
    sxc_file_free(file);
    sxc_free_uri(uri);
    sxc_cluster_listfiles_free(file_list);
    return ret;
} /* find_file */

static void create_block(rnd_state_t *state, unsigned char *block, uint64_t block_size) {
    uint64_t i;
    for(i=0; i<block_size; i++)
        block[i] = rand_2cmres(state);
} /* create_block */

static int create_file(const char* local_file_path, uint64_t block_size, uint64_t block_count, unsigned char sha_hash[SXI_SHA1_BIN_LEN], int force_size) {
    int ret = 1;
    uint64_t seed, i;
    unsigned char *block = NULL;
    FILE *file;
    rnd_state_t state;
    sxi_md_ctx *ctx = NULL;

    if(!force_size)
        switch(block_size) {
            case SX_BS_SMALL:
                if(block_count > 31)
                    WARNING("Wrong blocksize");
                break;
            case SX_BS_MEDIUM:
                if(block_count < 32 || block_count > 8192)
                    WARNING("Wrong blocksize");
                break;
            case SX_BS_LARGE:
                if(block_count < 129)
                    WARNING("Wrong blocksize");
                break;
            default:
                ERROR("Unknown blocksize");
                return ret;
        }
    file = fopen(local_file_path, "wrb");
    if(!file) {
        ERROR("Cannot create '%s' file: %s", local_file_path, strerror(errno));
        return ret;
    }
    if(block_size && block_count) {
        ctx = sxi_md_init();
        if(!ctx) {
            ERROR("Cannot allocate memory for checksum");
            goto create_file_err;
        }
        block = (unsigned char*)malloc(block_size);
        if(!block) {
            ERROR("Cannot allocate memory for block");
            goto create_file_err;
        }
        seed = make_seed();
        PRINT("Seed: %012lx", seed);
        rnd_seed(&state, seed);
        create_block(&state, block, block_size);
        if(sha_hash && !sxi_sha1_init(ctx)) {
            ERROR("Checksum init failure");
            goto create_file_err;
        }
        for(i=0; i<block_count; i++) {
            if(fwrite(block, sizeof(unsigned char), block_size, file) != block_size) {
                ERROR("Error while writing to '%s' file (%llu)", local_file_path, (unsigned long long)i);
                goto create_file_err;
            }
            if(sha_hash && !sxi_sha1_update(ctx, block, block_size)) {
                ERROR("Checksum update failure (%llu)", (unsigned long long)i);
                goto create_file_err;
            }
        }
        if(sha_hash && !sxi_sha1_final(ctx, sha_hash, NULL)) {
            ERROR("Checksum final calculation failure");
            goto create_file_err;
        }
    }

    ret = 0;
create_file_err:
    free(block);
    sxi_md_cleanup(&ctx);
    if(file) {
        if(fclose(file) == EOF)
            WARNING("Cannot close '%s' file: %s", local_file_path, strerror(errno));
        if(ret && unlink(local_file_path))
            WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    }
    return ret;
} /* create_file */

/* -1 - error
    0 - OK
    1 - hashes differ */
static int check_file_content(const char *path, unsigned char sha_hash[SXI_SHA1_BIN_LEN]) {
    int ret = -1, fd = -1;
    char buff[1024];
    unsigned char local_hash[SXI_SHA1_BIN_LEN];
    ssize_t rbytes;
    sxi_md_ctx *ctx = sxi_md_init();

    if(!ctx) {
        ERROR("Cannot allocate memory for checksum");
        return -1;
    }
    if(!sxi_sha1_init(ctx)) {
        ERROR("Checksum init failure");
        goto check_file_content_err;
    }
    fd = open(path, O_RDONLY);
    if(fd < 0) {
        ERROR("Cannot open '%s' file: %s", path, strerror(errno));
        goto check_file_content_err;
    }
    while(1) {
        if((rbytes = read(fd, buff, sizeof(buff))) < 0) {
            ERROR("Cannot read from '%s' file: %s", path, strerror(errno));
            goto check_file_content_err;
        }
        if(!rbytes)
            break;
        if(!sxi_sha1_update(ctx, buff, rbytes)) {
            ERROR("Checksum update failure");
            goto check_file_content_err;
        }
    }
    if(!sxi_sha1_final(ctx, local_hash, NULL)) {
        ERROR("Checksum final calculation failure");
        goto check_file_content_err;
    }
    if(memcmp(sha_hash, local_hash, SXI_SHA1_BIN_LEN)) {
        ERROR("Hashes differ");
        ret = 1;
        goto check_file_content_err;
    }

    ret = 0;
check_file_content_err:
    sxi_md_cleanup(&ctx);
    if(fd >= 0)
        close(fd);
    return ret;
} /* check_file_content */

static int check_filemeta(sxc_client_t *sx, sxc_file_t *file, const char *filter_name) {
    int ret = -1;
    const void *data;
    sxc_meta_t *fmeta;

    fmeta = sxc_filemeta_new(file);
    if(!fmeta) {
        ERROR("Cannot get filemeta: %s", sxc_geterrmsg(sx));
        return ret;
    }
    if(!filter_name || !strcmp(filter_name, "undelete")) {
        if(sxc_meta_count(fmeta) != 0) {
            ERROR("%s: Wrong number of entries (%u != 0)", filter_name, sxc_meta_count(fmeta));
            goto check_filemeta_err;
        }
    } else if(!strcmp(filter_name, "attribs")) {
        unsigned int i = 0;
        const char *attribs[] = {"attribsName", "attribsMode", "attribsUID", "attribsGID", "attribsAtime", "attribsMtime", "attribsSize", NULL};

        if(sxc_meta_count(fmeta) != sizeof(attribs) / sizeof(char*) - 1) { /* -1 is because of NULL at the end */
            ERROR("%s: Wrong number of entries (%u != %u)", filter_name, sxc_meta_count(fmeta), sizeof(attribs) / sizeof(char*) - 1);
            goto check_filemeta_err;
        }
        for(; attribs[i]; i++)
            if(sxc_meta_getval(fmeta, attribs[i], &data, NULL)) {
                ERROR("'%s' meta entry unavailable", attribs[i]);
                goto check_filemeta_err;
            }
    } else if(!strcmp(filter_name, "aes256")) {
        if(sxc_meta_count(fmeta) != 2) {
            ERROR("%s: Wrong number of entries (%u != 2)", filter_name, sxc_meta_count(fmeta));
            goto check_filemeta_err;
        }
    } else if(!strcmp(filter_name, "zcomp")) {
        if(sxc_meta_count(fmeta) != 1) {
            ERROR("%s: Wrong number of entries (%u != 1)", filter_name, sxc_meta_count(fmeta));
            goto check_filemeta_err;
        }
    } else {
        ERROR("Unknown filter: %s", filter_name);
        goto check_filemeta_err;
    }

    ret = 0;
check_filemeta_err:
    sxc_meta_free(fmeta);
    return ret;
} /* check_filemeta */

static int test_empty_file(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = 1;
    char *local_file_path, *remote_file_path = NULL;

    PRINT("Started");
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(EMPTY_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_empty_file_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, EMPTY_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(EMPTY_FILE_NAME) + 1);
    if(!remote_file_path) {
        ERROR("Cannot allocate memory for remote_file_path");
        goto test_empty_file_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, EMPTY_FILE_NAME);
    if(create_file(local_file_path, 0, 0, NULL, 1))
        goto test_empty_file_err;
    if(upload_file(sx, cluster, local_file_path, remote_dir_path, 0)) {
        ERROR("Cannot upload '%s' file", local_file_path);
        goto test_empty_file_err;
    }
    switch(find_file(sx, cluster, remote_file_path, 0)) {
        case -1:
            ERROR("Looking for '%s' file failed", remote_file_path);
            goto test_empty_file_err;
        case 0:
            ERROR("'%s' file has not been uploaded correctly", REV_FILE_NAME);
            goto test_empty_file_err;
        case 1: break;
    }

    ret = 0;
    PRINT("Succeeded");
test_empty_file_err:
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    free(remote_file_path);
    free(local_file_path);
    return ret;
} /* test_empty_file */

static int test_transfer(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = 1;
    char *local_file_path = NULL, *remote_file_path = NULL;
    unsigned char *block = NULL, hash[SXI_SHA1_BIN_LEN];

    PRINT("Started");
    if(sxc_cluster_set_progress_cb(sx, cluster, test_callback, (void*)&bytes)) {
        ERROR("Cannot set callback");
        return ret;
    }
    block = (unsigned char*)malloc(block_size);
    if(!block) {
        ERROR("Cannot allocate memory for block");
        return ret;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(UD_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_transfer_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, UD_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(UD_FILE_NAME) + 1);
    if(!remote_file_path) {
        ERROR("Cannot allocate memory for remote_file_path");
        goto test_transfer_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, UD_FILE_NAME);
    if(args->human_flag)
        PRINT("Creating file of size: %.2f%c (%llu*%.0f%c)", to_human(block_size*block_count), to_human_suffix(block_size*block_count), (unsigned long long)block_count, to_human(block_size), to_human_suffix(block_size));
    else
        PRINT("Creating file of size: %llu (%llu*%llu)", (unsigned long long)block_size*block_count, (unsigned long long)block_count, (unsigned long long)block_size);
    if(create_file(local_file_path, block_size, block_count, hash, 0))
        goto test_transfer_err;
    PRINT("Uploading");
    if(upload_file(sx, cluster, local_file_path, remote_dir_path, 0)) {
        ERROR("Cannot upload '%s' file", local_file_path);
        if(unlink(local_file_path))
            ERROR("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
        goto test_transfer_err;
    }
    if(unlink(local_file_path)) {
        ERROR("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
        goto test_transfer_err;
    }
    if(check_data_size && (int64_t)block_size != bytes) {
        ERROR("Wrong amount of data has been uploaded");
        goto test_transfer_err;
    }
    PRINT("Downloading");
    if(download_file(sx, cluster, local_file_path, remote_file_path)) {
        ERROR("Cannot download '%s' file", remote_file_path);
        goto test_transfer_err;
    }
    if(delete_files(sx, cluster, NULL, remote_file_path, 0)) {
        ERROR("Cannot remove '%s' file: %s", remote_file_path, sxc_geterrmsg(sx));
        goto test_transfer_err;
    }
    switch(check_file_content(local_file_path, hash)) {
        case -1:
            ERROR("Checking file content failed");
            goto test_transfer_err;
        case 0: /* Downloaded file is correct */
            break;
        case 1:
            ERROR("Downloaded file differs from the original one");
            goto test_transfer_err;
    }
    
    ret = 0;
    PRINT("Succeeded");
test_transfer_err:
    free(block);
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    free(remote_file_path);
    return ret;
} /* test_transfer */

static int test_revision(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = 1;
    char *local_file_path = NULL, *remote_file_path = NULL;
    unsigned char *block, **hashes = NULL;
    sxc_uri_t *uri = NULL;
    sxc_file_t *src = NULL, *dest = NULL, *dest2 = NULL, *dest3 = NULL;
    sxc_revlist_t *revs = NULL;
    unsigned int i;
    struct vol_data vdata;

    PRINT("Started (revision: %d)", max_revisions);
    memset(&vdata, 0, sizeof(vdata));
    block = (unsigned char*)malloc(block_size);
    if(!block) {
        ERROR("Cannot allocate memory for block");
        return ret;
    }
    hashes = (unsigned char**)calloc(max_revisions, sizeof(unsigned char*));
    if(!hashes) {
        ERROR("Cannot allocate memory for hashes");
        goto test_revision_err;
    }
    for(i=0; i<max_revisions; i++) {
        hashes[i] = (unsigned char*)malloc(SXI_SHA1_BIN_LEN);
        if(!hashes[i]) {
            ERROR("Cannot allocate memory for hashes[%d])", i);
            goto test_revision_err;
        }
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(REV_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_revision_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, REV_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(REV_FILE_NAME) + 1);
    if(!remote_file_path) {
        ERROR("Cannot allocate memory for remote_file_path");
        goto test_revision_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, REV_FILE_NAME);
    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(args->human_flag)
        PRINT("Creating and uploading files of size: %.2f%c (%llu*%.0f%c)", to_human(block_size*block_count), to_human_suffix(block_size*block_count), (unsigned long long)block_count, to_human(block_size), to_human_suffix(block_size));
    else
        PRINT("Creating and uploading files of size: %llu (%llu*%llu)", (unsigned long long)block_size*block_count, (unsigned long long)block_count, (unsigned long long)block_size);
    src = sxc_file_local(sx, local_file_path);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    dest = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!dest) {
        ERROR("Cannot open '%s' file: %s", remote_file_path, sxc_geterrmsg(sx));
        goto test_revision_err;
    }

    vdata.owner = args->owner_arg;
    vdata.replica = args->replica_arg;
    if(get_filters(filters, fcount, &vdata, 1, rand_filters, args)) {
        ERROR("Cannot get filter");
        goto test_revision_err;
    }
    PRINT("Using volume with filter: %s (%s)", vdata.filter_name, vdata.filter_cfg);
    if(prepare_volumes(sx, cluster, filters, fcount, &vdata, 1, args->human_flag, 0)) {
        ERROR("Failed to prepare volumes");
        goto test_revision_err;
    }

    for(i=0; i<max_revisions; i++) {
        if(create_file(local_file_path, block_size, block_count, hashes[max_revisions-1-i], !i))
            goto test_revision_err;
        if(sxc_copy_single(src, dest, 0, 0, 0, NULL, 1)) {
            ERROR("Cannot upload '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
            goto test_revision_err;
        }
        if(unlink(local_file_path)) {
            ERROR("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
            goto test_revision_err;
        }
    }
    sxc_file_free(src);
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", remote_file_path, sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    revs = sxc_revisions(src);
    if(!revs) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(max_revisions > revs->count) {
        ERROR("Not enough revisions");
        goto test_revision_err;
    } else if(max_revisions < revs->count) {
        ERROR("Too many revisions");
        goto test_revision_err;
    }
    PRINT("Checking file versions");
    for(i=0; i<max_revisions; i++) {
        sxc_file_free(src);
        src = sxc_file_remote(cluster, uri->volume, uri->path, sxc_file_get_revision(revs->revisions[i]->file));
        if(!src) {
            ERROR("Cannot open '%s' (%s) file: %s (%d)", remote_file_path, sxc_file_get_revision(revs->revisions[i]->file), sxc_geterrmsg(sx), i);
            goto test_revision_err;
        }
        sxc_file_free(dest);
        dest = sxc_file_local(sx, local_file_path);
        if(!dest) {
            ERROR("Cannot open '%s': %s", local_file_path, sxc_geterrmsg(sx));
            goto test_revision_err;
        }
        if(sxc_copy_sxfile(src, dest, 1)) {
            ERROR("Cannot download '%s' file: %s (%d)", remote_file_path, sxc_geterrmsg(sx), i);
            goto test_revision_err;
        }
        switch(check_file_content(local_file_path, hashes[i])) {
            case -1:
                ERROR("Checking file content failed (%d)", i);
                goto test_revision_err;
            case 0: /* Downloaded file is correct */
                break;
            case 1:
                ERROR("Downloaded file differs from the original one (%d)", i);
                goto test_revision_err;
        }
        if(unlink(local_file_path)) {
            ERROR("Cannot delete '%s' file: %s (%d)", local_file_path, strerror(errno), i);
            goto test_revision_err;
        }
    }

    sxc_file_free(src);
    src = sxc_file_remote(cluster, uri->volume, uri->path, sxc_file_get_revision(revs->revisions[max_revisions/2]->file));
    if(!src) {
        ERROR("Cannot open '%s' (%s) file: %s", remote_file_path, sxc_file_get_revision(revs->revisions[i]->file), sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(sxi_filemeta_process(sx, NULL, NULL, src, NULL)) { /* workaround for bb#1878 */
        ERROR("Cannot process filemeta: %s", sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    /* Copy the revision within the same volume */
    PRINT("Checking revision within the same volume");
    dest2 = sxc_file_remote(cluster, uri->volume, REV_FILE_NAME"-copy", NULL);
    if(!dest2) {
        ERROR("Cannot open '%s/%s' file: %s", uri->volume, REV_FILE_NAME"-copy", sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(sxc_copy_sxfile(src, dest2, 1)) {
        ERROR("Cannot copy '%s' file within same volume: %s", remote_file_path, sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(check_filemeta(sx, dest2, vol_filter))
        goto test_revision_err;
    /* Copy revision into another volume */
    PRINT("Checking revision on another volume");
    dest3 = sxc_file_remote(cluster, vdata.name, uri->path, NULL);
    if(!dest3) {
        ERROR("Cannot open '%s/%s' file: %s", vdata.name, uri->path, sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(sxc_copy_sxfile(src, dest3, 1)) {
        ERROR("Cannot copy '%s' file to another volume: %s", remote_file_path, sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    if(check_filemeta(sx, dest3, vdata.filter_name))
        goto test_revision_err;
    /* Remove the revision */
    if(sxc_remove_sxfile(src)) {
        ERROR("Cannot remove '%s' (%s) file: %s", remote_file_path, sxc_file_get_revision(revs->revisions[max_revisions/2]->file), sxc_geterrmsg(sx));
        goto test_revision_err;
    }
    /* Check the revision after its deletion */
    if(sxc_copy_sxfile(src, dest, 1)) {
        if(sxc_geterrnum(sx) == SXE_ECOMM)
            PRINT("File revision removed correctly");
        else {
            ERROR("Cannot download '%s' file: %s", remote_file_path, sxc_geterrmsg(sx));
            goto test_revision_err;
        }
    } else {
        ERROR("Nonexistent file revision has been downloaded");
        goto test_revision_err;
    }
    if(delete_files(sx, cluster, uri->volume, uri->path, 0)) {
        ERROR("Cannot delete '%s' file", remote_file_path);
        goto test_revision_err;
    }
    switch(find_file(sx, cluster, remote_file_path, 0)) {
        case -1:
            ERROR("Looking for '%s' file in '%s' failed", REV_FILE_NAME, remote_file_path);
            goto test_revision_err;
        case 0: break;
        case 1:
            ERROR("'%s' file has not been deleted correctly", REV_FILE_NAME);
            goto test_revision_err;
    }

    ret = 0;
    PRINT("Succeeded");
test_revision_err:
    cleanup_volumes(sx, cluster, &vdata, 1);
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
    sxc_file_free(dest2);
    sxc_file_free(dest3);
    sxc_revisions_free(revs);
    return ret;
} /* test_revision */

static int test_cat(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int fd = 0, ret = 1;
    char *local_file_path = NULL, *cat_file_path = NULL, *remote_file_path = NULL;
    unsigned char *block = NULL, hash[SXI_SHA1_BIN_LEN];
    sxc_uri_t *uri = NULL;
    sxc_file_t *src = NULL;

    PRINT("Started");
    block = (unsigned char*)malloc(SX_BS_LARGE);
    if(!block) {
        ERROR("Cannot allocate memory for block");
        return ret;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(CAT_FILE_NAME_IN) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_cat_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, CAT_FILE_NAME_IN);
    cat_file_path = (char*)malloc(strlen(local_dir_path) + strlen(CAT_FILE_NAME_OUT) + 1);
    if(!cat_file_path) {
        ERROR("Cannot allocate memory for cat_file_path");
        goto test_cat_err;
    }
    sprintf(cat_file_path, "%s%s", local_dir_path, CAT_FILE_NAME_OUT);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(CAT_FILE_NAME_IN) + 1);
    if(!remote_file_path) {
        ERROR("Cannot allocate memory for remote_file_path");
        goto test_cat_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, CAT_FILE_NAME_IN);
    if(create_file(local_file_path, SX_BS_LARGE, CAT_FILE_SIZE, hash, 1))
        goto test_cat_err;
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 0)) {
        ERROR("Cannot upload '%s' file", local_file_path);
        if(unlink(local_file_path))
            ERROR("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
        goto test_cat_err;
    }
    if(unlink(local_file_path)) {
        ERROR("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
        goto test_cat_err;
    }
    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
	ERROR("%s", sxc_geterrmsg(sx));
        goto test_cat_err;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", remote_file_path, sxc_geterrmsg(sx));
        goto test_cat_err;
    }
    fd = open(cat_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(fd < 0) {
        ERROR("Cannot create new file: %s", strerror(errno));
        goto test_cat_err;
    }
    PRINT("Processing the file");
    if(sxc_cat(src, fd)) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto test_cat_err;
    }
    switch(check_file_content(cat_file_path, hash)) {
        case -1:
            ERROR("Checking file content failed");
            goto test_cat_err;
        case 0: /* Downloaded file is correct */
            break;
        case 1:
            ERROR("Downloaded file differs from the original one");
            goto test_cat_err;
    }
    PRINT("Succeeded");

    ret = 0;
test_cat_err:
    if(fd >= 0 && close(fd))
        WARNING("Cannot close '%s' file: %s", cat_file_path, strerror(errno));
    if(cat_file_path && unlink(cat_file_path) && errno != ENOENT)
        WARNING("Cannot delete '%s' file: %s", cat_file_path, strerror(errno));
    free(block);
    free(local_file_path);
    free(cat_file_path);
    free(remote_file_path);
    sxc_free_uri(uri);
    sxc_file_free(src);
    return ret;
} /* test_cat */

static int test_rename(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = 1, retval;
    char *local_file_path, *remote_file_path;
    sxc_uri_t *uri = NULL;
    sxc_file_t *src = NULL, *dest = NULL;

    PRINT("Started");
    local_file_path = (char*)malloc(strlen(local_dir_path) + lenof(RENAME_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        return ret;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, RENAME_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + lenof(RENAME_FILE_NAME) + lenof("_new") + 1);
    if(!remote_file_path) {
        ERROR("Cannot allocate memory for remote_file_path");
        goto test_rename_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, RENAME_FILE_NAME);
    if(create_file(local_file_path, 0, 0, NULL, 1))
        goto test_rename_err;
    if(upload_file(sx, cluster, local_file_path, remote_dir_path, 0)) {
        ERROR("Cannot upload '%s' file", local_file_path);
        goto test_rename_err;
    }
    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto test_rename_err;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", remote_file_path, sxc_geterrmsg(sx));
        goto test_rename_err;
    }
    sprintf(remote_file_path, "%s%s_new", remote_dir_path, RENAME_FILE_NAME);
    sxc_free_uri(uri);
    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto test_rename_err;
    }
    dest = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!dest) {
        ERROR("Cannot open '%s' file: %s", remote_file_path, sxc_geterrmsg(sx));
        goto test_rename_err;
    }
    if((retval = sxc_mass_rename(cluster, src, dest, 0))) {
        if(!strcmp(vol_filter, "aes256") && retval == -2) {
            PRINT("Mass rename filename processing error enforced correctly");
        } else {
            ERROR("Mass rename failed: %s", sxc_geterrmsg(sx));
            goto test_rename_err;
        }
    }
    if(retval == 0) {
        switch(find_file(sx, cluster, remote_file_path, 0)) {
            case -1:
                ERROR("Looking for '%s' file failed", remote_file_path);
                goto test_rename_err;
            case 0:
                ERROR("'%s' file has not been renamed correctly", remote_file_path);
                goto test_rename_err;
            case 1: break;
        }
        if(delete_files(sx, cluster, NULL, remote_file_path, 1)) {
            ERROR("Cannot delete '%s' file", remote_file_path);
            goto test_rename_err;
        }
        sprintf(remote_file_path, "%s%s", remote_dir_path, RENAME_FILE_NAME);
        switch(find_file(sx, cluster, remote_file_path, 0)) {
            case -1:
                ERROR("Looking for '%s' file failed", remote_file_path);
                goto test_rename_err;
            case 0: break;
            case 1:
                ERROR("'%s' file has not been renamed correctly", remote_file_path);
                goto test_rename_err;
        }
    } else {
        switch(find_file(sx, cluster, remote_file_path, 0)) {
            case -1:
                ERROR("Looking for '%s' file failed", remote_file_path);
                goto test_rename_err;
            case 0: break;
            case 1:
                ERROR("'%s' file should not be renamed", remote_file_path);
                goto test_rename_err;
        }
        sprintf(remote_file_path, "%s%s", remote_dir_path, RENAME_FILE_NAME);
        switch(find_file(sx, cluster, remote_file_path, 0)) {
            case -1:
                ERROR("Looking for '%s' file failed", remote_file_path);
                goto test_rename_err;
            case 0:
                ERROR("'%s' file should not be renamed", remote_file_path);
                goto test_rename_err;
            case 1: break;
        }
        if(delete_files(sx, cluster, NULL, remote_file_path, 1)) {
            ERROR("Cannot delete '%s' file", remote_file_path);
            goto test_rename_err;
        }
    }
    PRINT("Succeeded");

    ret = 0;
test_rename_err:
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        ERROR("Cannot remove '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    free(remote_file_path);
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* test_rename */

static int test_errors(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = 1;
    char *local_file_path, *remote_file_path = NULL, *wrong_name = NULL, revision[]="2014-13-32 25:61:69.460:ac6ed3c7a371107a763da500c165c37c"; /* Revision is made of impossible date + md5sum of /dev/urandom */
    sxc_uri_t *uri = NULL;
    sxc_file_t *src = NULL, *dest = NULL;
    sxc_cluster_t *cl_tmp;

    PRINT("Started");
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(ERRORS_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        return ret;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, ERRORS_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + 1 + strlen(ERRORS_FILE_NAME) + 6 + 1); /* The 1's inside are for '@' and '/' characters + "XXXXXX" part */
    if(!remote_file_path) {
        ERROR("Cannot allocate memory for remote_file_path");
        goto test_errors_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, ERRORS_FILE_NAME);
    if(create_file(local_file_path, 0, 0, NULL, 1))
        goto test_errors_err;
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 0)) {
        ERROR("Cannot upload '%s' file", local_file_path);
        goto test_errors_err;
    }
    uri = sxc_parse_uri(sx, remote_file_path);
    if(!uri) {
	ERROR("%s", sxc_geterrmsg(sx));
        goto test_errors_err;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, revision);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", remote_file_path, sxc_geterrmsg(sx));
        goto test_errors_err;
    }
    dest = sxc_file_local(sx, local_file_path);
    if(!dest) {
        ERROR("Cannot open '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        goto test_errors_err;
    }
    if(sxc_copy_sxfile(src, dest, 1)) {
        if(sxc_geterrnum(sx) == SXE_ECOMM)
            PRINT("'Failed to download file content hashes' enforced correctly");
        else {
            ERROR("Cannot download '%s' file: %s", remote_file_path, sxc_geterrmsg(sx));
            goto test_errors_err;
        }
    } else {
        ERROR("Nonexistent file revision has been downloaded");
        goto test_errors_err;
    }
    if(delete_files(sx, cluster, uri->volume, uri->path, 0)) {
        ERROR("Cannot delete '%s' file", remote_file_path);
        goto test_errors_err;
    }
    sxc_file_free(src);
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", remote_file_path, sxc_geterrmsg(sx));
        goto test_errors_err;
    }
    if(sxc_cat(src, STDOUT_FILENO)) {
        if(sxc_geterrnum(sx) == SXE_ECOMM)
            PRINT("'Failed to locate volume' enforced correctly");
        else {
            ERROR("%s", sxc_geterrmsg(sx));
            goto test_errors_err;
        }
    } else {
        ERROR("File from nonexistent volume has been shown");
        goto test_errors_err;
    }
    wrong_name = (char*)malloc(strlen(uri->host) + strlen(uri->volume) + strlen("XXXXXX") + 1);
    if(!wrong_name) {
        ERROR("Cannot allocate memory for wrong_name");
        goto test_errors_err;
    }
    sprintf(wrong_name, "%sXXXXXXX", uri->host);
    if(randomize_name(wrong_name))
        goto test_errors_err;
    cl_tmp = sxc_cluster_load_and_update(sx, wrong_name, NULL);
    if(!cl_tmp) {
        if(sxc_geterrnum(sx) == SXE_ECFG)
            PRINT("'Cannot stat configuration directory' enforced correctly");
        else {
            ERROR("Cannot load '%s' cluster: %s", wrong_name, sxc_geterrmsg(sx));
            goto test_errors_err;
        }
    } else {
        ERROR("Loaded nonexistent cluster");
        sxc_cluster_free(cl_tmp);
        goto test_errors_err;
    }
    sprintf(wrong_name, "%sXXXXXXX", uri->volume);
    if(randomize_name(wrong_name))
        goto test_errors_err;
    sprintf(remote_file_path, "sx://%s%s%s/%s/", uri->profile ? uri->profile : "", uri->profile ? "@" : "", uri->host, wrong_name);
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 1)) {
        if(sxc_geterrnum(sx) == SXE_ECOMM)
            PRINT("'No such volume' enforced correctly");
        else {
            ERROR("Cannot upload '%s' file", local_file_path);
            goto test_errors_err;
        }
    } else {
        ERROR("File has been copied to nonexistent volume");
        goto test_errors_err;
    }
    if(unlink(local_file_path)) {
        ERROR("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
        goto test_errors_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, ERRORS_FILE_NAME);
    if(upload_file(sx, cluster, local_file_path, remote_dir_path, 1)) {
        if(sxc_geterrnum(sx) == SXE_EREAD)
            PRINT("'No such file or directory' enforced correctly");
        else {
            ERROR("Cannot upload '%s' file", local_file_path);
            goto test_errors_err;
        }
    } else {
        ERROR("Copied nonexistent file");
        goto test_errors_err;
    }
    if(sxc_volume_remove(cluster, wrong_name)) {
        if(sxc_geterrnum(sx) == SXE_ECOMM)
            PRINT("'Failed to locate volume' enforced correctly");
        else {
            ERROR("%s", sxc_geterrmsg(sx));
            goto test_errors_err;
        }
    } else {
        ERROR("Nonexistent volume has been removed");
        goto test_errors_err;
    }

    PRINT("Succeeded");
    ret = 0;
test_errors_err:
    if(unlink(local_file_path) && errno != ENOENT)
        WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    free(wrong_name);
    free(local_file_path);
    free(remote_file_path);
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* test_errors */

static int test_attribs(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int i, ret = 1, owner, group, other;
    long int tmp_time;
    char *local_files_paths[ATTRIBS_COUNT], *remote_files_paths[ATTRIBS_COUNT];
    uint64_t seed;
    mode_t attribs;
    rnd_state_t state;
    struct utimbuf time;
    struct timeval tv;
    struct stat st, t_st[ATTRIBS_COUNT];

    PRINT("Started");
    memset(local_files_paths, 0, sizeof(local_files_paths));
    memset(remote_files_paths, 0, sizeof(remote_files_paths));
    seed = make_seed();
    PRINT("Seed: %012lx", seed);
    rnd_seed(&state, seed);
    for(i=0; i<ATTRIBS_COUNT; i++) {
        local_files_paths[i] = (char*)malloc(strlen(local_dir_path) + strlen(ATTRIBS_FILE_NAME) + 2 + 1);
        if(!local_files_paths[i]) {
            ERROR("Cannot allocate memory for local_files_paths[%d]", i);
            goto test_attribs_err;
        }
        sprintf(local_files_paths[i], "%s%s%d", local_dir_path, ATTRIBS_FILE_NAME, i);
        remote_files_paths[i] = (char*)malloc(strlen(remote_dir_path) + strlen(ATTRIBS_FILE_NAME) + 2 + 1);
        if(!remote_files_paths[i]) {
            ERROR("Cannot allocate memory for remote_files_paths[%d]", i);
            goto test_attribs_err;
        }
        sprintf(remote_files_paths[i], "%s%s%d", remote_dir_path, ATTRIBS_FILE_NAME, i);
        if(create_file(local_files_paths[i], 0, 0, NULL, 1))
            goto test_attribs_err;
        owner = (rand_2cmres(&state)%8) | 4;
        group = rand_2cmres(&state)%8;
        other = rand_2cmres(&state)%8;
        PRINT("Rights being tested: %c%c%c%c%c%c%c%c%c", owner&4 ? 'r' : '-', owner&2 ? 'w' : '-', owner&1 ? 'x' : '-', group&4 ? 'r' : '-', group&2 ? 'w' : '-', group&1 ? 'x' : '-', other&4 ? 'r' : '-', other&2 ? 'w':'-', other&1 ? 'x' : '-');
        attribs = (owner<<6) | (group<<3) | other;
        if(chmod(local_files_paths[i], attribs)) {
            ERROR("Cannot set attributes for '%s' file: %s", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
        }
        if(gettimeofday(&tv, NULL)) {
            ERROR("Cannot get current time: %s", strerror(errno));
            goto test_attribs_err;
        }
        tmp_time = (long int)rand_2cmres(&state) % 100000000;
        if((owner + group + other)&1)
            tmp_time *= -1;
        time.actime = 0;
        time.modtime = tv.tv_sec + tmp_time;
        if(utime(local_files_paths[i], &time)) {
            ERROR("Cannot set modification time for '%s' file: %s", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
        }
        if(stat(local_files_paths[i], &t_st[i]) == -1) {
            ERROR("stat() failed for '%s': %s", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
	}
    }
    if(upload_file(sx, cluster, local_dir_path, remote_dir_path, 0)) {
        ERROR("Cannot upload files from '%s'", local_dir_path);
        goto test_attribs_err;
    }
    for(i=0; i<ATTRIBS_COUNT; i++) {
       if(unlink(local_files_paths[i])) {
            ERROR("Cannot delete '%s' file: %s", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
       }
    }
    if(download_file(sx, cluster, local_dir_path, remote_dir_path)) {
        ERROR("Cannot download files from '%s'", remote_dir_path);
        goto test_attribs_err;
    }
    for(i=0; i<ATTRIBS_COUNT; i++) {
        if(stat(local_files_paths[i], &st) == -1) {
            ERROR("stat() failed for '%s': %s", local_files_paths[i], strerror(errno));
            goto test_attribs_err;
	}
        if(st.st_mode != t_st[i].st_mode) {
            ERROR("File attributes differ for '%s'", local_files_paths[i]);
            goto test_attribs_err;
        }
        if(st.st_mtime != t_st[i].st_mtime) {
            ERROR("File modification time differs for '%s'", local_files_paths[i]);
            goto test_attribs_err;
        }
    }

    PRINT("Succeeded");
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

static int test_undelete(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = 1;
    char *local_file_path, *remote_file_path = NULL;
    sxc_uri_t *uri;

    PRINT("Started");
    uri = sxc_parse_uri(sx, remote_dir_path);
    if(!uri) {
        ERROR("%s", sxc_geterrmsg(sx));
        return ret;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(UNDELETE_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_undelete_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, UNDELETE_FILE_NAME);
    remote_file_path = (char*)malloc(strlen(remote_dir_path) + strlen(TRASH_NAME) + strlen(UNDELETE_FILE_NAME) + 1);
    if(!remote_file_path) {
        ERROR("Cannot allocate memory for remote_file_path");
        goto test_undelete_err;
    }
    sprintf(remote_file_path, "%s%s", remote_dir_path, UNDELETE_FILE_NAME);
    if(create_file(local_file_path, 0, 0, NULL, 1))
        goto test_undelete_err;
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 0)) {
        ERROR("Cannot upload '%s' file", local_file_path);
        goto test_undelete_err;
    }
    if(delete_files(sx, cluster, NULL, remote_file_path, 0)) {
        ERROR("Cannot delete '%s' file", remote_file_path);
        goto test_undelete_err;
    }
    sprintf(remote_file_path, "sx://%s%s%s/%s%s/%s/%s", uri->profile ? uri->profile : "", uri->profile ? "@" : "", uri->host, uri->volume, TRASH_NAME, REMOTE_DIR, UNDELETE_FILE_NAME);
    switch(find_file(sx, cluster, remote_file_path, 0)) {
        case -1:
            ERROR("Looking for '%s' file failed", remote_file_path);
            goto test_undelete_err;
        case 0:
            ERROR("'%s' file has not been deleted correctly", remote_file_path);
            goto test_undelete_err;
        case 1: break;
    }

    PRINT("Succeeded");
    ret = 0;
test_undelete_err:
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    free(remote_file_path);
    sxc_free_uri(uri);
    return ret;
} /* test_undelete */

static int test_undelete_vol(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = 1;
    char *local_file_path = NULL, *remote_dir = NULL, *remote_file_path = NULL;
    struct vol_data vdata[2];
    char filter_cfg[sizeof(vdata[0].name) + 1 + lenof(TRASH_NAME) + 1];

    PRINT("Started");
    memset(vdata, 0, sizeof(vdata));
    vdata[0].owner = vdata[1].owner = args->owner_arg;
    vdata[0].replica = vdata[1].replica = args->replica_arg;
    vdata[1].filter_name = "undelete";
    if(get_filters(filters, fcount, vdata, 1, rand_filters, args)) {
        ERROR("Cannot get filter");
        return ret;
    }
    if(prepare_volumes(sx, cluster, filters, fcount, vdata, 1, args->human_flag, 1)) { /* create first volume to have its name */
        ERROR("Failed to prepare first volume");
        return ret;
    }
    sprintf(filter_cfg, "%s:%s", vdata[0].name, TRASH_NAME);
    vdata[1].filter_cfg = (const char*)filter_cfg;
    if(prepare_volumes(sx, cluster, filters, fcount, &vdata[1], 1, args->human_flag, 1)) {
        ERROR("Failed to prepare second volume");
        goto test_undelete_vol_err;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(UNDELETE_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_undelete_vol_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, UNDELETE_FILE_NAME);
    remote_file_path = (char*)malloc(lenof("sx://") + (profile_name ? strlen(profile_name) + 1 : 0) + strlen(cluster_name) + 1 + strlen(vdata[0].name) + strlen(vdata[1].name) + 1 + strlen(TRASH_NAME) + 1 + strlen(UNDELETE_FILE_NAME) + 1);
    if(!remote_file_path) {
        ERROR("Cannot allocate memory for remote_file_path");
        goto test_undelete_vol_err;
    }
    sprintf(remote_file_path, "sx://%s%s%s/%s/%s/%s", profile_name ? profile_name : "", profile_name ? "@" : "", cluster_name, vdata[1].name, REMOTE_DIR, UNDELETE_FILE_NAME);
    if(create_file(local_file_path, 0, 0, NULL, 1))
        goto test_undelete_vol_err;
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 0)) {
        ERROR("Cannot upload '%s' file", local_file_path);
        goto test_undelete_vol_err;
    }
    if(delete_files(sx, cluster, NULL, remote_file_path, 0)) {
        ERROR("Cannot delete '%s' file", remote_file_path);
        goto test_undelete_vol_err;
    }
    sprintf(remote_file_path, "sx://%s%s%s/%s%s/%s/%s", profile_name ? profile_name : "", profile_name ? "@" : "", cluster_name, vdata[0].name, TRASH_NAME, REMOTE_DIR, UNDELETE_FILE_NAME);
    switch(find_file(sx, cluster, remote_file_path, 0)) {
        case -1:
            ERROR("Looking for '%s' file failed", remote_file_path);
            goto test_undelete_vol_err;
        case 0:
            ERROR("'%s' file has not been deleted correctly", remote_file_path);
            goto test_undelete_vol_err;
        case 1: break;
    }

    PRINT("Succeeded");
    ret = 0;
test_undelete_vol_err:
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    cleanup_volumes(sx, cluster, vdata, sizeof(vdata)/sizeof(*vdata));
    free(local_file_path);
    free(remote_dir);
    free(remote_file_path);
    return ret;
} /* test_undelete */

static int volume_test(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const sxc_uri_t *uri, const struct gengetopt_args_info *args, const sxf_handle_t *filters, int fcount, int filter_index, const char *filter_cfg, int max_revisions) {
    int i, ret = 1, test = 0, check_data_size;
    char *volname, *remote_dir_path = NULL;
    const sxc_filter_t *f = filter_index >= 0 ? sxc_get_filter(&filters[filter_index]) : NULL;

    volname = (char*)malloc(sizeof(VOLNAME) + 1 + (f ? strlen(f->shortname) : strlen("NonFilter")) + 1 + strlen("XXXXXX") + 1);
    if(!volname) {
        ERROR("Cannot allocate memory for volname");
        return 1;
    }
    sprintf(volname, "%s_%s_XXXXXX", VOLNAME, f ? f->shortname : "NonFilter");
    if(randomize_name(volname))
        goto volume_test_err;
    remote_dir_path = (char*)malloc(strlen("sx://") + (uri->profile ? strlen(uri->profile) + 1 : 0) + strlen(uri->host) + 1 + strlen(volname) + 1 + strlen(REMOTE_DIR) + 1 + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_dir_path) {
        ERROR("Cannot allocate memory for remote_dir_path");
        goto volume_test_err;
    }
    sprintf(remote_dir_path, "sx://%s%s%s/%s/%s/", uri->profile ? uri->profile : "", uri->profile ? "@" : "", uri->host, volname, REMOTE_DIR);
    for(i=0; tests[i].name; i++) {
        if(tests[i].for_volume && (args->run_test_given ? !strcmp(args->run_test_arg, tests[i].name) : (tests[i].additional ? args->all_flag : 1))) {
            if(tests[i].dedicated) {
                if(f && !strcmp(f->shortname, tests[i].name))
                    test = 1;
            } else {
                if(!tests[i].no_filter || !f)
                    test = 1;
            }
        }
    }
    if(!test) {
        ret = 0;
        goto volume_test_err;
    }
    if(f && (!strcmp(f->shortname, "zcomp") || !strcmp(f->shortname, "aes256")))
        check_data_size = 0;
    else
        check_data_size = 1;
    PRINT("Filter: %s; filter configuration: %s", f ? f->shortname : "<no filter>", filter_cfg ? filter_cfg : "<none>");
    if(create_volume(sx, cluster, volname, args->owner_arg, 0, filter_index >= 0 ? &filters[filter_index] : NULL, filter_cfg, args->replica_arg, max_revisions, args->human_flag, 0)) {
        ERROR("Cannot create new volume");
        goto volume_test_err;
    }
    for(i=0; tests[i].name; i++) {
        if(tests[i].for_volume && (args->run_test_given ? !strcmp(args->run_test_arg, tests[i].name) : (tests[i].additional ? args->all_flag : 1))) {
            if(tests[i].dedicated) {
                if(f && !strcmp(f->shortname, tests[i].name) && run_test(sx, cluster, local_dir_path, remote_dir_path, uri->profile, uri->host, f->shortname, filters, fcount, args, max_revisions, check_data_size, &tests[i])) {
                    failed_test_msg(args, &tests[i]);
                    goto volume_test_err;
                }
            } else if((!tests[i].no_filter || !f) && run_test(sx, cluster, local_dir_path, remote_dir_path, uri->profile, uri->host, f ? f->shortname : NULL, filters, fcount, args, max_revisions, check_data_size, &tests[i])) {
                failed_test_msg(args, &tests[i]);
                goto volume_test_err;
            }
        }
    }
    if(remove_volume(sx, cluster, volname, 0)) {
        ERROR("Cannot remove '%s' volume", volname);
        goto volume_test_err;
    }

    ret = 0;
volume_test_err:
    free(volname);
    free(remote_dir_path);
    return ret;
} /* volume_test */

/* Compare meta data, return 0 if they are the same, 1 if different, -1 on error */
static int cmp_meta(sxc_client_t *sx, sxc_meta_t *a, sxc_meta_t *b, int hide_errors) {
    unsigned int i, count;
    if(!sx || !a || !b) {
        ERROR("NULL argument");
        return -1;
    }
    count = sxc_meta_count(a);

    /* Compare sizes first */
    if(count != sxc_meta_count(b)) {
        if(!hide_errors)
            ERROR("Different meta sizes: %d != %d", count, sxc_meta_count(b));
        return 1;
    }

    for(i = 0; i < count; i++) {
        const char *metakey;
        const void *metavalue1, *metavalue2;
        unsigned int metavalue1_len, metavalue2_len;

        /* Get the first entry */
        if(sxc_meta_getkeyval(a, i, &metakey, &metavalue1, &metavalue1_len)) {
            if(!hide_errors)
                ERROR("Failed to read meta entry");
            return 1;
        }

        if(!metakey) {
            if(!hide_errors)
                ERROR("Invalid meta key");
            return 1;
        }

        if(sxc_meta_getval(b, metakey, &metavalue2, &metavalue2_len)) {
            if(!hide_errors)
                ERROR("Failed to get meta key from reference meta");
            return 1;
        }

        /* Check if the entry is the same as expected */
        if(!metavalue1 || !metavalue2 || metavalue1_len != metavalue2_len || memcmp(metavalue1, metavalue2, metavalue1_len)) {
            if(!hide_errors)
                ERROR("Different meta values for meta key '%s'", metakey);
            return 1;
        }
    }

    return 0;
}

static int test_volmeta(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = -1;
    sxc_meta_t *custom_meta = NULL, *custom_meta_remote = NULL;
    sxc_file_t *file = NULL;
    struct user_data udata[3];
    struct vol_data vdata[1];

    PRINT("Started");
    memset(udata, 0, sizeof(udata));
    memset(vdata, 0, sizeof(vdata));
    udata[2].admin = 1;

    /* Create 1 user */
    if(prepare_users(sx, cluster, udata, sizeof(udata) / sizeof(*udata))) {
        ERROR("Failed to prepare users");
        goto test_volmeta_err;
    }

    vdata[0].owner = udata[0].username;
    vdata[0].filter_name = vdata[0].filter_cfg = NULL;
    vdata[0].replica = args->replica_arg;
    /* Create 1 volume owned by user1 */
    if(prepare_volumes(sx, cluster, filters, fcount, vdata, sizeof(vdata) / sizeof(*vdata), args->human_flag, 1)) {
        ERROR("Failed to prepare volumes");
        goto test_volmeta_err;
    }

    /* Actual test begins here */

    /* Create remote file structure instance to pass it to sxc_custom_volumemeta_new() */
    file = sxc_file_remote(cluster, vdata[0].name, NULL, NULL);
    if(!file) {
        ERROR("Failed to initialize remote file structure");
        goto test_volmeta_err;
    }

    /* Create custom meta buffer */
    custom_meta = sxc_meta_new(sx);
    if(!custom_meta) {
        ERROR("Failed to create volume %s custom meta: %s", vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    custom_meta_remote = sxc_custom_volumemeta_new(file);
    if(!custom_meta_remote) {
        ERROR("Failed to get volume %s custom meta: %s", vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Compare local and remote meta */
    if(cmp_meta(sx, custom_meta, custom_meta_remote, 0))
        goto test_volmeta_err;

    /* Add new custom meta value */
    if(sxc_meta_setval(custom_meta, "1", "123", 3)) {
        ERROR("Failed to modify meta");
        goto test_volmeta_err;
    }

    /* Modify the volume */
    if(sxc_volume_modify(cluster, vdata[0].name, NULL, NULL, -1, -1, custom_meta)) {
        ERROR("Failed to modify meta");
        goto test_volmeta_err;
    }

    /* Get custom meta again */
    sxc_meta_free(custom_meta_remote);
    custom_meta_remote = sxc_custom_volumemeta_new(file);
    if(!custom_meta_remote) {
        ERROR("Failed to get volume %s custom meta: %s", vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Compare local and remote meta */
    if(cmp_meta(sx, custom_meta, custom_meta_remote, 0))
        goto test_volmeta_err;

    /* Switch to the volume owner account */
    if(sxc_cluster_set_access(cluster, udata[0].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Add new custom meta value */
    if(sxc_meta_setval(custom_meta, "2", "22222222", 8)) {
        ERROR("Failed to modify meta");
        goto test_volmeta_err;
    }

    /* Modify the volume as a volume owner */
    if(sxc_volume_modify(cluster, vdata[0].name, NULL, NULL, -1, -1, custom_meta)) {
        ERROR("Failed to modify meta");
        goto test_volmeta_err;
    }

    /* Get remote custom meta */
    sxc_meta_free(custom_meta_remote);
    custom_meta_remote = sxc_custom_volumemeta_new(file);
    if(!custom_meta_remote) {
        ERROR("Failed to get volume %s custom meta: %s", vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Compare local and remote meta */
    if(cmp_meta(sx, custom_meta, custom_meta_remote, 0))
        goto test_volmeta_err;

    /* Switch to the second user account */
    if(sxc_cluster_set_access(cluster, udata[1].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[1].username, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Add new custom meta value */
    if(sxc_meta_setval(custom_meta, "3", "A", 1)) {
        ERROR("Failed to modify meta");
        goto test_volmeta_err;
    }

    /* Try to modify the volume as a non-authorised user - should fail */
    if(!sxc_volume_modify(cluster, vdata[0].name, NULL, NULL, -1, -1, custom_meta)) {
        ERROR("Successfully changed volume %s meta as a non-authorised user '%s'", vdata[0].name, udata[1].username);
        goto test_volmeta_err;
    }

    /* Switch to the admin user account */
    if(sxc_cluster_set_access(cluster, udata[2].username)) {
        ERROR("Failed to set '%s' profile authentication: '%s'", udata[1].username, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Get remote custom meta */
    sxc_meta_free(custom_meta_remote);
    custom_meta_remote = sxc_custom_volumemeta_new(file);
    if(!custom_meta_remote) {
        ERROR("Failed to get volume %s custom meta: %s", vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Compare local and remote meta - should not be changed */
    if(!cmp_meta(sx, custom_meta, custom_meta_remote, 1))
        goto test_volmeta_err;

    /* Modify the volume as an admin user */
    if(sxc_volume_modify(cluster, vdata[0].name, NULL, NULL, -1, -1, custom_meta)) {
        ERROR("Failed to modify volume %s meta as the admin user '%s'", vdata[0].name, udata[2].username);
        goto test_volmeta_err;
    }

    /* Get remote custom meta */
    sxc_meta_free(custom_meta_remote);
    custom_meta_remote = sxc_custom_volumemeta_new(file);
    if(!custom_meta_remote) {
        ERROR("Failed to get volume %s custom meta: %s", vdata[0].name, sxc_geterrmsg(sx));
        goto test_volmeta_err;
    }

    /* Compare local and remote meta */
    if(cmp_meta(sx, custom_meta, custom_meta_remote, 0))
        goto test_volmeta_err;

    PRINT("Succeeded");
    ret = 0;
test_volmeta_err:
    if(sxc_cluster_set_access(cluster, profile_name))
        WARNING("Failed to set '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));

    cleanup_volumes(sx, cluster, vdata, sizeof(vdata) / sizeof(*vdata));
    cleanup_users(sx, cluster, udata, sizeof(udata) / sizeof(*udata));
    sxc_file_free(file);
    sxc_meta_free(custom_meta);
    sxc_meta_free(custom_meta_remote);
    return ret;
}

static int test_user_quota(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = -1, file_created = 0;
    sxc_meta_t *custom_meta = NULL, *custom_meta_remote = NULL;
    sxc_file_t *src = NULL, *dest = NULL;
    struct user_data udata[2];
    struct vol_data vdata[2]; /* using two volumes to divide the quota */
    char *local_file_path = NULL, *remote_path = NULL;
    int qret = 0;

    PRINT("Started");
    memset(udata, 0, sizeof(udata));
    memset(vdata, 0, sizeof(vdata));
    udata[1].admin = 1;

    /* Create 1 user */
    if(prepare_users(sx, cluster, udata, sizeof(udata) / sizeof(*udata))) {
        ERROR("Failed to prepare users");
        goto test_user_quota_err;
    }

    vdata[0].owner = udata[0].username;
    vdata[1].owner = udata[0].username;
    vdata[0].replica = vdata[1].replica = args->replica_arg;
    if(get_filters(filters, fcount, vdata, sizeof(vdata)/sizeof(*vdata), rand_filters, args)) {
        ERROR("Cannot get filters");
        goto test_user_quota_err;
    }

    /* Create 1 volume owned by user1 */
    if(prepare_volumes(sx, cluster, filters, fcount, vdata, sizeof(vdata) / sizeof(*vdata), args->human_flag, 1)) {
        ERROR("Failed to prepare volumes");
        goto test_user_quota_err;
    }

    local_file_path = malloc(strlen(local_dir_path) + lenof(QUOTA_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_user_quota_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, QUOTA_FILE_NAME);
    remote_path = malloc(lenof("sx://") + strlen(args->owner_arg) + 1 + strlen(cluster_name) + 1 + strlen(vdata[0].name) + 1 + lenof(REMOTE_DIR) + 1 + lenof(QUOTA_FILE_NAME) + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_path) {
        ERROR("Cannot allocate memory for remote_path");
        goto test_user_quota_err;
    }
    sprintf(remote_path, "%s/%s", REMOTE_DIR, QUOTA_FILE_NAME);
    src = sxc_file_local(sx, local_file_path);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        goto test_user_quota_err;
    }
    dest = sxc_file_remote(cluster, vdata[0].name, remote_path, NULL);
    if(!dest) {
        ERROR("Cannot open '%s' directory: %s", remote_path, sxc_geterrmsg(sx));
        goto test_user_quota_err;
    }

    /* Actual test begins here */

    /* Create test file: its size on local disk will be exactly one SX_BS_LARGE bytes */
    if(create_file(local_file_path, SX_BS_LARGE, 1, NULL, 1))
        goto test_user_quota_err;
    file_created = 1;

    /* Modify the first user quota, set it to be the same as raw file data - 1 byte */
    if(sxc_user_modify(cluster, udata[0].username, SX_BS_LARGE + lenof(REMOTE_DIR) + 1 + lenof(QUOTA_FILE_NAME) - 1, NULL)) {
        ERROR("Failed to modify user '%s' quota", udata[0].username);
        goto test_user_quota_err;
    }

    /* Switch to the volume owner account */
    if(sxc_cluster_set_access(cluster, udata[0].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_user_quota_err;
    }

    qret = sxc_copy_single(src, dest, 0, 0, 0, NULL, 1);
    if(qret && strstr(sxc_geterrmsg(sx), "User quota exceeded"))
        PRINT("User '%s' quota enforced correctly (file upload)", udata[0].username);
    else if(!qret) {
        ERROR("User '%s' quota not enforced", udata[0].username);
        goto test_user_quota_err;
    } else {
        ERROR("Cannot upload '%s' file: %s, error code: %d", local_file_path, sxc_geterrmsg(sx), qret);
        goto test_user_quota_err;
    }
    sxc_clearerr(sx);

    /* Switch to the admin account */
    if(sxc_cluster_set_access(cluster, udata[1].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_user_quota_err;
    }

    /* Modify the first user quota, set it to be the same as raw file data */
    if(sxc_user_modify(cluster, udata[0].username, SX_BS_LARGE + lenof(REMOTE_DIR) + 1 + lenof(QUOTA_FILE_NAME), NULL)) {
        ERROR("Failed to modify user '%s' quota", udata[0].username);
        goto test_user_quota_err;
    }

    /* Now file should exactly fit into user quota */
    if(sxc_copy_single(src, dest, 0, 0, 0, NULL, 1)) {
        ERROR("Cannot upload '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        goto test_user_quota_err;
    }

    PRINT("Succeeded");
    ret = 0;
test_user_quota_err:
    if(sxc_cluster_set_access(cluster, profile_name))
        WARNING("Failed to set '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));

    if(remote_path) {
        sprintf(remote_path, "sx://%s@%s/%s/%s/%s", args->owner_arg, cluster_name, vdata[0].name, REMOTE_DIR, QUOTA_FILE_NAME);
        if(delete_files(sx, cluster, NULL, remote_path, 0))
            WARNING("Cannot delete '%s' file", remote_path);
    }

    cleanup_volumes(sx, cluster, vdata, sizeof(vdata) / sizeof(*vdata));
    cleanup_users(sx, cluster, udata, sizeof(udata) / sizeof(*udata));
    sxc_meta_free(custom_meta);
    sxc_meta_free(custom_meta_remote);
    if(file_created && unlink(local_file_path))
        WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    free(remote_path);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
}

static int test_volume_quota(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = 1, file = 0, qret;
    char *local_file_path = NULL, *remote_path = NULL;
    sxc_file_t *src = NULL, *dest = NULL;
    struct vol_data vdata;

    PRINT("Started");
    memset(&vdata, 0, sizeof(vdata));
    vdata.owner = args->owner_arg;
    vdata.replica = args->replica_arg;
    vdata.size = QUOTA_VOL_SIZE * SX_BS_LARGE;
    if(prepare_volumes(sx, cluster, filters, fcount, &vdata, 1, args->human_flag, 0)) {
        ERROR("Failed to prepare volumes");
        goto test_quota_err;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(QUOTA_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_quota_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, QUOTA_FILE_NAME);
    remote_path = (char*)malloc(strlen("sx://") + strlen(args->owner_arg) + 1 + strlen(cluster_name) + 1 + strlen(vdata.name) + 1 + strlen(REMOTE_DIR) + 1 + strlen(QUOTA_FILE_NAME) + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_path) {
        ERROR("Cannot allocate memory for remote_path");
        goto test_quota_err;
    }
    sprintf(remote_path, "%s/%s", REMOTE_DIR, QUOTA_FILE_NAME);
    if(args->human_flag)
        PRINT("Creating file of size: %dM", QUOTA_FILE_SIZE);
    else
        PRINT("Creating file of size: %llu", (unsigned long long)QUOTA_FILE_SIZE*1024*1024);
    src = sxc_file_local(sx, local_file_path);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    dest = sxc_file_remote(cluster, vdata.name, remote_path, NULL);
    if(!dest) {
        ERROR("Cannot open '%s' directory: %s", remote_path, sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    if(create_file(local_file_path, SX_BS_LARGE, QUOTA_FILE_SIZE, NULL, 1))
        goto test_quota_err;
    file = 1;
    qret = sxc_copy_single(src, dest, 0, 0, 0, NULL, 1);
    if(qret && strstr(sxc_geterrmsg(sx), "Not enough space left on volume")) {
        PRINT("Volume size limit enforced correctly");
    } else if(!qret) {
        ERROR("Volume size limit not enforced");
        goto test_quota_err;
    } else {
        ERROR("Cannot upload '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    if(sxc_volume_modify(cluster, vdata.name, NULL, NULL, 5ULL*1024ULL*1024ULL*1024ULL, -1, NULL)) { /* Use almost all cluster space */
        ERROR("Cannot change volume size: %s", sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    if(sxc_copy_single(src, dest, 0, 0, 0, NULL, 1)) {
        ERROR("Cannot upload '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        goto test_quota_err;
    }
    PRINT("Volume size changed correctly");

    PRINT("Succeeded");
    ret = 0;
test_quota_err:
    cleanup_volumes(sx, cluster, &vdata, 1);
    if(file && unlink(local_file_path))
        WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    free(remote_path);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* test_quota */

static int test_copy(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = 1;
    char *local_file_path = NULL, *remote_file1_path = NULL, *remote_file2_path = NULL;
    unsigned char hash[SXI_SHA1_BIN_LEN];
    sxc_uri_t *uri = NULL;
    sxc_file_t *src = NULL, *dest = NULL;
    struct vol_data vdata[2];

    PRINT("Started");
    memset(vdata, 0, sizeof(vdata));
    vdata[0].owner = vdata[1].owner = args->owner_arg;
    vdata[0].replica = vdata[1].replica = args->replica_arg;
    if(get_filters(filters, fcount, vdata, sizeof(vdata)/sizeof(*vdata), rand_filters, args)) {
        ERROR("Cannot get filters");
        return ret;
    }
    PRINT("Filters: %s (%s) and %s (%s)", vdata[0].filter_name, vdata[0].filter_cfg, vdata[1].filter_name, vdata[1].filter_cfg);
    if(prepare_volumes(sx, cluster, filters, fcount, vdata, sizeof(vdata) / sizeof(*vdata), args->human_flag, 0)) {
        ERROR("Failed to prepare volumes");
        goto test_copy_err;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(COPY_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_copy_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, COPY_FILE_NAME);
    remote_file1_path = (char*)malloc(strlen("sx://") + (profile_name ? strlen(profile_name) + 1 : 0) + strlen(cluster_name) + 1 + strlen(vdata[0].name) + 1 + strlen(REMOTE_DIR) + 1 + strlen(COPY_FILE_NAME) + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_file1_path) {
        ERROR("Cannot allocate memory for remote_file1_path");
        goto test_copy_err;
    }
    sprintf(remote_file1_path, "sx://%s%s%s/%s/%s/%s", profile_name ? profile_name : "", profile_name ? "@" : "", cluster_name, vdata[0].name, REMOTE_DIR, COPY_FILE_NAME);
    remote_file2_path = (char*)malloc(strlen("sx://") + (profile_name ? strlen(profile_name) + 1 : 0) + strlen(cluster_name) + 1 + strlen(vdata[1].name) + 1 + strlen(REMOTE_DIR) + 1 + strlen(COPY_FILE_NAME) + 1); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_file2_path) {
        ERROR("Cannot allocate memory for remote_file2_path");
        goto test_copy_err;
    }
    sprintf(remote_file2_path, "sx://%s%s%s/%s/%s/%s", profile_name ? profile_name : "", profile_name ? "@" : "", cluster_name, vdata[1].name, REMOTE_DIR, COPY_FILE_NAME);
    if(create_file(local_file_path, SX_BS_MEDIUM, 10, hash, 1))
        goto test_copy_err;
    PRINT("Uploading file");
    if(upload_file(sx, cluster, local_file_path, remote_file1_path, 0)) {
        ERROR("Cannot upload '%s' file", local_file_path);
        if(unlink(local_file_path))
            ERROR("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
        goto test_copy_err;
    }
    if(unlink(local_file_path)) {
        ERROR("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
        goto test_copy_err;
    }
    uri = sxc_parse_uri(sx, remote_file1_path);
    if(!uri) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto test_copy_err;
    }
    src = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", remote_file1_path, sxc_geterrmsg(sx));
        sxc_free_uri(uri);
        uri = NULL;
        goto test_copy_err;
    }
    sxc_free_uri(uri);
    PRINT("Copying file between volumes");
    uri = sxc_parse_uri(sx, remote_file2_path);
    if(!uri) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto test_copy_err;
    }
    dest = sxc_file_remote(cluster, uri->volume, uri->path, NULL);
    if(!dest) {
        ERROR("Cannot open '%s' file: %s", remote_file2_path, sxc_geterrmsg(sx));
        goto test_copy_err;
    }
    if(sxc_copy_single(src, dest, 0, 0, 0, NULL, 1)) {
        ERROR("Cannot upload '%s' file: %s", remote_file2_path, sxc_geterrmsg(sx));
        goto test_copy_err;
    }
    if(check_filemeta(sx, src, vdata[0].filter_name))
        goto test_copy_err;
    if(check_filemeta(sx, dest, vdata[1].filter_name))
        goto test_copy_err;
    PRINT("Downloading file");
    if(download_file(sx, cluster, local_file_path, remote_file2_path)) {
        ERROR("Cannot download '%s' file", remote_file2_path);
        goto test_copy_err;
    }
    switch(check_file_content(local_file_path, hash)) {
        case -1:
            ERROR("Checking file content failed");
            goto test_copy_err;
        case 0: /* Downloaded file is correct */
            break;
        case 1:
            ERROR("Downloaded file differs from the original one");
            goto test_copy_err;
    }
    if(delete_files(sx, cluster, NULL, remote_file1_path, 0)) {
        ERROR("Cannot delete '%s' file", remote_file1_path);
        goto test_copy_err;
    }
    if(delete_files(sx, cluster, uri->volume, uri->path, 0)) {
        ERROR("Cannot delete '%s' file", remote_file2_path);
        goto test_copy_err;
    }
    
    PRINT("Succeeded");
    ret = 0;
test_copy_err:
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    cleanup_volumes(sx, cluster, vdata, sizeof(vdata) / sizeof(*vdata));
    free(local_file_path);
    free(remote_file1_path);
    free(remote_file2_path);
    sxc_free_uri(uri);
    sxc_file_free(src);
    sxc_file_free(dest);
    return ret;
} /* test_copy */

struct files_transfer {
    char src[SXLIMIT_MAX_FILENAME_LEN + 1], dest[SXLIMIT_MAX_FILENAME_LEN + 1];
};

static int test_paths(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = -1, n;
    unsigned int i;
    char *local_file_path = NULL;
    const char *paths[] = {"/file_paths", "/dir", "/dir/"};
    sxc_file_t *src = NULL, *dest = NULL, *file = NULL;
    sxc_cluster_lf_t *file_list = NULL;
    struct vol_data vdata[2];
    struct files_transfer ftrans[] = {{"fil?_pat?s", ""}, {"f*_*s", "dir/.sxnewdir"}, {"*", "dir"}};

    PRINT("Started");
    memset(vdata, 0, sizeof(vdata));
    vdata[0].filter_name = vdata[0].filter_cfg = vdata[1].filter_name = vdata[1].filter_cfg = NULL;
    vdata[0].owner = vdata[1].owner = args->owner_arg;
    vdata[0].replica = vdata[1].replica = args->replica_arg;
    if(get_filters(filters, fcount, vdata, sizeof(vdata)/sizeof(*vdata), rand_filters, args)) {
        ERROR("Cannot get filters");
        goto test_paths_err;
    }
    if(prepare_volumes(sx, cluster, filters, fcount, vdata, sizeof(vdata) / sizeof(*vdata), args->human_flag, 0)) {
        ERROR("Failed to prepare volumes");
        goto test_paths_err;
    }

    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen("file_paths") + 1); /* no macro for filename to be able to create static array */
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_paths_err;
    }
    sprintf(local_file_path, "%sfile_paths", local_dir_path);
    if(create_file(local_file_path, 0, 0, NULL, 1))
        goto test_paths_err;
    src = sxc_file_local(sx, local_file_path);
    if(!src) {
        ERROR("Cannot open '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        goto test_paths_err;
    }
    dest = sxc_file_remote(cluster, vdata[0].name, "file_paths", NULL);
    if(!dest) {
        ERROR("Cannot open 'file_trans' file: %s", sxc_geterrmsg(sx));
        goto test_paths_err;
    }
    if(sxc_copy_single(src, dest, 0, 0, 0, NULL, 1)) {
        ERROR("Cannot upload '%s' file: %s", local_file_path, sxc_geterrmsg(sx));
        goto test_paths_err;
    }
    for(i=0; i<sizeof(ftrans)/sizeof(*ftrans); i++) {
        PRINT("Copying '%s' to '%s'", ftrans[i].src, ftrans[i].dest);
        sxc_file_free(src);
        src = sxc_file_remote(cluster, vdata[0].name, ftrans[i].src, NULL);
        if(!src) {
            ERROR("Cannot open '%s' file: %s", ftrans[i].src, sxc_geterrmsg(sx));
            goto test_paths_err;
        }
        sxc_file_free(dest);
        dest = sxc_file_remote(cluster, vdata[1].name, ftrans[i].dest, NULL);
        if(!dest) {
            ERROR("Cannot open '%s' file: %s", ftrans[i].dest, sxc_geterrmsg(sx));
            goto test_paths_err;
        }
        if(sxc_copy_single(src, dest, 0, 0, 0, NULL, 1)) {
            ERROR("Cannot copy '%s' file to '%s': %s", ftrans[i].src, ftrans[i].dest, sxc_geterrmsg(sx));
            goto test_paths_err;
        }
    }
    /* Check file listing */
    file_list = sxc_cluster_listfiles(cluster, vdata[1].name, "", 0, NULL, 0); /* Not using find_file() - want to use sxc_cluster_listfiles() only once */
    if(!file_list) {
        ERROR("Cannot get volume files list: %s", sxc_geterrmsg(sx));
        goto test_paths_err;
    }
    while(1) {
        sxc_file_free(file);
        file = NULL;
        n = sxc_cluster_listfiles_next(cluster, vdata[1].name, file_list, &file);
        if(!n)
            break;
        if(n < 0) {
            ERROR("%s", sxc_geterrmsg(sx));
            goto test_paths_err;
        }
        if(!file || !sxc_file_get_path(file)) {
            ERROR("NULL file name pointer received");
            goto test_paths_err;
        }
        PRINT("Checking: %s", sxc_file_get_path(file));
        for(i=0; i<sizeof(paths)/sizeof(*paths); i++)
            if(paths[i] && !strcmp(paths[i], sxc_file_get_path(file))) {
                paths[i] = NULL;
                break;
            }
        if(i == sizeof(paths)/sizeof(*paths)) {
            ERROR("File not expected: %s", sxc_file_get_path(file));
            goto test_paths_err;
        }
    }
    for(i=0; i<sizeof(paths)/sizeof(*paths); i++)
        if(paths[i]) {
            ERROR("File missing: %s", paths[i]);
            goto test_paths_err;
        }

    PRINT("Succeeded");
    ret = 0;
test_paths_err:
    cleanup_volumes(sx, cluster, vdata, sizeof(vdata) / sizeof(*vdata));
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    free(local_file_path);
    sxc_file_free(src);
    sxc_file_free(dest);
    sxc_file_free(file);
    sxc_cluster_listfiles_free(file_list);
    return ret;
} /* test_paths */

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
        ERROR("Cannot allocate memory for remote_file_path");
        return ret;
    }
    if(sxc_cluster_set_access(cluster, user1)) {
        ERROR("Failed to set '%s' profile authentication: %s", user1, sxc_geterrmsg(sx));
        goto cross_copy_err;
    }
    sprintf(remote_file_path, "sx://%s@%s/%s/", user1, cluster_name, volname2);
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 1)) {
        if(sxc_geterrnum(sx) != SXE_EAUTH) {
            ERROR("Cannot upload '%s' file", local_file_path);
            goto cross_copy_err;
        }
    } else {
        ERROR("File upload succeeded without permission");
        ret = 1;
        goto cross_copy_err;
    }
    if(sxc_cluster_set_access(cluster, user2)) {
        ERROR("Failed to set '%s' profile authentication: %s", user2, sxc_geterrmsg(sx));
        goto cross_copy_err;
    }
    sprintf(remote_file_path, "sx://%s@%s/%s/", user2, cluster_name, volname1);
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 1)) {
        if(sxc_geterrnum(sx) != SXE_EAUTH) {
            ERROR("Cannot upload '%s' file", local_file_path);
            goto cross_copy_err;
        }
    } else {
        ERROR("File upload succeeded without permission");
        ret = 1;
        goto cross_copy_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        ERROR("Failed to set default profile: %s", sxc_geterrmsg(sx));
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
static int check_users(sxc_cluster_t *cluster, const char **users, int users_num) {
    int i, ret = -1, is_admin, next = 1, num = 0;
    char *user = NULL;
    int64_t quota, quota_used;
    sxc_cluster_lu_t *lstu;

    lstu = sxc_cluster_listusers(cluster);
    if(!lstu)
        return ret;
    while(next > 0) {
        free(user);
        user = NULL;
        next = sxc_cluster_listusers_next(lstu, &user, &is_admin, NULL, &quota, &quota_used);
        switch(next) {
            case -1: goto check_users_err;
            case 0: break;
            case 1:
                for(i=0; i<users_num; i++)
                    if(users[i] && !strcmp(users[i], user)) {
                        users[i] = NULL;
                        break;
                    }
                num++;
                break;
        }
    }
    for(i=0; i<users_num; i++)
        if(users[i]) {
            ret = 1;
            goto check_users_err;
        }

    ret = 0;
check_users_err:
    free(user);
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
                        PRINT("Rights: %x, acl: %x", rights, acl);
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

static int test_acl(sxc_client_t *sx, sxc_cluster_t *cluster, const char *local_dir_path, const char *remote_dir_path, const char *profile_name, const char *cluster_name, const char *vol_filter, int rand_filters, const sxf_handle_t *filters, int fcount, uint64_t block_size, uint64_t block_count, const struct gengetopt_args_info *args, unsigned int max_revisions, int check_data_size) {
    int ret = 1;
    unsigned int i;
    char key_tmp[AUTHTOK_ASCII_LEN], *local_file_path = NULL, *remote_file_path = NULL;
    FILE *file = NULL;
    int64_t quota, quota_used;
    struct user_data udata[3];
    struct vol_data vdata[2];
    const char *list[sizeof(udata) / sizeof(*udata)];

    PRINT("Started");
    memset(udata, 0, sizeof(udata));
    memset(vdata, 0, sizeof(vdata));
    switch(check_admin(cluster)) {
        case -1:
            ERROR("%s", sxc_geterrmsg(sx));
            return ret;
        case 0:
            ERROR("Current user is not an admin");
            return ret;
    }
    if(prepare_users(sx, cluster, udata, sizeof(udata) / sizeof(*udata) - 1)) { /* third user will be created by first user */
        ERROR("Failed to prepare users");
        goto test_acl_err;
    }
    vdata[0].owner = udata[0].username;
    vdata[0].filter_name = vdata[0].filter_cfg = vdata[1].filter_name = vdata[1].filter_cfg = NULL;
    vdata[1].owner = udata[1].username;
    vdata[0].replica = vdata[1].replica = args->replica_arg;
    if(sxc_cluster_set_access(cluster, udata[0].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(prepare_volumes(sx, cluster, filters, fcount, vdata, sizeof(vdata) / sizeof(*vdata), args->human_flag, 1)) {
        if(sxc_geterrnum(sx) == SXE_EAUTH)
            PRINT("Volume creation permission enforced correctly");
        else {
            ERROR("Cannot create '%s' volume: %s", vdata[0].name, sxc_geterrmsg(sx));
            goto test_acl_err;
        }
    } else {
        ERROR("Volume created without permission");
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        ERROR("Failed to set default profile: %s", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(prepare_volumes(sx, cluster, filters, fcount, vdata, sizeof(vdata) / sizeof(*vdata), args->human_flag, 0)) {
        ERROR("Failed to prepare volumes");
        goto test_acl_err;
    }
    remote_file_path = (char*)malloc(strlen("sx://") + strlen(udata[0].username) + strlen(udata[1].username) + 1 + strlen(cluster_name) + 1 + strlen(vdata[0].name) + strlen(vdata[1].name) + 2); /* The 1's inside are for '@' and '/' characters. */
    if(!remote_file_path) {
        ERROR("Cannot allocate memory for remote_file_path");
        goto test_acl_err;
    }
    local_file_path = (char*)malloc(strlen(local_dir_path) + strlen(ACL_FILE_NAME) + strlen(ACL_KEY_FILE_NAME) + 1);
    if(!local_file_path) {
        ERROR("Cannot allocate memory for local_file_path");
        goto test_acl_err;
    }
    sprintf(local_file_path, "%s%s", local_dir_path, ACL_FILE_NAME);
    if(create_file(local_file_path, 0, 0, NULL, 1))
        goto test_acl_err;
    switch(check_user(cluster, vdata[0].name, udata[0].username, SX_ACL_FULL)) { /* read + write + manager + owner */
        case -1:
            ERROR("%s", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 1:
            ERROR("'%s' has diferent rights on '%s'", udata[0].username, vdata[0].name);
            goto test_acl_err;
    }
    switch(check_user(cluster, vdata[0].name, udata[1].username, 0)) { /* no rights yet */
        case -1:
            ERROR("%s", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 1:
            ERROR("'%s' has diferent rights on '%s'", udata[1].username, vdata[0].name);
            goto test_acl_err;
    }
    switch(cross_copy(sx, cluster, cluster_name, vdata[0].name, vdata[1].name, udata[0].username, udata[1].username, profile_name, local_file_path)) {
        case -1:
            ERROR("Files uploading failure");
            goto test_acl_err;
        case 0:
            PRINT("Users permissions enforced correctly");
            break;
        case 1:
            ERROR("Files uploaded without permission");
            goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, udata[1].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[1].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    sprintf(remote_file_path, "sx://%s@%s/%s/%s", udata[0].username, cluster_name, vdata[1].name, ACL_FILE_NAME);
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 0)) { /* user1 in remote_file_path have no impact here */
        ERROR("Cannot upload '%s' file", local_file_path);
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, vdata[1].name, udata[0].username, SX_ACL_READ, 0)) {
        ERROR("Cannot add 'read' permission to '%s': %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, udata[0].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    switch(find_file(sx, cluster, remote_file_path, 0)) {
        case -1:
            ERROR("Looking for '%s' file failed", remote_file_path);
            goto test_acl_err;
        case 0:
            ERROR("'%s' file not found", remote_file_path);
            goto test_acl_err;
        case 1:
            PRINT("'read' permission granted correctly");
            break;
    }
    switch(check_user(cluster, vdata[1].name, udata[0].username, SX_ACL_READ)) { /* read */
        case -1:
            ERROR("%s", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 1:
            ERROR("'%s' has diferent rights on '%s'", udata[0].username, vdata[1].name);
            goto test_acl_err;
    }
    if(delete_files(sx, cluster, NULL, remote_file_path, 1)) {
        if(sxc_geterrnum(sx) == SXE_EAUTH)
            PRINT("'write' permission enforced correctly");
        else {
            ERROR("Cannot delete '%s' file", remote_file_path);
            goto test_acl_err;
        }
    } else {
        ERROR("File has been deleted without permission");
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, vdata[0].name, udata[1].username, SX_ACL_WRITE, 0)) {
        ERROR("Cannot add 'write' permission to '%s': %s", udata[1].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, udata[1].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[1].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(delete_files(sx, cluster, NULL, remote_file_path, 1)) {
        ERROR("Cannot delete '%s' file", remote_file_path);
        goto test_acl_err;
    }
    sprintf(remote_file_path, "sx://%s@%s/%s/%s", udata[1].username, cluster_name, vdata[0].name, ACL_FILE_NAME);
    if(upload_file(sx, cluster, local_file_path, remote_file_path, 1)) {
        ERROR("Cannot upload '%s' file", local_file_path);
        goto test_acl_err;
    } else
        PRINT("'write' permission granted correctly");
    if(find_file(sx, cluster, remote_file_path, 1) == -1) {
        if(sxc_geterrnum(sx) == SXE_EAUTH)
            PRINT("'read' permission enforced correctly");
        else {
            ERROR("Looking for '%s' file in %s failed", ACL_FILE_NAME, remote_file_path);
            goto test_acl_err;
        }
    } else {
        ERROR("Searching for a file done without permission");
        goto test_acl_err;
    }
    if(delete_files(sx, cluster, NULL, remote_file_path, 1)) {
        ERROR("Cannot delete '%s' file", remote_file_path);
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, vdata[1].name, udata[0].username, 0, SX_ACL_READ)) {
        ERROR("Cannot revoke 'read' permission from '%s': %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, udata[0].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, vdata[0].name, udata[1].username, 0, SX_ACL_WRITE)) {
        ERROR("Cannot revoke 'write' permission from '%s': %s", udata[1].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    switch(cross_copy(sx, cluster, cluster_name, vdata[0].name, vdata[1].name, udata[0].username, udata[1].username, profile_name, local_file_path)) {
        case -1:
            ERROR("Cannot upload file");
            goto test_acl_err;
        case 0:
            PRINT("User permissions revoked correctly");
            break;
        case 1:
            ERROR("File uploaded without permission");
            goto test_acl_err;
    }
    if(prepare_users(sx, cluster, udata + sizeof(udata) / sizeof(*udata) - 1, 1)) { /* create third user using first user rights */
        ERROR("Failed to prepare users");
        goto test_acl_err;
    }
    for(i=0; i<sizeof(list)/sizeof(*list); i++)
        list[i] = udata[i].username;
    switch(check_users(cluster, list, sizeof(list) / sizeof(*list))) {
        case -1:
            ERROR("%s", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 0: break;
        case 1: 
            ERROR("Wrong user list");
            goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, vdata[0].name, udata[2].username, SX_ACL_RW, 0)) {
        ERROR("Cannot add 'read,write' permission to %s: %s", udata[2].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, udata[2].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[2].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, vdata[0].name, udata[1].username, SX_ACL_READ, 0)) {
        if(sxc_geterrnum(sx) == SXE_EAUTH)
            PRINT("User permissions enforced correctly");
        else {
            ERROR("Cannot add 'read' permission to '%s': %s", udata[2].username, sxc_geterrmsg(sx));
            goto test_acl_err;
        }
    } else {
        ERROR("Permissions granted without permission");
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        ERROR("Failed to set default profile: %s", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_volume_acl(cluster, vdata[0].name, udata[2].username, 0, SX_ACL_RW)) {
        ERROR("Cannot revoke 'read,write' permission from '%s': %s", udata[2].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_volume_modify(cluster, vdata[0].name, NULL, udata[2].username, 0, -1, NULL)) {
        ERROR("Cannot change volume owner: %s", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, udata[2].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[2].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    switch(check_user(cluster, vdata[0].name, udata[0].username, SX_ACL_RW)) { /* read + write */
        case -1:
            ERROR("%s", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 1:
            ERROR("'%s' has diferent rights on '%s'", udata[0].username, vdata[0].name);
            goto test_acl_err;
    }
    switch(check_user(cluster, vdata[0].name, udata[2].username, SX_ACL_FULL)) { /* read + write + manager + owner */
        case -1:
            ERROR("%s", sxc_geterrmsg(sx));
            goto test_acl_err;
        case 1:
            ERROR("'%s' has diferent rights on '%s'", udata[0].username, vdata[0].name);
            goto test_acl_err;
    }
    if(remove_volume(sx, cluster, vdata[0].name, 1)) {
        if(sxc_geterrnum(sx) == SXE_EAUTH)
            PRINT("Volume removal permission enforced correctly");
        else {
            ERROR("Cannot remove '%s' volume", vdata[0].name, sxc_geterrmsg(sx));
            goto test_acl_err;
        }
    } else {
        ERROR("Volume removed without permission");
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        ERROR("Failed to set default profile: %s", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(unlink(local_file_path)) {
        ERROR("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
        file = NULL;
        goto test_acl_err;
    }
    sprintf(local_file_path, "%s/%s", local_dir_path, ACL_KEY_FILE_NAME);
    file = fopen(local_file_path, "w+");
    if(!file) {
        ERROR("Cannot open '%s' file: %s", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(sxc_user_getinfo(cluster, udata[0].username, file, NULL, 0)) {
        ERROR("Cannot get '%s' key: %s", udata[0].username, sxc_geterrmsg(sx));
        if(fclose(file) == EOF)
            ERROR("Cannot close '%s' file: %s", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(fflush(file) == EOF) {
        ERROR("Cannot flush '%s' file: %s", local_file_path, strerror(errno));
        if(fclose(file) == EOF)
            ERROR("Cannot close '%s' file: %s", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    rewind(file);
    if(ftell(file) == -1) {
        ERROR("Cannot rewind '%s' file: %s", local_file_path, strerror(errno));
        if(fclose(file) == EOF)
            ERROR("Cannot close '%s' file: %s", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(fread(key_tmp, 1, AUTHTOK_ASCII_LEN, file) != AUTHTOK_ASCII_LEN) {
        ERROR("Cannot get '%s' key", udata[0].username);
        if(fclose(file) == EOF)
            ERROR("Cannot close '%s' file: %s", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(fclose(file) == EOF) {
        ERROR("Cannot close '%s' file: %s", local_file_path, strerror(errno));
        goto test_acl_err;
    }
    if(memcmp(udata[0].key, key_tmp, AUTHTOK_ASCII_LEN)) {
        ERROR("User keys differs");
        goto test_acl_err;
    }
    free(udata[1].key);
    udata[1].key = sxc_user_newkey(cluster, udata[0].username, NULL, NULL, 1, NULL);
    if(!udata[1].key) {
        ERROR("Cannot generate new key for '%s': %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, udata[0].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    free(udata[2].key);
    if(sxc_cluster_whoami(cluster, &udata[2].key, NULL, NULL, NULL, NULL)) {
        if(sxc_geterrnum(sx) == 7) {
            PRINT("User permissions after key change enforced correctly");
        } else {
            ERROR("%s", sxc_geterrmsg(sx));
            goto test_acl_err;
        }
    } else {
        ERROR("Name checked without permission");
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        ERROR("Failed to set default profile: %s", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_add_access(cluster, udata[0].username, udata[1].key)) {
        ERROR("Failed to add '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, udata[0].username)) {
        ERROR("Failed to set '%s' profile authentication: %s", udata[0].username, sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    free(udata[2].key);
    if(sxc_cluster_whoami(cluster, &udata[2].key, NULL, NULL, &quota, &quota_used)) {
        ERROR("%s", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    if(quota || quota_used) {
        ERROR("Got non-zero quota and quota usage");
        goto test_acl_err;
    }
    if(strcmp(udata[0].username, udata[2].key)) {
        ERROR("Got wrong user name");
        goto test_acl_err;
    }
    if(sxc_cluster_set_access(cluster, profile_name)) {
        ERROR("Failed to set default profile: %s", sxc_geterrmsg(sx));
        goto test_acl_err;
    }
    
    PRINT("Succeeded");
    ret = 0;
test_acl_err:
    if(local_file_path && unlink(local_file_path) && errno != ENOENT)
        WARNING("Cannot delete '%s' file: %s", local_file_path, strerror(errno));
    cleanup_volumes(sx, cluster, vdata, sizeof(vdata) / sizeof(*vdata));
    cleanup_users(sx, cluster, udata, sizeof(udata) / sizeof(*udata));
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
/*  {for_volume, no_filter, dedicated, additional, rand_filters, block_size, block_count, name, function},*/
    {1, 1, 0, 0, 0, 0, 0, "empty_file", test_empty_file},
    {1, 0, 0, 0, 0, SX_BS_SMALL, 15, "transfer:small", test_transfer},
    {1, 0, 0, 1, 0, SX_BS_MEDIUM, 10, "transfer:medium", test_transfer},
    {1, 0, 0, 1, 0, SX_BS_LARGE, 130, "transfer:large", test_transfer},
    {1, 1, 0, 0, 0, SX_BS_SMALL, 15, "revision:small", test_revision},
    {1, 1, 0, 1, 0, SX_BS_MEDIUM, 10, "revision:medium", test_revision},
    {1, 1, 0, 1, 0, SX_BS_LARGE, 130, "revision:large", test_revision},
    {1, 1, 0, 0, 0, 0, 0, "cat", test_cat},
    {1, 1, 0, 0, 1, 0, 0, "rename", test_rename},
    {1, 0, 0, 1, 1, 0, 0, "rename:all", test_rename},
    {1, 1, 0, 0, 0, 0, 0, "errors", test_errors},
    {1, 0, 1, 0, 0, 0, 0, "attribs", test_attribs},
    {1, 0, 1, 0, 0, 0, 0, "undelete", test_undelete},
    {0, 0, 1, 1, 0, 0, 0, "undelete:volume", test_undelete_vol},
    {0, 0, 0, 0, 0, 0, 0, "volume_meta", test_volmeta},
    {0, 0, 0, 0, 0, 0, 0, "quota:user", test_user_quota},
/*    {0, 0, 0, 0, 1, 0, 0, "quota:user:filters", test_user_quota},*/ /* TODO: metadata is included in quota */
    {0, 0, 0, 0, 0, 0, 0, "quota:volume", test_volume_quota},
    {0, 0, 0, 0, 0, 0, 0, "copy", test_copy},
    {0, 0, 0, 0, 1, 0, 0, "copy:filters", test_copy},
    {0, 0, 0, 0, 1, 0, 0, "paths", test_paths},
    {0, 0, 0, 0, 0, 0, 0, "acl", test_acl},
    {-1, -1, -1, -1, -1, 0, 0, NULL, NULL}
};

int main(int argc, char **argv) {
    int i, j, ret = 1, fcount = 0;
    char *local_dir_path = NULL, *filter_dir = NULL;
    sxc_client_t *sx = NULL;
    sxc_logger_t log;
    sxc_cluster_t *cluster = NULL;
    sxc_uri_t *uri = NULL;
    const sxf_handle_t *filters = NULL;
    struct gengetopt_args_info args;

    if(QUOTA_FILE_SIZE <= QUOTA_VOL_SIZE) {
        ERROR("File size to test quota is smaller than volume size. Please contact with software developer.");
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
    } else {
        if(args.inputs_num != 1) {
            cmdline_parser_print_help();
            printf("\n");
            ERROR("Wrong number of arguments");
            goto main_err;
        }
        /* If particular test has been specified, check if it exists */
        if(args.run_test_given) {
            for(i=0; tests[i].name; i++)
                if(!strcmp(args.run_test_arg, tests[i].name))
                    break;
            if(!tests[i].name) {
                /* The given test has not been found, bail out with error message */
                ERROR("Cannot find test '%s'. Use --list-tests option to get the list of available tests", args.run_test_arg);
                goto main_err;
            }
        }

        sx = sxc_init(SRC_VERSION, sxc_file_logger(&log, argv[0], "/dev/null", 0), test_input_fn, NULL);
        if(!sx) {
            ERROR("Cannot initiate SX");
            goto main_err;
        }
        if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
            ERROR("Could not set configuration directory to '%s': %s", args.config_dir_arg, sxc_geterrmsg(sx));
            goto main_err;
        }
        sxc_set_debug(sx, args.debug_flag);
        uri = sxc_parse_uri(sx, args.inputs[0]);
        if(!uri) {
            ERROR("%s", sxc_geterrmsg(sx));
            goto main_err;
        }
        if(uri->volume) {
            ERROR("Volume name not expected");
            goto main_err;
        }
        cluster = sxc_cluster_load_and_update(sx, uri->host, uri->profile);
        if(!cluster) {
            ERROR("Cannot load cluster: %s", sxc_geterrmsg(sx));
            goto main_err;
        }
        local_dir_path = (char*)malloc(strlen(LOCAL_DIR) + strlen("XXXXXX") + 1 + 1); /* There is '/' character at the end */
        if(!local_dir_path) {
            ERROR("Cannot allocate memory for local_dir_path");
            goto main_err;
        }
        sprintf(local_dir_path, "%sXXXXXX", LOCAL_DIR);
        if(!mkdtemp(local_dir_path)) {
            ERROR("Cannot create '%s' temporary directory: %s", local_dir_path, strerror(errno));
            goto main_err;
        }
        strcat(local_dir_path, "/");
        /* Load filters */
        if(args.filter_dir_given) {
            filter_dir = strdup(args.filter_dir_arg);
        } else {
            const char *pt = sxi_getenv("SX_FILTER_DIR");
            if(pt)
                filter_dir = strdup(pt);
        }
        if(!filter_dir) {
            ERROR("Cannot get filter directory. Use --filter-dir or 'export SX_FILTER_DIR=<src_dir>/client/src/filters/'");
            goto main_err;
        }
        if(sxc_filter_loadall(sx, filter_dir)) {
            ERROR("Cannot load filters");
            goto main_err;
        }
        filters = sxc_filter_list(sx, &fcount);
        if(!filters) {
            ERROR("No filters available");
            goto main_err;
        }
        /* Test volume without any filter */
        if(volume_test(sx, cluster, local_dir_path, uri, &args, filters, fcount, -1, NULL, 3))
            goto main_err;
        /* Iterate over all filters */
        for(i=0; i<fcount; i++) {
            const sxc_filter_t *f = sxc_get_filter(&filters[i]);
            if(!strcmp(f->uuid, "35a5404d-1513-4009-904c-6ee5b0cd8634")) /* Skip old aes filter */
                continue;
            for(j=i+1; j<fcount; j++) {
                const sxc_filter_t *f2 = sxc_get_filter(&filters[j]);
                if(!strcmp(f2->shortname, f->shortname))
                    if((f->version[0] > f2->version[0]) || (f->version[0] == f2->version[0] && f->version[1] > f2->version[1])) {
                        j = fcount;
                        continue; /* There is newer version loaded */
                    }
            }
            /* 'f' is the latest version loaded */
            /* Test volume with found filter */
            if(volume_test(sx, cluster, local_dir_path, uri, &args, filters, fcount, i, get_filter_cfg(&filters[i]), 1))
                goto main_err;
        }
        /* Run the rest of tests */
        for(i=0; tests[i].name; i++)
            if(!tests[i].for_volume && (args.run_test_given ? !strcmp(args.run_test_arg, tests[i].name) : 1) && run_test(sx, cluster, local_dir_path, NULL, uri->profile, uri->host, NULL, filters, fcount, &args, 1, 1, &tests[i])) {
                failed_test_msg(&args, &tests[i]);
                goto main_err;
            }
        /* The end of tests */
        PRINT("All tests succeeded");
    }

    ret = 0;
main_err:
    if(local_dir_path && rmdir(local_dir_path)) {
        ERROR("Cannot delete '%s' directory: %s", local_dir_path, strerror(errno));
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

