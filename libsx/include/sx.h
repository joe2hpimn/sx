/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef __SX_H
#define __SX_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

typedef struct _sxc_client_t sxc_client_t;

typedef struct {
    void *ctx;
    const char *argv0;
    void (*log)(void* ctx, const char *argv0, int prio, const char *msg);
    void (*close)(void *ctx);
} sxc_logger_t;

const sxc_logger_t* sxc_default_logger(sxc_logger_t *logger, const char *argv0);
const sxc_logger_t* sxc_file_logger(sxc_logger_t *logger, const char *argv0, const char *file, int no_errors);

const char *sxc_get_version(void);
int sxc_compatible_with(sxc_client_t *sx, const char *server_version);
sxc_client_t *sxc_init(const char *client_version, const sxc_logger_t *func, int (*confirm)(const char *prompt, int default_answer));
void sxc_shutdown(sxc_client_t *sx, int signal);
void sxc_set_debug(sxc_client_t *sx, int enabled);
void sxc_set_verbose(sxc_client_t *sx, int enabled);
void sxc_clearerr(sxc_client_t *sx);
int sxc_geterrnum(sxc_client_t *sx);
const char *sxc_geterrmsg(sxc_client_t *sx);
void sxc_loglasterr(sxc_client_t *sx);
void sxc_set_confdir(sxc_client_t *sx, const char *config_dir);
const char *sxc_get_confdir(sxc_client_t *sx);
#define SXC_ALIAS_PREFIX ":"
int sxc_set_alias(sxc_client_t *sx, const char *alias, const char *profile, const char *host);
char *sxc_get_alias(sxc_client_t *sx, const char *profile, const char *host);

enum sxc_error_t {
    SXE_NOERROR,	/* No error occoured */
    SXE_EARG,		/* Invalid argument */
    SXE_EMEM,		/* Out of memory */
    SXE_EREAD,		/* Error reading from disk */
    SXE_EWRITE,		/* Error writing to disk */
    SXE_ETMP,		/* Error with temporary file creation and IO */
    SXE_ECRYPT,		/* Error reported by the cryto library */
    SXE_EAUTH,		/* Authentication related error */
    SXE_ECURL,		/* Error reported by the connector library */
    SXE_ECOMM,		/* Error in the communication with the cluster */
    SXE_ECFG,		/* Error parsing the configuration */
    SXE_ETIME,		/* Error retrieving the current time */
    SXE_EFILTER,	/* Filter related error */
    SXE_SKIP,           /* File was skipped */
};

typedef struct _sxc_cluster_t sxc_cluster_t;

sxc_cluster_t *sxc_cluster_init(sxc_client_t *sx, const char *uri, const char *clusterdir, char *hostlist, const char *auth_file, int cluster_user, int debug, int no_ssl, int no_check_certificate, int force_reinit);

sxc_cluster_t *sxc_cluster_new(sxc_client_t *sx);
void sxc_cluster_reset_hosts(sxc_cluster_t *cluster);
void sxc_cluster_free(sxc_cluster_t *cluster);
int sxc_cluster_set_dnsname(sxc_cluster_t *cluster, const char *dnsname);
int sxc_cluster_set_sslname(sxc_cluster_t *cluster, const char *sslname);
int sxc_cluster_fetch_ca(sxc_cluster_t *cluster, int quiet);
const char *sxc_cluster_get_dnsname(const sxc_cluster_t *cluster);
const char *sxc_cluster_get_sslname(const sxc_cluster_t *cluster);
int sxc_cluster_set_uuid(sxc_cluster_t *cluster, const char *uuid);
void sxc_cluster_remove_uuid(sxc_cluster_t *cluster);
const char *sxc_cluster_get_uuid(const sxc_cluster_t *cluster);
int sxc_cluster_add_host(sxc_cluster_t *cluster, const char *host);
int sxc_cluster_set_cafile(sxc_cluster_t *cluster, const char *cafile);
int sxc_cluster_add_access(sxc_cluster_t *cluster, const char *profile_name, const char *access_token);
int sxc_cluster_set_access(sxc_cluster_t *cluster, const char *profile_name);
sxc_cluster_t *sxc_cluster_load(sxc_client_t *sx, const char *config_dir, const char *cluster_name);
int sxc_cluster_save(sxc_cluster_t *cluster, const char *config_dir);
int sxc_cluster_remove(sxc_cluster_t *cluster, const char *config_dir);
int sxc_cluster_fetchnodes(sxc_cluster_t *cluster);
sxc_cluster_t *sxc_cluster_load_and_update(sxc_client_t *sx, const char *config_dir, const char *cluster_name, const char *profile_name);

int sxc_cluster_trigger_gc(sxc_cluster_t *cluster);

typedef struct _sxc_cluster_lu_t sxc_cluster_lu_t;
sxc_cluster_lu_t *sxc_cluster_listusers(sxc_cluster_t *cluster);
int sxc_cluster_listusers_next(sxc_cluster_lu_t *lu, char **user_name, int *is_admin);
void sxc_cluster_listusers_free(sxc_cluster_lu_t *lu);

typedef struct _sxc_cluster_la_t sxc_cluster_la_t;
sxc_cluster_la_t *sxc_cluster_listaclusers(sxc_cluster_t *cluster, const char *volume);
int sxc_cluster_listaclusers_next(sxc_cluster_la_t *la, char **acluser_name, int *can_read, int *can_write, int *is_owner, int *is_admin);
void sxc_cluster_listaclusers_free(sxc_cluster_la_t *la);

typedef struct _sxc_cluster_lv_t sxc_cluster_lv_t;
sxc_cluster_lv_t *sxc_cluster_listvolumes(sxc_cluster_t *cluster);
int sxc_cluster_listvolumes_next(sxc_cluster_lv_t *lv, char **volume_name, int64_t *volume_size, unsigned int *replica_count);
void sxc_cluster_listvolumes_free(sxc_cluster_lv_t *lv);

typedef struct _sxc_cluster_lf_t sxc_cluster_lf_t;
sxc_cluster_lf_t *sxc_cluster_listfiles(sxc_cluster_t *cluster, const char *volume, const char *glob_pattern, int recursive, int64_t *volume_size, unsigned int *replica_count, unsigned int *nfiles, int reverse);
int sxc_cluster_listfiles_next(sxc_cluster_lf_t *lf, char **file_name, int64_t *file_size, time_t *file_created_at);
void sxc_cluster_listfiles_free(sxc_cluster_lf_t *lf);

typedef struct _sxc_file_t sxc_file_t;
sxc_file_t *sxc_file_remote(sxc_cluster_t *cluster, const char *volume, const char *path);
sxc_file_t *sxc_file_local(sxc_client_t *sx, const char *path);
sxc_file_t *sxc_file_from_url(sxc_client_t *sx, sxc_cluster_t **cluster, const char *confdir, const char *url);
int sxc_file_is_sx(sxc_file_t *file);
int sxc_file_require_dir(sxc_file_t *file);
void sxc_file_free(sxc_file_t *sxfile);

typedef struct _sxc_xres_t sxc_xres_t;

uint64_t sxc_xres_get_total_size(sxc_xres_t *xres);
double sxc_xres_get_total_speed(sxc_xres_t *xres);
void sxc_xres_get_upload_blocks(sxc_xres_t *xres, unsigned int *all, unsigned int *requested, unsigned int *transferred);
void sxc_xres_get_download_blocks(sxc_xres_t *xres, unsigned int *all, unsigned int *requested, unsigned int *transferred);
double sxc_xres_get_upload_speed(sxc_xres_t *xres);
double sxc_xres_get_download_speed(sxc_xres_t *xres);
void sxc_free_xres(sxc_xres_t *xres);

int sxc_copy(sxc_file_t *source, sxc_file_t *dest, int recursive, sxc_xres_t **xres);
int sxc_cat(sxc_file_t *source, int dest);

typedef struct _sxc_file_list_t sxc_file_list_t;

sxc_file_list_t *sxc_file_list_new(sxc_client_t *sx, int recursive);
/* passes ownership of file too on success */
int sxc_file_list_add(sxc_file_list_t *lst, sxc_file_t *file, int allow_glob);
void sxc_file_list_free(sxc_file_list_t *sx);/* frees contained sx_file_t too */
unsigned sxc_file_list_get_total(const sxc_file_list_t *lst);
unsigned sxc_file_list_get_successful(const sxc_file_list_t *lst);

int sxc_rm(sxc_file_list_t *target);


typedef struct _sxi_ht_t sxc_meta_t;
sxc_meta_t *sxc_meta_new(sxc_client_t *sx);
sxc_meta_t *sxc_filemeta_new(sxc_file_t *file);
sxc_meta_t *sxc_volumemeta_new(sxc_file_t *file);
void sxc_meta_free(sxc_meta_t *meta);
unsigned int sxc_meta_count(sxc_meta_t *meta);
int sxc_meta_getval(sxc_meta_t *meta, const char *key, const void **value, unsigned int *value_len);
int sxc_meta_getkeyval(sxc_meta_t *meta, unsigned int itemno, const char **key, const void **value, unsigned int *value_len);
int sxc_meta_setval(sxc_meta_t *meta, const char *key, const void *value, unsigned int value_len);
int sxc_meta_setval_fromhex(sxc_meta_t *meta, const char *key, const char *valuehex, unsigned int valuehex_len);
void sxc_meta_delval(sxc_meta_t *meta, const char *key);
void sxc_meta_empty(sxc_meta_t *meta);

int sxc_user_add(sxc_cluster_t *cluster, const char *username, int admin, FILE *storeauth);
int sxc_user_getkey(sxc_cluster_t *cluster, const char *username, FILE *storeauth);

int sxc_volume_add(sxc_cluster_t *cluster, const char *url, int64_t size, unsigned int replica, sxc_meta_t *metadata, const char *owner);

int sxc_volume_acl(sxc_cluster_t *cluster, const char *url,
                  const char *user, const char *grant, const char *revoke);

typedef struct _sxc_uri_t {
    char *profile;
    char *host;
    char *volume;
    char *path;
} sxc_uri_t;

sxc_uri_t *sxc_parse_uri(sxc_client_t *sx, const char *uri);
void sxc_free_uri(sxc_uri_t *uri);

int sxc_fgetline(sxc_client_t *sx, FILE *f, char **ret);

/* filters */
#define SXF_ABI_VERSION	6

typedef enum {
    SXF_TYPE_NONE = 0,
    SXF_TYPE_COMPRESS,
    SXF_TYPE_CRYPT,
    SXF_TYPE_GENERIC
} sxf_type_t;

typedef enum {
    SXF_MODE_UPLOAD = 0,
    SXF_MODE_DOWNLOAD
} sxf_mode_t;

typedef enum {
    SXF_ACTION_NORMAL = 0,
    SXF_ACTION_REPEAT,
    SXF_ACTION_DATA_END
} sxf_action_t;

struct filter_handle;
typedef struct filter_handle sxf_handle_t;

typedef struct {
    int abi_version;
    const char *shortname;
    const char *fullname;
    const char *summary;
    const char *options;
    const char *uuid;
    sxf_type_t type;
    int version[2];
    /* filter functions */
    int (*init)(const sxf_handle_t *handle, void **ctx);
    int (*shutdown)(const sxf_handle_t *handle, void *ctx);
    int (*configure)(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len);
    int (*data_prepare)(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode);
    ssize_t (*data_process)(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action);
    int (*data_finish)(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode);
    int (*file_process)(const sxf_handle_t *handle, void *ctx, const char *filename, sxc_meta_t *meta, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode);
    /* internal */
    const char *tname;
} sxc_filter_t;

int sxc_filter_loadall(sxc_client_t *sx, const char *filter_dir);
const sxf_handle_t *sxc_filter_list(sxc_client_t *sx, int *count);
const sxc_filter_t* sxc_get_filter(const sxf_handle_t *handle);

enum sxc_log_level {
    SX_LOG_ALERT=1,
    SX_LOG_CRIT,
    SX_LOG_ERR,
    SX_LOG_WARNING,
    SX_LOG_NOTICE,
    SX_LOG_INFO,
    SX_LOG_DEBUG
};

int sxc_filter_msg(const sxf_handle_t *handle, int level, const char *format, ...);

#endif
