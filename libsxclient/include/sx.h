/*
 *  Copyright (C) 2012-2015 Skylable Ltd. <info-copyright@skylable.com>
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
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _sxc_client_t sxc_client_t;

typedef struct {
    void *ctx;
    const char *argv0;
    void (*log)(void* ctx, const char *argv0, int prio, const char *msg);
    void (*close)(void *ctx);
} sxc_logger_t;

const sxc_logger_t* sxc_default_logger(sxc_logger_t *logger, const char *argv0);
const sxc_logger_t* sxc_file_logger(sxc_logger_t *logger, const char *argv0, const char *file, int no_errors);

typedef enum {
    SXC_INPUT_PLAIN,	    /* Plain text input */
    SXC_INPUT_SENSITIVE,    /* Sensitive input (password, etc.) */
    SXC_INPUT_YN	    /* Y/N question */
} sxc_input_t;
typedef int (*sxc_input_cb)(sxc_client_t *sx, sxc_input_t type, const char *prompt, const char *def, char *in, unsigned int insize, void *ctx);

int sxc_lib_init(const char *client_version);
sxc_client_t *sxc_client_init(const sxc_logger_t *func, sxc_input_cb input_cb, void *input_ctx);
sxc_client_t *sxc_init(const char *client_version, const sxc_logger_t *func, sxc_input_cb input_cb, void *input_ctx);
const char *sxc_get_version(void);
void sxc_client_shutdown(sxc_client_t *sx, int signal);
void sxc_lib_shutdown(int signal);
void sxc_shutdown(sxc_client_t *sx, int signal);
void sxc_set_debug(sxc_client_t *sx, int enabled);
void sxc_set_verbose(sxc_client_t *sx, int enabled);
int sxc_is_verbose(sxc_client_t *sx);
void sxc_clearerr(sxc_client_t *sx);
int sxc_geterrnum(sxc_client_t *sx);
const char *sxc_geterrmsg(sxc_client_t *sx);
void sxc_loglasterr(sxc_client_t *sx);
int sxc_set_confdir(sxc_client_t *sx, const char *config_dir);
const char *sxc_get_confdir(sxc_client_t *sx);
#define SXC_ALIAS_PREFIX "@"
int sxc_set_alias(sxc_client_t *sx, const char *alias, const char *profile, const char *host);
/* Delete all aliases assigned to given cluster configuration */
int sxc_del_aliases(sxc_client_t *sx, const char *profile, const char *host);
int sxc_get_aliases(sxc_client_t *sx, const char *profile, const char *host, char **aliases);
int sxc_set_tempdir(sxc_client_t *sx, const char *tempdir);

enum sxc_error_t {
    SXE_NOERROR,	/* No error occured */
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
    SXE_EAGAIN,         /* Try again later  */
    SXE_ABORT,          /* Operation aborted */
};

typedef struct _sxc_cluster_t sxc_cluster_t;

sxc_cluster_t *sxc_cluster_init(sxc_client_t *sx, const char *uri, const char *clusterdir, char *hostlist, const char *auth_file, int cluster_user, int debug, int no_ssl, int no_check_certificate, int force_reinit);

sxc_cluster_t *sxc_cluster_new(sxc_client_t *sx);
void sxc_cluster_reset_hosts(sxc_cluster_t *cluster);
void sxc_cluster_free(sxc_cluster_t *cluster);
int sxc_cluster_set_dnsname(sxc_cluster_t *cluster, const char *dnsname);
int sxc_cluster_set_sslname(sxc_cluster_t *cluster, const char *sslname);
int sxc_cluster_disable_proxy(sxc_cluster_t *cluster);
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
const char *sxc_cluster_get_access(sxc_cluster_t *cluster, const char *profile_name);
int sxc_cluster_set_httpport(sxc_cluster_t *cluster, unsigned int port);
unsigned int sxc_cluster_get_httpport(const sxc_cluster_t *cluster);
sxc_cluster_t *sxc_cluster_load(sxc_client_t *sx, const char *config_dir, const char *cluster_name);
int sxc_cluster_save(sxc_cluster_t *cluster, const char *config_dir);
int sxc_cluster_remove(sxc_cluster_t *cluster, const char *config_dir);
int sxc_cluster_fetchnodes(sxc_cluster_t *cluster);
sxc_cluster_t *sxc_cluster_load_and_update(sxc_client_t *sx, const char *cluster_name, const char *profile_name);

/* Set upload and download transfer bandwidth in bits per second */
int sxc_cluster_set_bandwidth_limit(sxc_client_t *sx, sxc_cluster_t *cluster, int64_t bandwidth_limit);
/* Get upload and download transfer bandwidth in bits per second */
int64_t sxc_cluster_get_bandwidth_limit(sxc_client_t *sx, const sxc_cluster_t *cluster);

int sxc_cluster_trigger_gc(sxc_cluster_t *cluster, int delete_reservations);

typedef struct _sxc_cluster_lu_t sxc_cluster_lu_t;
sxc_cluster_lu_t *sxc_cluster_listusers(sxc_cluster_t *cluster);
sxc_cluster_lu_t *sxc_cluster_listclones(sxc_cluster_t *cluster, const char *username);
int sxc_cluster_listusers_next(sxc_cluster_lu_t *lu, char **user_name, int *is_admin, char **desc, int64_t *quota, int64_t *quota_used);
void sxc_cluster_listusers_free(sxc_cluster_lu_t *lu);

typedef enum {
    SX_ACL_READ_FLAG=0,
    SX_ACL_WRITE_FLAG,
    SX_ACL_MANAGER_FLAG,
    SX_ACL_OWNER_FLAG
} sx_acl_t;

#define SX_ACL_READ (1 << SX_ACL_READ_FLAG)
#define SX_ACL_WRITE (1 << SX_ACL_WRITE_FLAG)
#define SX_ACL_RW (SX_ACL_READ | SX_ACL_WRITE)
#define SX_ACL_MANAGER (1 << SX_ACL_MANAGER_FLAG)
#define SX_ACL_OWNER (1 << SX_ACL_OWNER_FLAG)
#define SX_ACL_FULL (SX_ACL_RW | SX_ACL_MANAGER | SX_ACL_OWNER)

typedef struct _sxc_cluster_la_t sxc_cluster_la_t;
sxc_cluster_la_t *sxc_cluster_listaclusers(sxc_cluster_t *cluster, const char *volume);
int sxc_cluster_listaclusers_next(sxc_cluster_la_t *la, char **acluser_name, int *acls);
void sxc_cluster_listaclusers_free(sxc_cluster_la_t *la);

typedef struct _sxi_ht_t sxc_meta_t;
typedef struct _sxc_cluster_lv_t sxc_cluster_lv_t;
sxc_cluster_lv_t *sxc_cluster_listvolumes(sxc_cluster_t *cluster, int get_meta);
int sxc_cluster_listvolumes_next(sxc_cluster_lv_t *lv, char **volume_name, char **volume_owner, int64_t *volume_used_size, int64_t *volume_files_size, int64_t *volume_nfiles, int64_t *volume_size, unsigned int *replica_count, unsigned int *effective_replica_count, unsigned int *revisions, char privs[3], sxc_meta_t **meta);
void sxc_cluster_listvolumes_free(sxc_cluster_lv_t *lv);

#define SXC_UINT64_UNDEFINED 0xffffffffffffffff
#define SXC_UINT32_UNDEFINED 0xffffffff

typedef struct _sxc_cluster_lf_t sxc_cluster_lf_t;
sxc_cluster_lf_t *sxc_cluster_listfiles(sxc_cluster_t *cluster, const char *volume, const char *glob_pattern, int recursive, unsigned int *nfiles, int reverse);
sxc_cluster_lf_t *sxc_cluster_listfiles_etag(sxc_cluster_t *cluster, const char *volume, const char *glob_pattern, int recursive, unsigned int *nfiles, int reverse, const char *etag_file);
typedef struct _sxc_file_t sxc_file_t;
int sxc_cluster_listfiles_next(sxc_cluster_t *cluster, const char *volume, sxc_cluster_lf_t *lf, sxc_file_t **file);
int sxc_cluster_listfiles_prev(sxc_cluster_t *cluster, const char *volume, sxc_cluster_lf_t *lf, sxc_file_t **file);

void sxc_cluster_listfiles_free(sxc_cluster_lf_t *lf);
void sxc_cluster_listvolumes_reset(sxc_cluster_lv_t *lv);


/*
 * Set active connections limits.
 * max_active - maximal number of running connections.
 * max_active_per_host - maximal number of running connections with each host.
 */
int sxc_cluster_set_conns_limit(sxc_cluster_t *cluster, unsigned int max_active, unsigned int max_active_per_host);

/* Return configuration link that can be passed to cluster users */
char *sxc_cluster_configuration_link(sxc_cluster_t *cluster, const char *username, const char *token);

/*
 * Return configuration link returned by sxaduthd
 *
 * username: A username used for authentication
 * pass: A user password
 * host: sxauthd hostname
 * port: sxauthd port number
 * quiet: Do not prompt for cluster certificate when set to 1.
 * hostlist: An optional hostlist used in place of sxauthd hostname
 */
char *sxc_fetch_sxauthd_credentials(sxc_client_t *sx, const char *username, const char *pass, const char *host, int port, int quiet, const char *hostlist);

int sxc_read_pass_file(sxc_client_t *sx, const char *pass_file, char *pass, unsigned int pass_len);

/* Transfer direction */
typedef enum { SXC_XFER_DIRECTION_DOWNLOAD = 1, SXC_XFER_DIRECTION_UPLOAD = 2, SXC_XFER_DIRECTION_BOTH = 3 } sxc_xfer_direction_t;

typedef struct {
    int64_t sent;
    int64_t skipped;
} sxc_xfer_timing_t;

/* Single direction transfer stats */
typedef struct {
    /* Currently transferred file name and size */
    const char *file_name;
    int64_t file_size;
    unsigned int blocksize; /* Size of blocks used to divide file */

    /* Transfer direction */
    sxc_xfer_direction_t direction;

    /* 
     * How much data should be transferred. At the begining it will be equal to file_size,
     * but can change if some hashes already exist. 
     */
    int64_t to_send;

    /* Total transferred */
    int64_t sent;

    /* Time spent on sending data */
    double total_time;
    /* Time when current transfer started */
    struct timeval start_time;

    /* Time window for ETA computation */
    sxc_xfer_timing_t timing[256];
    unsigned int last_time_idx;

    double eta; /* Estimated finish time */
    double speed; /* Number of bytes send and skipped divided by total time */
    double real_speed; /* Number of bytes sent divided by total time */
} sxc_xfer_progress_t;

/* Transfer state, place to add "stalled" or "canceled"... statuses */
typedef enum { 
    SXC_XFER_STATUS_STARTED,
    SXC_XFER_STATUS_RUNNING, 
    SXC_XFER_STATUS_WAITING, 
    SXC_XFER_STATUS_PART_STARTED,
    SXC_XFER_STATUS_PART_FINISHED, 
    SXC_XFER_STATUS_FINISHED, 
    SXC_XFER_STATUS_FINISHED_ERROR,
} sxc_xfer_status_t;

struct _sxc_xfer_stat;
typedef int (*sxc_xfer_callback)(const struct _sxc_xfer_stat *stat);
struct _sxc_xfer_stat {
    /* Current transfer information */
    sxc_xfer_progress_t current_xfer;

    /* Transfer status */
    sxc_xfer_status_t status;

    /* Global transfer timing information */
    struct timeval start_time;
    double total_time;

    /* Generic download and upload values */
    int64_t total_dl;
    int64_t total_ul; 

    /* Total number of bytes that needs to be downloaded and uploaded */
    int64_t total_to_dl;
    int64_t total_to_ul;

    /* Total number of bytes that downloaded and uploaded data contains */
    int64_t total_data_dl;
    int64_t total_data_ul;

    /* Timers used to compute speed and callbacks invocation frequency */
    struct timeval interval_timer;

    /* Invoked when transfer information changes */
    sxc_xfer_callback xfer_callback;

    /* Context */
    void *ctx;
};

typedef struct _sxc_xfer_stat sxc_xfer_stat_t;
int sxc_cluster_set_progress_cb(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_xfer_callback cb, void *ctx);
/*sxc_xfer_callback sxc_cluster_get_progress_cb(const sxc_cluster_t *cluster);*/

sxc_file_t *sxc_file_remote(sxc_cluster_t *cluster, const char *volume, const char *path, const char *revision);
sxc_file_t *sxc_file_local(sxc_client_t *sx, const char *path);
sxc_file_t *sxc_file_from_url(sxc_client_t *sx, sxc_cluster_t **cluster, const char *url);
int sxc_file_is_sx(sxc_file_t *file);
int sxc_file_is_remote_dir(sxc_file_t *file);
int sxc_file_require_dir(sxc_file_t *file);
int sxc_file_has_glob(sxc_file_t *file);
sxc_cluster_t *sxc_file_get_cluster(const sxc_file_t *file);
const char *sxc_file_get_volume(const sxc_file_t *file);
const char *sxc_file_get_path(const sxc_file_t *file);
const char *sxc_file_get_remote_path(const sxc_file_t *file);
const char *sxc_file_get_revision(const sxc_file_t *file);
mode_t sxc_file_get_mode(const sxc_file_t *file);
time_t sxc_file_get_ctime(const sxc_file_t *file);
time_t sxc_file_get_atime(const sxc_file_t *file);
time_t sxc_file_get_mtime(const sxc_file_t *file);
time_t sxc_file_get_created_at(const sxc_file_t *file);
uid_t sxc_file_get_uid(const sxc_file_t *file);
uid_t sxc_file_get_gid(const sxc_file_t *file);
int64_t sxc_file_get_size(const sxc_file_t *file);
int64_t sxc_file_get_remote_size(const sxc_file_t *file);
int sxc_file_set_path(sxc_file_t *file, const char *newpath);
void sxc_file_free(sxc_file_t *sxfile);

#define SXC_EXCLUDE     0
#define SXC_INCLUDE     1
typedef struct _sxc_exclude_t sxc_exclude_t;
/* Fill sxc_exlude_t structure */
sxc_exclude_t *sxc_exclude_init(sxc_client_t *sx, const char **patterns, unsigned int npatterns, int mode);
void sxc_exclude_delete(sxc_exclude_t *e);

typedef struct _sxc_file_list_t sxc_file_list_t;

int sxc_copy_single(sxc_file_t *source, sxc_file_t *dest, int recursive, int onefs, int ignore_errors, const sxc_exclude_t *exclude, int fail_same_file);
int sxc_copy(sxc_file_list_t *source, sxc_file_t *dest, int recursive, int onefs, const sxc_exclude_t *exclude, int fail_same_file);
int sxc_copy_sxfile(sxc_file_t *source, sxc_file_t *dest, int fail_same_file);
int sxc_cat(sxc_file_t *source, int dest);
int sxc_mass_rename(sxc_cluster_t *cluster, sxc_file_t *source, sxc_file_t *dest, int recursive);
int sxc_update_filemeta(sxc_file_t *file, sxc_meta_t *newmeta);


sxc_file_list_t *sxc_file_list_new(sxc_client_t *sx, int recursive, int ignore_errors);
/* passes ownership of file too on success */
int sxc_file_list_add(sxc_file_list_t *lst, sxc_file_t *file, int allow_glob);
void sxc_file_list_free(sxc_file_list_t *sx);/* frees contained sx_file_t too */
unsigned sxc_file_list_get_total(const sxc_file_list_t *lst);
unsigned sxc_file_list_get_successful(const sxc_file_list_t *lst);

int sxc_rm(sxc_file_list_t *target, int mass);
int sxc_remove_sxfile(sxc_file_t *file);


sxc_meta_t *sxc_meta_new(sxc_client_t *sx);
sxc_meta_t *sxc_filemeta_new(sxc_file_t *file);
sxc_meta_t *sxc_volumemeta_new(sxc_file_t *file);
sxc_meta_t *sxc_custom_volumemeta_new(sxc_file_t *file);
sxc_meta_t *sxc_clustermeta_new(sxc_cluster_t *cluster);
sxc_meta_t *sxc_cluster_settings_new(sxc_cluster_t *cluster, const char *key);
void sxc_meta_free(sxc_meta_t *meta);
unsigned int sxc_meta_count(sxc_meta_t *meta);
unsigned int sxc_meta_modcount(sxc_meta_t *meta);
int sxc_meta_getval(sxc_meta_t *meta, const char *key, const void **value, unsigned int *value_len);
int sxc_meta_getkeyval(sxc_meta_t *meta, unsigned int itemno, const char **key, const void **value, unsigned int *value_len);
int sxc_meta_setval(sxc_meta_t *meta, const char *key, const void *value, unsigned int value_len);
int sxc_meta_setval_fromhex(sxc_meta_t *meta, const char *key, const char *valuehex, int valuehex_len);
void sxc_meta_delval(sxc_meta_t *meta, const char *key);
void sxc_meta_empty(sxc_meta_t *meta);

/* Prompt for username */
int sxc_prompt_username(sxc_client_t *sx, char *buff, unsigned int bufflen, const char *prefix);
/* Prompt for user password */
int sxc_prompt_password(sxc_client_t *sx, char *buff, unsigned int buff_len, const char *prefix, int repeat, unsigned int min_length);
/* Return authentication token based on user name and password */
int sxc_pass2token(sxc_cluster_t *cluster, const char *username, const char *password, char *tok_buf, unsigned int tok_size);

char *sxc_user_add(sxc_cluster_t *cluster, const char *username, const char *pass, int admin, const char *oldtoken, const char *desc, int generate_key, int64_t quota);
/*
 * Clone existing user
 * username: existing user name
 * clonename: clone name
 * oldtoken: old authorisation token that will assigned to newly created clone
 * role: will receive cloned user role (same as existing users' role)
 * desc: human readable description of the user
 */
char *sxc_user_clone(sxc_cluster_t *cluster, const char *username, const char *clonename, const char *oldtoken, int *role, const char *desc);
int sxc_user_remove(sxc_cluster_t *cluster, const char *username, int remove_clones);
int sxc_user_getinfo(sxc_cluster_t *cluster, const char *username, FILE *storeauth, int *is_admin, int get_config_link);
char *sxc_user_newkey(sxc_cluster_t *cluster, const char *username, const char *pass, const char *oldtoken, int generate_key, const char *profile_name);
/* Set quota for files stored in all volumes owned by the user. 
 * Only non-negative values are allowed, when 0 is given, no quota enforcement will be performed for the user. */
int sxc_user_modify(sxc_cluster_t *cluster, const char *username, int64_t quota, const char *description);

int sxc_cluster_whoami(sxc_cluster_t *cluster, char **user, char **role, char **desc, int64_t *quota, int64_t *quota_used);

int sxc_volume_add(sxc_cluster_t *cluster, const char *name, int64_t size, unsigned int replica, unsigned int revisions, sxc_meta_t *metadata, const char *owner);
int sxc_volume_remove(sxc_cluster_t *cluster, const char *name);
int sxc_volume_modify(sxc_cluster_t *cluster, const char *volume, const char *newname, const char *newowner, int64_t newsize, int max_revs, sxc_meta_t *custom_meta);
int sxc_volume_acl(sxc_cluster_t *cluster, const char *url, const char *user, int grant_privs, int revoke_privs);
int sxc_volume_modify_replica(sxc_cluster_t *cluster, const char *volume, unsigned int replica);

typedef struct {
    sxc_file_t *file;
    unsigned int block_size;
} sxc_revision_t;

typedef struct {
    sxc_revision_t **revisions;
    unsigned int count;
} sxc_revlist_t;
    
sxc_revlist_t *sxc_revisions(sxc_file_t *file);
void sxc_revisions_free(sxc_revlist_t *revisions);


typedef struct _sxc_uri_t {
    char *profile;
    char *host;
    char *volume;
    char *path;
} sxc_uri_t;

sxc_uri_t *sxc_parse_uri(sxc_client_t *sx, const char *uri);
void sxc_free_uri(sxc_uri_t *uri);
/* Print basic cluster information */
int sxc_cluster_info(sxc_cluster_t *cluster, const char *profile, const char *host);

int sxc_fgetline(sxc_client_t *sx, FILE *f, char **ret);

int sxc_input_fn(sxc_client_t *sx, sxc_input_t type, const char *prompt, const char *def, char *in, unsigned int insize, void *ctx); /* default input function */

/* filters */
#define SXF_ABI_VERSION	12

/** Defines a filter's type
 * This is used to prioritize filters, for example
 * an encryption filter must always be run last on upload.
 */
typedef enum {
    SXF_TYPE_NONE = 0,
    SXF_TYPE_COMPRESS,/**< compression filter */
    SXF_TYPE_CRYPT,/**< encryption filter */
    SXF_TYPE_GENERIC /**< generic filter */
} sxf_type_t;

/** Defines the direction of the transfer
 */
typedef enum {
    SXF_MODE_UPLOAD = 1,/**< file upload */
    SXF_MODE_DOWNLOAD,/**< file download */
    SXF_MODE_RCOPY, /**< remote-to-remote copy (fast mode) */
    SXF_MODE_DELETE, /**< file delete */
    SXF_MODE_LIST /**< remote file listing (called when file is processed before download or upload) */
} sxf_mode_t;

/** EOF and looping control
 */
typedef enum {
    SXF_ACTION_NORMAL = 0,/**< first time a new block is processed */
    SXF_ACTION_REPEAT,/**< repeat call with same 'in' and 'insize' parameters */
    SXF_ACTION_DATA_END/**< marks the file's last block */
} sxf_action_t;

/** Determines whether filename is local or remote
 */
typedef enum {
    SXF_FILEMETA_LOCAL = 0,/**< file meta is local */
    SXF_FILEMETA_REMOTE /**< file meta is remote */
} sxf_filemeta_type_t;

struct filter_handle;
typedef struct filter_handle sxf_handle_t;

typedef struct {
    /** @{ */
    int abi_version;
    /**< must always be SXF_ABI_VERSION, used to detect ABI mismatches */

    const char *shortname;
    /**< filter name used by the tools: sxvol create -f shortname */

    const char *shortdesc;
    /**< used by: sxvol filter --list */

    const char *summary;
    /**< used by: sxvol filter --info shortname */

    const char *options;
    /**< describes [filterargs] in sxvol create -f shortname=[filterargs] */

    const char *uuid;
    /**< all clients must have a filter with this UUID to access the volume.
     * Use uuidgen to create a unique value */

    sxf_type_t type;
    /**< an \ref sxf_type_t enum value */

    int version[2];
    /**< if there are multiple versions of a filter in the load path,
     * then tools always load the filter with the highest version number */
    /**< @} */

    /**< @name filter functions */
    /**< @{ */

    int (*init)(const sxf_handle_t *handle, void **ctx);
    /**< Called once after a filter is loaded
     *
     * \note when a client tool starts it loads all filters
     *
     * @param[in] handle an opaque handle for sxc_filter_msg
     * @param[out] ctx context structure allocated by the filter
     * @retval 0 on success
     * @retval <0 on error
     * */

    int (*shutdown)(const sxf_handle_t *handle, void *ctx);
    /**<
     * Called once before a filter is unloaded
     * @param[in] handle an opaque handle for sxc_filter_msg
     * @param[in,out] ctx context structure
     *                 allocated by \ref init or \ref data_prepare
     */

    int (*configure)(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len, sxc_meta_t *custom_volume_meta);
    /**< Called when a volume is created by sxvol
     *
     * @param[in] handle an opaque handle for sxc_filter_msg
     * @param[in] cfgstr the filter arguments [filterargs]
     * @param[in] cfgdir per-volume directory used to store client-local data
     * @param[out] cfgdata allocate and store volume metadata here
     * @param[out] cfgdata_len length of cfgdata
     * @param[in] custom_volume_meta custom volume metadata
     * @retval 0 on success
     * @retval non-zero on error
     * */

    int (*data_prepare)(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_meta_t *custom_volume_meta, sxf_mode_t mode);
    /**< Called before processing a file
     *
     * If data_process is NULL this function might not be called at all.
     *
     * @param[in] handle an opaque handle for sxc_filter_msg
     * @param[in,out] ctxptr context pointer
     *                allocated by \ref init, or allocated here
     * @param[in] filename name of the original input file (might be a tempfile)
     * @param[in] cfgdir per-volume directory used to store client-local data
     * @param[in] cfgdata volume metadata here, as defined by \ref configure
     * @param[in] cfgdata_len length of cfgdata
     * @param[in] custom_volume_meta custom volume metadata
     * @param[in] mode either SXF_MODE_UPLOAD or SXF_MODE_DOWNLOAD
     * @retval 0 on success
     * @retval non-zero on error
     * */


    ssize_t (*data_process)(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action);
    /**< Called to transform a file during an upload/download
     *
     * @param[in] handle an opaque handle for sxc_filter_msg
     * @param[in] ctxptr context pointer
     *                   allocated in \ref init or \ref data_prepare
     * @param[in] in input buffer
     * @param[in] insize size of the input buffer
     *                   (not related to the file's blocksize)
     * @param[out] out output buffer
     * @param[in] outsize size of the output buffer
     *                   (not related to the file's blocksize)
     * @param[in] mode either SXF_MODE_UPLOAD or SXF_MODE_DOWNLOAD
     * @param[in] action SXF_ACTION_DATA_END means EOF,
     *                   SXF_ACTION_REPEAT means that 'in' and 'insize' is the same data
     *                   as in the last call,
     *                   SXF_ACTION_NORMAL means that 'in' points to a new buffer
     * @param[out] action
     *                   Set to SXF_ACTION_DATA_END to mark EOF on output
     *                   Set to SXF_ACTION_REPEAT if the input buffer
     *                   wasn't processed entirely, or the output buffer got full.
     *                   data_process will then get called again with
     *                   action=SXF_ACTION_REPEAT.
     *             \note data_process receives SXF_ACTION_DATA_END only once
     *                   SXF_ACTION_REPEAT takes precedence
     * @return amount of bytes written to the output buffer
     * \see sxf_action_t enum
     */

    int (*data_finish)(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode);
    /**<
     * Called after the last block is processed
     *
     * \note also called when an error is encountered during processing
     *
     * @param[in] handle an opaque handle for sxc_filter_msg
     * @param[in,out] ctx context structure
     *                you can free the context structure here, or in shutdown
     * @param[in] mode either SXF_MODE_UPLOAD or SXF_MODE_DOWNLOAD
     * @retval 0 on success
     * @retval non-zero on error
     */


    int (*file_process)(const sxf_handle_t *handle, void *ctx, sxc_file_t *file, sxc_meta_t *meta, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode);
    /**<
     * Process an entire file and/or its metadata.
     * It can process a file and set per-file metadata before the file begins to upload (called
     * before \ref data_prepare).
     * It can read per-file metadata and do additional file processing after a file finished
     * downloading and the temporary file was renamed to the final filename.
     *
     * @param[in] handle an opaque handle for sxc_filter_msg
     * @param[in] ctx context structure, allocated by \ref init
     * @param[in,out] file file structure
     * @param[in,out] meta file metadata
     * @param[in] cfgdir per-volume directory used to store client-local data
     * @param[in] cfgdata volume metadata here, as defined by \ref configure
     * @param[in] cfgdata_len length of cfgdata
     * @param[in] mode SXF_MODE_UPLOAD, SXF_MODE_DOWNLOAD or SXF_MODE_LIST
     * @retval 0 on success
     * @retval non-zero on error
     */

    void (*file_notify)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, const char *source_cluster, const char *source_volume, const char *source_path, const char *dest_cluster, const char *dest_volume, const char *dest_path);
    /**<
     * Called after a specific action (such as file upload, download) took place.
     *
     * @param[in] handle an opaque handle for sxc_filter_msg
     * @param[in] ctx context structure, allocated by \ref init
     * @param[in] cfgdata volume configuration metadata, as defined by \ref configure
     * @param[in] cfgdata_len length of cfgdata
     * @param[in] mode notification type (SXF_MODE_*)
     * @param[in] source_cluster name of cluster containing source file (NULL for local files)
     * @param[in] source_volume name of volume containing source file (NULL for local files)
     * @param[in] source_path source file path
     * @param[in] dest_cluster name of cluster for destination file (NULL for local files)
     * @param[in] dest_volume name of volume for destination file (NULL for local files)
     * @param[in] dest_path destination file path
     */

    int (*file_update)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, sxc_file_t *source, sxc_file_t *dest, int recursive);
    /**<
     * Process/update file objects before a specific action (such as upload, download) takes place.
     *
     * @param[in] handle an opaque handle for sxc_filter_msg
     * @param[in] ctx context structure, allocated by \ref init
     * @param[in] cfgdata volume configuration metadata, as defined by \ref configure
     * @param[in] cfgdata_len length of cfgdata
     * @param[in] mode mode type (SXF_MODE_*)
     * @param[in] source source file object
     * @param[in] dest destination file object
     * @param[in] recursive information whether a file operation is performed within recursive mode
     */

    int (*filemeta_process)(const sxf_handle_t *handle, void **ctx, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_file_t *file, sxf_filemeta_type_t filemeta_type, const char *filename, char **new_filename, sxc_meta_t *file_meta, sxc_meta_t *custom_volume_meta);
    /**<
     * Process filename and/or file meta before a specific action takes place.
     *
     * \note libsxclient is responsible for freeing pointer allocated and stored to new_filename
     *
     * @param[in] handle an opaque handle for sxc_filter_msg
     * @param[in,out] ctx context structure
     * @param[in] cfgdir per-volume directory used to store client-local data
     * @param[in] cfgdata volume configuration metadata, as defined by \ref configure
     * @param[in] cfgdata_len length of cfgdata
     * @param[in] file file object
     * @param[in] filemeta_type filemeta type (SXF_FILEMETA_*)
     * @param[in] filename filename to be processed
     * @param[out] new_filename new file name to be used
     * @param[out] file_meta file meta
     * @param[in] custom_volume_meta custom volume metadata
     */

    /** */
    /**< @} */

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
int sxc_filter_get_input(const sxf_handle_t *h, sxc_input_t type, const char *prompt, const char *def, char *in, unsigned int insize);

/* Escape string */
char *sxc_escstr(char *str);

/* Check if string contains any non-escaped globbing character */
int sxc_str_has_glob(const char *s);

/* URL-decode string */
char *sxc_urldecode(sxc_client_t *sx, const char *s);

int sxc_set_node_preference(sxc_client_t *sx, float preference);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
