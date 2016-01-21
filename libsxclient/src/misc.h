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

#ifndef _MISC_H
#define _MISC_H

#include "sx.h"
#include <sys/time.h>
#include <sys/types.h>

/* dest_size: size of destination buffer (sizeof() if static, or n if malloc(n))
 * src: NULL-terminated string
 * */
void sxi_strlcpy(char *dest, const char *src, size_t dest_size);

void *sxi_realloc(sxc_client_t *sx, void *ptr, unsigned int newlen);
int sxi_is_valid_authtoken(sxc_client_t *sx, const char *token);
char *sxi_b64_enc(sxc_client_t *sx, const void *data, unsigned int data_size);
int sxi_b64_dec(sxc_client_t *sx, const char *string, void *buf, unsigned int *buf_size);
char *sxi_b64_enc_core(const void *data, unsigned int data_size);
int sxi_b64_dec_core(const char *string, void *buf, unsigned int *buf_size);
void sxi_bin2hex(const void *bin, unsigned int len, char *hex);
int sxi_uuid_parse(const char *uuid_str, uint8_t *uuid);
void sxi_uuid_unparse(const uint8_t *uuid, char *uuid_str);
int sxi_hex2bin(const char *src, uint32_t src_len, uint8_t *dst, uint32_t dst_len);
unsigned int sxi_rand(void); /* Note: use sxi_rand_pseudo_bytes if you need to detect random generation errors */
char *sxi_getenv(const char *name);

typedef struct _sxi_ht_t sxi_ht;
sxi_ht *sxi_ht_new(sxc_client_t *sx, unsigned int initial_size);
int sxi_ht_add(sxi_ht *ht, const void *key, unsigned int key_length, void *value);
int sxi_ht_get(sxi_ht *ht, const void *key, unsigned int key_length, void **value);
void sxi_ht_del(sxi_ht *ht, const void *key, unsigned int key_length);
char *sxi_make_tempfile(sxc_client_t *sx, const char *basedir, FILE **f);
char *sxi_tempfile_track(sxc_client_t *sx, const char *basedir, FILE **f);
int sxi_tempfile_untrack(sxc_client_t *sx, const char *name);
void sxi_tempfile_unlink_untrack(sxc_client_t *sx, const char *name);
int sxi_tempfile_istracked(sxc_client_t *sx, const char *name);
char *sxi_urlencode(sxc_client_t *sx, const char *string, int encode_slash);

unsigned int sxi_ht_count(sxi_ht *ht);
unsigned int sxi_ht_modcount(sxi_ht *ht);
void sxi_ht_enum_reset(sxi_ht *ht);
int sxi_ht_enum_getnext(sxi_ht *ht, const void **key, unsigned int *key_len, const void **value);
void sxi_ht_empty(sxi_ht *ht);
void sxi_ht_free(sxi_ht *ht);

double sxi_timediff(const struct timeval *a, const struct timeval *b);
int sxi_utf8_validate_len(const char *str);
int sxi_utf8_validate(const char *str);

char *sxi_json_quote_string(const char *s);
int sxi_uri_is_sx(sxc_client_t *sx, const char *uri);

char sxi_read_one_char(void);
int sxi_mkdir_hier(sxc_client_t *sx, const char *fullpath, mode_t mode);
int sxi_rmdirs(const char *dir);

int64_t sxi_parse_size(sxc_client_t *sx, const char *str, int allow_0);

/* Hold information about alias */
typedef struct _alias_t {
    /* Alias name */
    char *name;
    /* Cluster name */
    char *cluster;
} alias_t;

/* Hold aliases list */
typedef struct _sxc_alias_list_t {
    /* Array of aliases */
    alias_t *entry;
    /* Number of aliases stored in entry array */
    int num;
} alias_list_t;

/* Get aliases stored in configuration directory */
alias_list_t *sxi_get_alias_list(sxc_client_t *sx);

/* List all aliases stored in configuration directory */
int sxi_load_aliases(sxc_client_t *sx, alias_list_t **list);
/* Free memory taken for aliases list */
void sxi_free_aliases(alias_list_t *aliases);

/* Compute checksum */
uint32_t sxi_checksum(uint32_t crc, const void *buf, size_t size);

/* Use blowfish key derivation */
int sxi_derive_key(const char *pass, const char *salt, unsigned salt_size, unsigned int log2_iter, char *out, unsigned int len);

/* Return index of first non-escaped globbing character (*, ? or [) or zero if it does not occur int input string.
 * Cannot be called with NULL argument. */
int sxi_str_has_glob(const char *s);

sxc_meta_t *sxi_meta_dup(sxc_client_t *sx, sxc_meta_t *meta);
int sxi_meta_checksum(sxc_client_t *sx, sxc_meta_t *meta, unsigned char *hash);

uint32_t sxi_swapu32(uint32_t v);
uint64_t sxi_swapu64(uint64_t v);

#endif

