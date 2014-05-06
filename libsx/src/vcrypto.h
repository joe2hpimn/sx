/*
 *  Copyright (C) 2014 Skylable Ltd. <info-copyright@skylable.com>
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

#include "sxlog.h"

int sxi_crypto_check_ver(struct sxi_logger *l);

typedef struct sxi_hmac_sha1_ctx sxi_hmac_sha1_ctx;
sxi_hmac_sha1_ctx *sxi_hmac_sha1_init(void);
int sxi_hmac_sha1_init_ex(sxi_hmac_sha1_ctx *ctx,
                     const void *key, int key_len);
int sxi_hmac_sha1_update(sxi_hmac_sha1_ctx *ctx, const void *d, int len);
int sxi_hmac_sha1_update_str(sxi_hmac_sha1_ctx *ctx, const char *str);
int sxi_hmac_sha1_final(sxi_hmac_sha1_ctx *ctx, unsigned char *md, unsigned int *len);
void sxi_hmac_sha1_cleanup(sxi_hmac_sha1_ctx **ctx);

typedef struct sxi_md_ctx sxi_md_ctx;
sxi_md_ctx *sxi_md_init(void);
int sxi_sha1_init(sxi_md_ctx *ctx);
int sxi_sha1_update(sxi_md_ctx *ctx, const void *d, size_t len);
int sxi_sha1_final(sxi_md_ctx *ctx, unsigned char *md, unsigned int *len);
void sxi_md_cleanup(sxi_md_ctx **ctx);

#define SHA256_DIGEST_LENGTH 32
void sxi_sha256(const unsigned char *d, size_t n,unsigned char *md);

void sxi_report_crypto(sxc_client_t *sx);

int sxi_rand_bytes(unsigned char *d, int len);
int sxi_rand_pseudo_bytes(unsigned char *d, int len);
void sxi_rand_cleanup(void);

int sxi_sha1_calc(const void *salt, unsigned salt_len, const void *buffer, unsigned int len, unsigned char *hash);

void sxi_vcrypto_cleanup(void);

int sxi_vcrypt_print_cert_info(sxc_client_t *sx, const char *file, int batch_mode);

int sxi_vcrypt_print_cipherlist(sxc_client_t *sx, const char *cipherlist);

int sxi_vcrypto_errmsg(sxc_client_t *sx);
