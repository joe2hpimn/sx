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
#include "sx.h"
#include "curlevents.h"
#include "cert.h"
#include "vcrypto.h"
#include "vcryptocurl.h"
#include "sxreport.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#ifdef HMAC_UPDATE_RETURNS_INT
#define hmac_init_ex HMAC_Init_ex
#define hmac_update HMAC_Update
#define hmac_final HMAC_Final
#else
#define hmac_init_ex(a, b, c, d, e) (HMAC_Init_ex((a), (b), (c), (d), (e)), 1)
#define hmac_update(a, b, c) (HMAC_Update((a), (b), (c)), 1)
#define hmac_final(a, b, c) (HMAC_Final((a), (b), (c)), 1)
#endif

static int ssl_verify_hostname(X509_STORE_CTX *ctx, void *arg)
{
    STACK_OF(X509) *sk;
    X509 *x;
    curlev_t *ev = arg;
    sxi_conns_t *conns = sxi_curlev_get_conns(ev);
    sxc_client_t *sx = sxi_conns_get_client(conns);
    const char *name;
    long err;

    /* build chain */
    int ok = X509_verify_cert(ctx);
    sk = X509_STORE_CTX_get_chain(ctx);
    SXDEBUG("verify result: %d\n",ok);
    if (!ok) {
        err = X509_STORE_CTX_get_error(ctx);
        if (sxi_curlev_verify_peer(ev)) {
            sxi_seterr(sx, SXE_ECOMM, "Failed to verify certificate: %s", X509_verify_cert_error_string(err));
            sxi_curlev_set_verified(ev, -1);
            return 0;
        }
        /* verify_peer is off, ignore error */
        SXDEBUG("verify_peer is off, ignoring error: %s", X509_verify_cert_error_string(err));
        X509_STORE_CTX_set_error(ctx,X509_V_OK);
    }
    if (!sk) {
        sxi_seterr(sx, SXE_ECOMM, "No certificate chain?");
        sxi_curlev_set_verified(ev, -1);
        return 0;
    }
    x = sk_X509_value(sk, 0);
    name = sxi_conns_get_sslname(conns) ? sxi_conns_get_sslname(conns) : sxi_conns_get_dnsname(conns);
    if (sxi_verifyhost(sx, name, x) != CURLE_OK) {
#if 0
        if (!e->cafile) {
            sxi_notice(sx, "Ignoring %s!", sxc_geterrmsg(sx));
            ev->ssl_verified = 2;
            return 1;
        }
#endif
        sxi_seterr(sx, SXE_ECOMM, "Hostname mismatch in certificate, expected: \"%s\"", name);
        X509_STORE_CTX_set_error(ctx,X509_V_ERR_APPLICATION_VERIFICATION);
        sxi_curlev_set_verified(ev, -1);
        return 0;
    }
    SXDEBUG("certificate verified");
    sxi_curlev_set_verified(ev, 1);
    return 1;
}

int sxi_sslctxfun(sxc_client_t *sx, curlev_t *ev, const struct curl_tlssessioninfo *info)
{
    if (info->backend != CURLSSLBACKEND_OPENSSL) {
        curl_version_info_data *data = curl_version_info(CURLVERSION_NOW);
        sxi_seterr(sx, SXE_ECURL, "SSL backend mismatch: OpenSSL expected, got %s",
                   data->ssl_version ? data->ssl_version : "N/A");
        return -1;
    }
    SSL_CTX *ctx = (SSL_CTX*)info->internals;
    SSL_CTX_set_cert_verify_callback(ctx, ssl_verify_hostname, ev);
    return 0;
}

struct sxi_hmac_sha1_ctx {
    HMAC_CTX ctx;
};

sxi_hmac_sha1_ctx *sxi_hmac_sha1_init(void)
{
    sxi_hmac_sha1_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    HMAC_CTX_init(&ctx->ctx);
    return ctx;
}

void sxi_hmac_sha1_cleanup(sxi_hmac_sha1_ctx **ctxptr)
{
    if (!ctxptr || !*ctxptr)
        return;
    HMAC_CTX_cleanup(&(*ctxptr)->ctx);
    free(*ctxptr);
    *ctxptr = NULL;
}

int sxi_hmac_sha1_init_ex(sxi_hmac_sha1_ctx *ctx,
                     const void *key, int key_len)
{
    if (!ctx)
        return 0;
    return hmac_init_ex(&ctx->ctx, key, key_len, EVP_sha1(), NULL);
}

int sxi_hmac_sha1_update(sxi_hmac_sha1_ctx *ctx, const void *d, int len)
{
    if (!ctx)
        return 0;
    return hmac_update(&ctx->ctx, d, len);
}

int sxi_hmac_sha1_final(sxi_hmac_sha1_ctx *ctx, unsigned char *out, unsigned int *len)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    if (!ctx)
        return 0;
    if (!hmac_final(&ctx->ctx, md, len))
        return 0;
    if (len && *len != SXI_SHA1_BIN_LEN)
        return 0;
    memcpy(out, md, SXI_SHA1_BIN_LEN);
    return 1;
}

int sxi_crypto_check_ver(struct sxi_logger *l)
{
    uint32_t runtime_ver = SSLeay();
    uint32_t compile_ver = SSLEAY_VERSION_NUMBER;
    if((runtime_ver & 0xff0000000) != (compile_ver & 0xff0000000)) {
        sxi_log_msg(l, "crypto_check_ver", SX_LOG_CRIT,
                    "OpenSSL library version mismatch: compiled: %x, runtime: %d", compile_ver, runtime_ver);
        return -1;
    }
    ERR_load_crypto_strings();
    return 0;
}

void sxi_report_crypto(sxc_client_t *sx)
{
    sxi_report_library_int(sx, "OpenSSL", SSLEAY_VERSION_NUMBER, SSLeay(), 0x10000000, 0x100000, 0x1000);
    sxi_info(sx, "OpenSSL CFLAGS: %s", SSLeay_version(SSLEAY_CFLAGS));
}

void sxi_sha256(const unsigned char *d, size_t n,unsigned char *md)
{
    SHA256(d, n, md);
}

struct sxi_md_ctx {
    EVP_MD_CTX ctx;
};

sxi_md_ctx *sxi_md_init(void)
{
    sxi_md_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    EVP_MD_CTX_init(&ctx->ctx);
    return ctx;
}

void sxi_md_cleanup(sxi_md_ctx **ctxptr)
{
    if (!ctxptr || !*ctxptr)
        return;
    EVP_MD_CTX_cleanup(&(*ctxptr)->ctx);
    free(*ctxptr);
    *ctxptr = NULL;
}

int sxi_sha1_init(sxi_md_ctx *ctx)
{
    if (!ctx)
        return 0;
    return EVP_DigestInit(&ctx->ctx, EVP_sha1());
}

int sxi_sha1_update(sxi_md_ctx *ctx, const void *d, size_t len)
{
    if (!ctx)
        return 0;
    return EVP_DigestUpdate(&ctx->ctx, d, len);
}

int sxi_sha1_final(sxi_md_ctx *ctx, unsigned char *out, unsigned int *len)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    if (!ctx)
        return 0;
    if(!EVP_DigestFinal(&ctx->ctx, md, len))
	return 0;
    if (len && *len != SXI_SHA1_BIN_LEN)
        return 0;
    memcpy(out, md, SXI_SHA1_BIN_LEN);
    return 1;
}

int sxi_rand_bytes(unsigned char *d, int len)
{
    char namebuf[1024];
    const char *rndfile = RAND_file_name(namebuf, sizeof(namebuf));
    if(rndfile)
        RAND_load_file(rndfile, -1);
    if(RAND_status() == 1 && RAND_bytes(d, len) == 1) {
        RAND_write_file(rndfile);
        return 1;
    }
    return 0;
}

int sxi_rand_pseudo_bytes(unsigned char *d, int len)
{
    return RAND_pseudo_bytes(d, len);
}

void sxi_rand_cleanup(void)
{
    RAND_cleanup();
}

void sxi_vcrypto_cleanup(void)
{
    ERR_free_strings();
}

static int sxi_fmt_X509_name(struct sxi_fmt* fmt, X509_NAME *name)
{
    char *bio_data;
    long n;
    BIO *mem = BIO_new(BIO_s_mem());
    if (!mem)
        return -1;

    X509_NAME_print_ex(mem, name, 0, XN_FLAG_SEP_CPLUS_SPC);
    n = BIO_get_mem_data(mem, &bio_data);
    if (n >= 0)
        sxi_fmt_msg(fmt, "%.*s", (int)n, bio_data);
    BIO_free(mem);
    if (n < 0)
        return -1;
    return 0;
}

static int print_certificate_info(sxc_client_t *sx, X509 *x)
{
    struct sxi_fmt fmt;
    unsigned int i, n;
    unsigned char hash[EVP_MAX_MD_SIZE];

    if (!sx)
        return -1;
    if (!x) {
        sxi_seterr(sx, SXE_EARG, "Called with NULL argument");
        return -1;
    }

    sxi_fmt_start(&fmt);
    sxi_fmt_msg(&fmt, "\tSubject: ");
    if (sxi_fmt_X509_name(&fmt, X509_get_subject_name(x)) == -1) {
        sxi_seterr(sx, SXE_EMEM, "Cannot print subject name");
        return -1;
    }

    sxi_fmt_msg(&fmt, "\n\tIssuer: ");
    if (sxi_fmt_X509_name(&fmt, X509_get_issuer_name(x)) == -1) {
        sxi_seterr(sx, SXE_EMEM, "Cannot print issuer name");
        return -1;
    }
    if (!X509_digest(x, EVP_sha1(), hash, &n)) {
        sxi_seterr(sx, SXE_EMEM, "Cannot compute certificate fingerprint");
        return -1;
    }
    sxi_fmt_msg(&fmt, "\n\tSHA1 Fingerprint: ");
    for (i=0; i<n; i++)
    {
        sxi_fmt_msg(&fmt, "%02X", hash[i]);
        if (i + 1 == n)
            sxi_fmt_msg(&fmt, "\n");
        else
            sxi_fmt_msg(&fmt,":");
    }
    sxi_notice(sx, "%s", fmt.buf);
    /* TODO: print subject alt name too */
    return 0;
}

static X509 *load_cert_file(sxc_client_t *sx, const char *file)
{
    X509 *x;
    FILE *f = fopen(file, "r");
    if (!f) {
        sxi_seterr(sx, SXE_ECFG, "Cannot open CA file '%s'", file);
        return NULL;
    }

    x = PEM_read_X509(f, NULL, NULL, NULL);
    if (!x) {
        sxi_seterr(sx, SXE_ECFG, "Cannot read PEM file");
        fclose(f);
        return NULL;
    }
    fclose(f);
    return x;
}

int sxi_vcrypt_get_cert_fingerprint(sxc_client_t *sx, const char *file, uint8_t *hash, unsigned int *len) {
    int rc = 0;
    if(!file || !hash || !len) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return -1;
    }
    X509 *x = load_cert_file(sx, file);
    if(!x)
        return -1;

    if (!X509_digest(x, EVP_sha1(), hash, len)) {
        sxi_seterr(sx, SXE_EMEM, "Cannot compute certificate fingerprint");
        return -1;
    }
    X509_free(x);
    return rc;
}

int sxi_vcrypt_print_cert_info(sxc_client_t *sx, const char *file, int batch_mode)
{
    int rc = 0;
    X509 *x = load_cert_file(sx, file);
    if(!x)
        return -1;
    if (!batch_mode) {
        sxi_info(sx, "\tSSL certificate:");
        if (print_certificate_info(sx, x)) {
            sxi_seterr(sx, SXE_ECFG, "Cannot print certificate info");
            rc = -1;
        }
    }
    X509_free(x);
    return rc;
}

static void print_cipherlist(sxc_client_t *sx, SSL *ssl)
{
    struct sxi_fmt fmt;
    unsigned i = 0;
    const char *cipher;

    sxi_fmt_start(&fmt);
    sxi_fmt_msg(&fmt, "SSL cipherlist (expanded) ");
    while((cipher = SSL_get_cipher_list(ssl, i++))) {
        sxi_fmt_msg(&fmt, ":%s", cipher);
    }
    sxi_info(sx, "%s", fmt.buf);
}

int sxi_vcrypt_print_cipherlist(sxc_client_t *sx, const char *list)
{
    SSL_CTX *ctx;
    OpenSSL_add_ssl_algorithms();
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx)
        return -1;
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    if (!SSL_CTX_set_cipher_list(ctx, list))
        return -1;
    SSL *ssl=SSL_new(ctx);
    if (ssl) {
        /* note: this prints some ciphers that the server won't actually use
         * without additional configuration like SRP, PSK, etc. */
        print_cipherlist(sx, ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ctx);
    return 0;
}

int sxi_vcrypto_errmsg(sxc_client_t *sx)
{
    char buf[256];
    unsigned long e;
    while ((e = ERR_get_error())) {
        ERR_error_string_n(e, buf, sizeof(buf));
        buf[sizeof(buf)-1] = 0;
        sxi_notice(sx, "OpenSSL error: %s", buf);
    }
    return 0;
}
