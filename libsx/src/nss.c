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
#include "vcrypto.h"
#include "vcryptocurl.h"
#include "curlevents.h"
#include <nss.h>
#include <ssl.h>
#include <pk11pub.h>
#include <nspr.h>
#include <secmod.h>
#include <errno.h>

int sxi_sslctxfun(sxc_client_t *sx, curlev_t *ev, const struct curl_tlssessioninfo *info)
{
    if (info->backend != CURLSSLBACKEND_NSS) {
        curl_version_info_data *data = curl_version_info(CURLVERSION_NOW);
        sxi_seterr(sx, SXE_ECURL, "SSL backend mismatch: NSS expected, got %s",
                   data->ssl_version ? data->ssl_version : "N/A");
        return -1;
    }
    PRFileDesc *desc = info->internals;
    CERTCertificate *cert = SSL_PeerCertificate(desc);
    if (!cert) {
        PRInt32 err = PR_GetError();
        SXDEBUG("Unable to retrieve certificate for cluster: %s",
                PR_ErrorToString(err, PR_LANGUAGE_I_DEFAULT));
        return -EAGAIN;
    }
    sxi_conns_t *conns = sxi_curlev_get_conns(ev);
    const char *hostname = sxi_conns_get_sslname(conns);
    SECStatus ret = CERT_VerifyCertName(cert, hostname);
    if (ret == SECSuccess) {
            /* workaround for NSS cache:
             * if we run with verify_peer on, it remember that certificate was
             * not trusted because it was self-signed.
             * Then even if we explicitly add it as trusted in curl, it still
             * considers it as untrusted.
             * So explicitly set trust settings here. If we reached this place
             * then NSS already validated the certificate.
             * */
            CERTCertTrust none;
            CERT_DecodeTrustString(&none, "PT,PT,PT");
            CERT_ChangeCertTrust(NULL, cert, &none);
        sxi_curlev_set_verified(ev, 1);
    } else {
        PRInt32 err = PR_GetError();
        sxi_seterr(sx, SXE_ECOMM, "Certificate is not valid for cluster '%s': %s", hostname,
                   PR_ErrorToString(err, PR_LANGUAGE_I_DEFAULT));
        sxi_curlev_set_verified(ev, -1);
        return -1;
    }
    return 0;
}

struct sxi_md_ctx {
    PK11Context *context;
};

sxi_md_ctx *sxi_md_init(void)
{
    sxi_md_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->context = PK11_CreateDigestContext(SEC_OID_SHA1);
    if (!ctx->context) {
        free(ctx);
	return NULL;
    }

    return ctx;
}

void sxi_md_cleanup(sxi_md_ctx **ctxptr)
{
    if (!ctxptr || !*ctxptr)
        return;
    if ((*ctxptr)->context)
      PK11_DestroyContext((*ctxptr)->context, PR_TRUE);
    free(*ctxptr);
    *ctxptr = NULL;
}

int sxi_sha1_init(sxi_md_ctx *ctx)
{
    if (!ctx)
        return 0;
    if (PK11_DigestBegin(ctx->context) != SECSuccess)
	return 0;
    return 1;
}

int sxi_sha1_update(sxi_md_ctx *ctx, const void *d, size_t len)
{
    if (!ctx)
        return 0;
    if (PK11_DigestOp(ctx->context, d, len) != SECSuccess)
	return 0;
    return 1;
}

int sxi_sha1_final(sxi_md_ctx *ctx, unsigned char *out, unsigned int *len)
{
    unsigned char md[SXI_SHA1_BIN_LEN];
    unsigned int mdlen;
    if (!ctx)
        return 0;
    if (PK11_DigestFinal(ctx->context, md, &mdlen, SXI_SHA1_BIN_LEN))
	return 0;
    if (len) {
        *len = mdlen;
        if (mdlen != SXI_SHA1_BIN_LEN)
            return 0;
    }
    memcpy(out, md, SXI_SHA1_BIN_LEN);
    return 1;
}

struct sxi_hmac_sha1_ctx {
    PK11SlotInfo *slot;
    PK11SymKey *key;
    SECItem *keysec;
    PK11Context *context;
};

sxi_hmac_sha1_ctx *sxi_hmac_sha1_init()
{
    sxi_hmac_sha1_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->slot = PK11_GetInternalKeySlot();
    if (!ctx->slot) {
        free(ctx);
	return NULL;
    }
    return ctx;
}

void sxi_hmac_sha1_cleanup(sxi_hmac_sha1_ctx **ctxptr)
{
    if (!ctxptr || !*ctxptr)
        return;
    if ((*ctxptr)->context)
      PK11_DestroyContext((*ctxptr)->context, PR_TRUE);
    if ((*ctxptr)->key)
        PK11_FreeSymKey((*ctxptr)->key);
    if ((*ctxptr)->keysec)
        SECITEM_FreeItem((*ctxptr)->keysec, PR_TRUE);
    if ((*ctxptr)->slot)
        PK11_FreeSlot((*ctxptr)->slot);
    free(*ctxptr);
    *ctxptr = NULL;
}

int sxi_hmac_sha1_init_ex(sxi_hmac_sha1_ctx *ctx,
                     const void *key, int key_len)
{
    if (!ctx)
        return 0;
    /* NOTE: params must be provided, but may be empty */
    SECItem noParams;
    noParams.type = siBuffer;
    noParams.data = 0;
    noParams.len = 0;

    if (ctx->context)
      PK11_DestroyContext(ctx->context, PR_TRUE);
    if (ctx->key)
        PK11_FreeSymKey(ctx->key);
    if (ctx->keysec)
        SECITEM_FreeItem(ctx->keysec, PR_TRUE);
    ctx->keysec = SECITEM_AllocItem(NULL, NULL, key_len);
    if (ctx->keysec) {
        memcpy(ctx->keysec->data, key, key_len);
        ctx->key = PK11_ImportSymKey(ctx->slot, CKM_SHA_1_HMAC, PK11_OriginDerive, CKA_SIGN,
                                     ctx->keysec, &noParams);
        if(ctx->key) {
            ctx->context = PK11_CreateContextBySymKey(CKM_SHA_1_HMAC, CKA_SIGN, ctx->key, &noParams);
            if (ctx->context && PK11_DigestBegin(ctx->context) == SECSuccess)
                return 1;
        }
    }
    return 0;
}

int sxi_hmac_sha1_update(sxi_hmac_sha1_ctx *ctx, const void *d, int len)
{
    if (!ctx)
        return 0;
    if (PK11_DigestOp(ctx->context, d, len) != SECSuccess)
	return 0;
    return 1;
}

int sxi_hmac_sha1_final(sxi_hmac_sha1_ctx *ctx, unsigned char *out, unsigned int *len)
{
    unsigned char hmac[SXI_SHA1_BIN_LEN];
    unsigned int mdlen;
    if (!ctx)
        return 0;
    if (PK11_DigestFinal(ctx->context, hmac, &mdlen, SXI_SHA1_BIN_LEN))
	return 0;
    if (len) {
        *len = mdlen;
        if (*len != SXI_SHA1_BIN_LEN)
            return 0;
    }
    memcpy(out, hmac, SXI_SHA1_BIN_LEN);
    return 1;
}

int sxi_crypto_check_ver(struct sxi_logger *l)
{
    if (NSS_NoDB_Init("/") != SECSuccess) {
        sxi_log_msg(l, "sxi_crypto_check_ver", SX_LOG_CRIT,
                    "Failed to initialize NSS: %d", PR_GetError());
        return -1;
    }
    return 0;
}

void sxi_sha256(const unsigned char *d, size_t n,unsigned char *md)
{
    unsigned len;
    PK11Context *context = PK11_CreateDigestContext(SEC_OID_SHA256);
    if (!context || PK11_DigestBegin(context) != SECSuccess ||
        PK11_DigestOp(context, d, n) != SECSuccess ||
        PK11_DigestFinal(context, md, &len, SHA256_DIGEST_LENGTH) != SECSuccess)
    {
        /* TODO: log */
    }
    if (context)
        PK11_DestroyContext(context, PR_TRUE);
}

void sxi_report_crypto(sxc_client_t *sx)
{
    sxi_info(sx, "NSS: %s", NSS_GetVersion());
}

int sxi_rand_bytes(unsigned char *d, int len)
{
    /* TODO: does this block, use /dev/urandom instead? */
    if (PK11_GenerateRandom(d, len) == SECSuccess)
        return 1;
    return 0;
}

int sxi_rand_pseudo_bytes(unsigned char *d, int len)
{
    return sxi_rand_bytes(d, len);
}

void sxi_rand_cleanup(void)
{
    SECMOD_RestartModules(PR_TRUE);
}

void sxi_vcrypto_cleanup(void)
{
    /* PL_ArenaFinish() may have to be called */
    PR_Cleanup();
}

int sxi_vcrypt_print_cipherlist(sxc_client_t *sx, const char *list)
{
    /* N/A */
    return -1;
}

#define PK11_SETATTRS(_attr, _idx, _type, _val, _len) do {  \
  CK_ATTRIBUTE *ptr = (_attr) + ((_idx)++);                 \
  ptr->type = (_type);                                      \
  ptr->pValue = (_val);                                     \
  ptr->ulValueLen = (_len);                                 \
} while(0)

int sxi_vcrypt_print_cert_info(sxc_client_t *sx, const char *file, int batch_mode)
{
    int rc= 0;
    SECMODModule *mod = SECMOD_LoadUserModule("library=libnsspem.so name=PEM", NULL, PR_FALSE);
    if (!mod || !mod->loaded) {
        if (mod)
            SECMOD_DestroyModule(mod);
        sxi_setsyserr(sx, SXE_ECFG, "Failed to load NSS PEM library");
        return -1;
    }

    sxi_crypto_check_ver(NULL);
    const char *slot_name = "PEM Token #0";
    CK_OBJECT_CLASS obj_class;
    CK_ATTRIBUTE attrs[/* max count of attributes */ 4];
    unsigned attr_cnt = 0;
    CK_BBOOL cktrue = CK_TRUE;
    PK11SlotInfo *slot = PK11_FindSlotByName(slot_name);
    if (slot) {
        obj_class = CKO_CERTIFICATE;
        PK11_SETATTRS(attrs, attr_cnt, CKA_CLASS, &obj_class, sizeof(obj_class));
        PK11_SETATTRS(attrs, attr_cnt, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL));
        PK11_SETATTRS(attrs, attr_cnt, CKA_LABEL, (unsigned char *)file,
                      strlen(file) + 1);

        if(CKO_CERTIFICATE == obj_class) {
            CK_BBOOL *pval = &cktrue;
            PK11_SETATTRS(attrs, attr_cnt, CKA_TRUST, pval, sizeof(*pval));
        }

        PK11GenericObject *obj = PK11_CreateGenericObject(slot, attrs, attr_cnt, PR_FALSE);
        if (!obj) {
            sxi_seterr(sx, SXE_ECFG, "Cannot load certificate from '%s': %s, %s",
                       file, PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT),
                       PR_ErrorToName(PR_GetError()));
            return -1;
        }
        CERTCertList *list = PK11_ListCertsInSlot(slot);
        if (list) {
            CERTCertListNode *node = CERT_LIST_HEAD(list);
            CERTCertificate *cert = node ? node->cert : NULL;
            if (cert && !batch_mode) {
                char *subject = CERT_NameToAscii(&cert->subject);
                char *issuer = CERT_NameToAscii(&cert->issuer);
                char *common_name = CERT_GetCommonName(&cert->subject);
                struct sxi_fmt fmt;
                char hash[SXI_SHA1_TEXT_LEN+1];
                sxi_fmt_start(&fmt);
                sxi_fmt_msg(&fmt, "\tSubject: %s\n", subject);
                sxi_fmt_msg(&fmt, "\tIssuer: %s\n", issuer);
                if (!sxi_conns_hashcalc_core(sx, NULL, 0,
                                             cert->derCert.data,
                                             cert->derCert.len, hash)) {
                    sxi_fmt_msg(&fmt, "\tSHA1 Fingerprint: %s\n", hash);
                }
                sxi_info(sx, "%s", fmt.buf);
                PR_Free(subject);
                PR_Free(issuer);
                PR_Free(common_name);
            }
            if (cert)
                CERT_DestroyCertificate(cert);
        }
        PK11_FreeSlot(slot);
    } else {
        sxi_seterr(sx, SXE_ECFG, "Failed to initialize NSS PEM token");
        rc = -1;
    }

    return rc;
}
