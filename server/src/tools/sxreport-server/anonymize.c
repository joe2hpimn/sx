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

#include "default.h"
#include <string.h>
#include "log.h"
#include "hashfs.h"
#include "../libsx/src/misc.h"
#include "../libsx/src/vcrypto.h"
#include <sys/types.h>
#include <regex.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>

static unsigned char hmac_key[20];

struct buffer {
    char *data;
    unsigned pos;
    unsigned size;
};

static int buf_append(struct buffer *buf, const char *str, unsigned n)
{
    if (!buf)
        return -1;
    const char *end = memchr(str, '\0', n);
    if (end)
        n = end - str;/* just in case n is too large */
    if (buf->pos + n >= buf->size) {
        buf->size = buf->pos + n + 1;
        buf->data = wrap_realloc_or_free(buf->data, buf->size);
        if (!buf->data) {
            buf->size = 0;
            return -1;
        }
    }
    memcpy(buf->data + buf->pos, str, n);/* copy string */
    /* terminate */
    buf->pos += n;
    buf->data[buf->pos] = '\0';
    return 0;
}

int anonymize_item(struct buffer *buf, const char *category, const char *str, size_t len)
{
    sxi_hmac_sha1_ctx *hmac_ctx;
    unsigned char md[SXI_SHA1_BIN_LEN];
    unsigned mdlen = sizeof(md);
    unsigned i;
    hmac_ctx = sxi_hmac_sha1_init();
    if (!sxi_hmac_sha1_init_ex(hmac_ctx, hmac_key, sizeof(hmac_key)) ||
        !sxi_hmac_sha1_update(hmac_ctx, category, strlen(category)+1) ||
        !sxi_hmac_sha1_update(hmac_ctx, str, len) ||
        !sxi_hmac_sha1_final(hmac_ctx, md, &mdlen)) {
        return -1;
    }
    sxi_hmac_sha1_cleanup(&hmac_ctx);
    /* Features:
     *  * same 'str' hashes to same value
     *      * so we can trace it in the logs (without knowing what it was)
     *      * this is true even across different nodes (as long as they are part
     *      of same cluster)
     *  * hash is one way: can't determine 'str' from hash
     *  * HMAC key is derived from cluster key using RFC5869
     *      * can't confirm 'str' by guessing
     *  * 'category' is used to ensure that the same str hashes to different values
     *  in different contexts. Thus known-values (for example volume names)
     *  can't be used to determine other values.
     *  * the hash is truncated to 80 bits to make the anonymized data shorter,
     *  the possibility of a collision is still small
     *  * the truncated hash is base64-encoded
     */

    /* truncated HMAC */
    char *encoded = sxi_b64_enc_core(md, mdlen/2);
    if (!encoded) {
        OOM();
        return -1;
    }
    for(i=0;i<strlen(encoded);i++) {
        /* base64url to prevent false match with path rule */
        if (encoded[i] == '/')
            encoded[i] = '_';
        else if (encoded[i] == '+')
            encoded[i] = '-';
    }
    if (buf_append(buf, category, strlen(category)) ||
        buf_append(buf, "{", 1) ||
        buf_append(buf, encoded, 14) ||
        buf_append(buf, "}", 1)) {
        free(encoded);
        return -1;
    }
    free(encoded);
    return 0;
}

/* returns NULL if the string cannot be categorized by this anonymizing filter,
 * or a category string that should be used in anonymize_item */
typedef const char *(*anon_cb)(const char *str);

static int check_block(const struct in_addr *in, const char *str, int bits)
{
    struct in_addr in_mask;
    if (inet_pton(AF_INET, str, &in_mask) != 1)
        return 0;
    bits = 32 - bits;
    return (ntohl(in_mask.s_addr) >> bits) == (ntohl(in->s_addr) >> bits);
}

static int check_block6(const struct in6_addr *in, const char *str, int bits)
{
    struct in6_addr in6;
    struct in6_addr in_mask;
    unsigned i;

    memcpy(&in6, in, sizeof(in6));
    if (inet_pton(AF_INET6, str, &in_mask) != 1)
        return 0;
    for (i=15;i>(bits-1)/8;i--) {
        in6.s6_addr[i] = 0;
    }
    in6.s6_addr[bits/8] &= ~ ((1 << (bits % 8)) - 1);
    return !memcmp(in6.s6_addr, in_mask.s6_addr, 16);
}

static const char* anon_ip4(const char *str)
{
    struct in_addr in;
    if (inet_pton(AF_INET, str, &in) != 1)
        return NULL;
    /* valid IPv4 address: check if it is a special-purpose address
     * http://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xml
     */
    if (check_block(&in, "0.0.0.0", 8) ||
        check_block(&in, "127.0.0.0", 8))
        return "IP4-RFC1122";

    else if (check_block(&in, "10.0.0.0", 8) ||
             check_block(&in, "172.16.0.0", 12) ||
             check_block(&in, "192.168.0.0", 16))
        return "IP4-RFC1918";

    else if (check_block(&in, "198.18.0.0", 15))
        return "IP4-RFC2544";

    else if (check_block(&in, "192.88.99.0", 24))
        return "IP4-RFC3068";

    else if (check_block(&in, "169.254.0.0", 16))
        return "IP4-RFC3927";

    else if (check_block(&in, "192.0.0.0", 29))
        return "IP4-RFC6333";

    else if (check_block(&in, "100.64.0.0", 10))
        return "IP4-RFC6598";

    else if (check_block(&in, "255.255.255.255", 32))
        return "IP4-RFC919";

    else
        return "IP4";
    return NULL;
}

static const char *anon_verb(const char *req)
{
    if (!req)
        return NULL;
    switch (*req) {
        case 'C':
            if (!strncmp(req, "CONNECT", strlen("CONNECT")))
                return "CONNECT";
            return NULL;
        case 'D':
            if (!strncmp(req, "DELETE", strlen("DELETE")))
                return "DELETE";
            return NULL;
        case 'G':
            if (!strncmp(req, "GET", strlen("GET")))
                return "GET";
            return NULL;
        case 'H':
            if (!strncmp(req, "HEAD", strlen("HEAD")))
                return "HEAD";
            return NULL;
        case 'O':
            if (!strncmp(req, "OPTIONS", strlen("OPTIONS")))
                return "OPTIONS";
            return NULL;
        case 'P':
            if (!strncmp(req, "POST", strlen("POST")))
                return "POST";
            if (!strncmp(req, "PUT", strlen("PUT")))
                return "PUT";
            return NULL;
        case 'T':
            if (!strncmp(req, "TRACE", strlen("TRACE")))
                return "TRACE";
            return NULL;
        default:
            return NULL;
    }
}

static const char *anon_quoted(const char *str)
{
    return ":QSTR";
}

static const char *anon_user(const char *str)
{
    return ":USER";
}

static const char *anon_mac(const char *str)
{
    return ":MAC";
}

static const char *anon_ip6(const char *str)
{
    struct in6_addr in;
    if (inet_pton(AF_INET6, str+1, &in) != 1)
        return NULL;
    if (check_block6(&in, "::1", 128))
        return "IP6-LOOPBACK";
    if (check_block6(&in, "::", 128))
        return "IP6-UNSPEC";
    if (check_block6(&in, "::ffff:0:0", 96))
        return "IP6-V4MAPPED";
    if (check_block6(&in, "64:ff9b::",96))
        return "IP6-RFC6052";
    if (check_block6(&in, "100::",64))
        return "IP6-RFC6666";
    if (check_block6(&in, "2001::",32))
        return "IP6-RFC4380";
    if (check_block6(&in, "2001:2::",48))
        return "IP6-RFC5180";
    if (check_block6(&in, "2001:db8::",32))
        return "IP6-RFC3849";
    if (check_block6(&in, "2001:10::",28))
        return "IP6-RFC4843";
    if (check_block6(&in, "2001::",23))
        return "IP6-RFC2928";
    if (check_block6(&in, "2002",16))
        return "IP6-RFC3056";
    if (check_block6(&in, "fc00::",7))
        return "IP6-RFC4193";
    if (check_block6(&in, "fe80::",10))
        return "IP6-LL";
    return "IP6";
}

static struct {
    const char *regex;
    anon_cb anon;
} regexes[] = {
    /* precedence: top to bottom */
    {"(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT) /[^| ]+", anon_verb},
    {"[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}", anon_ip4},
    {"user[: ]+[^ ]+", anon_user},
    {"owner[: ]+'[^']+'", anon_user},
    {"'[^']+'", anon_quoted},
    {" [0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", anon_mac},
    {" [0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){1,6}:([0-9a-fA-F]{0,4}|([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}))", anon_ip6}
};
#define N (sizeof(regexes)/sizeof(regexes[0]))

static struct {
    regex_t preg;
    anon_cb anon;
} actions[N];

static void compile_regexes(void)
{
    char errbuf[1024];
    unsigned i;
    for(i=0;i<N;i++) {
        int err = regcomp(&actions[i].preg, regexes[i].regex, REG_EXTENDED);
        if (err) {
            errbuf[0] = 0;
            regerror(err, &actions[i].preg, errbuf, sizeof(errbuf));
            WARN("Failed to compile regex '%s': %s",
                    regexes[i].regex, errbuf);
        } else
            actions[i].anon = regexes[i].anon;
    }
}

int anonymize_filter(sxc_client_t *sx, const char *datadir, FILE *in, FILE *out)
{
    int ret = 0;
    char *line = NULL;
    sx_hashfs_t *h = sx_hashfs_open(datadir, sx);
    if (h) {
        /* Derive an HMAC key from the cluster.key using RFC5869.
        */
        if (sx_hashfs_derive_key(h, hmac_key, sizeof(hmac_key), "anonymize")) {
            sx_hashfs_close(h);
            return -1;
        }
        sx_hashfs_close(h);
    } else {
        WARN("[Using random key for anonymization]");
        /* When there is no working hashfs use a random key */
        if(sxi_rand_pseudo_bytes(hmac_key, sizeof(hmac_key)) == -1) {
            return -1;
        }
    }

    compile_regexes();
    while (!ret && !feof(in) && !sxc_fgetline(sx, in, &line)) {
        unsigned i;
        struct buffer match;
        struct buffer buf;

        /* sxc_fgetline doesn't provide a way to distinguish EOF from an empty
         * line, so we have to do it above */
        if (!line) {
            fputc('\n', out);
            continue;/* empty line */
        }

        memset(&match, 0, sizeof(match));
        memset(&buf, 0, sizeof(buf));
        /* find matches */
        for(i=0;i<N;i++) {
            const char *src = line;
            regmatch_t pmatch;

            do {
                if (regexec(&actions[i].preg, src, 1, &pmatch, 0))
                    pmatch.rm_so = -1;
                if (pmatch.rm_so != -1) {
                    const char *category;
                    match.pos = 0;
                    if (buf_append(&match, src + pmatch.rm_so, pmatch.rm_eo - pmatch.rm_so) == -1)
                        break;
                    category = actions[i].anon(match.data);
                    if (!category) {
                        /* OK, not a real match */
                        pmatch.rm_so = -1;
                        break;
                    }
                    if (buf_append(&buf, src, pmatch.rm_so) == -1 ||/* stuff before match */
                        anonymize_item(&buf, category, match.data, match.pos))/* anonymized match */
                    {
                        ret = -1;
                        break;
                    }
                    src += pmatch.rm_eo;/* continue searching for more anonymizable items on this line */
                }
            } while(pmatch.rm_so != -1);
            if (ret == -1) {
                free(buf.data);
                break;
            }
            if (pmatch.rm_so == -1) {
                /* append remaining line */
                if(buf_append(&buf, src, strlen(src) == -1)) {
		    free(buf.data);
		    ret = -1;
		    break;
		}
            }
            /* line now contains anonymized data for regex i, switch it to be
             * the source */
            free(line);
            line = buf.data;
            memset(&buf, 0, sizeof(buf));
        }
        fprintf(out, "%s\n", line);
        free(line);
        free(match.data);
    }
    return ret;
}
