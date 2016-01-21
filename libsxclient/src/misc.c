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

#ifdef HAVE_CONFIG_H
#include "config.h"
#undef HAVE_CONFIG_H /* avoid reincluding it with default.h */
#endif

#if defined(__GNUC__) && defined(HAVE_SECURE_GETENV)
#define _GNU_SOURCE
#endif

#include "default.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <termios.h>
#include <pwd.h>
#include <limits.h>
#include <ctype.h>
#if HAVE_NFTW
#include <ftw.h>
#else
#include "sxftw.h"
#endif

#include "libsxclient-int.h"
#include "misc.h"
#include "vcrypto.h"
#include "crypt_blowfish.h"
#include "zlib.h"

int sxc_fgetline(sxc_client_t *sx, FILE *f, char **ret) {
    char buf[2048], *cur;
    int curlen = 0, len, eol = 0;

    *ret = cur = NULL;
    sxc_clearerr(sx);
    while(1) {
	if(!fgets(buf, sizeof(buf), f)) {
	    if(ferror(f)) {
		SXDEBUG("Failed to read line");
		sxi_setsyserr(sx, SXE_EREAD, "Failed to read line from stream");
		free(cur);
		return 1;
	    }
	    break;
	}
	len = strlen(buf);
	while(len) {
	    char l = buf[len-1];
	    if(l == '\n' || l == '\r') {
		eol = 1;
		len--;
	    } else
		break;
	}

	if(len) {
	    cur = sxi_realloc(sx, cur, curlen+len+1);
	    if(!cur)
		return 1;
	    memcpy(cur + curlen, buf, len);
	    curlen += len;
	    cur[curlen] = '\0';
	}
	if(eol)
	    break;
    }
    *ret = cur;
    return 0;
}

void *sxi_realloc(sxc_client_t *sx, void *ptr, unsigned int newlen) {
    void *oldptr = ptr;
    ptr = realloc(ptr, newlen);
    if(!ptr) {
	SXDEBUG("Failed to realloc to %u bytes", newlen);
	sxi_seterr(sx, SXE_EMEM, "Cannot increase allocated size: Out of memory");
	free(oldptr);
    }
    return ptr;
}

int sxi_is_valid_authtoken(sxc_client_t *sx, const char *token) {
    char buf[AUTHTOK_BIN_LEN];
    unsigned int buflen = AUTHTOK_BIN_LEN;

    if(!token || strlen(token) != AUTHTOK_ASCII_LEN || sxi_b64_dec(sx, token, buf, &buflen)) {
	SXDEBUG("Failed to verify token '%s':", token ? token : "(null)");
	return 0;
    }

    return 1;
}

char *sxi_b64_enc_core(const void *data, unsigned int data_size) {
    const char *b64tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const unsigned char *udata = (const unsigned char *)data;
    char *ret = malloc(((data_size / 3) + 1) * 4 + 1);
    unsigned int i;

    if (!ret)
	return NULL;

    for(i=0; data_size > 2; i+=4, data_size-=3, udata+=3) {
	ret[i+0] = b64tab[udata[0] >> 2];
	ret[i+1] = b64tab[((udata[0]&3) << 4) | (udata[1] >> 4)];
	ret[i+2] = b64tab[((udata[1]&15) << 2) | (udata[2] >> 6)];
	ret[i+3] = b64tab[udata[2]&63];
    }

    if(data_size--) {
	ret[i++] = b64tab[udata[0] >> 2];
	if(data_size) {
	    ret[i++] = b64tab[((udata[0]&3) << 4) | (udata[1] >> 4)];
	    ret[i++] = b64tab[((udata[1]&15) << 2)];
	} else {
	    ret[i++] = b64tab[((udata[0]&3) << 4)];
	    ret[i++] = '=';
	}
	ret[i++] = '=';
    }
    ret[i] = '\0';
    return ret;
}

char *sxi_b64_enc(sxc_client_t *sx, const void *data, unsigned int data_size) {
    char *ret = sxi_b64_enc_core(data, data_size);
    if(!ret) {
	SXDEBUG("OOM on %u bytes long input", data_size);
	sxi_seterr(sx, SXE_EMEM, "Cannot encode data in base64: Out of memory");
	return NULL;
    }
    return ret;
}

int sxi_b64_dec_core(const char *string, void *buf, unsigned int *buf_size) {
    unsigned int i, j, asciilen, binlen;
    const unsigned char *ustring = (const unsigned char *)string;
    unsigned char *ubuf = (unsigned char *)buf;
    const int b64tab[256] = {
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, 62,  -1, -1, -1, 63,
	52, 53, 54, 55,  56, 57, 58, 59,    60, 61, -1, -1,  -1, -1, -1, -1,
	-1,  0,  1,  2,   3,  4,  5,  6,     7,  8,  9, 10,  11, 12, 13, 14,
	15, 16, 17, 18,  19, 20, 21, 22,    23, 24, 25, -1,  -1, -1, -1, -1,
	-1, 26, 27, 28,  29, 30, 31, 32,    33, 34, 35, 36,  37, 38, 39, 40,
	41, 42, 43, 44,  45, 46, 47, 48,    49, 50, 51, -1,  -1, -1, -1, -1,

	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    };

    if(!string || !buf || !buf_size) {
	return 1;
    }

    asciilen = strlen(string);
    if(!asciilen) {
	*buf_size = 0;
	return 0;
    }

    if(asciilen % 4)
	return 1;
    binlen = asciilen / 4 * 3;
    if(string[asciilen-1] == '=')
	binlen--;
    if(string[asciilen-2] == '=')
	binlen--;
    if(binlen > *buf_size)
	return 1;
    *buf_size = binlen;

    for(i=0, j=0; i<asciilen; i+=4) {
	int v1 = b64tab[ustring[i+0]],
	    v2 = b64tab[ustring[i+1]],
	    v3 = b64tab[ustring[i+2]],
	    v4 = b64tab[ustring[i+3]];

	if((v1 |v2) < 0) return 1;
	ubuf[j++] = (v1<<2) | (v2>>4);

	if(j>=binlen) break;
	if(v3 < 0) return 1;
	ubuf[j++] = (v2<<4) | (v3>>2);

	if(j>=binlen) break;
	if(v4 < 0) return 1;
	ubuf[j++] = (v3 << 6) | (v4);
    }
    return 0;
}

int sxi_b64_dec(sxc_client_t *sx, const char *string, void *buf, unsigned int *buf_size) {
    if (!string || !buf || !buf_size) {
	SXDEBUG("called with NULL argument");
	sxi_seterr(sx, SXE_EARG, "Cannot decode base64 string: Invalid argument");
	return 1;
    }
    if (sxi_b64_dec_core(string, buf, buf_size)) {
	sxi_seterr(sx, SXE_EARG, "Cannot decode base64 string");
	return 1;
    }
    return 0;
}

char *sxi_urlencode(sxc_client_t *sx, const char *string, int encode_slash) {
    const unsigned int urlenctab[256] = {
	1, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 1, 1, 3,
	1, 1, 1, 1,  1, 1, 1, 1,    1, 1, 3, 3,  3, 3, 3, 3,
	3, 1, 1, 1,  1, 1, 1, 1,    1, 1, 1, 1,  1, 1, 1, 1,
	1, 1, 1, 1,  1, 1, 1, 1,    1, 1, 1, 3,  3, 3, 3, 1,
	3, 1, 1, 1,  1, 1, 1, 1,    1, 1, 1, 1,  1, 1, 1, 1,
	1, 1, 1, 1,  1, 1, 1, 1,    1, 1, 1, 3,  3, 3, 1, 3,

	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
    };
    unsigned int len = 0;
    const uint8_t *s;
    char *ret, *r;

    if(!string) {
	SXDEBUG("called with NULL argument");
	sxi_seterr(sx, SXE_EARG, "Cannot encode URL: Invalid argument");
	return NULL;
    }

    for(s=(const uint8_t *)string; *s; s++)
	len += urlenctab[*s];

    len++;
    if(!(ret = malloc(len))) {
	SXDEBUG("OOM allocating output buffer (%u bytes)", len);
	sxi_seterr(sx, SXE_EARG, "Cannot encode URL: Out of memory");
	return NULL;
    }

    r = ret;
    s = (const uint8_t *)string;
    while(1) {
	unsigned int c = *s;
	s++;

	if(urlenctab[c] == 1 || (!encode_slash && c == 0x2f)) {
	    *r = c;
	    r++;
	    if(!c)
		break;
	} else {
	    sprintf(r, "%%%02x", c);
	    r += 3;
	}
    }

    return ret;
}

/* URL decoding: http://geekhideout.com/urlcode.shtml */

/* Converts a hex character to its integer value */
static char from_hex(char ch) {
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

char *sxc_urldecode(sxc_client_t *sx, const char *s) {
    char *q, *ret = calloc(1, strlen(s) + 1);
    if(!ret) {
        sxi_seterr(sx, SXE_EMEM, "Failed to allocate decoded string: Out of memory");
        return NULL;
    }

    q = ret;
    while(*s) {
        if(*s == '%' && s[1] && s[2]) {
            *q++ = from_hex(s[1]) << 4 | from_hex(s[2]);
            s+=3;
        } else if(*s == '+')
            *q++ = ' ';
        else
            *q++ = *s++;
    }
    *q = '\0';
    return ret;
}

static void downcase(char *s) {
    for(;*s;s++) {
	char c = *s;
	if(c >='A' && c <= 'Z')
	    *s = c + ('a' - 'A');
    }
}

#define SXPROTO "sx://"
int sxi_uri_is_sx(sxc_client_t *sx, const char *uri) {
    return strncmp(uri, SXPROTO, strlen(SXPROTO)) == 0 || strncmp(uri, SXC_ALIAS_PREFIX, strlen(SXC_ALIAS_PREFIX)) == 0;
}

#define ALIAS_FGET_BUFF 512

/* Get name of file containing aliases. Allocates memory for return value that should be freed */
static char *get_aliases_file_name(sxc_client_t *sx) {
    const char *confdir = NULL;
    char *aliases_file_name = NULL;
    int aliases_fn_len = 0;

    confdir = sxc_get_confdir(sx);
    if(!confdir){
        sxi_seterr(sx, SXE_ECFG, "Could not locate configuration directory");
        return NULL;
    }

    aliases_fn_len = strlen(confdir) + strlen("/.aliases") + 1; 
    aliases_file_name = malloc(aliases_fn_len);
    if(!aliases_file_name) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
        return NULL;
    }

    snprintf(aliases_file_name, aliases_fn_len, "%s/.aliases", confdir);

    return aliases_file_name;
}

/* Free memory taken for aliases list */
void sxi_free_aliases(alias_list_t *aliases) {
    int i = 0;
    if(!aliases)
        return;
    for(i = aliases->num - 1; i >= 0; i--) {
        free(aliases->entry[i].name);
        free(aliases->entry[i].cluster);
    }
    free(aliases->entry);
    aliases->num = 0;
    aliases->entry = NULL;
}

/* List all aliases stored in configuration directory */
int sxi_load_aliases(sxc_client_t *sx, alias_list_t **aliases) {
    char *aliases_file_name = NULL;
    char buffer[ALIAS_FGET_BUFF] = { 0 };
    FILE *f = NULL;
    alias_list_t *list = NULL;

    /* Wrong params given */
    if(!sx || !aliases)
        return 1;

    if(*aliases) /* Aliases list already filled */
        return 0;

    aliases_file_name = get_aliases_file_name(sx);
    if(!aliases_file_name) {
        sxi_seterr(sx, SXE_EREAD, "Could not read aliases file: %s", sxc_geterrmsg(sx));
        return 1;
    }

    list = malloc(sizeof(alias_list_t));
    if(!list) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
        free(aliases_file_name);
        return 1;
    }

    *aliases = list;
    list->num = 0;
    list->entry = NULL;

    f = fopen(aliases_file_name, "r");
    if(!f) {
        /* This situation is OK - aliases are correctly filled (with 0 and NULL) and this function should return 0 */
        free(aliases_file_name);
        return 0;
    }
    free(aliases_file_name);

    while(fgets(buffer, ALIAS_FGET_BUFF, f)) {
        char *alias = buffer, *cluster;
        alias_t *tmp = NULL;
        char *tmp_alias = NULL, *tmp_cluster = NULL;

        /* Parse the line with alias, skip the line and proceed when parsing fails */
        cluster = strchr(buffer, ' ');
        if(!cluster)
            continue;
        *cluster++ = '\0';
        if(cluster[strlen(cluster) - 1] == '\n')
            cluster[strlen(cluster) - 1] = '\0';

        tmp_alias = strdup(alias);
        if(!tmp_alias) {
            sxi_seterr(sx, SXE_EMEM, "Could not allocate memory for alias name");
            fclose(f);
            return 1;
        }
        tmp_cluster = strdup(cluster);
        if(!tmp_cluster) {
            sxi_seterr(sx, SXE_EMEM, "Could not allocate memory for cluster name");
            free(tmp_alias);
            fclose(f);
            return 1;
        }

        tmp = realloc(list->entry, (list->num + 1) * sizeof(alias_t));
        if(!tmp) {
            sxi_seterr(sx, SXE_EMEM, "Could not allocate memory for alias list");
            fclose(f);
            free(tmp_alias);
            free(tmp_cluster);
            return 1;
        } 
        list->entry = tmp;
        list->entry[list->num].name = tmp_alias;
        list->entry[list->num].cluster = tmp_cluster;
        list->num++;
    }
    fclose(f);

    return 0;
}

static int write_aliases(sxc_client_t *sx, const alias_list_t *list) {
    char *aliases_file_name = NULL;
    FILE *f = NULL;
    int i = 0;

    if(!list)
        return 1;

    if(list->num > 0) {
        aliases_file_name = get_aliases_file_name(sx);
        if(!aliases_file_name) {
            sxi_seterr(sx, SXE_EWRITE, "Could not write to aliases file");
            return 1;
        }

        if(!access(aliases_file_name, F_OK)) {
            if(unlink(aliases_file_name)) {
                sxi_seterr(sx, SXE_EWRITE, "Could not unlink aliases file");
                free(aliases_file_name);
                return 1;
            } 
        } 

        f = fopen(aliases_file_name, "w");
        if(!f) {
            sxi_seterr(sx, SXE_EWRITE, "Could not write to aliases file");
            free(aliases_file_name);
            return 1;
        }

        for(i = 0; i < list->num; i++) {
            int to_write;

            if(!list->entry[i].cluster || !list->entry[i].name)
                continue;
            to_write = strlen(list->entry[i].name) + strlen(list->entry[i].cluster) + 2;
            if(fprintf(f, "%s %s\n", list->entry[i].name, list->entry[i].cluster) != to_write) {
                fclose(f);
                unlink(aliases_file_name);
                sxi_seterr(sx, SXE_EWRITE, "Could not write to file %s", aliases_file_name);
                free(aliases_file_name);
                return 1;
            }
        }

	if(fclose(f)) {
            unlink(aliases_file_name);
            sxi_seterr(sx, SXE_EWRITE, "fclose() failed for file %s", aliases_file_name);
            free(aliases_file_name);
            return 1;
        }

        free(aliases_file_name);
    }

    return 0;
}

int sxc_set_alias(sxc_client_t *sx, const char *alias, const char *profile, const char *host) {
    char *cluster_uri = NULL;
    int cluster_uri_len = 0;
    int i = 0;
    alias_list_t *list = NULL;
    char *tmp_name = NULL;
    int alias_found = -1;

    if(!sx || !profile || !host || !alias) {
        sxi_seterr(sx, SXE_EARG, "Bad argument");
        return 1;
    }

    list = sxi_get_alias_list(sx);
    if(!list) {
        sxi_seterr(sx, SXE_EMEM, "Could not get aliases list");
        return 1;
    }

    /* Prepare cluster uri */
    cluster_uri_len = strlen(profile) + strlen(host) + strlen(SXPROTO) + 2;
    cluster_uri = malloc(cluster_uri_len);
    if(!cluster_uri) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
        return 1;
    }

    if(!strcmp(profile, "default"))
	snprintf(cluster_uri, cluster_uri_len, "%s%s", SXPROTO, host);
    else
	snprintf(cluster_uri, cluster_uri_len, "%s%s@%s", SXPROTO, profile, host);

    for(i = 0; i < list->num; i++) {
        if(!list->entry[i].cluster || !list->entry[i].name)
            continue;
        if(strcmp(list->entry[i].name, alias) == 0) {
            alias_found = i;
            break;
        }        
    }

    if(alias_found >= 0) {
        /* Alias has been found, check if it matches cluster */
        if(strcmp(list->entry[alias_found].cluster, cluster_uri)) {
            /* Alias points to different cluster */
            sxi_seterr(sx, SXE_EARG, "Alias %s is already used for %s", list->entry[alias_found].name, list->entry[alias_found].cluster);
            free(cluster_uri);
            return 1;
        } else {
            /* Alias already points to given cluster, do nothing */
            free(cluster_uri);
            return 0;
        }
    }

    tmp_name = strdup(alias);
    if(!tmp_name) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory for alias name");
        free(cluster_uri);
        return 1;
    }

    alias_t *tmp = realloc(list->entry, (list->num + 1) * sizeof(alias_t));
    if(!tmp) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory for new alias");
        free(cluster_uri);
        free(tmp_name);
        return 1;
    }
    list->entry = tmp;
    list->entry[list->num].name = tmp_name;
    list->entry[list->num].cluster = cluster_uri;
    list->num++;

    return write_aliases(sx, list);
}

int sxc_del_aliases(sxc_client_t *sx, const char *profile, const char *host) {
    alias_list_t *list;
    unsigned int i, cluster_uri_len;
    char *cluster_uri;

    if(!sx || !profile || !host) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return 1;
    }

    list = sxi_get_alias_list(sx);
    if(!list) {
        sxi_seterr(sx, SXE_EMEM, "Could not get alias list");
        return 1;
    }

    /* Prepare cluster uri */
    cluster_uri_len = strlen(profile) + strlen(host) + strlen(SXPROTO) + 2;
    cluster_uri = malloc(cluster_uri_len);
    if(!cluster_uri) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
        return 1;
    }

    if(!strcmp(profile, "default"))
        snprintf(cluster_uri, cluster_uri_len, "%s%s", SXPROTO, host);
    else
        snprintf(cluster_uri, cluster_uri_len, "%s%s@%s", SXPROTO, profile, host);

    /* Iterate over all aliases matching to profile name */
    for(i = 0; i < list->num; i++) {
        if(!list->entry[i].cluster || !list->entry[i].name)
            continue;
        if(!strcmp(list->entry[i].cluster, cluster_uri)) {
            free(list->entry[i].cluster);
            free(list->entry[i].name);
            list->entry[i].cluster = NULL;
            list->entry[i].name = NULL;
        }
    }

    free(cluster_uri);
    return write_aliases(sx, list);
}

int sxc_get_aliases(sxc_client_t *sx, const char *profile, const char *host, char **aliases) {
    alias_list_t *list;
    char *c;
    int clen = 0;
    int i, len = 0;
    char *ret = NULL;
    if(!profile || !host || !aliases) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return 1;
    }

    list = sxi_get_alias_list(sx);
    if(!list) {
        sxi_seterr(sx, SXE_EMEM, "Could not get alias list");
        return 1;
    }

    clen = strlen(profile) + strlen(host) + strlen(SXPROTO) + 2;
    c = malloc(clen); 
    if(!c) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
        return 1;
    }
    if(!strcmp(profile, "default"))
        snprintf(c, clen, "%s%s", SXPROTO, host);
    else
        snprintf(c, clen, "%s%s@%s", SXPROTO, profile, host);

    for(i = 0; i < list->num; i++) {
        if(!list->entry[i].cluster || !list->entry[i].name)
            continue;
        if(!strncmp(c, list->entry[i].cluster, clen)) {
            ret = sxi_realloc(sx, ret, len + strlen(list->entry[i].name) + 2);
            if(!ret) {
                sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
                free(c);
                return 1;
            }
            snprintf(ret + len, strlen(list->entry[i].name) + 2, "%s%s", len > 0 ? " " : "", list->entry[i].name);
            if(len) /* count white space */
                len++;
            len += strlen(list->entry[i].name);
        }
    }
        
    free(c);
    *aliases = ret;
    return 0;
}

sxc_uri_t *sxc_parse_uri(sxc_client_t *sx, const char *uri) {
    unsigned int len = strlen(uri);
    sxc_uri_t *u;
    char *p;
    char *tmp_uri = NULL;

    sxc_clearerr(sx);

    /* Check if alias was given */
    if(strncmp(SXC_ALIAS_PREFIX, uri, lenof(SXC_ALIAS_PREFIX)) == 0) {
        alias_list_t *list = NULL;
        char *tmp_volume = memchr(uri, '/', len);
        int i = 0;

        list = sxi_get_alias_list(sx);
        if(!list) {
            sxi_seterr(sx, SXE_EMEM, "Could not get alias list: %s", sxc_geterrmsg(sx));
            return NULL;
        }

        if(tmp_volume) 
            len = tmp_volume - uri;

        for(i = 0; i < list->num; i++) {
            if(!list->entry[i].cluster || !list->entry[i].name)
                continue;
            if(strncmp(list->entry[i].name, uri, strlen(list->entry[i].name)) == 0) {
                if(strlen(list->entry[i].name) < strlen(uri) && uri[strlen(list->entry[i].name)] != '/')
                    continue;
                len = strlen(list->entry[i].cluster) + strlen(uri) - strlen(list->entry[i].name);
                tmp_uri = malloc(len + 1);
                if(!tmp_uri) {
                    sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
                    return NULL;
                }
                if(tmp_volume)
                    snprintf(tmp_uri, len + 1, "%s%s", list->entry[i].cluster, tmp_volume);
                else
                    snprintf(tmp_uri, len + 1, "%s", list->entry[i].cluster);

                /* This is a new uri to be used tmp_uri must be freed */
                uri = tmp_uri;
                break;
            }
        }
	if(!tmp_uri) {
	    if(tmp_volume) {
		len = tmp_volume - uri;
		p = malloc(len + 1);
		if(p) {
		    sxi_strlcpy(p, uri, len+1);
		    sxi_seterr(sx, SXE_ECFG, "Alias '%s' doesn't exist", p);
		    free(p);
		} else {
                    sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
                }
	    } else {
		sxi_seterr(sx, SXE_ECFG, "Alias '%s' doesn't exist", uri);
	    }
	    return NULL;
	}
    }

    if(len <= lenof(SXPROTO) || strncmp(SXPROTO, uri, lenof(SXPROTO))) {
        SXDEBUG("URI '%s' is too short", uri);
        sxi_seterr(sx, SXE_EARG, "Cannot parse URL '%s': Invalid argument", uri);
        free(tmp_uri);
        return NULL;
    }

    uri += lenof(SXPROTO);
    len -= lenof(SXPROTO);

    u = malloc(sizeof(*u) + len + 1);
    if(!u) {
	SXDEBUG("OOM allocating result struct for '%s'", uri);
	sxi_seterr(sx, SXE_EMEM, "Cannot parse URL '%s': Out of memory", uri);
        free(tmp_uri);
	return NULL;
    }

    p = ((char *)u) + sizeof(*u);
    memcpy(p, uri, len+1);
    u->volume = memchr(p, '/', len);
    if(u->volume) {
	int hostlen = u->volume - p;
	do {
	    *u->volume = '\0';
	    u->volume++;
	} while(*u->volume == '/');
	if(!*u->volume)
	    u->volume=NULL;
	else {
	    int inlen = len - (u->volume - p);
	    u->path = memchr(u->volume, '/', inlen);
	    if(u->path) {
		do {
		    *u->path = '\0';
		    u->path++;
		} while(*u->path == '/');
		if(!*u->path)
		    u->path = NULL;
	    }
	}
	len = hostlen;
    }
    if(!u->volume)
	u->path = NULL;

    u->host = strrchr(p, '@');
    if(u->host) {
        *u->host = '\0';
        u->host++;
	if(!*u->host)
	    u->host = u->profile = NULL;
	else
	    u->profile = p;
    } else {
	u->host = p;
	u->profile = NULL;
    }

    if(!u->host || !*u->host) {
	SXDEBUG("URI has a NULL or empty host");
	sxi_seterr(sx, SXE_EARG, "Cannot parse URL '%s': Invalid host", uri);
	free(u);
        free(tmp_uri);
	return NULL;
    }

    downcase(u->host);
    free(tmp_uri);
    return u;
}

void sxc_free_uri(sxc_uri_t *uri) {
    free(uri);
}

static const char hexchar[16] = "0123456789abcdef";
void sxi_bin2hex(const void *bin, unsigned int len, char *hex) {
    const uint8_t *s = (const uint8_t *)bin;
    while(len--) {
        uint8_t c = *s;
	s++;
        hex[0] = hexchar[c >> 4];
        hex[1] = hexchar[c & 0xf];
        hex += 2;
    }
    *hex = '\0';
}

static const int hexchars[256] = {
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
     0,  1,  2,  3,   4,  5,  6,  7,     8,  9, -1, -1,  -1, -1, -1, -1,
    -1, 10, 11, 12,  13, 14, 15, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, 10, 11, 12,  13, 14, 15, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,

    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
};

int sxi_hex2bin(const char *src, uint32_t src_len, uint8_t *dst, uint32_t dst_len)
{
    uint32_t i;
    if((src_len % 2) || (dst_len < src_len / 2))
	return -1;
    for (i = 0; i < src_len; i += 2) {
        int32_t h = (hexchars[(unsigned int)src[i]] << 4) | hexchars[(unsigned int)src[i+1]];
        if (h < 0)
            return -1;
        dst[i >> 1] = h;
    }
    return 0;
}

int sxi_uuid_parse(const char *uuid_str, uint8_t *uuid)
{

    if(strlen(uuid_str) != 36 ||
	sxi_hex2bin(uuid_str, 8, uuid, 4) ||
	uuid_str[8] != '-' ||
	sxi_hex2bin(uuid_str+9, 4, uuid+4, 2) ||
	uuid_str[13] != '-' ||
	sxi_hex2bin(uuid_str+14, 4, uuid+6, 2) ||
	uuid_str[18] != '-' ||
	sxi_hex2bin(uuid_str+19, 4, uuid+8, 2) ||
	uuid_str[23] != '-' ||
	sxi_hex2bin(uuid_str+24, 12, uuid+10, 6)
    ) return -1;

    return 0;
}

void sxi_uuid_unparse(const uint8_t *uuid, char *uuid_str)
{
    sprintf(uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
	uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

char *sxi_make_tempfile(sxc_client_t *sx, const char *basedir, FILE **f) {
    unsigned int len;
    char *tmpname;
    int fd;
    mode_t mask;

    if(!f) {
	SXDEBUG("called with NULL arg");
	sxi_seterr(sx, SXE_EARG, "Cannot create temporary file: Invalid argument");
	return NULL;
    }
    if(!basedir)
	basedir = sxi_get_tempdir(sx);

    len = strlen(basedir);

    tmpname = malloc(len + sizeof("/.sxtmpXXXXXX"));
    if(!tmpname) {
	SXDEBUG("OOM allocating tempname (%u bytes)", len);
	sxi_seterr(sx, SXE_EMEM, "Cannot create temporary file: Out of memory");
	return NULL;
    }
    memcpy(tmpname, basedir, len);
    memcpy(tmpname + len, "/.sxtmpXXXXXX", sizeof("/.sxtmpXXXXXX"));
    mask = umask(0);
    umask(077);
    fd = mkstemp(tmpname);
    umask(mask);
    if(fd < 0) {
	SXDEBUG("failed to create %s", tmpname);
	sxi_setsyserr(sx, SXE_ETMP, "Cannot create unique temporary file");
	free(tmpname);
	return NULL;
    }

    if(!(*f = fdopen(fd, "wb+"))) {
	SXDEBUG("failed to fdopen %s", tmpname);
	sxi_setsyserr(sx, SXE_ETMP, "Cannot create temporary file stream");
	close(fd);
	unlink(tmpname);
	free(tmpname);
	return NULL;
    }

    return tmpname;
}

char *sxi_tempfile_track(sxc_client_t *sx, const char *basedir, FILE **f)
{
    struct tempfile_track *temptrack;
    int i, slot = -1;
    char **newnames;

    if(!sx)
	return NULL;
    if (f)
        *f = NULL;

    temptrack = sxi_get_temptrack(sx);
    for(i = 0; i < temptrack->slots; i++) {
	if(!temptrack->names[i]) {
	    slot = i;
	    break;
	}
    }

    if(slot == -1) {
	newnames = (char **) realloc(temptrack->names, (temptrack->slots + 1) * sizeof(char *));
	if(!newnames) {
	    sxi_seterr(sx, SXE_EMEM, "Out of memory");
	    return NULL;
	}
	temptrack->names = newnames;
	slot = temptrack->slots++;
    }

    temptrack->names[slot] = sxi_make_tempfile(sx, basedir, f);

    return temptrack->names[slot];
}

void sxi_tempfile_unlink_untrack(sxc_client_t *sx, const char *name) {
    unlink(name);
    sxi_tempfile_untrack(sx, name);
}

int sxi_tempfile_untrack(sxc_client_t *sx, const char *name)
{
    struct tempfile_track *temptrack;
    int i;

    if(!sx || !name)
	return 1;

    temptrack = sxi_get_temptrack(sx);
    for(i = 0; i < temptrack->slots; i++) {
	if(temptrack->names[i] && !strcmp(temptrack->names[i], name)) {
	    free(temptrack->names[i]);
	    temptrack->names[i] = NULL;
	    return 0;
	}
    }
    return 1;
}

int sxi_tempfile_istracked(sxc_client_t *sx, const char *name)
{
    struct tempfile_track *temptrack;
    int i;

    if(!sx || !name)
	return 0;

    temptrack = sxi_get_temptrack(sx);
    for(i = 0; i < temptrack->slots; i++) {
	if(temptrack->names[i] && !strcmp(temptrack->names[i], name)) {
	    return 1;
	}
    }
    return 0;
}

/*
 * mixing/hashing functions by Bob Jenkins, December 1996, Public Domain.
 * http://burtleburtle.net/bob/c/lookup2.c
 */
#define mix(a,b,c) \
{ \
  a=a-b;  a=a-c;  a=a^(c>>13); \
  b=b-c;  b=b-a;  b=b^(a<<8);  \
  c=c-a;  c=c-b;  c=c^(b>>13); \
  a=a-b;  a=a-c;  a=a^(c>>12); \
  b=b-c;  b=b-a;  b=b^(a<<16); \
  c=c-a;  c=c-b;  c=c^(b>>5);  \
  a=a-b;  a=a-c;  a=a^(c>>3);  \
  b=b-c;  b=b-a;  b=b^(a<<10); \
  c=c-a;  c=c-b;  c=c^(b>>15); \
}

static uint32_t hashfn(const void *key, unsigned int key_length) {
    uint32_t a,b,c,len;
    const uint8_t *k = key;

    /* Set up the internal state */
    len = key_length;
    a = b = c = 0x9e3779b9;  /* the golden ratio; an arbitrary value */

    /*---------------------------------------- handle most of the key */
    while (len >= 12) {
	a += (k[0] +((uint32_t)k[1]<<8) +((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
	b += (k[4] +((uint32_t)k[5]<<8) +((uint32_t)k[6]<<16) +((uint32_t)k[7]<<24));
	c += (k[8] +((uint32_t)k[9]<<8) +((uint32_t)k[10]<<16)+((uint32_t)k[11]<<24));
	mix(a,b,c);
	k += 12; len -= 12;
    }

   /*------------------------------------- handle the last 11 bytes */
   c += key_length;
   switch(len) { /* all the case statements fall through */
   case 11: c+=((uint32_t)k[10]<<24);
   case 10: c+=((uint32_t)k[9]<<16);
   case 9 : c+=((uint32_t)k[8]<<8);
       /* the first byte of c is reserved for the length */
   case 8 : b+=((uint32_t)k[7]<<24);
   case 7 : b+=((uint32_t)k[6]<<16);
   case 6 : b+=((uint32_t)k[5]<<8);
   case 5 : b+=k[4];
   case 4 : a+=((uint32_t)k[3]<<24);
   case 3 : a+=((uint32_t)k[2]<<16);
   case 2 : a+=((uint32_t)k[1]<<8);
   case 1 : a+=k[0];
       /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}

static unsigned int next_pow2(unsigned int i) {
    i--;
    i |= i >> 1;
    i |= i >> 2;
    i |= i >> 4;
    i |= i >> 8;
    i |= i >> 16;
    i++;
    return i;
}

static const char *HT_DELETED = "DELETED";
struct sxi_ht_item_t {
    void *key;
    unsigned int key_len;
    void *value;
};

struct _sxi_ht_t {
    sxc_client_t *sx;
    struct sxi_ht_item_t **tab;
    unsigned int items;
    unsigned int deleted;
    unsigned int size;
    unsigned int current;
    unsigned int modcount;
};


sxi_ht *sxi_ht_new(sxc_client_t *sx, unsigned int initial_size) {
    sxi_ht *ht;
    if(initial_size<128)
	initial_size = 128;
    else
	initial_size = next_pow2(initial_size);
    if(!(ht = malloc(sizeof(*ht)))) {
	SXDEBUG("failed to allocate hash struct");
	sxi_seterr(sx, SXE_EMEM, "Cannot create new hash table: Out of memory");
	return NULL;
    }

    if(!(ht->tab = calloc(sizeof(struct sxi_ht_item_t *), initial_size))) {
	SXDEBUG("failed to create a hash with %u items", initial_size);
	sxi_seterr(sx, SXE_EMEM, "Cannot create new hash table: Out of memory");
	free(ht);
	return NULL;
    }

    ht->sx = sx;
    ht->items = 0;
    ht->size = initial_size;
    ht->deleted = 0;
    ht->current = 0;
    ht->modcount = 0;
    return ht;
}

static unsigned int gethashpos(unsigned int i) {
    return i*(i-1)/2;
}

int sxi_ht_add(sxi_ht *ht, const void *key, unsigned int key_length, void *value) {
    uint32_t h = hashfn(key, key_length), pos;
    struct sxi_ht_item_t *item;
    sxc_client_t *sx = ht->sx;
    unsigned int i;

    ht->modcount++;
    for(i=1; ;i++) {
	pos = (h + gethashpos(i)) & (ht->size - 1);
	item = ht->tab[pos];

	if(!item)
	    break;

	if(key_length != item->key_len || memcmp(key, item->key, key_length))
	    continue;

	if(item->value == HT_DELETED)
	    ht->deleted--;
	item->value = value;
	return 0;
    }

    item = malloc(sizeof(*item) + key_length);
    if(!item) {
	SXDEBUG("OOM allocating new item (key len: %u)", key_length);
	sxi_seterr(sx, SXE_EMEM, "Cannot add item to hash table: Out of memory");
	return 1;
    }

    item->key = item+1;
    item->key_len = key_length;
    item->value = value;
    memcpy(item->key, key, key_length);
    ht->tab[pos] = item;
    ht->items++;

    if(ht->items * 100 / ht->size > 78) {
	unsigned int j;
	sxi_ht new_ht;

	memcpy(&new_ht, ht, sizeof(new_ht));

	if((new_ht.items - new_ht.deleted) * 100 / new_ht.size > 50)
	    new_ht.size *= 2;

	new_ht.tab = calloc(sizeof(struct sxi_ht_item_t *), new_ht.size);
	if(!new_ht.tab) {
	    SXDEBUG("OOM growing hash from %u to %u items", ht->size, new_ht.size);
	    sxi_seterr(sx, SXE_EMEM, "Cannot add item to hash table: Out of memory");
	    return 1;
	}
	new_ht.items = 0;
	new_ht.deleted = 0;

	for(i=0; i<ht->size; i++) {
	    item = ht->tab[i];
	    if(!item)
		continue;
	    if(item->value == HT_DELETED) {
		free(item);
		continue;
	    }

	    new_ht.items++;
	    h = hashfn(item->key, item->key_len);
	    for(j=1; ;j++) {
		pos = (h + gethashpos(j)) & (new_ht.size - 1);
		if(new_ht.tab[pos])
		    continue;
		new_ht.tab[pos] = item;
		break;
	    }
	}
	free(ht->tab);
	memcpy(ht, &new_ht, sizeof(*ht));
    }

    return 0;
}

unsigned int sxi_ht_count(sxi_ht *ht) {
    return ht ? ht->items - ht->deleted: 0;
}

unsigned int sxi_ht_modcount(sxi_ht *ht) {
    return ht ? ht->modcount : 0;
}

int sxi_ht_get(sxi_ht *ht, const void *key, unsigned int key_length, void **value) {
    uint32_t h = hashfn(key, key_length), pos;
    struct sxi_ht_item_t *item;
    unsigned int i;

    for(i=1; ;i++) {
	pos = (h + gethashpos(i)) & (ht->size - 1);
	item = ht->tab[pos];

	if(!item)
	    return 1;

	if(key_length != item->key_len || memcmp(key, item->key, key_length))
	    continue;

	if(item->value == HT_DELETED)
	    return 1;

	if(value)
	    *value = item->value;
	return 0;
    }
}

void sxi_ht_del(sxi_ht *ht, const void *key, unsigned int key_length) {
    uint32_t h = hashfn(key, key_length), pos;
    struct sxi_ht_item_t *item;
    unsigned int i;

    ht->modcount++;
    for(i=1; ;i++) {
	pos = (h + gethashpos(i)) & (ht->size - 1);
	item = ht->tab[pos];

	if(!item)
	    return;

	if(key_length != item->key_len || memcmp(key, item->key, key_length))
	    continue;

	if(item->value != HT_DELETED) {
	    ht->deleted++;
	    item->value = (void *)HT_DELETED;
	}
	if(ht->items == ht->deleted)
	    sxi_ht_empty(ht);
	return;
    }
}

void sxi_ht_empty(sxi_ht *ht) {
    unsigned int i;
    if(!ht)
	return;
    for(i=0;i<ht->size; i++) {
	if(!ht->tab[i])
	    continue;
	free(ht->tab[i]);
    }
    memset(ht->tab, 0, sizeof(struct sxi_ht_item_t *) * ht->size);
    ht->items = ht->deleted = ht->modcount = 0;
}

void sxi_ht_enum_reset(sxi_ht *ht) {
    ht->current = 0;
}

int sxi_ht_enum_getnext(sxi_ht *ht, const void **key, unsigned int *key_len, const void **value) {
    while(ht->current < ht->size) {
	struct sxi_ht_item_t *item = ht->tab[ht->current++];
	if(!item || item->value == HT_DELETED)
	    continue;
	if(key)
	    *key = item->key;
	if(key_len)
	    *key_len = item->key_len;
	if(value)
	    *value = item->value;
	return 0;
    }
    sxi_ht_enum_reset(ht);
    return 1;
}

void sxi_ht_free(sxi_ht *ht) {
    unsigned int i;
    if(!ht)
	return;
    for(i=0; i<ht->size;i++)
	free(ht->tab[i]);
    free(ht->tab);
    free(ht);
}

double sxi_timediff(const struct timeval *a, const struct timeval *b) {
    double rs = a->tv_sec - b->tv_sec;
    double ru = a->tv_usec - b->tv_usec;
    if(ru < 0) {
	rs = rs - 1;
	ru += 1000000;
    }
    return rs + ru/1000000.0;
}

int sxi_utf8_validate_len(const char *str)
{
  uint8_t c;
  int l = 0;
  while ((c = *str++)) {
    l++;
    if (c < 0x80)
      continue;
    /* validate UTF-8 according to RFC3629 */
    if (c >= 0xC2 && c <= 0xDF) {
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c == 0xE0) {
      c = *str++;
      if (c < 0xA0 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c >= 0xE1 && c <= 0xEC) {
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c == 0xED) {
      c = *str++;
      if (c < 0x80 || c > 0x9F)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c >= 0xEE && c <= 0xEF) {
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c == 0xF0) {
      c = *str++;
      if (c < 0x90 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c >= 0xF1 && c <= 0xF3) {
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c == 0xF4) {
      c = *str++;
      if (c < 0x80 || c > 0x8F)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
   } else
       return -1;
  }
  return l;
}

int sxi_utf8_validate(const char *str)
{
    if(sxi_utf8_validate_len(str) < 0)
        return -1;
    return 0;
}


char *sxi_json_quote_string(const char *s) {
    const char *hex_digits = "0123456789abcdef", *begin = s;
    unsigned int pos = 0;
    char *p, *ret = malloc(strlen(s) * 6 + 3);

    if(!ret)
	return NULL;
    *ret = '"';
    p = ret + 1;
    while(1) {
        unsigned char c = begin[pos];
        /* flush on end of string and escape quotation mark, reverse solidus,
         * and the control characters (U+0000 through U+001F) */
        if(c < ' ' || c == '"' || c== '\\') {
            if(pos) { /* flush */
		memcpy(p, begin, pos);
		p += pos;
	    }
            begin = &begin[pos+1];
            pos = 0;
            if(!c) {
                p[0] = '"';
		p[1] = '\0';
                return ret;
            }
	    p[0] = '\\';
	    p[1] = 'u';
	    p[2] = '0';
	    p[3] = '0';
	    p[4] = hex_digits[c >> 4];
            p[5] = hex_digits[c & 0xf];
	    p += 6;
        } else
            pos++;
    }
}


struct meta_val_t {
    uint8_t *value;
    unsigned int value_len;
};

sxc_meta_t *sxc_meta_new(sxc_client_t *sx) {
    return sxi_ht_new(sx, 0);
}

void sxc_meta_empty(sxc_meta_t *meta) {
    void *item;

    if(!meta)
	return;

    sxi_ht_enum_reset(meta);
    while(!sxi_ht_enum_getnext(meta, NULL, NULL, (const void **)&item))
	free(item);

    sxi_ht_empty(meta);
}

void sxc_meta_free(sxc_meta_t *meta) {
    sxc_meta_empty(meta);
    sxi_ht_free(meta);
}

int sxc_meta_getval(sxc_meta_t *meta, const char *key, const void **value, unsigned int *value_len) {
    const struct meta_val_t *item;

    if(!meta)
	return -1;
    if(!key) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot lookup key: Invalid argument");
	return -1;
    }

    if(sxi_ht_get(meta, key, strlen(key)+1, (void **)&item))
	return 1;

    if(value)
	*value = item->value;
    if(value_len)
	*value_len = item->value_len;

    return 0;
}

void sxc_meta_delval(sxc_meta_t *meta, const char *key) {
    unsigned int klen;
    void *freeme;

    if(!meta || !key)
	return;

    klen = strlen(key)+1;

    if(!sxi_ht_get(meta, key, klen, &freeme)) {
	free(freeme);
	sxi_ht_del(meta, key, klen);
    }
}

unsigned int sxc_meta_count(sxc_meta_t *meta) {
    return meta ? sxi_ht_count(meta) : 0;
}

unsigned int sxc_meta_modcount(sxc_meta_t *meta) {
    return meta ? sxi_ht_modcount(meta) : 0;
}

int sxc_meta_getkeyval(sxc_meta_t *meta, unsigned int itemno, const char **key, const void **value, unsigned int *value_len) {
    unsigned int i, nitems = sxc_meta_count(meta);
    const struct meta_val_t *item;

    if(!meta)
	return -1;
    if(itemno >= nitems) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot lookup item: Index out of bounds");
	return -1;
    }

    sxi_ht_enum_reset(meta);

    for(i=0; i < itemno ; i++)
	if(sxi_ht_enum_getnext(meta, NULL, NULL, NULL))
	    return -1;

    if(sxi_ht_enum_getnext(meta, (const void **)key, NULL, (const void **)&item))
	return -1;

    if(value)
	*value = item->value;
    if(value_len)
	*value_len = item->value_len;

    return 0;
}

int sxc_meta_setval(sxc_meta_t *meta, const char *key, const void *value, unsigned int value_len) {
    struct meta_val_t *item;

    if(!meta)
	return -1;
    if(!key || (!value && value_len)) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot set meta value: Invalid argument");
	return -1;
    }

    item = malloc(sizeof(*item) + value_len);
    if(!item) {
	sxi_seterr(meta->sx, SXE_EMEM, "Cannot set meta value: Out of memory");
	return 1;
    }

    item->value = (uint8_t *)(item + 1);
    item->value_len = value_len;
    if(value_len)
	memcpy(item->value, value, value_len);

    sxc_meta_delval(meta, key);

    if(sxi_ht_add(meta, key, strlen(key)+1, item))
	return -1;

    return 0;
}

int sxc_meta_setval_fromhex(sxc_meta_t *meta, const char *key, const char *valuehex, int valuehex_len) {
    struct meta_val_t *item;

    if(!meta)
	return -1;
    if(!key) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot set meta value: Invalid key");
	return -1;
    }
    if(valuehex) {
	if(valuehex_len < 0)
	    valuehex_len = strlen(valuehex);
	if(valuehex_len & 1) {
	    sxi_seterr(meta->sx, SXE_EARG, "Cannot set meta value: Invalid value");
	    return -1;
	}
    } else if(valuehex_len) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot set meta value: Invalid value length");
	return -1;
    }

    item = malloc(sizeof(*item) + valuehex_len / 2);
    if(!item) {
	sxi_seterr(meta->sx, SXE_EMEM, "Cannot set meta value: Out of memory");
	return 1;
    }

    item->value = (uint8_t *)(item + 1);
    item->value_len = valuehex_len / 2;
    if(sxi_hex2bin(valuehex, valuehex_len, item->value, item->value_len)) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot set meta value: Invalid value");
        free(item);
	return -1;
    }

    sxc_meta_delval(meta, key);

    if(sxi_ht_add(meta, key, strlen(key)+1, item))
	return -1;

    return 0;
}

sxc_meta_t *sxi_meta_dup(sxc_client_t *sx, sxc_meta_t *meta) {
    sxc_meta_t *ret;
    unsigned int i;

    if(!meta)
        return NULL;

    ret = sxc_meta_new(sx);
    if(!ret)
        return NULL;
    for(i = 0; i < sxc_meta_count(meta); i++) {
        const char *key;
        const void *value;
        unsigned int value_len;

        if(sxc_meta_getkeyval(meta, i, &key, &value, &value_len)) {
            sxc_meta_free(ret);
            return NULL;
        }

        if(sxc_meta_setval(ret, key, value, value_len)) {
            sxc_meta_free(ret);
            return NULL;
        }
    }

    return ret;
}

int sxi_meta_checksum(sxc_client_t *sx, sxc_meta_t *meta, unsigned char *hash) {
    sxi_md_ctx *ctx = sxi_md_init();
    unsigned int i;
    if (!ctx || !meta || !hash)
        return 1;
    if (!sxi_sha1_init(ctx)) {
        sxi_md_cleanup(&ctx);
        return 1;
    }

    for(i = 0; i < sxc_meta_count(meta); i++) {
        const char *key;
        const void *value;
        unsigned int value_len;

        if(sxc_meta_getkeyval(meta, i, &key, &value, &value_len)) {
            sxi_md_cleanup(&ctx);
            return 1;
        }

        if(!sxi_sha1_update(ctx, key, strlen(key)) || !sxi_sha1_update(ctx, value, value_len)) {
            sxi_md_cleanup(&ctx);
            return 1;
        }
    }

    if(!sxi_sha1_final(ctx, hash, NULL)) {
        sxi_md_cleanup(&ctx);
        return 1;
    }
    sxi_md_cleanup(&ctx);
    return 0;
}

char sxi_read_one_char(void)
{
    char line[3];
    if (!fgets(line, sizeof(line), stdin)) {
        putchar('\n');
        return EOF;
    }
    if (line[0] == '\n' || (line[0] && line[1] == '\n'))
        return line[0]; /* one character, terminated by a newline */
    /* skip till EOL */
    while (fgets(line, 2, stdin) && line[0] && line[0] != '\n') {}
    /* more than one character read */
    return '\0';
}

/*
 * returns -1 on error and 0 when input was received and stored
 * SXC_INPUT_YN: def == "y" or "n", stores 'y' or 'n' in in[0]
 */
int sxc_input_fn(sxc_client_t *sx, sxc_input_t type, const char *prompt, const char *def, char *in, unsigned int insize, void *ctx)
{
    char c;
    struct termios told, tnew;
    int restore_ta = 1;

    if(!sx || !prompt || !in || !insize) {
	if(sx)
	    sxi_seterr(sx, SXE_EARG, "NULL argument");
	return -1;
    }

    switch(type) {
	case SXC_INPUT_YN:
	    if(def && *def == 'y')
		printf("%s [Y/n] ", prompt);
	    else
		printf("%s [y/N] ", prompt);
	    fflush(stdout);
	    c = sxi_read_one_char();
	    if(c == 'y' || c == 'Y')
		*in = 'y';
	    else if(c == 'n' || c == 'N')
		*in = 'n';
	    else if(c == '\n' || c == EOF)
		*in = def ? *def : 'n';
	    break;

	case SXC_INPUT_PLAIN:
	    printf("%s", prompt);
	    fflush(stdout);
	    if(!fgets(in, insize, stdin)) {
		sxi_seterr(sx, SXE_EREAD, "fgets() failed");
		return -1;
	    }
	    in[strlen(in) - 1] = 0;
	    break;

	case SXC_INPUT_SENSITIVE:
	    tcgetattr(0, &told);
	    tnew = told;
	    tnew.c_lflag &= ~ECHO;
	    tnew.c_lflag |= ECHONL;
	    if(tcsetattr(0, TCSANOW, &tnew)) {
		fprintf(stderr, "WARNING: Unable to set terminal attributes, your password may be echoed.\n");
		restore_ta = 0;
	    }
	    printf("%s", prompt);
	    fflush(stdout);
	    if(!fgets(in, insize, stdin)) {
		sxi_seterr(sx, SXE_EREAD, "fgets() failed");
		return -1;
	    }
	    in[strlen(in) - 1] = 0;
	    if(restore_ta && tcsetattr(0, TCSANOW, &told)) {
		memset(in, 0, insize);
		sxi_seterr(sx, SXE_EARG, "tcsetattr() failed");
		return -1;
	    }
	    break;

	default:
	    sxi_seterr(sx, SXE_EARG, "Unknown input type");
	    return -1;
    }

    return 0;
}

static int rm_fn(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if(typeflag == FTW_F || typeflag == FTW_SL || typeflag == FTW_SLN)
	return unlink(path);
    if(typeflag == FTW_DP) {
	if(rmdir(path) == -1)
	    return -1;
        return 0;
    }
    if (typeflag == FTW_D)
        return 0;
    return -1;
}

int sxi_rmdirs(const char *dir)
{
    if(access(dir, F_OK) == -1 && errno == ENOENT)
	return 0;
    return nftw(dir, rm_fn, 10, FTW_MOUNT | FTW_PHYS | FTW_DEPTH);
}

int sxi_mkdir_hier(sxc_client_t *sx, const char *fullpath, mode_t mode) {
    unsigned int i, len;
    char *dir;

    if(!fullpath || !*fullpath) {
	SXDEBUG("called with NULL or empty path");
	sxi_seterr(sx, SXE_EARG, "Directory creation failed: Invalid argument");
	return 1;
    }

    len = strlen(fullpath);
    dir = malloc(len+1);
    if(!dir) {
	SXDEBUG("OOM duplicating path");
	sxi_seterr(sx, SXE_EMEM, "Directory creation failed: Out of memory");
	return 1;
    }

    memcpy(dir, fullpath, len+1);
    while(len && dir[len-1] == '/') {
        /* len > 0 */
	len--;
        /* len >= 0 */
	dir[len] = '\0';
    }

    for(i=1; i<=len; i++) {
	if(dir[i] == '/' || !dir[i]) {
	    dir[i] = '\0';
	    if(mkdir(dir, mode) < 0 && errno != EEXIST)
		break;
	    dir[i] = '/';
	}
    }

    if(i<=len) {
	sxi_setsyserr(sx, SXE_EWRITE, "Directory creation failed");
	SXDEBUG("failed to create directory %s", dir);
	free(dir);
	return 1;
    }

    free(dir);
    return 0;
}

int sxi_hmac_sha1_update_str(sxi_hmac_sha1_ctx *ctx, const char *str) {
    if (!ctx)
        return 0;
    int r = sxi_hmac_sha1_update(ctx, (unsigned char *)str, strlen(str));
    if(r)
	r = sxi_hmac_sha1_update(ctx, (unsigned char *)"\n", 1);
    return r;
}

int64_t sxi_parse_size(sxc_client_t *sx, const char *str, int allow_0) {
    const char *suffixes = "kKmMgGtT";
    char *ptr;
    int64_t size;

    size = strtoll(str, (char **)&ptr, 0);
    if(size < 0 || size == LLONG_MAX || (!allow_0 && !size)) {
        sxi_seterr(sx, SXE_EARG, "ERROR: Bad size: %s\n", str);
        return -1;
    }
    if(*ptr) {
        unsigned int shl;
        *ptr = (char) toupper(*ptr);
        ptr = strchr(suffixes, *ptr);
        if(!ptr) {
            sxi_seterr(sx, SXE_EARG, "ERROR: Bad size: %s\n", str);
            return -1;
        }
        shl = (((ptr-suffixes)/2) + 1) * 10;
        size <<= shl;
    }

    return size;
}

unsigned int sxi_rand(void)
{
    unsigned int r = 0;
    sxi_rand_pseudo_bytes((unsigned char*)&r, sizeof(r));
    return r;
}

char *sxi_getenv(const char *name)
{
#ifdef HAVE_SECURE_GETENV
    return secure_getenv(name);
#else
    if(getuid() != geteuid() || getgid() != getegid())
	return NULL;
    return getenv(name);
#endif
}

void sxi_strlcpy(char *dest, const char *src, size_t dest_size)
{
    if (!dest)
        return;
    if (dest_size) {
        size_t n = src ? strlen(src) : 0;
        if (n >= dest_size)
            n = dest_size - 1;
        memcpy(dest, src, n);
        dest[n] = '\0';
    }
}

uint32_t sxi_checksum(uint32_t checksum, const void *buf, size_t size)
{
    return adler32(checksum, buf, size);
}

int sxi_derive_key(const char *pass, const char *salt, unsigned salt_size, unsigned int log2_iter, char *out, unsigned int len)
{
    char settingbuf[30];
    const char *genkey, *setting;

    setting = _crypt_gensalt_blowfish_rn("$2b$", log2_iter, salt, salt_size, settingbuf, sizeof(settingbuf));
    if (!setting)
        return -1;
    genkey = _crypt_blowfish_rn(pass, setting, out, len);
    if (!genkey)
        return -1;

    return 0;
}

int sxi_str_has_glob(const char *s) {
    unsigned int len = strlen(s), i;
    int esc = 0;
    for(i = 0; i < len; i++) {
        if(s[i] == '\\')
            esc = !esc;
        else if(strchr("?*[", s[i]) && !esc)
            break;
        else
            esc = 0;
    }
    if(len && i < len)
        return 1;
    return 0;
}

int sxc_str_has_glob(const char *s)
{
    return s ? sxi_str_has_glob(s) : -1;
}

#ifdef WORDS_BIGENDIAN
uint32_t sxi_swapu32(uint32_t v)
{
    v = ((v << 8) & 0xff00ff00) | ((v >> 8) & 0xff00ff); 
    return (v << 16) | (v >> 16);
}
uint64_t sxi_swapu64(uint64_t v)
{
    v = ((v << 8) & 0xff00ff00ff00ff00ULL) | ((v >> 8) & 0x00ff00ff00ff00ffULL);
    v = ((v << 16) & 0xffff0000ffff0000ULL) | ((v >> 16) & 0x0000ffff0000ffffULL);
    return (v << 32) | (v >> 32);
}
#else
uint64_t sxi_swapu64(uint64_t v) {
    return v;
}
uint32_t sxi_swapu32(uint32_t v)
{
    return v;
}
#endif
