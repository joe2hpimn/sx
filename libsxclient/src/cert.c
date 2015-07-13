/*
 * Based on lib/{ssluse,hostcheck,rawstr}.c from libcurl which has the following
 * license:
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
 * 
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright
 * notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name of a copyright holder shall not
 * be used in advertising or otherwise to promote the sale, use or other dealings
 * in this Software without prior written authorization of the copyright holder.
 */

#include "default.h"
#include "cert.h"
#include <curl/curl.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libsxclient-int.h"

#define CURL_HOST_NOMATCH 0
#define CURL_HOST_MATCH   1
/* Portable, consistent toupper (remember EBCDIC). Do not use toupper() because
   its behavior is altered by the current locale. */
static char Curl_raw_toupper(char in)
{
  switch (in) {
  case 'a':
    return 'A';
  case 'b':
    return 'B';
  case 'c':
    return 'C';
  case 'd':
    return 'D';
  case 'e':
    return 'E';
  case 'f':
    return 'F';
  case 'g':
    return 'G';
  case 'h':
    return 'H';
  case 'i':
    return 'I';
  case 'j':
    return 'J';
  case 'k':
    return 'K';
  case 'l':
    return 'L';
  case 'm':
    return 'M';
  case 'n':
    return 'N';
  case 'o':
    return 'O';
  case 'p':
    return 'P';
  case 'q':
    return 'Q';
  case 'r':
    return 'R';
  case 's':
    return 'S';
  case 't':
    return 'T';
  case 'u':
    return 'U';
  case 'v':
    return 'V';
  case 'w':
    return 'W';
  case 'x':
    return 'X';
  case 'y':
    return 'Y';
  case 'z':
    return 'Z';
  }
  return in;
}

/*
 * Curl_raw_equal() is for doing "raw" case insensitive strings. This is meant
 * to be locale independent and only compare strings we know are safe for
 * this.  See http://daniel.haxx.se/blog/2008/10/15/strcasecmp-in-turkish/ for
 * some further explanation to why this function is necessary.
 *
 * The function is capable of comparing a-z case insensitively even for
 * non-ascii.
 */

static int Curl_raw_equal(const char *first, const char *second)
{
  while(*first && *second) {
    if(Curl_raw_toupper(*first) != Curl_raw_toupper(*second))
      /* get out of the loop as soon as they don't match */
      break;
    first++;
    second++;
  }
  /* we do the comparison here (possibly again), just to make sure that if the
     loop above is skipped because one of the strings reached zero, we must not
     return this as a successful match */
  return (Curl_raw_toupper(*first) == Curl_raw_toupper(*second));
}

static int Curl_raw_nequal(const char *first, const char *second, size_t max)
{
  while(*first && *second && max) {
    if(Curl_raw_toupper(*first) != Curl_raw_toupper(*second)) {
      break;
    }
    max--;
    first++;
    second++;
  }
  if(0 == max)
    return 1; /* they are equal this far */

  return Curl_raw_toupper(*first) == Curl_raw_toupper(*second);
}

/*
 * Match a hostname against a wildcard pattern.
 * E.g.
 *  "foo.host.com" matches "*.host.com".
 *
 * We use the matching rule described in RFC6125, section 6.4.3.
 * http://tools.ietf.org/html/rfc6125#section-6.4.3
 */

static int hostmatch(const char *hostname, const char *pattern)
{
  const char *pattern_label_end, *pattern_wildcard, *hostname_label_end;
  int wildcard_enabled;
  size_t prefixlen, suffixlen;
  pattern_wildcard = strchr(pattern, '*');
  if(pattern_wildcard == NULL)
    return Curl_raw_equal(pattern, hostname) ?
      CURL_HOST_MATCH : CURL_HOST_NOMATCH;

  /* We require at least 2 dots in pattern to avoid too wide wildcard
     match. */
  wildcard_enabled = 1;
  pattern_label_end = strchr(pattern, '.');
  if(pattern_label_end == NULL || strchr(pattern_label_end+1, '.') == NULL ||
     pattern_wildcard > pattern_label_end ||
     Curl_raw_nequal(pattern, "xn--", 4)) {
    wildcard_enabled = 0;
  }
  if(!wildcard_enabled)
    return Curl_raw_equal(pattern, hostname) ?
      CURL_HOST_MATCH : CURL_HOST_NOMATCH;

  hostname_label_end = strchr(hostname, '.');
  if(hostname_label_end == NULL ||
     !Curl_raw_equal(pattern_label_end, hostname_label_end))
    return CURL_HOST_NOMATCH;

  /* The wildcard must match at least one character, so the left-most
     label of the hostname is at least as large as the left-most label
     of the pattern. */
  if(hostname_label_end - hostname < pattern_label_end - pattern)
    return CURL_HOST_NOMATCH;

  prefixlen = pattern_wildcard - pattern;
  suffixlen = pattern_label_end - (pattern_wildcard+1);
  return Curl_raw_nequal(pattern, hostname, prefixlen) &&
    Curl_raw_nequal(pattern_wildcard+1, hostname_label_end - suffixlen,
                    suffixlen) ?
    CURL_HOST_MATCH : CURL_HOST_NOMATCH;
}

static int Curl_cert_hostcheck(const char *match_pattern, const char *hostname)
{
  if(!match_pattern || !*match_pattern ||
      !hostname || !*hostname) /* sanity check */
    return 0;

  if(Curl_raw_equal(hostname, match_pattern)) /* trivial case */
    return 1;

  if(hostmatch(hostname,match_pattern) == CURL_HOST_MATCH)
    return 1;
  return 0;
}


/* Quote from RFC2818 section 3.1 "Server Identity"

   If a subjectAltName extension of type dNSName is present, that MUST
   be used as the identity. Otherwise, the (most specific) Common Name
   field in the Subject field of the certificate MUST be used. Although
   the use of the Common Name is existing practice, it is deprecated and
   Certification Authorities are encouraged to use the dNSName instead.

   Matching is performed using the matching rules specified by
   [RFC2459].  If more than one identity of a given type is present in
   the certificate (e.g., more than one dNSName name, a match in any one
   of the set is considered acceptable.) Names may contain the wildcard
   character * which is considered to match any single domain name
   component or component fragment. E.g., *.a.com matches foo.a.com but
   not bar.foo.a.com. f*.com matches foo.com but not bar.com.

*/

#if LIBCURL_VERSION_NUM < 0x071101
#define CURLE_PEER_FAILED_VERIFICATION CURLE_SSL_PEER_CERTIFICATE
#endif

CURLcode sxi_verifyhost(sxc_client_t *sx, const char *hostname, X509 *server_cert)
{
    int matched = -1; /* -1 is no alternative match yet, 1 means match and 0
                         means mismatch */
    STACK_OF(GENERAL_NAME) *altnames;
    CURLcode res = CURLE_OK;

    /* get a "list" of alternative names */
    altnames = X509_get_ext_d2i(server_cert, NID_subject_alt_name, NULL, NULL);

    if(altnames) {
        int numalts;
        int i;

        /* get amount of alternatives, RFC2459 claims there MUST be at least
           one, but we don't depend on it... */
        numalts = sk_GENERAL_NAME_num(altnames);

        /* loop through all alternatives while none has matched */
        for(i=0; (i<numalts) && (matched != 1); i++) {
            /* get a handle to alternative name number i */
            const GENERAL_NAME *check = sk_GENERAL_NAME_value(altnames, i);

            /* only check alternatives of the same type the target is */
            if(check->type == GEN_DNS) {
                /* get data and length */
                const char *altptr = (char *)ASN1_STRING_data(check->d.ia5);
                size_t altlen = (size_t) ASN1_STRING_length(check->d.ia5);

                /* name/pattern comparison */
                /* The OpenSSL man page explicitly says: "In general it cannot be
                   assumed that the data returned by ASN1_STRING_data() is null
                   terminated or does not contain embedded nulls." But also that
                   "The actual format of the data will depend on the actual string
                   type itself: for example for and IA5String the data will be ASCII"

                   Curl uses strlen(altptr) == altlen here to check for embedded \0s.
                   We use memchr() to be safer from a possible non-null terminated string.
                   */
                if(!memchr(altptr, 0, altlen) &&
                   /* if this isn't true, there was an embedded zero in the name
                      string and we cannot match it. */
                   Curl_cert_hostcheck(altptr, hostname))
                    matched = 1;
                else
                    matched = 0;
            }
        }
        GENERAL_NAMES_free(altnames);
    }

    if(matched == 1)
        /* an alternative name matched the server hostname */
        SXDEBUG("\t subjectAltName: %s matched\n", hostname);
    else if(matched == 0) {
        /* an alternative name field existed, but didn't match and then
           we MUST fail */
        sxi_seterr(sx, SXE_ECOMM, "subjectAltName does not match %s\n", hostname);
        res = CURLE_PEER_FAILED_VERIFICATION;
    }
    else {
        /* we have to look to the last occurrence of a commonName in the
           distinguished one to get the most significant one. */
        int j,i=-1 ;

        /* The following is done because of a bug in 0.9.6b */

        unsigned char *nulstr = (unsigned char *)"";
        unsigned char *peer_CN = nulstr;

        X509_NAME *name = X509_get_subject_name(server_cert) ;
        if(name)
            while((j = X509_NAME_get_index_by_NID(name, NID_commonName, i))>=0)
                i=j;

        /* we have the name entry and we will now convert this to a string
           that we can use for comparison. Doing this we support BMPstring,
           UTF8 etc. */

        if(i>=0) {
            ASN1_STRING *tmp = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name,i));

            /* In OpenSSL 0.9.7d and earlier, ASN1_STRING_to_UTF8 fails if the input
               is already UTF-8 encoded. We check for this case and copy the raw
               string manually to avoid the problem. This code can be made
               conditional in the future when OpenSSL has been fixed. Work-around
               brought by Alexis S. L. Carvalho. */
            if(tmp) {
                if(ASN1_STRING_type(tmp) == V_ASN1_UTF8STRING) {
                    j = ASN1_STRING_length(tmp);
                    if(j >= 0) {
                        peer_CN = OPENSSL_malloc(j+1);
                        if(peer_CN) {
                            memcpy(peer_CN, ASN1_STRING_data(tmp), j);
                            peer_CN[j] = '\0';
                        }
                    }
                }
                else /* not a UTF8 name */
                    j = ASN1_STRING_to_UTF8(&peer_CN, tmp);

                if(peer_CN && memchr(peer_CN, 0, j)) {
                    /* there was a terminating zero before the end of string, this
                       cannot match and we return failure! */
                    sxi_seterr(sx, SXE_ECOMM, "SSL: Illegal cert name field");
                    res = CURLE_PEER_FAILED_VERIFICATION;
                }
            }
        }

        if(peer_CN == nulstr)
            peer_CN = NULL;
        /* curl would convert from UTF8 to host encoding if built with HAVE_ICONV (not default) */

        if(res)
            /* error already detected, pass through */
            ;
        else if(!peer_CN) {
            SXDEBUG("SSL: Unable to obtain common name from peer certificate");
            res = CURLE_PEER_FAILED_VERIFICATION;
        }
        else if(!Curl_cert_hostcheck((const char *)peer_CN, hostname)) {
            sxi_seterr(sx, SXE_ECOMM, "SSL: Certificate subject name '%s' does not match "
                    "target host name '%s'", peer_CN, hostname);
            res = CURLE_PEER_FAILED_VERIFICATION;
        }
        else {
            SXDEBUG("\t common name: %s (matched)\n", peer_CN);
        }
        if(peer_CN)
            OPENSSL_free(peer_CN);
    }
    return res;
}
