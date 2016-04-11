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

#include "config.h"
#include "default.h"

#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "../libsxclient/src/vcrypto.h"

#include "fcgi-utils.h"
#include "fcgi-actions.h"
#include "utils.h"
#include "hashfs.h"
#include "../libsxclient/src/misc.h"
#include "version.h"

#define MAX_CLOCK_DRIFT 10

uint8_t hashbuf[UPLOAD_CHUNK_SIZE];
time_t last_flush;
void send_server_info(void) {
    last_flush = time(NULL);
    CGI_PRINTF("Server: Skylable SX\r\nSX-Cluster: %s (%s)%s\r\nSX-API-Version: %u\r\nVary: Accept-Encoding\r\n", src_version(), sx_hashfs_uuid(hashfs)->string, sx_hashfs_uses_secure_proto(hashfs) ? " ssl" : "", SRC_API_VERSION);
}

static const char *http_err_str(int http_status) {
    int h = http_status / 100;

    switch(h) {
    case 1:
	WARN("called with informational response %d", http_status);
	return "No error";
    case 2:
	WARN("called with positive response %d", http_status);
	return "OK";
    case 3:
	WARN("called with redirect response %d", http_status);
	return "Redirection";
    case 4:
	switch(http_status) {
	case 401:
	    return "Unauthorized";
	case 403:
	    return "Forbidden";
	case 404:
	    return "Not Found";
	case 405:
	    return "Method Not Allowed";
	case 408:
	    return "Request Timeout";
	case 409:
	    return "Conflict";
	case 413:
	    return "Request Entity Too Large";
	case 414:
	    return "Request-URI Too Long";
        case 429:
            return "Too many requests";
	default:
	    WARN("unhandled status: %d", http_status);
	case 400:
	    return "Bad Request";
	}
    case 5:
	switch(http_status) {
	case 501:
	    return "Not Implemented";
	case 503:
	    return "Service Unavailable";
	case 507:
	    return "Insufficient Storage";
	default:
	    WARN("unhandled status: %d", http_status);
	case 500:
	    return "Internal Server Error";
	}
    }

    WARN("called with invalid response %d", http_status);
    return "Unknown error";
}

#define HTML_1 "<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n<title>Skylable - SX Node</title>\n<meta name=\"Description\" content=\"SX Node\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n\n<style type=\"text/css\">\n\n        /*IPHONE STYLES*/\n        @media only screen and (max-width: 1110px) {\n\n        .see {\n        position:static!important;\n        text-align: right;\n        margin-left:4px;\n       }  \n\n        }\n\n\n        /*IPHONE STYLES*/\n        @media only screen and (max-width: 920px) {\n         body {\n            display: inline!important;\n         }\n\n         .main {\n          width: 99%%!important;\n          text-align: center;\n          margin: auto;\n         }\n\n         .pp {\n            width: 91%%!important;\n         }\n\n         .pp p {\n            width: 98%%!important;\n         }\n\n        }\n        @media only screen and (max-width: 480px) {\n         body {\n            display: inline!important;\n         }\n\n         .main {\n          width: 99%%!important;\n          text-align: center;\n          margin: auto;\n         }\n\n         .pp {\n            width: 91%%!important;\n         }\n\n         .pp p {\n            width: 98%%!important;\n         }\n\n        }\n        @media only screen and (max-width: 380px) {\n         body {\n            display: inline!important;\n         }            \n         .main {\n          width: 99%%!important;\n          text-align: center;\n          margin: auto;\n         }\n         .pp {\n            width: 91%%!important;\n         }    \n\n         .pp p {\n            width: 98%%!important;\n         }    \n     }\n\nbody, html {\n    margin: 0;\n    padding: 0;\n}\n\nbody {\n    height: 100%%;\n    -moz-background-size: cover;\n    -webkit-background-size: cover;\n    -o-background-size: cover;\n    background-size: cover;\n    display: table;\n    margin:auto;\n    font-family: \"Tahoma\", sans-serif;\n    font-weight: 200;\n    vertical-align: middle;\n}\n\na {\n    color: #0077c1;\n    text-decoration: none;\n}\n\n.main {\n    width:680px;\n    height:%dpx;\n    margin-top: 20%%;\n    margin-bottom: 20%%;\n    text-align: center;\n    background: rgba(255,255,255,0.7);\n    -webkit-box-shadow: 0px 0px 14px 0px rgba(50, 50, 50, 0.8);\n    -moz-box-shadow:    0px 0px 14px 0px rgba(50, 50, 50, 0.8);\n    box-shadow:         0px 0px 14px 0px rgba(50, 50, 50, 0.8);\n}\n\n.main img {\n    margin-top: 40px;\n}\n\nh1 {\n    font-size: 42px;\n    font-weight: 400;\n}\n\n.blue {\n    color: #0077c1;\n}\n\n.pp {\n    background: #fff;\n    margin-top: 30px;\n    margin-left: auto;\n    margin-right: auto;\n    margin-bottom: 40px;\n    width:70%%;\n    padding: 5px;\n    -webkit-box-shadow: 0px 0px 14px 0px rgba(50, 50, 50, 0.8);\n    -moz-box-shadow:    0px 0px 14px 0px rgba(50, 50, 50, 0.8);\n    box-shadow:         0px 0px 14px 0px rgba(50, 50, 50, 0.8);}\n\np {\n    font-size: 16px;\n    border-bottom: 1px solid #cfcfcf;\n    width: 90%%;\n    margin: 5px auto;\n    padding-bottom: 5px;\n}\n\np span {\n    color: #0077c1;\n    font-size: 24px;\n}\n\n.learn {\n    border-radius: 10px;\n    background: #3096d6; /* Old browsers */\n    background: -moz-linear-gradient(top,  #3096d6 0%%, #1f72c0 100%%); /* FF3.6+ */\n    background: -webkit-gradient(linear, left top, left bottom, color-stop(0%%,#3096d6), color-stop(100%%,#1f72c0)); /* Chrome,Safari4+ */\n    background: -webkit-linear-gradient(top,  #3096d6 0%%,#1f72c0 100%%); /* Chrome10+,Safari5.1+ */\n    background: -o-linear-gradient(top,  #3096d6 0%%,#1f72c0 100%%); /* Opera 11.10+ */\n    background: -ms-linear-gradient(top,  #3096d6 0%%,#1f72c0 100%%); /* IE10+ */\n    background: linear-gradient(to bottom,  #3096d6 0%%,#1f72c0 100%%); /* W3C */\n"
#define HTML_2 "    filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#3096d6', endColorstr='#1f72c0',GradientType=0 ); /* IE6-9 */\n    padding-top: 15px;\n    padding-bottom: 15px;\n    padding-left: 20px;\n    padding-right: 20px;\n    color: #fff;\n    text-decoration: none;\n    font-family: 'Arial', sans-serif;\n    margin-top: 110px;\n}\n\n.learn:hover {\n    background: #1f72c0; /* Old browsers */\n    background: -moz-linear-gradient(top, #1f72c0 0%, #3096d6 100%); /* FF3.6+ */\n    background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#1f72c0), color-stop(100%,#3096d6)); /* Chrome,Safari4+ */\n    background: -webkit-linear-gradient(top, #1f72c0 0%,#3096d6 100%); /* Chrome10+,Safari5.1+ */\n    background: -o-linear-gradient(top, #1f72c0 0%,#3096d6 100%); /* Opera 11.10+ */\n    background: -ms-linear-gradient(top, #1f72c0 0%,#3096d6 100%); /* IE10+ */\n    background: linear-gradient(to bottom, #1f72c0 0%,#3096d6 100%); /* W3C */\n    filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#1f72c0', endColorstr='#3096d6',GradientType=0 ); /* IE6-9 */\n}\n\n.see {\n    position: fixed;\n    right: 20px;\n    bottom: 20px;\n    border: none;\n    font-size:14px;\n    font-weight:bold;\n    padding-top:10px;\n    padding-bottom: 10px;\n    padding-left: 20px;\n    padding-right: 20px;\n    background: rgba(255,255,255,0.7);\n    -webkit-box-shadow: 0px 0px 14px 0px rgba(50, 50, 50, 0.8);\n    -moz-box-shadow:    0px 0px 14px 0px rgba(50, 50, 50, 0.8);\n    box-shadow:         0px 0px 14px 0px rgba(50, 50, 50, 0.8);}\n}\n\n\n</style>\n\n</head>\n\n<body>\n\n<div class=\"main\">\n"

#define LOGO "    <img src=\"data:image/png;base64,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\" />\n"

#define HTML_3 "    <h1>Your <a href=\"http://www.skylable.com/products/sx/\">S<sup>X</sup> node</a> is up and running</h1>\n"
#define HTML_4 "    <div class=\"pp\">\n            <p><span>Cluster UUID:</span><br> %s</p>\n            <p><span>Node UUID:</span><br> %s</p>\n            <p><span>Distribution:</span><br> %s(%u)</p>\n        </div>\n\n        <p class=\"desc\">Skylable, a complete <a href=\"http://www.skylable.com/products/\">distributed object-storage</a> software solution.</p><br>\n\n    <a class=\"learn\" href=\"http://www.skylable.com\">Learn More</a>\n</div>\n\n<a class=\"see\" href=\"http://www.skylable.com/docs/faq/#error-messages-interpretation\">Why am I seeing this page?</a>\n\n</body>\n</html>\n"
static void print_html(int status, const char *title, int errnum, const char *errmsg)
{
    if (status)
	CGI_PRINTF("Status: %d\r\n", status);
    CGI_PRINTF("Content-Type: text/html\r\n\r\n");
    CGI_PRINTF(HTML_1, errmsg ? 653: 600);
    CGI_PUTS(HTML_2);
    CGI_PUTS(LOGO);
    CGI_PUTS(HTML_3);
    if (errmsg)
        CGI_PRINTF("<h2>Error %d: %s</h2>", errnum, errmsg);
    unsigned int version;
    const sx_uuid_t *cluster_uuid = sx_hashfs_uuid(hashfs);
    const sx_uuid_t *dist_uuid = sx_hashfs_distinfo(hashfs, &version, NULL);
    sx_uuid_t node_uuid;
    CGI_PRINTF(HTML_4,
               cluster_uuid->string,
               sx_hashfs_self_uuid(hashfs, &node_uuid) == OK ? node_uuid.string : "&lt;not assigned yet&gt;",
               dist_uuid ? dist_uuid->string : "&lt;not defined yet&gt;",
               dist_uuid ? version : 0
               );
}

static void send_error_helper(const char sep, int errnum, const char *message) {
    sx_uuid_t node_uuid;
    CGI_PRINTF("%c\"ErrorMessage\":", sep);
    json_send_qstring(message ? message : "");
    if (errnum == 500 || errnum == 400) {
        if (message)
            WARN("HTTP %d: %s", errnum, message);
        CGI_PUTS(",\"ErrorDetails\":");
        json_send_qstring(msg_log_end());
    }
    CGI_PUTS(",\"NodeId\":");
    json_send_qstring(sx_hashfs_self_uuid(hashfs, &node_uuid)==OK ? node_uuid.string : "<UNKNOWN>");
    CGI_PUTS(",\"ErrorId\":");
    json_send_qstring(msg_get_id());
    CGI_PUTC('}');
}

void send_partial_error(const char *message, rc_ty rc) {
    char *reason = *msg_get_reason() ? strdup(msg_get_reason()) : NULL;
    msg_set_reason("%s: %s", message, reason ? reason : rc2str(rc));
    free(reason);
    send_error_helper(',', 500, msg_get_reason());
}

static sxi_hmac_sha1_ctx *hmac_ctx;
static sxi_md_ctx *body_ctx;
void send_error(int errnum, const char *message) {
    sxi_hmac_sha1_cleanup(&hmac_ctx);
    sxi_md_cleanup(&body_ctx);
    if(!message || !*message)
	message = http_err_str(errnum);

    if(!is_sky()) {
        print_html(errnum, "Error", errnum, message);
    } else {
	CGI_PRINTF("Status: %d\r\nContent-Type: application/json\r\n", errnum);
        if (verb == VERB_HEAD) {
            /* workaround for old curl: it would close (instead of reusing)
             * the connection if a HEAD doesn't have Content-Length/chunked
             * encoding. And then we run out of ports due to too many
             * TIME_WAIT connections */
            CGI_PUTS("Content-Length: 0\r\n\r\n");
        } else {
            CGI_PUTS("\r\n");
            send_error_helper('{',errnum,message);
        }
    }
}

void send_home(void) {
    print_html(0, SERVER_NAME, 0, NULL);
    sxi_hmac_sha1_cleanup(&hmac_ctx);
    sxi_md_cleanup(&body_ctx);
}

int is_http_10(void) {
    const char *proto = FCGX_GetParam("SERVER_PROTOCOL", envp);
    return strcmp(proto, "HTTP/1.0") == 0;
}

uint8_t user[AUTH_UID_LEN], rhmac[20];
sx_uid_t uid;
int64_t user_quota;
static sx_priv_t role;

static enum authed_t { AUTH_NOTAUTH, AUTH_BODYCHECK, AUTH_BODYCHECKING, AUTH_OK } authed;

int get_body_chunk(char *buf, int buflen) {
    int r = FCGX_GetStr(buf, buflen, fcgi_in);
    if(r>=0) {
	if(authed == AUTH_BODYCHECK)
	    authed = AUTH_BODYCHECKING;
	if(authed == AUTH_BODYCHECKING && !sxi_sha1_update(body_ctx, buf, r)) {
            WARN("digest update failed");
	    authed = AUTH_NOTAUTH;
	    return -1;
	}
    } else
	authed = AUTH_NOTAUTH;
    return r;
}

void auth_complete(void) {
    char content_hash[41];
    unsigned char d[20];
    unsigned int dlen = 20;

    if(authed == AUTH_OK)
	return;

    if(authed != AUTH_BODYCHECK && authed != AUTH_BODYCHECKING)
	goto auth_complete_fail;
    
    if(!sxi_sha1_final(body_ctx, d, NULL))
        quit_errmsg(500, "Failed to initialize crypto engine");

    bin2hex(d, sizeof(d), content_hash, sizeof(content_hash));
    content_hash[sizeof(content_hash)-1] = '\0';
    
    if(!sxi_hmac_sha1_update_str(hmac_ctx, content_hash))
        quit_errmsg(500, "Failed to initialize crypto engine");

    if(!sxi_hmac_sha1_final(hmac_ctx, d, &dlen))
        quit_errmsg(500, "Failed to initialize crypto engine");

    if(!hmac_compare(d, rhmac, sizeof(rhmac))) {
	authed = AUTH_OK;
	return;
    }

 auth_complete_fail:
    authed = AUTH_NOTAUTH;
}

int is_authed(void) {
    return (authed == AUTH_BODYCHECK || authed == AUTH_OK);
}

int is_sky(void) {
    const char *param = FCGX_GetParam("HTTP_AUTHORIZATION", envp);
    return (param && strlen(param) == 4 + 56 && !strncmp(param, "SKY ", 4));
}

void send_authreq(void) {
    CGI_PUTS("WWW-Authenticate: SKY realm=\"SXAUTH\"\r\n");
    quit_errmsg(401, "Invalid credentials");
}

static char *inplace_urldecode(char *s, char forbid, char dedup, int *has_forbidden, int plusdec) {
    enum { COPY, PCT } mode = COPY;
    char *src = s, *dst = s, c;
    int v;

    if(!s)
	return NULL;
    if (has_forbidden)
        *has_forbidden = 0;
    while(1) {
	c = *src;
	src++;
	switch(mode) {
	case COPY:
	    if(!c) {
		*dst = '\0';
		return s;
	    }
	    if(c == '%') {
		mode = PCT;
		break;
	    }
	    if(plusdec && c == '+')
		*dst = ' ';
	    else if(dst != src - 1)
		*dst = c;
	    dst++;
	    if(dedup && c == dedup) {
		while(*src == c)
		    src++;
	    }
	    break;
	case PCT:
	    v = hexcharval(c);
	    if(v<0)
		return NULL;
	    *dst = v<<4;
	    c = *src;
	    src++;
	    v = hexcharval(c);
	    if(v<0)
		return NULL;
	    *dst |= v;
	    if(!*dst || *dst == forbid) {
                if (has_forbidden)
                    *has_forbidden = 1;
		return NULL;
            }
	    dst++;
	    mode = COPY;
	    break;
	}
    }
}


#define MAX_ARGS 256
char *volume, *path, *args[MAX_ARGS];
unsigned int nargs;
verb_t verb;

int arg_num(const char *arg) {
    unsigned int i, len = strlen(arg);
    for(i=0; i<nargs; i++) {
	if(strncmp(args[i], arg, len))
	    continue;
	if(args[i][len] == '\0' || args[i][len] == '=')
	    return i;
    }
    return -1;
}

const char *get_arg(const char *arg) {
    const char *ret;
    int i = arg_num(arg);
    if(i<0)
	return NULL;
    ret = strchr(args[i], '=');
    if(ret) {
	ret++;
	if(!*ret)
	    ret = NULL;
    }
    return ret;
}

int get_arg_uint(const char *arg) {
    const char *str = get_arg(arg);
    if (!str)
        return -1;
    char *eon;
    int n = strtol(str, &eon, 10);
    if (*eon || n < 0)
        return -1;
    return n;
}

int arg_is(const char *arg, const char *ref) {
    const char *val = get_arg(arg);
    if(!val) return 0;
    return strcmp(val, ref) == 0;
}

/*
 * Nginx supports a Request line of at most 8192 bytes:
 * 8192 = max(VERB URI HTTP/1.1\n) =>
 * 8192 = max(VERB) + 1 + max(URI) + 10
 * max(VERB) = strlen(OPTIONS) = 7
 * max(URI) = 8174 
 */
static char reqbuf[8174];
void handle_request(worker_type_t wtype) {
    const char *param, *p_method, *p_uri;
    char *argp;
    unsigned int plen;
    int cluster_readonly = 0, s2sreq = 0;

    if(sx_hashfs_cluster_get_mode(hashfs, &cluster_readonly)) {
        CRIT("Failed to get cluster operating mode");
        quit_errmsg(500, "Internal error: failed to check cluster operating mode");
    }

    if(sx_hashfs_distcheck(hashfs) < 0) {
	CRIT("Failed to reload distribution");
	quit_errmsg(503, "Internal error: failed to load distribution");
    }

    if(sx_hashfs_is_orphan(hashfs))
	quit_errmsg(410, "This node is no longer a cluster member");

    msg_new_id();
    verb = VERB_UNSUP;
    p_method = FCGX_GetParam("REQUEST_METHOD", envp);
    if(p_method) {
	plen = strlen(p_method);
	switch(plen) {
	case 3:
	    if(!memcmp(p_method, "GET", 4))
		verb = VERB_GET;
	    else if(!memcmp(p_method, "PUT", 4))
		verb = VERB_PUT;
	    break;
	case 4:
	    if(!memcmp(p_method, "HEAD", 5))
		verb = VERB_HEAD;
	    else if(!memcmp(p_method, "POST", 5))
		verb = VERB_POST;
	    break;
	case 6:
	    if(!memcmp(p_method, "DELETE", 7))
		verb = VERB_DELETE;
	    break;
	case 7:
	    if(!memcmp(p_method, "OPTIONS", 8)) {
		CGI_PUTS("Allow: GET,HEAD,OPTIONS,PUT,DELETE\r\nContent-Length: 0\r\n\r\n");
		return;
	    }
	    break;
	}
    }
    if(verb == VERB_UNSUP)
	quit_errmsg(405, "Method Not Allowed");

    if(content_len()<0 || (verb != VERB_PUT && content_len()))
	quit_errmsg(400, "Invalid Content-Length: must be positive and method must be PUT");

    p_uri = param = FCGX_GetParam("REQUEST_URI", envp);
    if(!p_uri)
	quit_errmsg(400, "No URI provided");
    plen = strlen(p_uri);
    if(*p_uri != '/')
	quit_errmsg(400, "URI must start with /");
    if(plen > sizeof(reqbuf) - 1)
	quit_errmsg(414, "URL too long: request line must be <8k");

    do {
	param++;
	plen--;
    } while(*param == '/');

    if(!strncmp(param, ".s2s/", lenof(".s2s/"))) {
	param += lenof(".s2s/");
	plen -= lenof(".s2s/");
	while(*param == '/') {
	    param++;
	    plen--;
	}
	s2sreq = 1;
    }
    if(wtype == WORKER_S2S && !s2sreq)
	WARN("Misconfiguration detected. Please make sure your restricted-socket config option is properly set.");
    /* FIXME: we could detect the opposite kind of mismatch
     * at the cost of extra complications in the wtype definition
     * I prefer to privilege simplicity at this point */

    memcpy(reqbuf, param, plen+1);
    argp = memchr(reqbuf, '?', plen);
    nargs = 0;
    if(argp) {
	unsigned int argslen = plen - (argp - reqbuf);
	plen = argp - reqbuf;
	do {
	    *argp = '\0';
	    argp++;
	    argslen--;
	} while(*argp == '?');
	if(!argslen)
	    argp = NULL;
	else {
	    do {
		char *nextarg;
		if(nargs >= MAX_ARGS)
		    quit_errmsg(414, "Too many parameters");
		nextarg = memchr(argp, '&', argslen);
		if(nextarg) {
		    do {
			*nextarg = '\0';
			nextarg++;
		    } while(*nextarg == '&');
		}
		if(*argp) {
		    if(!(args[nargs] = inplace_urldecode(argp, 0, 0, NULL, 1)))
			quit_errmsg(400, "Invalid URL encoding");
		    if(sxi_utf8_validate_len(args[nargs]) < 0)
			quit_errmsg(400, "Parameters with invalid utf-8 encoding");
		    nargs++;
		}
		argslen -= nextarg - argp;
		argp = nextarg;
	    } while (argp);
	}
    }

    while(plen && reqbuf[plen-1] == '/') {
	plen--;
	reqbuf[plen] = '\0';
    }

    path = memchr(reqbuf, '/', plen);
    if(path) {
	do {
	    *path = '\0';
	    path ++;
	} while(*path == '/');
	if(!*path)
	    path = NULL;
    }
    volume = *reqbuf ? reqbuf : NULL;

    int forbidden = 0;
    if((volume && !inplace_urldecode(volume, '/', 0, &forbidden, 0)) || (path && !inplace_urldecode(path, '/', '/', &forbidden, 0))) {
        if (forbidden)
            quit_errmsg(400, "Volume or path with forbidden %2f or %00");
        else
            quit_errmsg(400, "Invalid URL encoding");
    }

    int vlen = volume ? sxi_utf8_validate_len(volume) : 0;
    int flen = path ? strlen(path) : 0;

    if (vlen < 0 || flen < 0)
       quit_errmsg(400, "URL with invalid utf-8 encoding");

    if (is_reserved()) {
        /* No UTF8/url-encoding used on reserved volumes, allow higher limit.
         * Otherwise we hit the 1024 limit with batch requests already */
        if (path && strlen(path) > SXLIMIT_MAX_FILENAME_LEN * 3) {
            msg_set_reason("Path too long: filename must be <%d bytes (%ld)",
                           SXLIMIT_MAX_FILENAME_LEN*3+ 1, strlen(path));
            quit_errmsg(414, msg_get_reason());
        }
    } else {
        if (flen > SXLIMIT_MAX_FILENAME_LEN) {
            msg_set_reason("Path too long: filename must be <%d bytes (%d)",
                           SXLIMIT_MAX_FILENAME_LEN + 1, flen);
            quit_errmsg(414, msg_get_reason());
        }
    }

    if (volume && strlen(volume) > SXLIMIT_MAX_VOLNAME_LEN) {
        msg_set_reason("Volume name too long: must be <= %d bytes", SXLIMIT_MAX_VOLNAME_LEN);
        quit_errmsg(414, msg_get_reason());
    }

    body_ctx = sxi_md_init();
    if (!body_ctx || !sxi_sha1_init(body_ctx))
	quit_errmsg(500, "Failed to initialize crypto engine");
    hmac_ctx = sxi_hmac_sha1_init();
    if (!hmac_ctx)
        quit_errmsg(503, "Cannot initialize crypto library");

    authed = AUTH_NOTAUTH;
    role = PRIV_NONE;


    /* Begin auth check */
    uint8_t buf[AUTHTOK_BIN_LEN], key[AUTH_KEY_LEN];
    unsigned int blen = sizeof(buf);
    time_t reqdate, now;

    param = FCGX_GetParam("HTTP_AUTHORIZATION", envp);
    if(!param || strlen(param) != lenof("SKY ") + AUTHTOK_ASCII_LEN || strncmp(param, "SKY ", 4)) {
	if(volume) {
	    send_authreq();
	    return;
	}
	quit_home();
    }

    if(sxi_b64_dec_core(param+4, buf, &blen) || blen != sizeof(buf)) {
	send_authreq();
	return;
    }

    memcpy(user, buf, sizeof(user));
    memcpy(rhmac, buf+20, sizeof(rhmac));

    if(sx_hashfs_get_user_info(hashfs, user, &uid, key, &role, NULL, &user_quota) != OK) /* no such user */ {
	DEBUG("No such user: %s", param+4);
	send_authreq();
	return;
    }
    DEBUG("Request from uid %lld", (long long)uid);
    if(cluster_readonly && (verb == VERB_PUT || verb == VERB_DELETE) && !has_priv(PRIV_CLUSTER) && !has_priv(PRIV_ADMIN))
        quit_errmsg(503, "Cluster is in read-only mode");

    if(s2sreq && !has_priv(PRIV_CLUSTER)) {
	send_authreq();
	return;
    }

    if(!sxi_hmac_sha1_init_ex(hmac_ctx, key, sizeof(key))) {
	WARN("hmac_init failed");
	quit_errmsg(500, "Failed to initialize crypto engine");
    }

    if(!sxi_hmac_sha1_update_str(hmac_ctx, p_method))
	quit_errmsg(500, "Crypto error authenticating the request");

    if(!sxi_hmac_sha1_update_str(hmac_ctx, p_uri+1))
	quit_errmsg(500, "Crypto error authenticating the request");

    param = FCGX_GetParam("HTTP_DATE", envp);
    if(!param)
	quit_errmsg(400, "Missing Date: header");
    if(httpdate_to_time_t(param, &reqdate))
	quit_errmsg(400, "Date header in wrong format");
    now = time(NULL);
    if(reqdate < now - MAX_CLOCK_DRIFT * 60 || reqdate > now + MAX_CLOCK_DRIFT * 60) {
	CGI_PUTS("WWW-Authenticate: SKY realm=\"SXCLOCK\"\r\n");
	quit_errmsg(401, "Client clock drifted more than "STRIFY(MAX_CLOCK_DRIFT)" minutes");
    }
    if(!sxi_hmac_sha1_update_str(hmac_ctx, param))
	quit_errmsg(500, "Crypto error authenticating the request");

    if(!content_len()) {
	/* If no body is present, complete authentication now */
	uint8_t chmac[20];
	unsigned int chmac_len = 20;
	if(!sxi_hmac_sha1_update_str(hmac_ctx, "da39a3ee5e6b4b0d3255bfef95601890afd80709"))
	    quit_errmsg(500, "Crypto error authenticating the request");
	if(!sxi_hmac_sha1_final(hmac_ctx, chmac, &chmac_len))
	    quit_errmsg(500, "Crypto error authenticating the request");
	if(!hmac_compare(chmac, rhmac, sizeof(rhmac))) {
	    authed = AUTH_OK;
	} else {
	    /* WARN("auth mismatch"); */
	    send_authreq();
	    return;
	}
    } else /* Otherwise set it as pending */
	authed = AUTH_BODYCHECK;

    if(has_priv(PRIV_CLUSTER) && sx_hashfs_uses_secure_proto(hashfs) != is_https() &&
       !sx_storage_is_bare(hashfs)) {
        /* programmed nodes: must obey cluster SSL mode
         * unprogrammed nodes: can use SSL instead of non-SSL,
         *  it is the cluster's responsibility to initiate programming via SSL,
         *  as the unprogrammed node would accept both         *
         * */
        WARN("hashfs use-ssl: %d, https: %d, is_bare: %d",
              sx_hashfs_uses_secure_proto(hashfs), is_https(),
              sx_storage_is_bare(hashfs));
	quit_errmsg(403, sx_hashfs_uses_secure_proto(hashfs) ? "Cluster operations require SECURE mode" : "Cluster operations require INSECURE mode");
    }

    if(!volume)
	cluster_ops();
    else if(!strncmp(volume, ".upgrade", lenof(".upgrade")))
        upgrade_ops();
    else if(!path)
	volume_ops();
    else
	file_ops();

    if(authed == AUTH_BODYCHECKING)
	DEBUG("Bad request signature");

    sxi_hmac_sha1_cleanup(&hmac_ctx);
    sxi_md_cleanup(&body_ctx);
}

int64_t content_len(void) {
    const char *clen = FCGX_GetParam("CONTENT_LENGTH", envp);
    if(!clen)
	return 0;

    return atoll(clen);
}

int get_priv(int volume_priv) {
    sx_priv_t mypriv;
    if(role < PRIV_ADMIN && volume_priv) {
	/* Volume specific check, requires lookup */
	if(sx_hashfs_get_access(hashfs, user, volume, &mypriv) != OK) {
	    WARN("Unable to lookup volume access for uid %llu", (long long int )uid);
	    return 0;
	}
    } else {
	/* Non volume check, use the base role */
        mypriv = 0;
        if (role >= PRIV_ADMIN)
            mypriv |= PRIV_READ | PRIV_WRITE | PRIV_MANAGER | PRIV_OWNER | PRIV_ADMIN;/* admin has all below */
        if (role >= PRIV_CLUSTER)
            mypriv |= PRIV_CLUSTER;
    }
    return mypriv;
}

int has_priv(sx_priv_t reqpriv) {
    return get_priv(!(reqpriv & ~(PRIV_READ | PRIV_WRITE | PRIV_MANAGER | PRIV_OWNER))) & reqpriv;
}

int is_reserved(void) {
    return (volume && *volume == '.');
}

int volume_exists(void) {
    const sx_hashfs_volume_t *vol;
    return (sx_hashfs_volume_by_name(hashfs, volume, &vol) == OK);
}

void json_send_qstring(const char *s) {
    const char *hex_digits = "0123456789abcdef", *begin = s;
    unsigned int len = 0;
    char escaped[6] = { '\\', 'u', '0', '0', 'x', 'x' };

    CGI_PUTC('"');
    while(1) {
	unsigned char c = begin[len];
	/* flush on end of string and escape quotation mark, reverse solidus,
	 * and the control characters (U+0000 through U+001F) */
	if(c < ' ' || c == '"' || c== '\\') {
	    if(len) /* flush */
		CGI_PUTD(begin, len);
	    begin = &begin[len+1];
	    len = 0;
	    if(!c) {
		CGI_PUTC('"');
		return;
	    }
	    escaped[4] = hex_digits[c >> 4];
	    escaped[5] = hex_digits[c & 0xf];
	    CGI_PUTD(escaped, 6);
	} else
	    len++;
    }
}

void send_httpdate(time_t t) {
    const char *month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    const char *wkday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    char buf[32];

    struct tm *ts = gmtime(&t);
    if(!ts)
	return;

    sprintf(buf, "%s, %02u %s %04u %02u:%02u:%02u GMT", wkday[ts->tm_wday], ts->tm_mday, month[ts->tm_mon], ts->tm_year + 1900, ts->tm_hour, ts->tm_min, ts->tm_sec);
    CGI_PUTS(buf);
}


void send_qstring_hash(const sx_hash_t *h) {
    char buf[sizeof(sx_hash_t) * 2 + 1];

    bin2hex(h->b, sizeof(h->b), buf, sizeof(buf));
    CGI_PUTC('"');
    CGI_PUTD(buf, sizeof(buf) - 1);
    CGI_PUTC('"');
}


int httpdate_to_time_t(const char *d, time_t *t) {
    if(!t || !d)
	return -1;

    d = strptimegm(d, "%a, %d %b %Y %H:%M:%S GMT", t);
    if(!d || *d)
	return -1;

    return 0;
}

void send_keepalive(void) {
    time_t now = time(NULL);
    if(now - last_flush > MAX_KEEPALIVE_INTERVAL) {
	last_flush = now;
	CGI_PUTC(' ');
	FCGX_FFlush(fcgi_out);
    }
}

void send_nodes(const sx_nodelist_t *nodes) {
    unsigned int i, comma = 0, nnodes;
    CGI_PUTC('[');
    for(i=0, nnodes = sx_nodelist_count(nodes); i<nnodes; i++) {
	const sx_node_t *node = sx_nodelist_get(nodes, i);

	if(comma)
	    CGI_PUTC(',');
	else
	    comma |= 1;

	if(has_priv(PRIV_CLUSTER))
	    json_send_qstring(sx_node_internal_addr(node));
	else
	    json_send_qstring(sx_node_addr(node));
    }
    CGI_PUTC(']');
}

void send_nodes_randomised(const sx_nodelist_t *nodes) {
    unsigned int nodeno, pos, comma = 0, nnodes;
    unsigned int list[256];

    CGI_PUTC('[');

    nnodes = sx_nodelist_count(nodes);
    for(nodeno=0, pos=0; nodeno<nnodes; nodeno++) {
	unsigned int i, j, t;

	list[pos++] = nodeno;
	if(pos != sizeof(list)/sizeof(list[0]) && nodeno != nnodes - 1)
	    continue;

	for(i=pos-1; i>=1; i--) {
	    j = sxi_rand() % (i+1);
	    if(i == j)
		continue;
	    t = list[i];
	    list[i] = list[j];
	    list[j] = t;
	}

	for(i=0; i<pos; i++) {
	    const sx_node_t *node = sx_nodelist_get(nodes, list[i]);

	    if(comma)
		CGI_PUTC(',');
	    else
		comma |= 1;

	    if(has_priv(PRIV_CLUSTER))
		json_send_qstring(sx_node_internal_addr(node));
	    else
		json_send_qstring(sx_node_addr(node));
	}

	pos = 0;
    }
    CGI_PUTC(']');
}

void send_job_info(job_t job) {
    sx_uuid_t node;
    rc_ty s = sx_hashfs_self_uuid(hashfs, &node);

    if(s)
	quit_errmsg(rc2http(s), msg_get_reason());
    CGI_PRINTF("Content-Type: application/json\r\n\r\n{\"requestId\":\"%s:", node.string);
    CGI_PUTLL(job);
    CGI_PRINTF("\",\"minPollInterval\":100,\"maxPollInterval\":%d}",JOBMGR_DELAY_MIN*1000);
}

int is_https(void) {
    const char *proto = FCGX_GetParam("HTTPS", envp);
    return (proto && !strcasecmp(proto, "on"));
}

int is_object_fresh(const sx_hash_t *etag, char type, unsigned int last_modified) {
    char tagbuf[3 + sizeof(*etag) * 2 + 1];
    const char *cond;
    int is_cached = 0, skip_modsince = 0;

    CGI_PUTS("Cache-control: public, must-revalidate\r\n");

    if(etag) {
	tagbuf[0] = '"';
	tagbuf[1] = type;
	bin2hex(etag, sizeof(*etag), tagbuf + 2, sizeof(tagbuf) - 2);
	tagbuf[sizeof(tagbuf) - 2] = '"';
	tagbuf[sizeof(tagbuf) - 1] = '\0';
	CGI_PRINTF("ETag: %s\r\n", tagbuf);
    }

    if(last_modified != NO_LAST_MODIFIED) {
	CGI_PUTS("Last-Modified: ");
	send_httpdate(last_modified);
	CGI_PUTS("\r\n");
    } else
	skip_modsince = 1;

    if(etag && (cond = FCGX_GetParam("HTTP_IF_NONE_MATCH", envp))) {
	if(!strcmp(tagbuf, cond))
	    is_cached = 1;
	else
	    skip_modsince = 1;
    }

    if(!skip_modsince && (cond = FCGX_GetParam("HTTP_IF_MODIFIED_SINCE", envp))) {
	time_t modsince;
	if(!httpdate_to_time_t(cond, &modsince) && modsince >= last_modified)
	    is_cached = 1;
	else
	    is_cached = 0;
    }

    if(is_cached) {
	CGI_PUTS("Status: 304\r\n\r\n");
	return 1;
    }

    return 0;
}
