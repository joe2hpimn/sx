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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <termios.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <errno.h>

#include "sx.h"

/* logger prefixes with aes256: already */
#define NOTICE(...)	{ sxc_filter_msg(handle, SX_LOG_NOTICE, __VA_ARGS__); }
#define WARN(...)	{ sxc_filter_msg(handle, SX_LOG_WARNING, __VA_ARGS__); }
#define ERROR(...)	{ sxc_filter_msg(handle, SX_LOG_ERR, __VA_ARGS__); }

#define FILTER_BLOCK_SIZE 16384
struct aes256_ctx {
    EVP_CIPHER_CTX ectx, dctx;
    unsigned char key[32], iv[16];
    unsigned int inbytes, blkbytes, data_in, data_out_left, data_end;
    unsigned char in[FILTER_BLOCK_SIZE + AES_BLOCK_SIZE];
    unsigned char blk[FILTER_BLOCK_SIZE + AES_BLOCK_SIZE];
    char *new_keyfile;
    int decrypt_err;
};

#define KEY_ITERATIONS 1024000

const char *skysalt = "sky14bl3"; /* salt should be 8 bytes */

static int aes256_init(const sxf_handle_t *handle, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static int getpassword(const sxf_handle_t *handle, int repeat, sxf_mode_t mode, unsigned char *key, unsigned char *iv)
{
	char pass1[1024], pass2[1024];
	struct termios told, tnew;
	SHA256_CTX sctx;
	unsigned char digest[SHA256_DIGEST_LENGTH];

    tcgetattr(0, &told);
    tnew = told;
    tnew.c_lflag &= ~ECHO;
    tnew.c_lflag |= ECHONL;
    if(tcsetattr(0, TCSANOW, &tnew)) {
	ERROR("tcsetattr failed");
	return -1;
    }

    printf("[aes256]: Enter %s password: ", mode == SXF_MODE_UPLOAD ? "encryption" : "decryption");
    mlock(pass1, sizeof(pass1));
    fgets(pass1, sizeof(pass1), stdin);
    pass1[strlen(pass1) - 1] = 0;
    if(strlen(pass1) < 8) {
	tcsetattr(0, TCSANOW, &told);
	memset(pass1, 0, sizeof(pass1));
	munlock(pass1, sizeof(pass1));
	printf("[aes256]: ERROR: Password must be at least 8 characters long\n");
	return 1;
    }

    if(repeat) {
	printf("[aes256]: Re-enter encryption password: ");
	mlock(pass2, sizeof(pass2));
	fgets(pass2, sizeof(pass2), stdin);
	pass2[strlen(pass2) - 1] = 0;
	if(strcmp(pass1, pass2)) {
	    tcsetattr(0, TCSANOW, &told);
	    memset(pass2, 0, sizeof(pass2));
	    munlock(pass2, sizeof(pass2));
	    printf("[aes256]: ERROR: Passwords don't match\n");
	    return 1;
	}
	memset(pass2, 0, sizeof(pass2));
	munlock(pass2, sizeof(pass2));
    }

    if(tcsetattr(0, TCSANOW, &told)) {
	memset(pass1, 0, sizeof(pass1));
	munlock(pass1, sizeof(pass1));
	ERROR("tcsetattr failed");
	return -1;
    }

    if(!SHA256_Init(&sctx) ||
       !SHA256_Update(&sctx, skysalt, strlen(skysalt)) ||
       !SHA256_Update(&sctx, pass1, strlen(pass1)) ||
       !SHA256_Final(digest, &sctx)) {
	memset(pass1, 0, sizeof(pass1));
	munlock(pass1, sizeof(pass1));
	ERROR("Can't create encryption key");
	return -1;
    }
    memset(pass1, 0, sizeof(pass1));
    munlock(pass1, sizeof(pass1));

    if(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), (unsigned char *) skysalt, digest, SHA256_DIGEST_LENGTH, KEY_ITERATIONS, key, iv) != 32) {
	ERROR("Invalid resulting key size");
	return -1;
    }

    return 0;
}

char *keyfp(const sxf_handle_t *handle, const unsigned char *key, const unsigned char *iv, char *current_fp)
{
	unsigned char salt[8], digest[SHA256_DIGEST_LENGTH];
	unsigned char current_salt[8], current_digest[SHA256_DIGEST_LENGTH];
	int i;
	SHA256_CTX sctx;
	char *fp, *pt;

    if(current_fp) {
	pt = current_fp;
	for(i = 0; i < sizeof(current_salt); i++) {
	    sscanf(pt, "%2hhx", &current_salt[i]);
	    pt += 2;
	}
	memcpy(salt, current_salt, sizeof(salt));
	for(i = 0; i < sizeof(current_digest); i++) {
	    sscanf(pt, "%2hhx", &current_digest[i]);
	    pt += 2;
	}
    } else {
	RAND_pseudo_bytes(salt, sizeof(salt));
    }
    memset(digest, 0, sizeof(digest));
    memcpy(digest, iv, 16);
    for(i = 0; i < KEY_ITERATIONS; i++) {
	if(!SHA256_Init(&sctx) ||
	   !SHA256_Update(&sctx, digest, sizeof(digest)) ||
	   !SHA256_Update(&sctx, key, 32) ||
	   !SHA256_Update(&sctx, salt, sizeof(salt)) ||
	   !SHA256_Final(digest, &sctx)) {
	    ERROR("Can't create key fingerprint");
	    return NULL;
	}
    }

    if(current_fp) {
	if(memcmp(digest, current_digest, sizeof(digest))) {
	    ERROR("Invalid password");
	    return NULL;
	}
	return current_fp;

    } else {
	/* fp:SaltDigest */
	fp = malloc(3 + 2 * sizeof(salt) + 2 * sizeof(digest) + 1);
	if(!fp) {
	    ERROR("OOM");
	    return NULL;
	}
	strcpy(fp, "fp:");
	pt = &fp[3];
	for(i = 0; i < sizeof(salt); i++) {
	    sprintf(pt, "%02x", salt[i]);
	    pt += 2;
	}
	for(i = 0; i < sizeof(digest); i++) {
	    sprintf(pt, "%02x", digest[i]);
	    pt += 2;
	}
	*pt = 0;
	return fp;
    }

    return NULL;
}

static int aes256_configure(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len)
{
	unsigned char key[32], iv[16];
	char *keyfile;
	int fd;

    if(cfgstr) {
	if(strcmp(cfgstr, "paranoid")) {
	    ERROR("Invalid option");
	    return -1;
	}
	*cfgdata = strdup(cfgstr);
	if(!*cfgdata) {
	    ERROR("OOM");
	    return -1;
	}
	*cfgdata_len = strlen(cfgstr);
	return 0;
    }

    if(cfgdir) {
	int ret;
	while((ret = getpassword(handle, 1, SXF_MODE_UPLOAD, key, iv)) == 1);
	if(ret)
	    return -1;

	keyfile = malloc(strlen(cfgdir) + 5);
	if(!keyfile) {
	    ERROR("OOM");
	    return -1;
	}
	sprintf(keyfile, "%s/key", cfgdir);

	fd = open(keyfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if(fd == -1) {
	    ERROR("Can't open file %s for writing", keyfile);
	    free(keyfile);
	    return -1;
	}
	if(write(fd, key, sizeof(key)) != sizeof(key) || write(fd, iv, sizeof(iv)) != sizeof(iv)) {
	    ERROR("Can't write key data to file %s", keyfile);
	    free(keyfile);
	    close(fd);
	    return -1;
	}
	free(keyfile);
	close(fd);

	*cfgdata = keyfp(handle, key, iv, NULL);
	if(!*cfgdata)
	    return -1;
	*cfgdata_len = strlen(*cfgdata);
    }

    return 0;
}

static int aes256_shutdown(const sxf_handle_t *handle, void *ctx)
{
    if(ctx) {
	memset(ctx, 0, sizeof(struct aes256_ctx));
	free(ctx);
    }
    return 0;
}

static int aes256_data_prepare(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode)
{
	struct aes256_ctx *actx;
	int keyread = 0, ret;
	unsigned char key[32], iv[16];
	char *keyfile = NULL, fp[81];
	int fd, have_fp = 0;

    mlock(key, sizeof(key));
    mlock(iv, sizeof(iv));
    if(cfgdata) {
	if(!memcmp(cfgdata, "paranoid", strlen("paranoid"))) {
	    printf("[aes256]: File '%s' will be %s with provided password\n", filename, mode == SXF_MODE_UPLOAD ? "encrypted" : "decrypted");
	    while((ret = getpassword(handle, mode == SXF_MODE_UPLOAD ? 1 : 0, mode, key, iv)) == 1);
	    if(ret)
		return -1;
	    keyread = 1;
	} else if(cfgdata_len == 83 && !memcmp(cfgdata, "fp:", 3)) {
	    memcpy(fp, &((unsigned char *)cfgdata)[3], 80);
	    fp[80] = 0;
	    have_fp = 1;
	} else {
	    ERROR("Invalid configuration data");
	    return -1;
	}
    }

    if(!keyread) {
	keyfile = malloc(strlen(cfgdir) + 5);
	if(!keyfile) {
	    ERROR("OOM");
	    return -1;
	}
	sprintf(keyfile, "%s/key", cfgdir);
	fd = open(keyfile, O_RDONLY);
	if(fd == -1) {
	    if(errno == ENOENT) {
		NOTICE("The key file doesn't exist and will be created now");
	    } else {
		WARN("Can't open key file %s -- attempt to recreate it", keyfile);
	    }
	} else {
	    if(read(fd, key, sizeof(key)) != sizeof(key) || read(fd, iv, sizeof(iv)) != sizeof(iv))
		WARN("Can't read key file %s -- new key file will be created", keyfile)
	    else
		keyread = 1;
	    close(fd);
	}
	if(!keyread) {
	    while((ret = getpassword(handle, 0, mode, key, iv)) == 1);
	    if(ret) {
		free(keyfile);
		return -1;
	    }
	    if(have_fp && !keyfp(handle, key, iv, fp)) {
		free(keyfile);
		return -1;
	    }
	    fd = open(keyfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	    if(fd == -1) {
		WARN("Can't open file %s for writing -- continuing without key file", keyfile);
	    } else {
		if(write(fd, key, sizeof(key)) != sizeof(key) || write(fd, iv, sizeof(iv)) != sizeof(iv))
		    WARN("Can't write key data to file %s -- continuing without key file", keyfile);
		close(fd);
	    }
	}
    }

    actx = calloc(1, sizeof(struct aes256_ctx));
    if(!actx) {
	ERROR("OOM");
        free(keyfile);
	return -1;
    }
    actx->new_keyfile = keyfile;
    mlock(actx->key, sizeof(actx->key));
    mlock(actx->iv, sizeof(actx->iv));
    memcpy(actx->key, key, sizeof(actx->key));
    memcpy(actx->iv, iv, sizeof(actx->iv));
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    munlock(key, sizeof(key));
    munlock(iv, sizeof(iv));

    if(mode == SXF_MODE_UPLOAD) {
	mlock(&actx->ectx, sizeof(actx->ectx));
	EVP_CIPHER_CTX_init(&actx->ectx);
	if(EVP_EncryptInit_ex(&actx->ectx, EVP_aes_256_cbc(), NULL, actx->key, actx->iv) != 1) {
	    ERROR("Can't initialize encryption context");
	    free(keyfile);
	    free(actx);
	    return -1;
	}
    } else {
	mlock(&actx->dctx, sizeof(actx->dctx));
	EVP_CIPHER_CTX_init(&actx->dctx);
	if(EVP_DecryptInit_ex(&actx->dctx, EVP_aes_256_cbc(), NULL, actx->key, actx->iv) != 1) {
	    ERROR("Can't initialize decryption context");
	    free(keyfile);
	    free(actx);
	    return -1;
	}
    }

    *ctx = actx;
    return 0;
}

static ssize_t aes256_data_process(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action)
{
	struct aes256_ctx *actx = ctx;
	unsigned int bytes;
	unsigned int bsize = mode == SXF_MODE_UPLOAD ? FILTER_BLOCK_SIZE : FILTER_BLOCK_SIZE + AES_BLOCK_SIZE;

    if(*action == SXF_ACTION_REPEAT && actx->data_out_left) {
	if(actx->data_out_left > outsize) {
	    memcpy(out, &actx->blk[actx->blkbytes - actx->data_out_left], outsize);
	    actx->data_out_left -= outsize;
	    return outsize;
	} else {
		unsigned int data_out = actx->data_out_left;

	    memcpy(out, &actx->blk[actx->blkbytes - actx->data_out_left], actx->data_out_left);
	    actx->data_out_left = 0;
	    actx->blkbytes = 0;
            if(actx->data_in == insize) {
		actx->data_in = 0;
		if(!actx->data_end)
		    *action = SXF_ACTION_NORMAL;
		else {
		    *action = SXF_ACTION_DATA_END;
		}
	    }
	    return data_out;
	}
    }

    if(*action == SXF_ACTION_DATA_END)
	actx->data_end = 1;

    do {
	if(insize - actx->data_in >= bsize - actx->inbytes) {
	    bytes = bsize - actx->inbytes;
	    memcpy(&actx->in[actx->inbytes], (unsigned char *) in + actx->data_in, bytes);
	    actx->data_in += bytes;
	    actx->inbytes += bytes;
	} else {
	    bytes = insize - actx->data_in;
	    memcpy(&actx->in[actx->inbytes], (unsigned char *) in + actx->data_in, bytes);
	    actx->data_in += bytes;
	    actx->inbytes += bytes;
	}

	if(actx->inbytes == bsize || (actx->inbytes && (*action == SXF_ACTION_DATA_END || actx->data_end))) {
		int final;

	    if(mode == SXF_MODE_UPLOAD) {
		if(!EVP_EncryptInit_ex(&actx->ectx, NULL, NULL, NULL, NULL)) {
		    ERROR("EVP_EncryptInit_ex failed");
		    return -1;
		}
		if(!EVP_EncryptUpdate(&actx->ectx, actx->blk, (int *) &actx->blkbytes, actx->in, actx->inbytes)) {
		    ERROR("EVP_EncryptUpdate failed");
		    return -1;
		}
		if(!EVP_EncryptFinal_ex(&actx->ectx, actx->blk + actx->blkbytes, &final)) {
		    ERROR("EVP_EncryptFinal_ex failed");
		    return -1;
		}
	    } else {
		if(!EVP_DecryptInit_ex(&actx->dctx, NULL, NULL, NULL, NULL)) {
		    ERROR("EVP_DecryptInit_ex failed");
		    return -1;
		}
		if(!EVP_DecryptUpdate(&actx->dctx, actx->blk, (int *) &actx->blkbytes, actx->in, actx->inbytes)) {
		    ERROR("EVP_DecryptUpdate failed");
		    return -1;
		}
		if(!EVP_DecryptFinal_ex(&actx->dctx, actx->blk + actx->blkbytes, &final)) {
		    ERROR("EVP_DecryptFinal_ex failed (Invalid password/key file or broken data)");
		    actx->decrypt_err = 1;
		    return -1;
		}
	    }
	    actx->blkbytes += final;
	    actx->inbytes = 0;

	    if(actx->blkbytes > outsize) {
		memcpy(out, actx->blk, outsize);
		actx->data_out_left = actx->blkbytes - outsize;
		*action = SXF_ACTION_REPEAT;
		return outsize;
	    } else {
		memcpy(out, actx->blk, actx->blkbytes);
	    }

	    final = actx->blkbytes;
	    actx->blkbytes = 0;

	    if(actx->data_in == insize) {
		if(!actx->data_end)
		    *action = SXF_ACTION_NORMAL;
		else {
		    *action = SXF_ACTION_DATA_END;
		}
		actx->data_in = 0;
	    } else {
		*action = SXF_ACTION_REPEAT;
	    }

	    return final;
	} else { /* need more input data */
	    actx->data_in = 0;
	    *action = SXF_ACTION_NORMAL;
	    return 0;
	}

    } while(actx->data_in != insize);

    return -1;
}

static int aes256_data_finish(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode)
{
	struct aes256_ctx *actx = *ctx;

    if(actx) {
	if(mode == SXF_MODE_UPLOAD) {
	    EVP_CIPHER_CTX_cleanup(&actx->ectx);
	    memset(&actx->ectx, 0, sizeof(actx->ectx));
	    munlock(&actx->ectx, sizeof(actx->ectx));
	} else {
	    EVP_CIPHER_CTX_cleanup(&actx->dctx);
	    memset(&actx->dctx, 0, sizeof(actx->dctx));
	    munlock(&actx->dctx, sizeof(actx->dctx));
	}
	if(actx->decrypt_err && actx->new_keyfile)
	    unlink(actx->new_keyfile);
	free(actx->new_keyfile);
	memset(*ctx, 0, sizeof(struct aes256_ctx));
	munlock(actx->key, sizeof(actx->key));
	munlock(actx->iv, sizeof(actx->iv));
	free(*ctx);
	*ctx = NULL;
    }
    return 0;
}

sxc_filter_t sxc_filter={
/* int abi_version */		    SXF_ABI_VERSION,
/* const char *shortname */	    "aes256",
/* const char *fullname */	    "Encrypt data using AES-256 in CBC mode.",
/* const char *summary */	    "The filter automatically encrypts and decrypts all data using OpenSSL's AES-256 in CBC mode.",
/* const char *options */	    "paranoid (don't use key files)",
/* const char *uuid */		    "1532eefd-3f59-46c7-82e6-0b4c6422f5b8",
/* sxf_type_t type */		    SXF_TYPE_CRYPT,
/* int version[2] */		    {1, 1},
/* int (*init)(const sxf_handle_t *handle, void **ctx) */	    aes256_init,
/* int (*shutdown)(const sxf_handle_t *handle, void *ctx) */    aes256_shutdown,
/* int (*parse_cfgstr)(const char *cfgstr, void **cfgdata, unsigned int *cfgdata_len) */
/* int (*configure)(const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len) */
				    aes256_configure,
/* int (*data_prepare)(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode) */
				    aes256_data_prepare,
/* ssize_t (*data_process)(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action) */
				    aes256_data_process,
/* int (*data_finish)(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode) */
				    aes256_data_finish,
/* int (*file_process)(const sxf_handle_t *handle, void *ctx, const char *filename, sxc_metalist_t **metalist, sxc_meta_t *meta, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode) */
				    NULL,
/* internal */
/* const char *tname; */	    NULL
};

