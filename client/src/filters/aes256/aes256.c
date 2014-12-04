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
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <errno.h>

#include "libsx/src/misc.h"
#include "sx.h"
#include "crypt_blowfish.h"

/* logger prefixes with aes256: already */
#define NOTICE(...)	{ sxc_filter_msg(handle, SX_LOG_NOTICE, __VA_ARGS__); }
#define WARN(...)	{ sxc_filter_msg(handle, SX_LOG_WARNING, __VA_ARGS__); }
#define ERROR(...)	{ sxc_filter_msg(handle, SX_LOG_ERR, __VA_ARGS__); }

#define FILTER_BLOCK_SIZE 16384
#define BCRYPT_ITERATIONS_LOG2 14
#define KEY_SIZE SHA512_DIGEST_LENGTH
#define IV_SIZE 16
#define MAC_SIZE 32
#define SALT_SIZE 16
#define FP_SIZE (SALT_SIZE + KEY_SIZE)

#ifdef HMAC_UPDATE_RETURNS_INT
#define hmac_init_ex HMAC_Init_ex
#define hmac_update HMAC_Update
#define hmac_final HMAC_Final
#else
#define hmac_init_ex(a, b, c, d, e) (HMAC_Init_ex((a), (b), (c), (d), (e)), 1)
#define hmac_update(a, b, c) (HMAC_Update((a), (b), (c)), 1)
#define hmac_final(a, b, c) (HMAC_Final((a), (b), (c)), 1)
#endif

struct aes256_ctx {
    EVP_CIPHER_CTX ectx, dctx;
    HMAC_CTX ivhash;
    HMAC_CTX hmac;
    unsigned char key[KEY_SIZE], ivmac[EVP_MAX_MD_SIZE];
    unsigned int inbytes, blkbytes, data_in, data_out_left, data_end;
    unsigned char in[IV_SIZE + FILTER_BLOCK_SIZE + AES_BLOCK_SIZE + MAC_SIZE];
    unsigned char blk[IV_SIZE + FILTER_BLOCK_SIZE + AES_BLOCK_SIZE + MAC_SIZE];
    char *keyfile;
    int decrypt_err;
};


static int aes256_init(const sxf_handle_t *handle, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static int derive_key(const sxf_handle_t *handle, const char *pass, const unsigned char *salt, unsigned salt_size, unsigned char *out, unsigned out_size)
{
    char keybuf[61], settingbuf[30];
    const char *genkey, *setting;
    EVP_MD_CTX ctx;
    int ret;

    setting = _crypt_gensalt_blowfish_rn("$2b$", BCRYPT_ITERATIONS_LOG2, (const char*)salt, salt_size, settingbuf, sizeof(settingbuf));
    if (!setting) {
        ERROR("crypt_gensalt_blowfish_rn failed");
        return -1;
    }
    genkey = _crypt_blowfish_rn(pass, setting, keybuf, sizeof(keybuf));
    if (!genkey) {
        ERROR("crypt_blowfish_rn failed");
        return -1;
    }
    /* crypt returns a string containing the setting, the salt and the hashed
     * password, hash it once more to avoid accidentally using the salt as a key
     * */
    EVP_MD_CTX_init(&ctx);
    ret = -1;
    do {
        unsigned int len;
        if (EVP_DigestInit_ex(&ctx, EVP_sha512(), NULL) != 1) {
            ERROR("EVP_DigestInit_ex failed");
            break;
        }
        if (EVP_DigestUpdate(&ctx, genkey, strlen(genkey)) != 1) {
            ERROR("EVP_DigestUpdate failed");
            break;
        }
        if (EVP_DigestFinal_ex(&ctx, out, &len) != 1) {
            ERROR("EVP_DigestFinal_ex failed");
            break;
        }
        if (len != out_size) {
            ERROR("Bad digest size: %d bytes", len);
            break;
        }
        ret = 0;
    } while(0);
    EVP_MD_CTX_cleanup(&ctx);
    return ret;
}

static int getpassword(const sxf_handle_t *handle, int repeat, sxf_mode_t mode, unsigned char *key, const unsigned char *salt)
{
    char pass1[1024], pass2[1024], prompt[64];
    int ret;

    snprintf(prompt, sizeof(prompt), "[aes256]: Enter %s password: ", mode == SXF_MODE_UPLOAD ? "encryption" : "decryption");
    mlock(pass1, sizeof(pass1));
    if(sxc_filter_get_input(handle, SXC_INPUT_SENSITIVE, prompt, NULL, pass1, sizeof(pass1))) {
	munlock(pass1, sizeof(pass1));
	printf("[aes256]: Can't obtain password\n");
	return -1;
    }

    if(strlen(pass1) < 8) {
	memset(pass1, 0, sizeof(pass1));
	munlock(pass1, sizeof(pass1));
	printf("[aes256]: ERROR: Password must be at least 8 characters long\n");
	return 1;
    }

    if(repeat) {
	mlock(pass2, sizeof(pass2));
	if(sxc_filter_get_input(handle, SXC_INPUT_SENSITIVE, "[aes256]: Re-enter encryption password: ", NULL, pass2, sizeof(pass2))) {
	    memset(pass1, 0, sizeof(pass1));
	    munlock(pass1, sizeof(pass1));
	    munlock(pass2, sizeof(pass2));
	    printf("[aes256]: Can't obtain password\n");
	    return -1;
	}
	if(strcmp(pass1, pass2)) {
	    memset(pass1, 0, sizeof(pass1));
	    munlock(pass1, sizeof(pass1));
	    memset(pass2, 0, sizeof(pass2));
	    munlock(pass2, sizeof(pass2));
	    printf("[aes256]: ERROR: Passwords don't match\n");
	    return 1;
	}
	memset(pass2, 0, sizeof(pass2));
	munlock(pass2, sizeof(pass2));
    }

    ret = derive_key(handle, pass1, salt, SALT_SIZE, key, KEY_SIZE);
    memset(pass1, 0, sizeof(pass1));
    munlock(pass1, sizeof(pass1));
    return ret;
}

static int keyfp(const sxf_handle_t *handle, const unsigned char *key, const unsigned char *current_fp, unsigned char *new_fp)
{
    unsigned char salt[SALT_SIZE], tmp[SHA256_DIGEST_LENGTH], digest[KEY_SIZE];
    unsigned char current_salt[SALT_SIZE], current_digest[KEY_SIZE];
    char keyfphex[SHA256_DIGEST_LENGTH*2+1];
    SHA256_CTX sctx;

    if(current_fp) {
	memcpy(current_salt, current_fp, SALT_SIZE);
	memcpy(salt, current_salt, sizeof(salt));
	memcpy(current_digest, current_fp + SALT_SIZE, KEY_SIZE);
    } else {
	RAND_pseudo_bytes(salt, sizeof(salt));
    }
    if(!SHA256_Init(&sctx) ||
       !SHA256_Update(&sctx, key, KEY_SIZE) ||
       !SHA256_Final(tmp, &sctx)) {
        ERROR("Can't create key fingerprint (sha256)");
        return -1;
    }
    sxi_bin2hex(tmp, sizeof(tmp), keyfphex);
    if (derive_key(handle, keyfphex, salt, sizeof(salt), digest, sizeof(digest))) {
        ERROR("Can't create key fingerprint");
        return -1;
    }

    if(current_fp) {
	if(memcmp(digest, current_digest, sizeof(digest))) {
	    ERROR("Invalid password");
	    return -1;
	}
	return 0;

    } else {
	/* FP = FP_SALT + DIGEST */
	memcpy(new_fp, salt, SALT_SIZE);
	memcpy(new_fp + SALT_SIZE, digest, KEY_SIZE);
	return 0;
    }

    return -1;
}

static int aes256_configure(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len)
{
	unsigned char key[KEY_SIZE], salt[SALT_SIZE];
	char *keyfile;
	int fd, user_salt = 0, nogenkey = 0, paranoid = 0;
	const char *pt;

    if(cfgstr) {
	if(strstr(cfgstr, "paranoid") && strstr(cfgstr, "salt:")) {
	    ERROR("User provided salt cannot be used in paranoid mode");
	    return -1;
	} else if(strncmp(cfgstr, "paranoid", 8) && strncmp(cfgstr, "salt:", 5) && strncmp(cfgstr, "nogenkey", 8)) {
	    ERROR("Invalid configuration '%s'", cfgstr);
	    return -1;
	}
	if((pt = strstr(cfgstr, "salt:"))) {
	    if(strlen(pt) < 5 + 2 * SALT_SIZE) {
		ERROR("Invalid salt length - must be %u bytes (hex string len %u)\n", SALT_SIZE, SALT_SIZE * 2);
		return -1;
	    }
	    if(sxi_hex2bin(&pt[5], 2 * SALT_SIZE, salt, sizeof(salt))) {
		ERROR("Invalid salt - can't decode hex string '%s'\n", &pt[5]);
		return -1;
	    }
	    user_salt = 1;
	}
	if(strstr(cfgstr, "nogenkey"))
	    nogenkey = 1;
	if(strstr(cfgstr, "paranoid"))
	    paranoid = 1;
    }

    if(!user_salt) {
	if(!RAND_bytes(salt, sizeof(salt))) {
	    ERROR("Can't generate salt, please try again");
	    return -1;
	}
    }

    if(paranoid || nogenkey) {
	*cfgdata = calloc(sizeof(salt) + nogenkey, sizeof(char));
	if(!*cfgdata) {
	    ERROR("OOM");
	    return -1;
	}
	memcpy(*cfgdata, salt, sizeof(salt));
	*cfgdata_len = sizeof(salt) + nogenkey;
	return 0;
    }

    if(cfgdir) {
	int ret;
	while((ret = getpassword(handle, 1, SXF_MODE_UPLOAD, key, salt)) == 1);
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
	if(write(fd, key, sizeof(key)) != sizeof(key)) {
	    ERROR("Can't write key data to file %s", keyfile);
	    close(fd);
	    unlink(keyfile);
	    free(keyfile);
	    return -1;
	}
	if(close(fd)) {
	    ERROR("Can't close file %s", keyfile);
	    unlink(keyfile);
	    free(keyfile);
	    return -1;
	}
	free(keyfile);

	*cfgdata = malloc(SALT_SIZE + FP_SIZE);
	if(!*cfgdata)
	    return -1;

	memcpy(*cfgdata, salt, SALT_SIZE);
	if(keyfp(handle, key, NULL, (unsigned char *) *cfgdata + SALT_SIZE)) {
	    free(*cfgdata);
	    return -1;
	}
	*cfgdata_len = SALT_SIZE + FP_SIZE;
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
	unsigned char key[KEY_SIZE], salt[SALT_SIZE], fp[FP_SIZE];
	char *keyfile = NULL;
	int fd, have_fp = 0;

    mlock(key, sizeof(key));
    if(cfgdata) {
	if(cfgdata_len == SALT_SIZE) { /* paranoid (no-key-file) mode */
	    printf("[aes256]: File '%s' will be %s with provided password\n", filename, mode == SXF_MODE_UPLOAD ? "encrypted" : "decrypted");
	    memcpy(salt, cfgdata, SALT_SIZE);
	    while((ret = getpassword(handle, mode == SXF_MODE_UPLOAD ? 1 : 0, mode, key, salt)) == 1);
	    if(ret)
		return -1;
	    keyread = 1;
	} else if(cfgdata_len == SALT_SIZE + 1) { /* nogenkey mode -> no fingerprint available */
	    memcpy(salt, cfgdata, SALT_SIZE);
	} else if(cfgdata_len == SALT_SIZE + FP_SIZE) {
	    memcpy(salt, cfgdata, SALT_SIZE);
	    memcpy(fp, (unsigned char *) cfgdata + SALT_SIZE, FP_SIZE);
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
	    if(read(fd, key, sizeof(key)) != sizeof(key))
		WARN("Can't read key file %s -- new key file will be created", keyfile)
	    else
		keyread = 1;
	    close(fd);
	}
	if(!keyread) {
	    while((ret = getpassword(handle, have_fp ? 0 : 1, mode, key, salt)) == 1);
	    if(ret) {
		free(keyfile);
		return -1;
	    }
	    if(have_fp && keyfp(handle, key, fp, NULL)) {
		free(keyfile);
		return -1;
	    }
	    fd = open(keyfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	    if(fd == -1) {
		WARN("Can't open file %s for writing -- continuing without key file", keyfile);
	    } else {
		if(write(fd, key, sizeof(key)) != sizeof(key)) {
		    close(fd);
		    unlink(keyfile);
		    WARN("Can't write key data to file %s -- continuing without key file", keyfile);
		} else if(close(fd)) {
		    unlink(keyfile);
		    WARN("Can't close file %s -- continuing without key file", keyfile);
		}
	    }
	}
    }

    actx = calloc(1, sizeof(struct aes256_ctx));
    if(!actx) {
	ERROR("OOM");
        free(keyfile);
	return -1;
    }
    actx->keyfile = keyfile;
    mlock(actx->key, sizeof(actx->key));
    memcpy(actx->key, key, sizeof(actx->key));
    memset(key, 0, sizeof(key));
    munlock(key, sizeof(key));

    HMAC_CTX_init(&actx->ivhash);
    HMAC_CTX_init(&actx->hmac);

    if (hmac_init_ex(&actx->ivhash, actx->key, KEY_SIZE/2, EVP_sha1(), NULL) != 1) {
        ERROR("Can't initialize HMAC context(1)");
        free(keyfile);
        free(actx);
        return -1;
    }
    if (hmac_init_ex(&actx->hmac, actx->key, KEY_SIZE/2, EVP_sha512(), NULL) != 1) {
        ERROR("Can't initialize HMAC context(2)");
        free(keyfile);
        free(actx);
        return -1;
    }
    if(mode == SXF_MODE_UPLOAD) {
	mlock(&actx->ectx, sizeof(actx->ectx));
	EVP_CIPHER_CTX_init(&actx->ectx);
	if(EVP_EncryptInit_ex(&actx->ectx, EVP_aes_256_cbc(), NULL, actx->key + KEY_SIZE, NULL) != 1) {
	    ERROR("Can't initialize encryption context");
	    free(keyfile);
	    free(actx);
	    return -1;
	}
    } else {
	mlock(&actx->dctx, sizeof(actx->dctx));
	EVP_CIPHER_CTX_init(&actx->dctx);
	if(EVP_DecryptInit_ex(&actx->dctx, EVP_aes_256_cbc(), NULL, actx->key + KEY_SIZE, NULL) != 1) {
	    ERROR("Can't initialize decryption context");
	    free(keyfile);
	    free(actx);
	    return -1;
	}
    }

    *ctx = actx;
    memset(actx->ivmac, 0, sizeof(actx->ivmac));
    return 0;
}

static int hmac_compare(const unsigned char *hmac1, const unsigned char *hmac2, size_t len)
{
    int mismatch = 0;

    /* always compare all bytes to eliminate remote timing attacks */
    while(len--)
        mismatch |= *hmac1++ ^ *hmac2++;

    return mismatch;
}


static ssize_t aes256_data_process(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action)
{
	struct aes256_ctx *actx = ctx;
	unsigned int bytes;
	unsigned int bsize = mode == SXF_MODE_UPLOAD ? FILTER_BLOCK_SIZE : sizeof(actx->in);

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
        unsigned char mac[EVP_MAX_MD_SIZE], ivaes[IV_SIZE];
        unsigned int maclen;
        int final;
	if(mode == SXF_MODE_UPLOAD) {
            unsigned int ivlen;
            if (hmac_init_ex(&actx->ivhash, NULL, 0, NULL, NULL) != 1) {
                ERROR("hmac_init_ex failed(1)");
                return -1;
            }
            if (hmac_update(&actx->ivhash, actx->ivmac, sizeof(actx->ivmac)) != 1 ||
                hmac_update(&actx->ivhash, actx->in, actx->inbytes) != 1) {
                ERROR("EVP_DigestUpdate failed");
                return -1;
            }
            if (hmac_final(&actx->ivhash, mac, &ivlen) != 1) {
                ERROR("DigestFinal_ex failed");
                return -1;
            }
            if (ivlen < IV_SIZE) {
                ERROR("Wrong digest size: %d", ivlen);
                return -1;
            }
            /* calculate iv of next block using iv of previous block */
            memcpy(actx->ivmac, mac, ivlen);
            memcpy(ivaes, mac, IV_SIZE);
            memcpy(actx->blk, ivaes, IV_SIZE);
	    if(!EVP_EncryptInit_ex(&actx->ectx, NULL, NULL, NULL, ivaes)) {
		ERROR("EVP_EncryptInit_ex failed");
		return -1;
	    }
	    if(!EVP_EncryptUpdate(&actx->ectx, actx->blk + IV_SIZE, (int *) &actx->blkbytes, actx->in, actx->inbytes)) {
		ERROR("EVP_EncryptUpdate failed");
		return -1;
	    }
            actx->blkbytes += IV_SIZE;
	    if(!EVP_EncryptFinal_ex(&actx->ectx, actx->blk + actx->blkbytes, &final)) {
		ERROR("EVP_EncryptFinal_ex failed");
		return -1;
	    }
            if (hmac_init_ex(&actx->hmac, NULL, 0, NULL, NULL) != 1) {
                ERROR("hmac_init_ex failed");
                return -1;
            }
            actx->blkbytes += final;
            if (hmac_update(&actx->hmac, actx->blk, actx->blkbytes) != 1) {
                ERROR("hmac_update failed");
                return -1;
            }
            if (hmac_final(&actx->hmac, mac, &maclen) != 1) {
                ERROR("hmac_final failed");
                return -1;
            }
            maclen /= 2;
            if (maclen != MAC_SIZE) {
                ERROR("Bad MAC size: %d", maclen);
                return -1;
            }
            memcpy(actx->blk + actx->blkbytes, mac, maclen);
            actx->blkbytes += maclen;
	} else {
            if (hmac_init_ex(&actx->hmac, NULL, 0, NULL, NULL) != 1) {
                ERROR("hmac_init_ex failed");
                return -1;
            }
            if (actx->inbytes < IV_SIZE + MAC_SIZE) {
                ERROR("Incomplete data: %d bytes", actx->inbytes);
                return -1;
            }
            actx->inbytes -= MAC_SIZE;
            if (hmac_update(&actx->hmac, actx->in, actx->inbytes) != 1) {
                ERROR("hmac_update failed");
                return -1;
            }
            if (hmac_final(&actx->hmac, mac, &maclen) != 1) {
                ERROR("hmac_final failed");
                return -1;
            }
            maclen /= 2;
            if (maclen != MAC_SIZE) {
                ERROR("Bad HMAC size: %d bytes", maclen);
                return -1;
            }
            if (hmac_compare(actx->in + actx->inbytes, mac, maclen)) {
                ERROR("HMAC mismatch (Invalid password/key file or broken data)");
		actx->decrypt_err = 1;
                return -1;
            }
            memcpy(ivaes, actx->in, IV_SIZE);
	    if(!EVP_DecryptInit_ex(&actx->dctx, NULL, NULL, NULL, ivaes)) {
		ERROR("EVP_DecryptInit_ex failed");
		return -1;
	    }
	    if(!EVP_DecryptUpdate(&actx->dctx, actx->blk, (int *) &actx->blkbytes, actx->in + IV_SIZE, actx->inbytes - IV_SIZE)) {
		ERROR("EVP_DecryptUpdate failed");
		return -1;
	    }
	    if(!EVP_DecryptFinal_ex(&actx->dctx, actx->blk + actx->blkbytes, &final)) {
		ERROR("EVP_DecryptFinal_ex failed (Invalid password/key file or broken data)");
		actx->decrypt_err = 1;
		return -1;
	    }
            actx->blkbytes += final;
	}
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
	    else
		*action = SXF_ACTION_DATA_END;
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
}

static int aes256_data_finish(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode)
{
	struct aes256_ctx *actx = *ctx;

    if(actx) {
        HMAC_CTX_cleanup(&actx->hmac);
        HMAC_CTX_cleanup(&actx->ivhash);
	if(mode == SXF_MODE_UPLOAD) {
	    EVP_CIPHER_CTX_cleanup(&actx->ectx);
	    memset(&actx->ectx, 0, sizeof(actx->ectx));
	    munlock(&actx->ectx, sizeof(actx->ectx));
	} else {
	    EVP_CIPHER_CTX_cleanup(&actx->dctx);
	    memset(&actx->dctx, 0, sizeof(actx->dctx));
	    munlock(&actx->dctx, sizeof(actx->dctx));
	}
	if(actx->decrypt_err && actx->keyfile)
	    unlink(actx->keyfile);
	free(actx->keyfile);
	memset(*ctx, 0, sizeof(struct aes256_ctx));
	munlock(actx->key, sizeof(actx->key));
	free(*ctx);
	*ctx = NULL;
    }
    return 0;
}

sxc_filter_t sxc_filter={
/* int abi_version */		    SXF_ABI_VERSION,
/* const char *shortname */	    "aes256",
/* const char *shortdesc */	    "Encrypt data using AES-256-CBC-HMAC-512 mode.",
/* const char *summary */	    "The filter automatically encrypts and decrypts all data using OpenSSL's AES-256 in CBC-HMAC-512 mode.",
/* const char *options */	    "\n\tnogenkey (don't generate a key file when creating a volume)\n\tparanoid (don't use key files at all - always ask for a password)\n\tsalt:HEX (force given salt, HEX must be 32 chars long)",
/* const char *uuid */		    "35a5404d-1513-4009-904c-6ee5b0cd8634",
/* sxf_type_t type */		    SXF_TYPE_CRYPT,
/* int version[2] */		    {1, 4},
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
/* void (*file_notify)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, const char *source_cluster, const char *source_volume, const char *source_path, const char *dest_cluster, const char *dest_volume, const char *dest_path) */
				    NULL,
/* int (*file_update)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, sxc_file_t *source, sxc_file_t *dest, int recursive) */
				    NULL,
/* internal */
/* const char *tname; */	    NULL
};

