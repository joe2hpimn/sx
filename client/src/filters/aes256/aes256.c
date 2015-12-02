/*
 *  Copyright (C) 2012-2015 Skylable Ltd. <info-copyright@skylable.com>
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

#include "libsxclient/src/misc.h"
#include "libsxclient/src/fileops.h"
#include "server/src/common/sxlimits.h"
#include "sx.h"

#ifdef ENABLE_VGHINTS
#include "valgrind/memcheck.h"
#endif

/* logger prefixes with aes256: already */
#define NOTICE(...)	sxc_filter_msg(handle, SX_LOG_NOTICE, __VA_ARGS__)
#define WARN(...)	sxc_filter_msg(handle, SX_LOG_WARNING, __VA_ARGS__)
#define ERROR(...)	sxc_filter_msg(handle, SX_LOG_ERR, __VA_ARGS__)

#define FILTER_BLOCK_SIZE 16384
#define BCRYPT_AES_ITERATIONS_LOG2 14
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
    unsigned char keys[2 * KEY_SIZE];
    unsigned char key[KEY_SIZE], ivmac[EVP_MAX_MD_SIZE];
    unsigned int inbytes, blkbytes, data_in, data_out_left, data_end;
    unsigned char in[IV_SIZE + FILTER_BLOCK_SIZE + AES_BLOCK_SIZE + MAC_SIZE];
    unsigned char blk[IV_SIZE + FILTER_BLOCK_SIZE + AES_BLOCK_SIZE + MAC_SIZE];
    char *keyfile;
    char *cfgdir;
    int decrypt_err;
    sxf_mode_t crypto_inited;
};


static int aes256_init(const sxf_handle_t *handle, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static int derive_key(const sxf_handle_t *handle, const char *pass, const unsigned char *salt, unsigned salt_size, unsigned char *key, unsigned int key_size, unsigned char *meta_key, unsigned int meta_key_size)
{
    char keybuf[61];
    EVP_MD_CTX ctx;
    int ret;

    if(sxi_derive_key(pass, (const char*)salt, salt_size, BCRYPT_AES_ITERATIONS_LOG2, keybuf, sizeof(keybuf))) {
        ERROR("Failed to derive key");
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
        if (EVP_DigestUpdate(&ctx, keybuf, strlen(keybuf)) != 1) {
            ERROR("EVP_DigestUpdate failed");
            break;
        }
        if (EVP_DigestFinal_ex(&ctx, key, &len) != 1) {
            ERROR("EVP_DigestFinal_ex failed");
            break;
        }
        if (len != key_size) {
            ERROR("Bad digest size: %d bytes", len);
            break;
        }
        ret = 0;
    } while(0);
    EVP_MD_CTX_cleanup(&ctx);

    if(meta_key) {
	/* generate a key for meta encryption from the bcrypt one */
	if(PKCS5_PBKDF2_HMAC(keybuf, strlen(keybuf), salt, salt_size, 1, EVP_sha512(), meta_key_size, meta_key) == 0) {
	    ERROR("Failed to generate meta key");
	    return -1;
	}
    }

    return ret;
}

static int getpassword(const sxf_handle_t *handle, int repeat, sxf_mode_t mode, unsigned char *keys, const unsigned char *salt, int gen_meta_key)
{
    char pass1[1024], pass2[1024], prompt[64];
    int ret;

    snprintf(prompt, sizeof(prompt), "[aes256]: Enter %s password: ", mode == SXF_MODE_UPLOAD ? "encryption" : "decryption");
    mlock(pass1, sizeof(pass1));
    if(sxc_filter_get_input(handle, SXC_INPUT_SENSITIVE, prompt, NULL, pass1, sizeof(pass1))) {
	munlock(pass1, sizeof(pass1));
	ERROR("Can't obtain password");
	return -1;
    }

    if(strlen(pass1) < 8) {
	memset(pass1, 0, sizeof(pass1));
	munlock(pass1, sizeof(pass1));
	ERROR("Password must be at least 8 characters long");
	return 1;
    }

    if(repeat) {
	mlock(pass2, sizeof(pass2));
	if(sxc_filter_get_input(handle, SXC_INPUT_SENSITIVE, "[aes256]: Re-enter encryption password: ", NULL, pass2, sizeof(pass2))) {
	    memset(pass1, 0, sizeof(pass1));
	    munlock(pass1, sizeof(pass1));
	    munlock(pass2, sizeof(pass2));
	    ERROR("Can't obtain password");
	    return -1;
	}
	if(strcmp(pass1, pass2)) {
	    memset(pass1, 0, sizeof(pass1));
	    munlock(pass1, sizeof(pass1));
	    memset(pass2, 0, sizeof(pass2));
	    munlock(pass2, sizeof(pass2));
	    ERROR("Passwords don't match");
	    return 1;
	}
	memset(pass2, 0, sizeof(pass2));
	munlock(pass2, sizeof(pass2));
    }

    ret = derive_key(handle, pass1, salt, SALT_SIZE, keys, KEY_SIZE, gen_meta_key ? &keys[KEY_SIZE] : NULL, gen_meta_key ? KEY_SIZE : 0);
    memset(pass1, 0, sizeof(pass1));
    munlock(pass1, sizeof(pass1));
    return ret;
}

static int keyfp(const sxf_handle_t *handle, const unsigned char *key, unsigned int key_size, const unsigned char *current_fp, unsigned char *new_fp)
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
#ifdef ENABLE_VGHINTS
	VALGRIND_MAKE_MEM_DEFINED(salt, sizeof(salt));
#endif
    }
    if(!SHA256_Init(&sctx) ||
       !SHA256_Update(&sctx, key, key_size) ||
       !SHA256_Final(tmp, &sctx)) {
        ERROR("Can't create key fingerprint (sha256)");
        return -1;
    }
    sxi_bin2hex(tmp, sizeof(tmp), keyfphex);
    if (derive_key(handle, keyfphex, salt, sizeof(salt), digest, sizeof(digest), NULL, 0)) {
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

static int aes256_configure(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len, sxc_meta_t *custom_volume_meta)
{
	unsigned char keys[2 * KEY_SIZE], salt[SALT_SIZE];
	char *keyfile;
	int fd, user_salt = 0, nogenkey = 1, paranoid = 0, encrypt_meta = 0;
	const char *pt;

    if(cfgstr) {
	if(strstr(cfgstr, "paranoid") && strstr(cfgstr, "salt:")) {
	    ERROR("User provided salt cannot be used in paranoid mode");
	    return -1;
	} else if(strncmp(cfgstr, "paranoid", 8) && strncmp(cfgstr, "salt:", 5) && strncmp(cfgstr, "nogenkey", 8) && strncmp(cfgstr, "setkey", 6) && strncmp(cfgstr, "encrypt_filenames", 17)) {
	    ERROR("Invalid configuration '%s'", cfgstr);
	    return -1;
	}
	if((pt = strstr(cfgstr, "salt:"))) {
	    if(strlen(pt) < 5 + 2 * SALT_SIZE) {
		ERROR("Invalid salt length - must be %u bytes (hex string len %u)", SALT_SIZE, SALT_SIZE * 2);
		return -1;
	    }
	    if(sxi_hex2bin(&pt[5], 2 * SALT_SIZE, salt, sizeof(salt))) {
		ERROR("Invalid salt - can't decode hex string '%s'", &pt[5]);
		return -1;
	    }
	    user_salt = 1;
	}
	if(strstr(cfgstr, "setkey"))
	    nogenkey = 0;
	if(strstr(cfgstr, "encrypt_filenames")) {
	    encrypt_meta = 1;
	    if(sxc_meta_setval(custom_volume_meta, "aes256_encrypt_meta", "x", 1)) {
		ERROR("Failed to set custom meta");
		return -1;
	    }
	}
	if(strstr(cfgstr, "paranoid"))
	    paranoid = 1;
    }

    if(!user_salt) {
	if(!RAND_bytes(salt, sizeof(salt))) {
	    ERROR("Can't generate salt, please try again");
	    return -1;
	}
#ifdef ENABLE_VGHINTS
	VALGRIND_MAKE_MEM_DEFINED(salt, sizeof(salt));
#endif
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
	int ret, key_size = encrypt_meta ? 2 * KEY_SIZE : KEY_SIZE;
	while((ret = getpassword(handle, 1, SXF_MODE_UPLOAD, keys, salt, encrypt_meta)) == 1);
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
	if(write(fd, keys, key_size) != key_size) {
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
	if(keyfp(handle, keys, key_size, NULL, (unsigned char *) *cfgdata + SALT_SIZE)) {
	    free(*cfgdata);
	    *cfgdata = NULL;
	    return -1;
	}
	*cfgdata_len = SALT_SIZE + FP_SIZE;

	if(sxc_meta_setval(custom_volume_meta, "aes256_fp", *cfgdata, *cfgdata_len)) {
	    ERROR("Failed to set custom meta");
	    free(*cfgdata);
	    *cfgdata = NULL;
	    *cfgdata_len = 0;
	    return -1;
	}
    }

    return 0;
}

static int aes256_shutdown(const sxf_handle_t *handle, void *ctx)
{
	struct aes256_ctx *actx = ctx;

    if(!actx)
	return 0;

    free(actx->keyfile);
    free(actx->cfgdir);
    memset(actx, 0, sizeof(struct aes256_ctx));
    munlock(actx->keys, sizeof(actx->keys));
    free(actx);
    return 0;
}

static int ctx_prepare(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_meta_t *custom_volume_meta, sxf_mode_t mode, int use_meta_key)
{
	int fd, have_fp = 0, encrypted_meta = 0;
	unsigned char keys[2 * KEY_SIZE], salt[SALT_SIZE], fp[FP_SIZE];
	int keyread = 0, key_size, ret;
	char *keyfile = NULL;
	struct aes256_ctx *actx;
	const void *mdata;
	unsigned int mdata_len;

    if(!cfgdata || cfgdata_len == SALT_SIZE + 1) {
	unsigned char custfp[SALT_SIZE + FP_SIZE];
	char *fpfile;
        if(!sxc_meta_getval(custom_volume_meta, "aes256_fp", &mdata, &mdata_len)) {
	    cfgdata = mdata;
	    cfgdata_len = mdata_len;
	    fpfile = malloc(strlen(cfgdir) + 8);
	    if(!fpfile) {
		ERROR("OOM");
		return -1;
	    }
	    sprintf(fpfile, "%s/custfp", cfgdir);
	    if(access(fpfile, F_OK)) {
		fd = open(fpfile, O_WRONLY | O_CREAT, 0600);
		if(fd == -1) {
		    ERROR("Can't create file %s", fpfile);
		    free(fpfile);
		    return -1;
		}
		if(write(fd, mdata, mdata_len) != mdata_len) {
		    ERROR("Can't write to file %s", fpfile);
		    free(fpfile);
		    close(fd);
		    return -1;
		}
	    } else {
		fd = open(fpfile, O_RDONLY);
		if(fd == -1) {
		    ERROR("Can't open file %s", fpfile);
		    free(fpfile);
		    return -1;
		}
		if(read(fd, custfp, sizeof(custfp)) != sizeof(custfp)) {
		    ERROR("Can't read file %s", fpfile);
		    free(fpfile);
		    close(fd);
		    return -1;
		}
		if(memcmp(custfp, mdata, mdata_len)) {
		    NOTICE("Detected volume password change");
		    unlink(fpfile);
		    sprintf(fpfile, "%s/key", cfgdir);
		    unlink(fpfile);
		}
	    }
	    free(fpfile);
	    if(close(fd)) {
		ERROR("Can't close descriptor %d", fd);
		return -1;
	    }
	}
    }
    if(!sxc_meta_getval(custom_volume_meta, "aes256_encrypt_meta", &mdata, &mdata_len))
	encrypted_meta = 1;

    mlock(keys, sizeof(keys));
    if(cfgdata) {
	if(cfgdata_len == SALT_SIZE) { /* paranoid (no-key-file) mode */
	    NOTICE("File '%s' will be %s with provided password", filename, mode == SXF_MODE_UPLOAD ? "encrypted" : "decrypted");
	    memcpy(salt, cfgdata, SALT_SIZE);
	    while((ret = getpassword(handle, mode == SXF_MODE_UPLOAD ? 1 : 0, mode, keys, salt, 0)) == 1);
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
		if(have_fp)
		    NOTICE("The local key file doesn't exist and will be created now");
		else
		    NOTICE("First upload to the encrypted volume, set the volume password now");
	    } else {
		WARN("Can't open key file %s -- attempt to recreate it", keyfile);
	    }
	} else {
	    if((key_size = read(fd, keys, sizeof(keys))) == -1)
		WARN("Can't read key file %s -- new key file will be created", keyfile);
	    else {
		if((!encrypted_meta && key_size != KEY_SIZE) || (encrypted_meta && key_size != 2 * KEY_SIZE)) {
		    ERROR("Local configuration doesn't match remote settings (filename encryption)");
		    NOTICE("Something has changed remotely or your local configuration is corrupted: you will need to reset the local or remote volume configuration to continue using the volume.");
		    close(fd);
		    free(keyfile);
		    return -1;
		}
		keyread = 1;
	    }
	    close(fd);
	}
	if(!keyread) {
	    if(have_fp || encrypted_meta)
		NOTICE("Filename encryption is %s", encrypted_meta ? "enabled" : "disabled");
	    else if(!encrypted_meta) {
		char answer, def = 'n';
		if(sxc_filter_get_input(handle, SXC_INPUT_YN, "[aes256]: Enable filename encryption (introduces additional slowdown)?", &def, &answer, sizeof(char))) {
		    ERROR("Failed to get user input");
		    free(keyfile);
		    return -1;
		}
		if(answer == 'y')
		    encrypted_meta = 1;
	    }
	    while((ret = getpassword(handle, have_fp ? 0 : (mode == SXF_MODE_UPLOAD ? 1 : 0), mode, keys, salt, encrypted_meta)) == 1);
	    if(ret) {
		free(keyfile);
		return -1;
	    }
	    if(have_fp) {
		if(keyfp(handle, keys, encrypted_meta ? 2 * KEY_SIZE : KEY_SIZE, fp, NULL)) {
		    free(keyfile);
		    return -1;
		}
	    } else {
		unsigned char mdata[SALT_SIZE + FP_SIZE];
		memcpy(mdata, salt, SALT_SIZE);
		if(keyfp(handle, keys, encrypted_meta ? 2 * KEY_SIZE : KEY_SIZE, NULL, mdata + SALT_SIZE)) {
		    free(keyfile);
		    return -1;
		}

		if(sxc_meta_setval(custom_volume_meta, "aes256_fp", mdata, sizeof(mdata)) || (encrypted_meta && sxc_meta_setval(custom_volume_meta, "aes256_encrypt_meta", "x", 1))) {
		    ERROR("Failed to set custom meta");
		    free(keyfile);
		    return -1;
		}
	    }
	    fd = open(keyfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	    if(fd == -1) {
		WARN("Can't open file %s for writing -- continuing without key file", keyfile);
	    } else {
		key_size = encrypted_meta ? 2 * KEY_SIZE : KEY_SIZE;
		if(write(fd, keys, key_size) != key_size) {
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
    actx->cfgdir = strdup(cfgdir);
    if(!actx->cfgdir) {
	ERROR("OOM");
        free(actx->keyfile);
        free(actx);
	return -1;
    }
    mlock(actx->keys, sizeof(actx->keys));
    memcpy(actx->keys, keys, sizeof(actx->keys));
    memset(keys, 0, sizeof(keys));
    munlock(keys, sizeof(keys));

    *ctx = actx;
    return 0;
}

static int data_prepare(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_meta_t *custom_volume_meta, sxf_mode_t mode, int use_meta_key)
{
	struct aes256_ctx *actx;
	uint32_t runtime_ver = SSLeay();
	uint32_t compile_ver = SSLEAY_VERSION_NUMBER;

    if((runtime_ver & 0xff0000000) != (compile_ver & 0xff0000000)) {
	ERROR("OpenSSL library version mismatch: compiled: %x, runtime: %d", compile_ver, runtime_ver);
	return -1;
    }

    if((actx = *ctx) && strcmp(cfgdir, actx->cfgdir)) {
	aes256_shutdown(handle, *ctx);
	*ctx = NULL;
    }

    if(!*ctx && ctx_prepare(handle, ctx, filename, cfgdir, cfgdata, cfgdata_len, custom_volume_meta, mode, use_meta_key))
	return -1;

    actx = *ctx;

    if(actx->crypto_inited) {
	HMAC_CTX_cleanup(&actx->hmac);
	HMAC_CTX_cleanup(&actx->ivhash);
	memset(actx->key, 0, sizeof(actx->key));
	munlock(actx->key, sizeof(actx->key));
	if(actx->crypto_inited == SXF_MODE_UPLOAD) {
	    EVP_CIPHER_CTX_cleanup(&actx->ectx);
	    memset(&actx->ectx, 0, sizeof(actx->ectx));
	    munlock(&actx->ectx, sizeof(actx->ectx));
	} else {
	    EVP_CIPHER_CTX_cleanup(&actx->dctx);
	    memset(&actx->dctx, 0, sizeof(actx->dctx));
	    munlock(&actx->dctx, sizeof(actx->dctx));
	}
	actx->inbytes = actx->blkbytes = actx->data_in = actx->data_out_left = actx->data_end = 0;
	actx->crypto_inited = 0;
    }

    mlock(actx->key, sizeof(actx->key));
    memcpy(actx->key, use_meta_key ? &actx->keys[KEY_SIZE] : actx->keys, KEY_SIZE);

    HMAC_CTX_init(&actx->ivhash);
    HMAC_CTX_init(&actx->hmac);

    if (hmac_init_ex(&actx->ivhash, actx->key, KEY_SIZE/2, EVP_sha1(), NULL) != 1) {
        ERROR("Can't initialize HMAC context(1)");
        return -1;
    }
    if (hmac_init_ex(&actx->hmac, actx->key, KEY_SIZE/2, EVP_sha512(), NULL) != 1) {
        ERROR("Can't initialize HMAC context(2)");
        return -1;
    }
    if(mode == SXF_MODE_UPLOAD) {
	mlock(&actx->ectx, sizeof(actx->ectx));
	EVP_CIPHER_CTX_init(&actx->ectx);
	if(EVP_EncryptInit_ex(&actx->ectx, EVP_aes_256_cbc(), NULL, actx->key + KEY_SIZE/2, NULL) != 1) {
	    ERROR("Can't initialize encryption context");
	    return -1;
	}
    } else {
	mlock(&actx->dctx, sizeof(actx->dctx));
	EVP_CIPHER_CTX_init(&actx->dctx);
	if(EVP_DecryptInit_ex(&actx->dctx, EVP_aes_256_cbc(), NULL, actx->key + KEY_SIZE/2, NULL) != 1) {
	    ERROR("Can't initialize decryption context");
	    return -1;
	}
    }

    memset(actx->ivmac, 0, sizeof(actx->ivmac));
    actx->crypto_inited = mode;
    return 0;
}

static int aes256_data_prepare(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_meta_t *custom_volume_meta, sxf_mode_t mode)
{
    return data_prepare(handle, ctx, filename, cfgdir, cfgdata, cfgdata_len, custom_volume_meta, mode, 0);
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

    if(!actx || !actx->crypto_inited)
	return 0;

    HMAC_CTX_cleanup(&actx->hmac);
    HMAC_CTX_cleanup(&actx->ivhash);
    memset(actx->key, 0, sizeof(actx->key));
    munlock(actx->key, sizeof(actx->key));
    if(mode == SXF_MODE_UPLOAD) {
	EVP_CIPHER_CTX_cleanup(&actx->ectx);
	memset(&actx->ectx, 0, sizeof(actx->ectx));
	munlock(&actx->ectx, sizeof(actx->ectx));
    } else {
	EVP_CIPHER_CTX_cleanup(&actx->dctx);
	memset(&actx->dctx, 0, sizeof(actx->dctx));
	munlock(&actx->dctx, sizeof(actx->dctx));
    }
    if(actx->decrypt_err && actx->keyfile) {
	unlink(actx->keyfile);
	aes256_shutdown(handle, actx);
	*ctx = NULL;
    }

    return 0;
}


static int aes256_filemeta_process(const sxf_handle_t *handle, void **ctx, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_file_t *file, sxf_filemeta_type_t filemeta_type, const char *filename, char **new_filename, sxc_meta_t *file_meta, sxc_meta_t *custom_volume_meta)
{
    ssize_t bytes;
    char fmeta_padded[SXLIMIT_MAX_FILENAME_LEN + 19 + 1];
    const void *meta;
    unsigned int meta_len;
    sxf_action_t action = SXF_ACTION_DATA_END;
    int ret = -1;

    if(sxc_meta_getval(custom_volume_meta, "aes256_encrypt_meta", &meta, &meta_len)) {
	uint64_t fsize;
	if(filemeta_type == SXF_FILEMETA_LOCAL) {
	    fsize = sxi_swapu64(sxc_file_get_size(file));
	    if(sxc_meta_setval(file_meta, "aesSize", &fsize, sizeof(fsize))) {
		ERROR("Failed to set file size meta");
		return -1;
	    }
	} else {
	    if(sxc_meta_getval(file_meta, "aesSize", &meta, &meta_len) || meta_len != sizeof(uint64_t)) {
		ERROR("Failed to obtain the original file size");
		return -1;
	    }
	    fsize = sxi_swapu64(*(uint64_t *) meta);
	    if(sxi_file_set_size(file, fsize)) {
		ERROR("Failed to set file size");
		return -1;
	    }
	}
	*new_filename = strdup(filename);
	if(!*new_filename) {
	    ERROR("OOM");
	    return -1;
	}
	return 0;
    }

    if(data_prepare(handle, ctx, filename, cfgdir, cfgdata, cfgdata_len, custom_volume_meta, filemeta_type == SXF_FILEMETA_LOCAL ? SXF_MODE_UPLOAD : SXF_MODE_DOWNLOAD, 1))
	return -1;

    if(filemeta_type == SXF_FILEMETA_LOCAL) {
	SHA_CTX sctx;
        unsigned char output_bin[SHA_DIGEST_LENGTH];
        char *output;
	char fname_enc[SXLIMIT_MAX_FILENAME_LEN + 19 + 1 + IV_SIZE + AES_BLOCK_SIZE + MAC_SIZE];
	struct aes256_ctx *actx = *ctx;

	bytes = snprintf(fmeta_padded, sizeof(fmeta_padded), "%s:%llu", filename, (unsigned long long) sxc_file_get_size(file));
	memset(&fmeta_padded[bytes], 0, sizeof(fmeta_padded) - bytes);

	bytes = aes256_data_process(handle, *ctx, fmeta_padded, sizeof(fmeta_padded), fname_enc, sizeof(fname_enc), SXF_MODE_UPLOAD, &action);
	if(bytes <= 0)
	    goto filemeta_err;

	if(!SHA1_Init(&sctx) ||
	  !SHA1_Update(&sctx, filename, strlen(filename)) ||
	  !SHA1_Update(&sctx, &actx->keys[KEY_SIZE], KEY_SIZE) ||
	  !SHA1_Final(output_bin, &sctx)) {
	    ERROR("Failed to compute hash");
	    goto filemeta_err;
	}

        output = malloc(2 * SHA_DIGEST_LENGTH + 1);
        if(!output) {
            ERROR("Failed to allocate memory");
	    goto filemeta_err;
        }
        sxi_bin2hex(output_bin, SHA_DIGEST_LENGTH, output);

        if(sxc_meta_setval(file_meta, "aesEncryptedMeta", fname_enc, bytes)) {
            ERROR("Failed to set filemeta value");
            free(output);
	    goto filemeta_err;
        }

        *new_filename = output;

    } else if(filemeta_type == SXF_FILEMETA_REMOTE) {
	char *pt;

        if(sxc_meta_getval(file_meta, "aesEncryptedMeta", &meta, &meta_len)) {
            ERROR("Failed to get encrypted meta");
	    goto filemeta_err;
        }
	bytes = aes256_data_process(handle, *ctx, meta, meta_len, fmeta_padded, sizeof(fmeta_padded), SXF_MODE_DOWNLOAD, &action);
	if(bytes <= 0)
	    goto filemeta_err;

	if(!(pt = strrchr(fmeta_padded, ':'))) {
	    ERROR("Invalid file meta format");
	    goto filemeta_err;
	}
	*pt++ = 0;

	if(sxi_file_set_size(file, (unsigned long long) atoll(pt))) {
	    ERROR("Failed to set file size");
	    goto filemeta_err;
	}

        *new_filename = strdup(fmeta_padded);
	if(!*new_filename) {
	    ERROR("OOM");
	    goto filemeta_err;
	}
    }

    ret = 0;
filemeta_err:
    aes256_data_finish(handle, ctx, filemeta_type == SXF_FILEMETA_LOCAL ? SXF_MODE_UPLOAD : SXF_MODE_DOWNLOAD);
    return ret;
}

sxc_filter_t sxc_filter={
/* int abi_version */		    SXF_ABI_VERSION,
/* const char *shortname */	    "aes256",
/* const char *shortdesc */	    "Encrypt data using AES-256-CBC-HMAC-512 mode.",
/* const char *summary */	    "The filter automatically encrypts and decrypts all data using OpenSSL's AES-256 in CBC-HMAC-512 mode.",
/* const char *options */	    "\n\tsetkey (set a permanent key when creating a volume)\n\tparanoid (don't use key files at all - always ask for a password)\n\tencrypt_filenames: enable encryption of filenames (may be slow with big number of files)\n\tsalt:HEX (force given salt, HEX must be 32 chars long)",
/* const char *uuid */		    "15b0ac3c-404f-481e-bc98-6598e4577bbd",
/* sxf_type_t type */		    SXF_TYPE_CRYPT,
/* int version[2] */		    {2, 0},
/* int (*init)(const sxf_handle_t *handle, void **ctx) */	    aes256_init,
/* int (*shutdown)(const sxf_handle_t *handle, void *ctx) */    aes256_shutdown,
/* int (*configure)(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len, sxc_meta_t *custom_volume_meta) */
				    aes256_configure,
/* int (*data_prepare)(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_meta_t *custom_volume_meta, sxf_mode_t mode) */
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
/* int (*filemeta_process)(const sxf_handle_t *handle, void **ctx, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_file_t *file, sxf_filemeta_type_t filemeta_type, const char *filename, char **new_filename, sxc_meta_t *file_meta, sxc_meta_t *custom_volume_meta) */
				    aes256_filemeta_process,
/* internal */
/* const char *tname; */	    NULL
};
