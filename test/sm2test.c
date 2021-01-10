/* ====================================================================
 * Copyright (c) 2014 - 2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

//#define SGD_MAX_ECC_BITS_256
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../e_os.h"
#include <openssl/sdf.h>
#include <openssl/gmapi.h>

#ifdef OPENSSL_NO_SM2
int main(int argc, char **argv)
{
	printf("NO SM2 support\n");
	return 0;
}
#else
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/engine.h>
# include <openssl/sm2.h>
# include "../crypto/sm2/sm2_lcl.h"

# define VERBOSE 1

RAND_METHOD fake_rand;
const RAND_METHOD *old_rand;

static const char rnd_seed[] =
	"string to make the random number generator think it has entropy";
static const char *rnd_number = NULL;

static int fbytes(unsigned char *buf, int num)
{
	int ret = 0;
	BIGNUM *bn = NULL;

	if (!BN_hex2bn(&bn, rnd_number)) {
		goto end;
	}
	if (BN_num_bytes(bn) > num) {
		goto end;
	}
	memset(buf, 0, num);
	if (!BN_bn2bin(bn, buf + num - BN_num_bytes(bn))) {
		goto end;
	}
	ret = 1;
end:
	BN_free(bn);
	return ret;
}

static int change_rand(const char *hex)
{
	if (!(old_rand = RAND_get_rand_method())) {
		return 0;
	}

	fake_rand.seed		= old_rand->seed;
	fake_rand.cleanup	= old_rand->cleanup;
	fake_rand.add		= old_rand->add;
	fake_rand.status	= old_rand->status;
	fake_rand.bytes		= fbytes;
	fake_rand.pseudorand	= old_rand->bytes;

	if (!RAND_set_rand_method(&fake_rand)) {
		return 0;
	}

	rnd_number = hex;
	return 1;
}

static int restore_rand(void)
{
	rnd_number = NULL;
	if (!RAND_set_rand_method(old_rand))
		return 0;
	else	return 1;
}

static int hexequbin(const char *hex, const unsigned char *bin, size_t binlen)
{
	int ret = 0;
	char *buf = NULL;
	size_t buflen = binlen * 2 + 1;
	size_t i = 0;


	if (binlen * 2 != strlen(hex)) {
		return 0;
	}
	if (!(buf = malloc(binlen * 2 + 1))) {
		return 0;
	}
	for (i = 0; i < binlen; i++) {
		sprintf(buf + i*2, "%02X", bin[i]);
	}
	buf[buflen - 1] = 0;

	if (memcmp(hex, buf, binlen * 2) == 0) {
		ret = 1;
	}

	free(buf);
	return ret;
}

static EC_GROUP *new_ec_group(int is_prime_field,
	const char *p_hex, const char *a_hex, const char *b_hex,
	const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
	int ok = 0;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	EC_POINT *G = NULL;
	point_conversion_form_t form = SM2_DEFAULT_POINT_CONVERSION_FORM;
	int flag = 0;

	if (!(ctx = BN_CTX_new())) {
		goto err;
	}

	if (!BN_hex2bn(&p, p_hex) ||
	    !BN_hex2bn(&a, a_hex) ||
	    !BN_hex2bn(&b, b_hex) ||
	    !BN_hex2bn(&x, x_hex) ||
	    !BN_hex2bn(&y, y_hex) ||
	    !BN_hex2bn(&n, n_hex) ||
	    !BN_hex2bn(&h, h_hex)) {
		goto err;
	}

	if (is_prime_field) {
		if (!(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))) {
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx)) {
			goto err;
		}
	} else {
		if (!(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) {
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GF2m(group, G, x, y, ctx)) {
			goto err;
		}
	}

	if (!EC_GROUP_set_generator(group, G, n, h)) {
		goto err;
	}

	EC_GROUP_set_asn1_flag(group, flag);
	EC_GROUP_set_point_conversion_form(group, form);

	ok = 1;
err:
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(n);
	BN_free(h);
	EC_POINT_free(G);
	if (!ok && group) {
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		group = NULL;
	}

	return group;
}

static EC_KEY *new_ec_key(const EC_GROUP *group,
	const char *sk, const char *xP, const char *yP)
{
	int ok = 0;
	EC_KEY *ec_key = NULL;
	BIGNUM *d = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	OPENSSL_assert(group);
	//OPENSSL_assert(xP);
	OPENSSL_assert(yP);

	if (!(ec_key = EC_KEY_new())) {
		goto end;
	}
	if (!EC_KEY_set_group(ec_key, group)) {
		goto end;
	}

	if (sk) {
		if (!BN_hex2bn(&d, sk)) {
			goto end;
		}
		if (!EC_KEY_set_private_key(ec_key, d)) {
			goto end;
		}
	}

	if (xP && yP) {
		if (!BN_hex2bn(&x, xP)) {
			goto end;
		}
		if (!BN_hex2bn(&y, yP)) {
			goto end;
		}
		printf("\n");
		BN_print_fp(stderr, x);
		printf("\n");
		BN_print_fp(stderr, y);
		printf("\n");
		if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
			goto end;
		}
	}

	ok = 1;
end:
	if (d) BN_free(d);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (!ok && ec_key) {
		ERR_print_errors_fp(stderr);
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	return ec_key;
}

static int test_sm2_sign(const EC_GROUP *group,
	const char *sk, const char *xP, const char *yP,
	const char *id, const char *Z,
	const char *M, const char *e,
	const char *k, const char *r, const char *s)
{
	int ret = 0;
	int verbose = VERBOSE;
	const EVP_MD *id_md = EVP_sm3();
	const EVP_MD *msg_md = EVP_sm3();
	int type = NID_undef;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	size_t dgstlen;
	unsigned char sig[256];
	unsigned int siglen;
	const unsigned char *p;
	EC_KEY *ec_key = NULL;
	EC_KEY *pubkey = NULL;
	ECDSA_SIG *sm2sig = NULL;
	BIGNUM *rr = NULL;
	BIGNUM *ss = NULL;
	const BIGNUM *sig_r;
	const BIGNUM *sig_s;

	change_rand(k);

	if (!(ec_key = new_ec_key(group, sk, xP, yP))) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (verbose > 1) {
		EC_KEY_print_fp(stdout, ec_key, 4);
	}

	dgstlen = sizeof(dgst);
	if (!SM2_compute_id_digest(id_md, id, strlen(id), dgst, &dgstlen, ec_key)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (verbose > 1) {
		size_t j;
		printf("id=%s\n", id);
		printf("zid(xx):");
		for (j = 0; j < dgstlen; j++) { printf("%02x", dgst[j]); } printf("\n");
	}

	if (!hexequbin(Z, dgst, dgstlen)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	dgstlen = sizeof(dgst);
	if (!SM2_compute_message_digest(id_md, msg_md,
		(const unsigned char *)M, strlen(M), id, strlen(id),
		dgst, &dgstlen, ec_key)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}
	if (!hexequbin(e, dgst, dgstlen)) {
		size_t i;
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);

		printf("%s\n", e);
		printf(" my: "); for (i = 0; i < dgstlen; i++) { printf("%02x", dgst[i]); } printf("\n");

		goto err;
	}


	/* sign */
	siglen = sizeof(sig);
	if (!SM2_sign(type, dgst, dgstlen, sig, &siglen, ec_key)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	p = sig;
	if (!(sm2sig = d2i_ECDSA_SIG(NULL, &p, siglen))) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}
	if (!BN_hex2bn(&rr, r) || !BN_hex2bn(&ss, s)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	ECDSA_SIG_get0(sm2sig, &sig_r, &sig_s);

	if (BN_cmp(sig_r, rr) || BN_cmp(sig_s, ss)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}


	/* verify */
	if (!(pubkey = new_ec_key(group, NULL, xP, yP))) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (1 != SM2_verify(type, dgst, dgstlen, sig, siglen, pubkey)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	ret = 1;
err:
	restore_rand();
	if (ec_key) EC_KEY_free(ec_key);
	if (pubkey) EC_KEY_free(pubkey);
	if (sm2sig) ECDSA_SIG_free(sm2sig);
	if (rr) BN_free(rr);
	if (ss) BN_free(ss);
	return ret;
}

static int test_sm2_enc(const EC_GROUP *group, const EVP_MD *md,
	const char *d, const char *xP, const char *yP,
	const char *M, const char *k, const char *C)
{
	int ret = 0;
	EC_KEY *pub_key = NULL;
	EC_KEY *pri_key = NULL;
	SM2CiphertextValue *cv = NULL;
	unsigned char *tbuf = NULL;
	long tlen;
	unsigned char mbuf[128] = {0};
	unsigned char cbuf[sizeof(mbuf) + 256] = {0};
	size_t mlen, clen;
	unsigned char *p;

	/* test encrypt */
	if (!(pub_key = new_ec_key(group, NULL, xP, yP))) {
		goto end;
	}

	change_rand(k);
	if (!(cv = SM2_do_encrypt(md, (unsigned char *)M, strlen(M), pub_key))) {
		goto end;
	}

	p = cbuf;
	if ((clen = i2o_SM2CiphertextValue(group, cv, &p)) <= 0) {
		goto end;
	}

	if (!(tbuf = OPENSSL_hexstr2buf(C, &tlen))) {
		EXIT(1);
	}

	if ((size_t)tlen != clen || memcmp(tbuf, cbuf, clen) != 0) {
		goto end;
	}

	/* test decrypt */
	if (!(pri_key = new_ec_key(group, d, xP, yP))) {
		goto end;
	}

	mlen = sizeof(mbuf);
	if (!SM2_do_decrypt(md, cv, mbuf, &mlen, pri_key)) {
		goto end;
	}

	if (mlen != strlen(M) || memcmp(mbuf, M, strlen(M))) {
		goto end;
	}

	ret = 1;

end:
	ERR_print_errors_fp(stderr);
	restore_rand();
	EC_KEY_free(pub_key);
	EC_KEY_free(pri_key);
	SM2CiphertextValue_free(cv);
	OPENSSL_free(tbuf);
	return ret;
}

static int test_sm2_kap(const EC_GROUP *group,
	const char *A, const char *dA, const char *xA, const char *yA, const char *ZA,
	const char *B, const char *dB, const char *xB, const char *yB, const char *ZB,
	const char *rA, const char *rB, const char *KAB, const char *S1, const char *S2)
{
	int ret = 0;
	EC_KEY *eckeyA = NULL;
	EC_KEY *eckeyB = NULL;
	EC_KEY *pubkeyA = NULL;
	EC_KEY *pubkeyB = NULL;
	SM2_KAP_CTX ctxA;
	SM2_KAP_CTX ctxB;
	unsigned char RA[256];
	unsigned char RB[256];
	size_t RAlen = sizeof(RA);
	size_t RBlen = sizeof(RB);
	unsigned char kab[64];
	unsigned char kba[64];
	size_t kablen = strlen(KAB)/2;
	size_t kbalen = strlen(KAB)/2;
	unsigned char s1[64];
	unsigned char s2[64];
	size_t s1len, s2len;

	memset(&ctxA, 0, sizeof(ctxA));
	memset(&ctxB, 0, sizeof(ctxB));

	eckeyA = new_ec_key(group, dA, xA, yA);
	eckeyB = new_ec_key(group, dB, xB, yB);
	pubkeyA = new_ec_key(group, NULL, xA, yA);
	pubkeyB = new_ec_key(group, NULL, xB, yB);
	if (!eckeyA || !eckeyB || !pubkeyA || !pubkeyB) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!SM2_KAP_CTX_init(&ctxA, eckeyA, A, strlen(A), pubkeyB, B, strlen(B), 1, 1)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	if (!SM2_KAP_CTX_init(&ctxB, eckeyB, B, strlen(B), pubkeyA, A, strlen(A), 0, 1)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	change_rand(rA);
	if (!SM2_KAP_prepare(&ctxA, RA, &RAlen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	restore_rand();

	change_rand(rB);
	if (!SM2_KAP_prepare(&ctxB, RB, &RBlen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	restore_rand();

	if (!SM2_KAP_compute_key(&ctxA, RB, RBlen, kab, kablen, s1, &s1len)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!SM2_KAP_compute_key(&ctxB, RA, RAlen, kba, kbalen, s2, &s2len)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!SM2_KAP_final_check(&ctxA, s2, s2len)) {
		goto end;
	}
	if (!SM2_KAP_final_check(&ctxB, s1, s1len)) {
		goto end;
	}

	ret = 1;

end:
	ERR_print_errors_fp(stderr);
	EC_KEY_free(eckeyA);
	EC_KEY_free(eckeyB);
	EC_KEY_free(pubkeyA);
	EC_KEY_free(pubkeyB);
	SM2_KAP_CTX_cleanup(&ctxA);
	SM2_KAP_CTX_cleanup(&ctxB);
	return ret;
}

void test_verify() {
  // Group
  EC_GROUP *sm2_test_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
  unsigned char e[32] = {0x38, 0x54, 0xC4, 0x63, 0xFA, 0x3F, 0x73, 0x78,
                         0x36, 0x21, 0xB1, 0xCE, 0x4E, 0xF8, 0x3F, 0x7C,
                         0x78, 0x04, 0x8A, 0xAC, 0x79, 0xB2, 0x21, 0xFC,
                         0xDD, 0x29, 0x08, 0x66, 0xCC, 0x13, 0x11, 0x74};
  
  const char *xP = "B42401E1609F3DD4F22A75FEFE90494FB95CD1AA01D01F0AE35A27AAD7E73909";
  const char *yP = "9AA2D2C4882C8767CBCDCD29B13C93EF417B5CF40C3D399106A3DE63A3A4DBFC";
  const char* r = "76B99FB97104E442CC128DA646891CED80BDAC3D21417BFED8478C606A34F2C8";
  const char* s = "54956652BAA7BCE5BA66C1D5D9BA1B59DBAB96C71395FEFF0D2812EBF23AC34F";

  BIGNUM *rr = NULL;
  BIGNUM *ss = NULL;
  ECDSA_SIG* sig = ECDSA_SIG_new();

  EC_KEY *pubkey = new_ec_key(sm2_test_group, NULL, xP, yP);

  if (!BN_hex2bn(&rr, r) || !BN_hex2bn(&ss, s)) {
  	fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
	return;
  }

  ECDSA_SIG_set0(sig, rr, ss);

  int verify_res = SM2_do_verify(e, 32, sig, pubkey);

  printf("verify res is: %d\n", verify_res);
}

void test_decrypt() {

EC_GROUP *sm2_test_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
const char* da = "E7CB09606A53320B347F61F3F142DCB118F723A9BC27879F2805BE778F24AEE5";
const char* cx = "9E2A4A1AA4CF772622ABBBF1C6D661EE58FF01FF9843782E5A63185ABF6C2EFA";
const char* cy = "9B2D59B2B1E0D0A795BFEF53FABB24C03A02265751B820591200F0D31C551ED6";

// const char* cx =  "6a16a34b1112aac1bb1453af3c52ec01d41677b0da8bbed2e5a23f4f83ea03ce"; 
// const char* cy =  "6119b9616bfb7e4f421fb02b20e3024cac0018df24f84325165741e190a6a754";
// const char* da =  "41f7fa0c783a70d7a661b1623349b70a7a9cb3d693fe282c087a564d44af18ee";
	unsigned char cc[32] = {0x7D, 0xFD, 0xFC, 0x65, 0xCC, 0x9D, 0xF7, 0xD6};
	const char* cm = "287D5BF3358BED992881B69FBA13C8AF76EFC157455DB81ECFACC7B443EA1DB0";
 
  //EC_KEY* pri_key = new_ec_key(sm2_test_group, da, cx, cy);
  EC_KEY* pri_key = new_ec_key(sm2_test_group, da, NULL, cy);
  if(pri_key == NULL) {
	  printf("new_ec_key error!\n");
          return;
  }

  SM2CiphertextValue *cv = SM2CiphertextValue_new();

  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  
  if (!BN_hex2bn(&x, cx) || !BN_hex2bn(&y, cy)) {
  	fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
	return;
  }
  
  cv->xCoordinate = x;
  cv->yCoordinate = y;

  cv->ciphertext = ASN1_OCTET_STRING_new();
  cv->hash = ASN1_OCTET_STRING_new();

  ASN1_OCTET_STRING_set(cv->ciphertext, cc, 8);
  ASN1_OCTET_STRING_set(cv->hash, cm, 32);

  unsigned char mbuf[1024];
  uint64_t mlen;

  int decrypt_res = SM2_do_decrypt(EVP_sm3(), cv, mbuf, &mlen, pri_key);
   
   printf("\n");
   for (int i = 0; i < mlen; ++i) {
 	  printf("%x", mbuf[i]);
   }
   printf("\n");
   const char* file;
   int line;
   ERR_get_error_line(&file, &line);
 
   printf("decrypt res is: %d, ssl error: %ld\n", decrypt_res, ERR_get_error());
   printf("file: %s, line: %d\n", file, line);

}

void test_decrypt_sdf() {
   // original data
  unsigned char da[32] = {0xE7, 0xCB, 0x09, 0x60, 0x6A, 0x53, 0x32, 0x0B,
                          0x34, 0x7F, 0x61, 0xF3, 0xF1, 0x42, 0xDC, 0xB1,
                          0x18, 0xF7, 0x23, 0xA9, 0xBC, 0x27, 0x87, 0x9F,
                          0x28, 0x05, 0xBE, 0x77, 0x8F, 0x24, 0xAE, 0xE5};

  unsigned char P[32] = {0xEA, 0x4E, 0xC3, 0x52, 0xF0, 0x76, 0xA6, 0xBE};

  unsigned char cx[32] = {0x9E, 0x2A, 0x4A, 0x1A, 0xA4, 0xCF, 0x77, 0x26,
                          0x22, 0xAB, 0xBB, 0xF1, 0xC6, 0xD6, 0x61, 0xEE,
                          0x58, 0xFF, 0x01, 0xFF, 0x98, 0x43, 0x78, 0x2E,
                          0x5A, 0x63, 0x18, 0x5A, 0xBF, 0x6C, 0x2E, 0xFA};
  unsigned char cy[32] = {0x9B, 0x2D, 0x59, 0xB2, 0xB1, 0xE0, 0xD0, 0xA7,
                          0x95, 0xBF, 0xEF, 0x53, 0xFA, 0xBB, 0x24, 0xC0,
                          0x3A, 0x02, 0x26, 0x57, 0x51, 0xB8, 0x20, 0x59,
                          0x12, 0x00, 0xF0, 0xD3, 0x1C, 0x55, 0x1E, 0xD6};
  unsigned char cc[32] = {0x7D, 0xFD, 0xFC, 0x65, 0xCC, 0x9D, 0xF7, 0xD6};
  unsigned char cM[32] = {0x28, 0x7D, 0x5B, 0xF3, 0x35, 0x8B, 0xED, 0x99,
                          0x28, 0x81, 0xB6, 0x9F, 0xBA, 0x13, 0xC8, 0xAF,
                          0x76, 0xEF, 0xC1, 0x57, 0x45, 0x5D, 0xB8, 0x1E,
                          0xCF, 0xAC, 0xC7, 0xB4, 0x43, 0xEA, 0x1D, 0xB0};

  ECCrefPrivateKey ECC_PriKey;
  ECCCipher ECC_CipherData;

  unsigned char pucOutData[136] = {0};
  unsigned int uiOutDataLen;

  memset(&ECC_PriKey, 0, sizeof(ECCrefPrivateKey));
  memcpy(ECC_PriKey.K, da, 32);
  ECC_PriKey.bits = 256;

  memset(&ECC_CipherData, 0, sizeof(ECCCipher));
  ECC_CipherData.L = 8;
  memcpy(ECC_CipherData.x, cx, 32);
  memcpy(ECC_CipherData.y, cy, 32);
  memcpy(ECC_CipherData.C, cc, 8);
  memcpy(ECC_CipherData.M, cM, 32);
 
   unsigned char out[32];
   uint64_t outlen;
 
   EC_KEY *privkey = EC_KEY_new_from_ECCrefPrivateKey(&ECC_PriKey);
 
   SM2CiphertextValue *cv = SM2CiphertextValue_new_from_ECCCipher(&ECC_CipherData);
   if(cv == NULL) {
     printf("cv is NULL\n");
     return;
   }
 
   int decrypt_res = SM2_do_decrypt(EVP_sm3(), cv, out, &outlen, privkey);
 
   printf("\n");
   for (int i = 0; i < outlen; ++i) {
          printf("%x", out[i]);
   }
   printf("\n");
   const char* file;
   int line;
   ERR_get_error_line(&file, &line);
 
   printf("decrypt res is: %d, ssl error: %ld\n", decrypt_res, ERR_get_error());
   printf("file: %s, line: %d\n", file, line);
}


int main(int argc, char **argv)
{
  //test_verify();
  if(argc > 1)
    test_decrypt();
  else
    test_decrypt_sdf();
}
#endif
