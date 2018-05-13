/*
 * SSH Certificate module for PuTTY
 */

#include "ssh.h"

static void getstring(const char **data, int *datalen,
                      const char **p, int *length)
{
    *p = NULL;
    if (*datalen < 4)
        return;
    *length = toint(GET_32BIT(*data));
    if (*length < 0)
        return;
    *datalen -= 4;
    *data += 4;
    if (*datalen < *length)
        return;
    *p = *data;
    *data += *length;
    *datalen -= *length;
}

static void certv1_freekey(void *key)
{
    struct certv1_key *cert = (struct certv1_key *) key;
    if (cert->key)
      cert->alg->freekey(cert->key);
    sfree(cert->cert);
    sfree(cert->pub);
}

static unsigned char *certv1_inner_blob(void *key, int *len)
{
    struct certv1_key *cert = (struct certv1_key *) key;
    unsigned char *blob = snewn(cert->publen, unsigned char);
    memcpy(blob, cert->pub, cert->publen);
    *len = cert->publen;
    return blob;
}

static unsigned char *certv1_public_blob(void *key, int *len)
{
    struct certv1_key *cert = (struct certv1_key *) key;
    unsigned char *blob = snewn(cert->certlen, unsigned char);
    memcpy(blob, cert->cert, cert->certlen);
    *len = cert->certlen;
    return blob;
}

static unsigned char *certv1_private_blob(void *key, int *len)
{
    struct certv1_key *cert = (struct certv1_key *) key;
    if (cert->key == NULL) {
	*len = 0;
	return NULL;
    }
    return cert->alg->private_blob(cert->key, len);
}

static void *certv1_createkey(const struct ssh_signkey *self,
                              const unsigned char *cert_blob,
                              int cert_len,
                              const unsigned char *priv_blob,
                              int priv_len)
{
    const struct ssh_signkey *alg;
    int pub_len;
    unsigned char *pub_blob;
    struct certv1_key *cert;

    alg = find_pubkey_alg((const char*)self->extra);
    pub_blob = openssh_certv1_to_pub_key(cert_blob, cert_len, &pub_len, alg);
    if (pub_blob == NULL)
	return NULL;

    cert = snew(struct certv1_key);
    cert->alg = alg;
    cert->pub = pub_blob;
    cert->publen = pub_len;
    if (priv_len > 0) {
	/* We might be doing a partial load to match with the
	 * private key later */
	cert->key = alg->createkey(alg, pub_blob, pub_len,
	                           priv_blob, priv_len);
    } else {
	cert->key = NULL;
    }
    cert->cert = snewn(cert_len, unsigned char);
    memcpy(cert->cert, cert_blob, cert_len);
    cert->certlen = cert_len;
    // TODO
    return cert;
}

static int certv1_openssh_fmtkey(void *key, unsigned char *blob, int len)
{
    struct certv1_key *cert = (struct certv1_key *) key;
    int bloblen;

    bloblen = 4 + cert->certlen;
    if (cert->key) {
	// TODO
    }

    if (bloblen > len)
        return bloblen;

    /* Encode the certificate */
    PUT_32BIT(blob, cert->certlen);
    blob += 4;
    memcpy(blob, cert->cert, cert->certlen);
    blob += cert->certlen;

    if (cert->key == NULL)
	return bloblen;

    return bloblen;
}

static void *certv1_openssh_createkey(const struct ssh_signkey *self,
                                     const unsigned char **blob, int *len)
{
    struct certv1_key *cert;
    const char **b = (const char **) blob;
    const char *certblob;
    int certbloblen;

    getstring(b, len, &certblob, &certbloblen);

    cert = (struct certv1_key *)certv1_createkey(self, certblob, certbloblen,
                                                 NULL, 0);

    // TODO(bluecmd):
    // This part is a bit tricky. ECDSA has this format usually:
    /*
    	string			ecdsa_curve_name
	string			ecdsa_public_key
	mpint			ecdsa_private
	string			key_comment
	constraint[]		key_constraints
	*/
    /* but for certificates its:
    	string			certificate
	mpint			ecdsa_private_key
	string			key_comment
	constraint[]		key_constraints
*/
    /* The ordering is a bit weird as well so we might need to create per-algo functions here */
    return cert;
}


static int certv1_pubkey_bits(const struct ssh_signkey *self,
                              const void *blob, int len)
{
    const struct ssh_signkey *alg;
    alg = find_pubkey_alg((const char*)self->extra);
    return alg->pubkey_bits(alg, blob, len);
}

static unsigned char *certv1_sign(void *key, const char *data, int datalen,
                                  int *siglen)
{
    struct certv1_key *cert = (struct certv1_key *) key;
    return cert->alg->sign(cert->key, data, datalen, siglen);
}

const struct ssh_signkey ssh_ecdsa_nistp256_certv1 = {
    NULL /* newkey */,
    certv1_freekey,
    NULL /* fmtkey */,
    certv1_public_blob,
    certv1_private_blob,
    certv1_inner_blob,
    certv1_createkey,
    certv1_openssh_createkey,
    certv1_openssh_fmtkey,
    -1,
    certv1_pubkey_bits,
    NULL /* verifysig */,
    certv1_sign,
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256",
};

const struct ssh_signkey ssh_ecdsa_nistp384_certv1 = {
    NULL /* newkey */,
    certv1_freekey,
    NULL /* fmtkey */,
    certv1_public_blob,
    certv1_private_blob,
    certv1_inner_blob,
    certv1_createkey,
    certv1_openssh_createkey,
    certv1_openssh_fmtkey,
    -1,
    certv1_pubkey_bits,
    NULL /* verifysig */,
    certv1_sign,
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384",
};

const struct ssh_signkey ssh_ecdsa_nistp521_certv1 = {
    NULL /* newkey */,
    certv1_freekey,
    NULL /* fmtkey */,
    certv1_public_blob,
    certv1_private_blob,
    certv1_inner_blob,
    certv1_createkey,
    certv1_openssh_createkey,
    certv1_openssh_fmtkey,
    -1,
    certv1_pubkey_bits,
    NULL /* verifysig */,
    certv1_sign,
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521",
};