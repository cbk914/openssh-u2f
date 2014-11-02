// TODO: SSL_load_error_strings(), requires -lssl i think?
#include "includes.h"

#ifdef U2F

#include <ctype.h>
#include <openssl/x509.h>
#include <u2f-host.h>
#include <fcntl.h>

#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "ssh.h"
#include "ssh2.h"
#include "log.h"
#include "dispatch.h"
#include "misc.h"
#include "servconf.h"
#include "packet.h"
#include "digest.h"
#include "xmalloc.h"
#include "monitor_wrap.h"

extern ServerOptions options;

static void input_userauth_u2f_info_response(int, u_int32_t, void *);
static void input_userauth_u2f_register_response(int type, u_int32_t seq, void *ctxt);

static const int u2f_pubkey_len = 65;

//static const unsigned char *pubkey = "\x04\x8a\x82\x65\xbf\xb0\xd5\xcc\xb7\x82\x4a\x4f\xe9\x85\x06\x09\x4d\xf4\x22\x06\x19\xc2\x18\xc2\xa1\xf2\x6f\x3c\x0d\x92\x9a\x21\xba\xf4\x93\x0a\x10\x58\x87\x2d\x97\x77\x39\xab\xf4\x8f\xc0\x29\x26\x73\x65\xa1\xbb\x49\x8c\xf1\x5b\x18\x07\x17\x97\xd9\x15\x24\xe0";
static const unsigned char *pubkeyprefix = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";
static const char *appid = "ssh://localhost";

void u2f_sha256(u_char *dest, u_char *src, size_t srclen) {
	struct ssh_digest_ctx *ctx = ssh_digest_start(SSH_DIGEST_SHA256);
	ssh_digest_update(ctx, src, srclen);
	ssh_digest_final(ctx, dest, ssh_digest_bytes(SSH_DIGEST_SHA256));
}

/* We can get away without a JSON parser because all values in the JSON
 * messages used in U2F are (websafe) base64 encoded, therefore we don’t need
 * to care about escaping at all. We can just look for the starting double
 * quote and take everything until the next double quote.
 */
static char *
extract_json_string(const char *json, const char *key)
{
	char *quotedkey;
	char *keypos;
	char *value;
	char *end;
	int quotedkeylen;

	quotedkeylen = xasprintf(&quotedkey, "\"%s\"", key);
	if ((keypos = strstr(json, quotedkey)) == NULL)
		return NULL;

	keypos += quotedkeylen;
	if (*keypos == ':')
		keypos++;
	while (*keypos != '\0' && isspace(*keypos))
		keypos++;
	if (*keypos != '"')
		return NULL;
	keypos++;
	value = xstrdup(keypos);
	if ((end = strchr(value, '"')) == NULL) {
		free(value);
		return NULL;
	}
	*end = '\0';
	return value;
}

static int
urlsafe_base64_decode(const char *base64, u_char *buffer, size_t bufferlen)
{
	// U2F uses urlsafe base64, which replaces + with - and / with _, so we
	// need to revert that before base64 decoding.
	char *replaced;
	char *pos;

	replaced = xstrdup(base64);
	while ((pos = strchr(replaced, '-')) != NULL)
        *pos = '+';
	while ((pos = strchr(replaced, '_')) != NULL)
		*pos = '/';

	return b64_pton(replaced, buffer, bufferlen);
}

static int
urlsafe_base64_encode(u_char const *src, size_t srclength, char *target, size_t targsize)
{
	char *pos;
	int len;

	if ((len = b64_ntop(src, srclength, target, targsize)) == -1)
		return -1;

	while ((pos = strchr(target, '+')) != NULL)
		*pos = '-';

	while ((pos = strchr(target, '/')) != NULL)
		*pos = '_';

	return len;
}

static Key*
read_keyfile(FILE *fp, char *filename, struct passwd *pw, u_long *linenum)
{
	// TODO: do we need to use a different constant here?
	char line[SSH_MAX_PUBKEY_BYTES];
	Key *found = NULL;

	while (read_keyfile_line(fp, filename, line, sizeof(line), linenum) != -1) {
		char *cp, *key_options;
		if (found != NULL)
			key_free(found);
		found = key_new(KEY_U2F);
		// TODO: auth_clear_options();?

		/* Skip leading whitespace, empty and comment lines. */
        for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
            ;
        if (!*cp || *cp == '\n' || *cp == '#')
            continue;

		debug("reading key from line %lu", *linenum);
		if (key_read(found, &cp) != 1) {
			debug("key_read failed, skipping line %lu", *linenum);
			continue;
		}
		debug("key type: %d (u2f = %d)", found->type, KEY_U2F);
		if (found->type == KEY_U2F) {
		//if (key_equal(found, key)) {
			//if (auth_parse_options(pw, key_options, filename, *linenum) != 1)
			//	continue;
			// TODO: calculate and display a fingerprint of the key handle and pubkey?
			debug("matching key found: file %s, line %lu", filename, *linenum);
			// TODO: store multiple matches in authctx->methoddata, or rather authctxt->keys? (see sshconnect2.c)
			return found;
		}
	}
	return NULL;
}

/*
 * Read a key from the key files.
 */
Key*
read_user_u2f_key(struct passwd *pw, u_int key_idx)
{
	size_t i;
	// TODO: It might not be safe to pass the key back to the unprivileged
	// process. It probably is, but we should review this.

	// In the first step, we need to go through all u2f keys that we have and
	// collect their key handles.
	for (i = 0; i < options.num_authkeys_files; i++) {
		FILE *fp;
		char *file;
		Key *key = NULL;
		u_long linenum = 0;
		if (strcasecmp(options.authorized_keys_files[i], "none") == 0)
			continue;
		file = expand_authorized_keys(options.authorized_keys_files[i], pw);
		debug("need to check %s", file);
		fp = fopen(file, "r");
		do
		{
			// TODO: Hackish way to allow getting more than one key
			key_free(key);
			key = read_keyfile(fp, file, pw, &linenum);
		}
		while(key_idx-- > 0);
		fclose(fp);
		free(file);
		if (key != NULL)
			return key;
	}
	return NULL;
}

static int
userauth_u2f(Authctxt *authctxt)
{
	u_int i;
	int mode;

	mode = packet_get_int();
	packet_check_eom();
	// TODO: shared constants
	if (mode == 0) {
		debug("u2f mode is registration");
		u_char random[32];
		char challenge[((sizeof(random)+2)/3)*4 + 1];
		char *json;
		arc4random_buf(random, sizeof(random));
		if (urlsafe_base64_encode(random, sizeof(random), challenge, sizeof(challenge)) == -1)
			fatal("TODO");

		xasprintf(&json, "{\"challenge\": \"%s\", \"version\": \"U2F_V2\", \"appId\": \"%s\"}",
			challenge, appid);

		packet_start(SSH2_MSG_USERAUTH_INFO_REQUEST);
		packet_put_cstring(json);
		packet_send();
		dispatch_set(SSH2_MSG_USERAUTH_INFO_RESPONSE,
			&input_userauth_u2f_register_response);
		authctxt->postponed = 1;
		return (0);
	} else {
		debug("u2f mode is authentication");
	}

	// This is on the server. See sshconnect2.c for the client
	debug("auth-u2f.c:userauth_u2f");

	Key *key;
	u_int idx = 0;
	// Get multiple keys by increasing idx until key == NULL
	// TODO: send multiple challenges for all keys (or something)
	key = PRIVSEP(read_user_u2f_key(authctxt->pw, idx));
	if (key == NULL)
	{
		debug("no registered u2f keys found\n");
		return (0);
	}

	// TODO: handle empty signatureData with a nice message. this seems to happen when the keyhandle is wrong?

	// TODO: to what should we set the appid?
	//
	// TODO: what does auth_info() do?
	// TODO: we need to store challenge in this authctx somehow :)

	packet_start(SSH2_MSG_USERAUTH_INFO_REQUEST);
	u_char random[32];
	char challenge[((sizeof(random)+2)/3)*4 + 1];
	char pubkey[((u2f_pubkey_len+2)/3)*4 + 1];
	char keyhandle[((key->u2f_key_handle_len+2)/3)*4 + 1];
	char *json;
	arc4random_buf(random, sizeof(random));
	authctxt->u2f_challenge = xmalloc(sizeof(random));
	memcpy(authctxt->u2f_challenge, random, sizeof(random));
	authctxt->u2f_key = key;
	if (urlsafe_base64_encode(random, sizeof(random), challenge, sizeof(challenge)) == -1)
		fatal("TODO");
	if (urlsafe_base64_encode(key->u2f_pubkey, u2f_pubkey_len, pubkey, sizeof(pubkey)) == -1)
		fatal("TODO");
	if (urlsafe_base64_encode(key->u2f_key_handle, key->u2f_key_handle_len, keyhandle, sizeof(keyhandle)) == -1)
		fatal("TODO");
	xasprintf(&json, "{\"challenge\": \"%s\", \"keyHandle\": \"%s\", \"appId\": \"%s\"}",
		challenge, keyhandle, appid);
	packet_put_cstring(json);
	free(json);
	packet_send();
	dispatch_set(SSH2_MSG_USERAUTH_INFO_RESPONSE,
		&input_userauth_u2f_info_response);
	authctxt->postponed = 1;
	return (0);
}

static void
input_userauth_u2f_register_response(int type, u_int32_t seq, void *ctxt)
{
#define u2f_bounds_check(necessary_bytes) do { \
	if (restlen < necessary_bytes) { \
		logit("U2F response too short: need %d bytes, but only %d remaining", \
			necessary_bytes, restlen); \
		goto out; \
	} \
} while (0)

#define u2f_advance(parsed_bytes) do { \
	int advance = parsed_bytes; \
	walk += advance; \
	restlen -= advance; \
} while (0)

    Authctxt *authctxt = ctxt;
	char *response, *regdata, *clientdata;
	u_char *decoded = NULL;
	u_char *walk = NULL;
	u_char *keyhandle = NULL;
	u_char *pubkey = NULL;
	u_char *signature = NULL;
	u_char *dummy = NULL;
	u_char *cdecoded = NULL;
	X509 *x509;
	EVP_MD_CTX mdctx;
	int restlen;
	int khlen;
	int cdecodedlen;
	int err;
	char errorbuf[4096];
	u_char digest[ssh_digest_bytes(SSH_DIGEST_SHA256)];

	authctxt->postponed = 0;

	response = packet_get_string(NULL);
	packet_check_eom();
	if ((regdata = extract_json_string(response, "registrationData")) == NULL) {
		logit("Response not JSON, or does not contain \"registrationData\"");
		goto out;
	}

	decoded = xmalloc(strlen(regdata) * 3 / 4);
	restlen = urlsafe_base64_decode(regdata, decoded, strlen(regdata) * 3 / 4);
	walk = decoded;

	// Header (magic byte)
	u2f_bounds_check(1);
	if (walk[0] != 0x05) {
		logit("U2F response does not start with magic byte 0x05");
		goto out;
	}
	u2f_advance(1);

	// Length of the public key
	u2f_bounds_check(u2f_pubkey_len);
	pubkey = walk;
	u2f_advance(u2f_pubkey_len);

	// Length of the key handle
	u2f_bounds_check(1);
	khlen = walk[0];
	u2f_advance(1);

	// Key handle
	u2f_bounds_check(khlen);
	keyhandle = walk;
	u2f_advance(khlen);

	// Attestation certificate
	u2f_bounds_check(1);
	signature = walk;
	if ((x509 = d2i_X509(NULL, &signature, restlen)) == NULL) {
		logit("U2F response contains an invalid attestation certificate.");
		goto out;
	}

	// U2F dictates that the length of the certificate should be determined by
	// encoding the certificate using DER.
	u2f_advance(i2d_X509(x509, &dummy));
	free(dummy);

	// Ensure we have at least one byte of signature.
	u2f_bounds_check(1);

	if ((clientdata = extract_json_string(response, "clientData")) == NULL) {
		logit("U2F response JSON lacks the \"clientData\" key.");
		goto out;
	}

	cdecoded = xmalloc(strlen(clientdata) * 3 / 4);
	cdecodedlen = urlsafe_base64_decode(clientdata, cdecoded, strlen(clientdata) * 3 / 4);
	EVP_PKEY *pkey = X509_get_pubkey(x509);

	if ((err = EVP_VerifyInit(&mdctx, EVP_ecdsa())) != 1) {
		ERR_error_string(ERR_get_error(), errorbuf);
		fatal("EVP_VerifyInit() failed: %s (reason: %s)",
				errorbuf, ERR_reason_error_string(err));
	}
	EVP_VerifyUpdate(&mdctx, "\0", 1);
	u2f_sha256(digest, appid, strlen(appid));
	EVP_VerifyUpdate(&mdctx, digest, sizeof(digest));
	u2f_sha256(digest, cdecoded, cdecodedlen);
	EVP_VerifyUpdate(&mdctx, digest, sizeof(digest));
	EVP_VerifyUpdate(&mdctx, keyhandle, khlen);
	EVP_VerifyUpdate(&mdctx, pubkey, u2f_pubkey_len);

	if ((err = EVP_VerifyFinal(&mdctx, walk, restlen, pkey)) == -1) {
		ERR_error_string(ERR_get_error(), errorbuf);
		logit("Verifying the U2F registration signature failed: %s (reason: %s)",
				errorbuf, ERR_reason_error_string(err));
		goto out;
	}
	EVP_PKEY_free(pkey);

	{
		char *authorizedkey;
		char key[u2f_pubkey_len + khlen];
		char key64[((sizeof(key)+2)/3)*4 + 1];

		memcpy(key, pubkey, u2f_pubkey_len);
		memcpy(key+u2f_pubkey_len, keyhandle, khlen);

		if (b64_ntop(key, sizeof(key), key64, sizeof(key64)) == -1)
			fatal("b64_ntop()");

		xasprintf(&authorizedkey, "ssh-u2f %s", key64);
		packet_start(SSH2_MSG_USERAUTH_INFO_REQUEST);
		packet_put_cstring(authorizedkey);
		packet_send();
		free(authorizedkey);
		dispatch_set(SSH2_MSG_USERAUTH_INFO_RESPONSE, NULL);
	}

out:
	free(decoded);
    userauth_finish(authctxt, 0, "u2f", NULL);
	return;

#undef u2f_bounds_check
#undef u2f_advance
}

int
verify_u2f_user(Key *key, u_char *dgst, size_t dgstlen, u_char *sig, size_t siglen)
{
	int ret;
	EC_KEY *ec;
	unsigned char *pk;

	// TODO: replace a lot of stuff here with constants
	pk = malloc(sizeof(unsigned char) * (u2f_pubkey_len+26));

	memcpy(pk, pubkeyprefix, 26);
	memcpy(pk+26, key->u2f_pubkey, u2f_pubkey_len);

	if ((ec = d2i_EC_PUBKEY(NULL, &pk, u2f_pubkey_len+26)) == NULL)
		fatal("d2i_EC_PUBKEY() failed");
	debug("pubkey loaded, yay");

	if ((ret = ECDSA_verify(0, dgst, dgstlen, sig, siglen, ec)) == -1)
		fatal("ECDSA_verify failed");
	debug("ret = %d", ret);
	if (ret == 1)
		debug("sig verified!");

	EC_KEY_free(ec);
	return ret == 1;
}

// TODO: can we send multiple authrequests at the same time, so that we don’t
// need multiple round-trips but still support multiple security keys
static void
input_userauth_u2f_info_response(int type, u_int32_t seq, void *ctxt)
{
	int authenticated = 0;
    Authctxt *authctxt = ctxt;
	u_char digest[ssh_digest_bytes(SSH_DIGEST_SHA256)];
    debug("input_userauth_u2f_info_response\n");
    u_int len;
	char *clientdata;
	u_char *cdecoded;
	int cdecodedlen;
    char *resp = packet_get_string(&len);
    debug("u2f resp len (server): %d\n", len);
    debug("u2f resp (server): %s\n", resp);
    packet_check_eom();

	char *sig = extract_json_string(resp, "signatureData");
	if (sig == NULL)
		fatal("could not extract signature");
	// TODO: free sig

	debug("signature is *%s*", sig);
	if (*sig == '\0')
		fatal("u2f authentication failed: empty signature. Probably the key is not registered (i.e. your key handle/pubkey do not exist on the key you are using)");

	// TODO: is there a macro for this size?
	u_char decoded[strlen(sig) * 3 / 4];
	int decodedlen = urlsafe_base64_decode(sig, decoded, sizeof(decoded));
	// Ensure that the user presence byte, the counter and at least one byte of
	// signature are present.
	if (decodedlen <= (sizeof(u_char) + sizeof(u_int32_t)))
		fatal("decoded signature too short");
	if ((decoded[0] & 0x01) != 0x01)
		fatal("user presence bit not set");
	u_int32_t counter = ntohl(*((u_int32_t*)&decoded[1]));
	debug("usage counter = %d\n", counter);

	struct sha_digest_ctx *sha256ctx = ssh_digest_start(SSH_DIGEST_SHA256);
	u2f_sha256(digest, appid, strlen(appid));
	ssh_digest_update(sha256ctx, digest, sizeof(digest));
	ssh_digest_update(sha256ctx, decoded, sizeof(u_char));
	ssh_digest_update(sha256ctx, decoded+1, 4 * sizeof(u_char));

	if ((clientdata = extract_json_string(resp, "clientData")) == NULL) {
		fatal("U2F response JSON lacks the \"clientData\" key.");
	}

	cdecoded = xmalloc(strlen(clientdata) * 3 / 4);
	cdecodedlen = urlsafe_base64_decode(clientdata, cdecoded, strlen(clientdata) * 3 / 4);
	u2f_sha256(digest, cdecoded, cdecodedlen);
	ssh_digest_update(sha256ctx, digest, sizeof(digest));
	ssh_digest_final(sha256ctx, digest, sizeof(digest));
	debug("hashed sig");

	authenticated = PRIVSEP(verify_u2f_user(
		authctxt->u2f_key, digest, sizeof(digest), decoded+5, decodedlen-5));

	authctxt->postponed = 0;
	dispatch_set(SSH2_MSG_USERAUTH_INFO_RESPONSE, NULL);
	userauth_finish(authctxt, authenticated, "u2f", NULL);
}

Authmethod method_u2f = {
	"u2f",
	userauth_u2f,
	&options.u2f_authentication
};

#endif /* U2F */
