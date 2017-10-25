// Basic Header
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// OpenSSL Header
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int generate_firmware_signature(char* sign)
{
	FILE* fp = NULL;

	// SHA1 Value
	int i;
	SHA_CTX ctx;
	unsigned char buf[256];
	char sha1_result[SHA_DIGEST_LENGTH];
	
	// Signature Value
	int sign_len;
	RSA* priv_key = NULL;
	
	// Hash New Firmware
	if (!(fp = fopen("Firmware", "rb")))
	{
		printf("Firmware Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(sha1_result, &ctx);

	fclose(fp);

	// Generate New Firmware Signature
	if (!(fp = fopen("private", "rb")))
	{
		printf("Private Key Open Error\n");
		return 1;
	}

	priv_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	if (priv_key == NULL)
	{
		printf("Read Private Key for RSA Error\n");
		return 1;
	}

	fclose(fp);

	sign_len = RSA_private_encrypt(20, sha1_result, sign, priv_key, RSA_PKCS1_PADDING);
	if (sign_len < 1)
	{
		printf("RSA private encryption failed\n");
		return 1;
	}

	return 0;
}

int sendData(BIO* sbio, char* sign)
{
	int len;
	FILE* fp = NULL;
	char* buf = NULL;
	char recvBuf[10] = "";

	// Send New Firmware
	if (!(fp = fopen("Firmware", "rb")))
	{
		printf("Firmware Open Error\n");
		return 1;
	}

	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	buf = (char*)calloc(len, sizeof(char));
	fread(buf, 1, len, fp);

	fclose(fp);

	if (BIO_write(sbio, buf, len) < 0)
	{
		printf("Send New Firmware Fail\n");
		free(buf);
		return 1;
	}

	free(buf);

	while (1)
	{
		if (BIO_read(sbio, recvBuf, 10) > 0)
			if (strcmp(recvBuf, "Success") == 0)
				break;
	}

	// Send Certificate
	if (!(fp = fopen("cert", "rb")))
	{
		printf("Firmware Open Error\n");
		return 1;
	}

	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	buf = (char*)calloc(len, sizeof(char));
	fread(buf, 1, len, fp);

	fclose(fp);

	if (BIO_write(sbio, buf, len) < 0)
	{
		printf("Send Certificate Fail\n");
		free(buf);
		return 1;
	}

	free(buf);

	while (1)
	{
		if (BIO_read(sbio, recvBuf, 10) > 0)
			if (strcmp(recvBuf, "Success") == 0)
				break;
	}

	// Send Signature
	if (BIO_write(sbio, sign, 256) < 0)
	{
		printf("Send Signature Fail\n");
		return 1;
	}

	return 0;
}

int main()
{
	// Signature Value
	char sign[256];

	// SSL Value
	BIO *bio, *abio, *out;
	BIO *bio_err = 0;
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	int res;

	// SSL Connection Start
	if (!bio_err)
	{
		SSL_library_init();
		SSL_load_error_strings();
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	res = SSL_CTX_use_certificate_chain_file(ctx, "cert");
	assert(res);

	res = SSL_CTX_use_PrivateKey_file(ctx, "private", SSL_FILETYPE_PEM);
	assert(res);

	res = SSL_CTX_check_private_key(ctx);
	assert(res);

	bio = BIO_new_ssl(ctx, 0);
	BIO_get_ssl(bio, &ssl);
	assert(ssl);

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	abio = BIO_new_accept("4000");

	BIO_set_accept_bios(abio, bio);
	if (BIO_do_accept(abio) <= 0)
	{
		fprintf(stderr, "Error setting up accept BIO\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (BIO_do_accept(abio) <= 0)
	{
		fprintf(stderr, "Error in connection\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	out = BIO_pop(abio);

	if (BIO_do_handshake(out) <= 0)
	{
		fprintf(stderr, "Error in SSL handshake\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	else
		printf("SSL Connection Success\n");

	// Generate New Firmware Signature
	memset(sign, 0, 256);
	if (generate_firmware_signature(sign) != 0)
	{
		printf("New Firmware Signature Generation Fail\n");
		return 1;
	}

	// Send New Firmware and Signature
	sendData(out, sign);

	return 0;
}