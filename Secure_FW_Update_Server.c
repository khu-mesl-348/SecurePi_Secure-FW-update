#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>

int generate_firmware_hash(char* digest)
{
	FILE* fp = NULL;
	int fileSize;
	char* tmpbuf = NULL;
	SHA_CTX sha1;

	if (!(fp = fopen("firmware", "rb")))
	{
		printf("File open error\n");
		return 1;
	}

	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	tmpbuf = malloc(size + 1);

	fread(tmpbuf, 1, fileSize, fp);
	fclose(fp);

	SHA1_Init(&sha1);
	SHA1_Update(&sha1, tmpbuf, fileSize);
	SHA1_Final(digest, &sha1);

	free(tmpbuf);

	return 0;
}

int generate_firmware_signature(char* digest)
{
	FILE* fp = NULL;
	RSA* priv_key = NULL;
	int sign_len;
	char sign[256];

	if (!(fp = fopen("private", "rb")))
	{
		printf("File open error\n");
		return 1;
	}

	priv_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	if (priv_key == NULL)
	{
		printf("Read Private Key for RSA Error\n");
		return 1;
	}

	sign_len = RSA_private_encrypt(20, digest, sign, priv_key, RSA_PKCS1_PADDING);
	if (sign_len < 1)
		printf("RSA private encryption failed\n");

	fclose(fp);

	if (!(fp = fopen("Signature", "wb")))
	{
		printf("File open error\n");
		return 1;
	}
	fwrite(sign, 1, 256, fp);
	fclose(fp);

	return 0;
}

int sendData(BIO* sbio)
{
	int len;
	FILE* fp = NULL;
	char* buf = NULL;

	if (!(fp = fopen("firmware", "rb")))
	{
		printf("File open error\n");
		return 1;
	}
	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	buf = (char*)calloc(len, sizeof(char));

	fread(buf, 1, len, fp);
	BIO_write(sbio, buf, len);
	fclose(fp);
	free(buf);

	if (!(fp = fopen("Signature", "rb")))
	{
		printf("File open error\n");
		return 1;
	}
	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	buf = (char*)calloc(len, sizeof(char));

	fread(buf, 1, len, fp);
	BIO_write(sbio, buf, len);
	fclose(fp);
	free(buf);

	return 0;
}

int main()
{
	char digest[20];

	BIO *sbio, *bbio, *acpt, *out;
	BIO *bio_err = 0;
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;

	if (!bio_err) {
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

	sbio = BIO_new_ssl(ctx, 0);
	BIO_get_ssl(sbio, &ssl);
	assert(ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	bbio = BIO_new(BIO_f_buffer());
	sbio = BIO_push(bbio, sbio);
	acpt = BIO_new_accept("PORT");

	BIO_set_accept_bios(acpt, sbio);
	out = BIO_new_fp(stdout, BIO_NOCLOSE);
	if (BIO_do_accept(acpt) <= 0) {
		fprintf(stderr, "Error setting up accept BIO\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (BIO_do_accept(acpt) <= 0) {
		fprintf(stderr, "Error in connection\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	sbio = BIO_pop(acpt);
	BIO_free_all(acpt);

	if (BIO_do_handshake(sbio) <= 0) {
		fprintf(stderr, "Error in SSL handshake\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (generate_firmware_hash(digest) != 0)
	{
		printf("Firmware hash generation failed\n");
		return 1;
	}

	if (generate_firmware_signature(digest) != 0)
	{
		printf("Firmware signature generation failed\n");
		return 1;
	}

	sendData(sbio);

	return 0;
}