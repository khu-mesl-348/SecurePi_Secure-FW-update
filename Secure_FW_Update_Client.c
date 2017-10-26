// Basic Header
#include <stdio.h>
#include <stdlib.h>

// TPM Header
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

// OpenSSL Header
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 1, 2}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

void TPM_ERROR_PRINT(int res, char* msg)
{
#if DEBUG
	DBG(msg, res);
#endif
	if (res != 0) exit(1);
}

int generate_signature(unsigned char* xor_result)
{
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HKEY hSRK, hSigning_key;
	TSS_HPOLICY hSRKPolicy, hNVPolicy;
	TSS_UUID MY_UUID = SIGN_KEY_UUID;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	TSS_FLAG initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
	TSS_HHASH hHash;
	TSS_HNVSTORE hNVStore;
	BYTE *sign;
	UINT32 srk_authusage, signLen;

	result = Tspi_Context_Create(&hContext);
	TPM_ERROR_PRINT(result, "Create TPM Context\n");

	result = Tspi_Context_Connect(hContext, NULL);
	TPM_ERROR_PRINT(result, "Connect to TPM\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_key);
	TPM_ERROR_PRINT(result, "Create the Signing key Object\n");

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	TPM_ERROR_PRINT(result, "Get SRK Handle\n");

	result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage);
	TPM_ERROR_PRINT(result, "Get SRK Attribute\n");

	if (srk_authusage)
	{
		result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
		TPM_ERROR_PRINT(result, "Get SRK Policy\n");

		result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
		//result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD);
		TPM_ERROR_PRINT(result, "Set SRK Secret\n");
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
	TPM_ERROR_PRINT(result, "Create Hash Object\n");

	result = Tspi_Hash_SetHashValue(hHash, 20, xor_result);
	TPM_ERROR_PRINT(result, "Set Hash Value for Generating Signature\n");

	result = Tspi_Hash_Sign(hHash, hSigning_key, &signLen, &sign);
	TPM_ERROR_PRINT(result, "Generate Signature\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
	TPM_ERROR_PRINT(result, "Create NVRAM Object\n");

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 2);
	TPM_ERROR_PRINT(result, "Set NVRAM Index\n");

	result = Tspi_NV_ReleaseSpace(hNVStore);
	TPM_ERROR_PRINT(result, "Release NVRAM Space\n");

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, TPM_NV_PER_OWNERWRITE);
	TPM_ERROR_PRINT(result, "Set NVRAM Attribute\n");

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 256);
	TPM_ERROR_PRINT(result, "Set NVRAM Data Size\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNVPolicy);
	TPM_ERROR_PRINT(result, "Set NVRAM Policy\n");

//	result = Tspi_Policy_AssignToObject(hNVPolicy, hNVStore);
//	TPM_ERROR_PRINT(result, "Assign NVRAM Object\n");

	result = Tspi_NV_DefineSpace(hNVStore, 0, 0);
	TPM_ERROR_PRINT(result, "Create NVRAM Space\n");

	result = Tspi_NV_WriteValue(hNVStore, 0, signLen, sign);
	TPM_ERROR_PRINT(result, "Write Signature in NVRAM\n");

	result = Tspi_Policy_FlushSecret(hSRKPolicy);
	TPM_ERROR_PRINT(result, "Flush SRKPolicy Secret\n");

	result = Tspi_Policy_FlushSecret(hNVPolicy);
	TPM_ERROR_PRINT(result, "Flush NVPolicy Secret\n");

	result = Tspi_Context_FreeMemory(hContext, NULL);
	TPM_ERROR_PRINT(result, "Free TPM Memory\n");

	result = Tspi_Context_Close(hContext);
	TPM_ERROR_PRINT(result, "Close TPM\n");

	return 0;
}

int verify_firmware_signature2(unsigned char* decrypt_sign)
{
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HKEY hSRK, hSigning_key;
	TSS_HPOLICY hSRKPolicy, hNVPolicy;
	TSS_UUID MY_UUID = SIGN_KEY_UUID;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	TSS_FLAG initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
	TSS_HHASH hHash;
	TSS_HNVSTORE hNVStore;
	BYTE *sign, *data;
	UINT32 srk_authusage, signLen, datasize = 256;

	result = Tspi_Context_Create(&hContext);
	TPM_ERROR_PRINT(result, "Create TPM Context\n");

	result = Tspi_Context_Connect(hContext, NULL);
	TPM_ERROR_PRINT(result, "Connect to TPM\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
	TPM_ERROR_PRINT(result, "Create NVRAM Object\n");

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 2);
	TPM_ERROR_PRINT(result, "Set NVRAM Index\n");

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 256);
	TPM_ERROR_PRINT(result, "Set NVRAM Data Size\n");

	result = Tspi_NV_ReadValue(hNVStore, 0, &datasize, &data);
	TPM_ERROR_PRINT(result, "Read Signature in NVRAM\n");

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	TPM_ERROR_PRINT(result, "Get SRK Handle\n");

	result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage);
	TPM_ERROR_PRINT(result, "Get SRK Attribute\n");

	if (srk_authusage)
	{
		result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
		TPM_ERROR_PRINT(result, "Get SRK Policy\n");

		result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
		TPM_ERROR_PRINT(result, "Set SRK Secret\n");
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_key);
	TPM_ERROR_PRINT(result, "Create the Signing key Object\n");

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, MY_UUID, &hSigning_key);
	TPM_ERROR_PRINT(result, "Load the Signing Key\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
	TPM_ERROR_PRINT(result, "Create Hash Object\n");

	result = Tspi_Hash_SetHashValue(hHash, 20, decrypt_sign);
	TPM_ERROR_PRINT(result, "Set Hash Value for Verifying Signature\n");

	result = Tspi_Hash_VerifySignature(hHash, hSigning_key, 256, data);
	TPM_ERROR_PRINT(result, "Verify Signature\n");

	result = Tspi_Policy_FlushSecret(hSRKPolicy);
	TPM_ERROR_PRINT(result, "Flush SRKPolicy Secret\n");

	result = Tspi_Policy_FlushSecret(hNVPolicy);
	TPM_ERROR_PRINT(result, "Flush NVPolicy Secret\n");

	result = Tspi_Context_FreeMemory(hContext, NULL);
	TPM_ERROR_PRINT(result, "Free TPM Memory\n");

	result = Tspi_Context_Close(hContext);
	TPM_ERROR_PRINT(result, "Close TPM\n");

	return 0;
}

void dividestr(char* dest, char* source, int start, int end)
{
	int i, j=0;

	for (i = start; i < end; i++)
	{
		dest[j++] = source[i];
		printf("dest[%d]: %c, source[%d]: %c\n", j, dest[j - 1], i, source[i]);
	}
}

int receiveData2(BIO *sbio, char* sign)
{
	int len;
	FILE* fp;
	char buf[2048];
	char data[2048];
	char fileLen[3][10];
	char* token = NULL;
	int i, start, end;

	for (i = 0; i < 3; i++)
		memset(fileLen[i], 0, 10);
	memset(data, 0, 2048);

	// Data Rececive Start
	while ((len = BIO_read(sbio, buf, 2048)) != 0);

	token = strtok(buf, "  ");
	strcpy(fileLen[0], token);

	token = strtok(NULL, "  ");
	strcpy(fileLen[1], token);

	token = strtok(NULL, "  ");
	strcpy(fileLen[2], token);

	token = strtok(NULL, "");
	strcpy(data, token);

	// Store New Firmware
	if (!(fp = fopen("Firmware", "wb")))
	{
		printf("Firmware Open Fail\n");
		return 1;
	}
	
	memset(buf, 0, 2048);
	start = 1;
	end = atoi(fileLen[0]);
	dividestr(buf, data, start, end);
	fwrite((void*)buf, 1, atoi(fileLen[0]), fp);

	fclose(fp);
	
	// Store Certificate
	if (!(fp = fopen("Cert", "wb")))
	{
		printf("Cert Open Fail\n");
		return 1;
	}

	memset(buf, 0, 2048);
	start = end + 1;
	end = start + atoi(fileLen[1]);
	dividestr(buf, data, start, end);
	fwrite((void*)buf, 1, atoi(fileLen[1]), fp);
	fclose(fp);

	memset(buf, 0, 2048);
	start = end + 1;
	end = start + atoi(fileLen[2]);
	dividestr(buf, data, start, end);
	strcpy(sign, buf);
	
	return 0;
}

int verify_firmware_signature(char* sign)
{
	// SHA Value
	SHA_CTX ctx;
	char sha1_result[SHA_DIGEST_LENGTH];
	unsigned char buf[256];
	int i;

	// Decrypt Value
	FILE* fp;
	char decrypt_sign[20];
	int decrypt_signlen;
	X509* user_x509 = NULL;
	RSA* pub_key = NULL;
	EVP_PKEY* e_pub_key = NULL;

	// Extract Public Key
	if (!(fp = fopen("Cert", "rb")))
	{
		printf("Cert Open Error\n");
		return 1;
	}

	user_x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	e_pub_key = X509_get_pubkey(user_x509);
	pub_key = EVP_PKEY_get1_RSA(e_pub_key);

	fclose(fp);

	// Decrypt Signature
	decrypt_signlen = RSA_public_decrypt(256, sign, decrypt_sign, pub_key, RSA_PKCS1_PADDING);

	if (decrypt_signlen < 1)
	{
		printf("Signature Decryption Fail\n");
		return 1;
	}
	else
		printf("Signature Decryption Success\n");

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

	// Verify New Firmware
	if(!memcmp(decrypt_sign, sha1_result, 20))
		printf("New Firmware Verification Success\n");
	else
	{
		printf("New Firmware Verification Fail\n");
		return 1;
	}

	return 0;
}

int main()
{
	// Signature Value
	char sign[256];

	// SSL Value
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *sbio, *out;
	BIO *bio_err = 0;
	int len, res;

	// SSL Connection Start
	if (!bio_err)
	{
		SSL_library_init();
		SSL_load_error_strings();
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);
	sbio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(sbio, &ssl);

	if (!ssl)
	{
		fprintf(stderr, "Can't locate SSL pointer\n");
		exit(1);
	}
	
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(sbio, "163.180.118.145:4000");
	out = BIO_new_fp(stdout, BIO_NOCLOSE);

	res = BIO_do_connect(sbio);
	if (res <= 0)
	{
		fprintf(stderr, "Error connecting to server\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	res = BIO_do_handshake(sbio);
	if (res <= 0)
	{
		fprintf(stderr, "Error establishing SSL connection \n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	else
		printf("SSL Connection Success\n");

	// Receive Firmware
	memset(sign, 0, 256);
	if (receiveData2(sbio, sign) != 0)
	{
		printf("Data receive failed\n");
		return 1;
	}

	//if (receiveData(sbio, sign) != 0)
	//{
	//	printf("Data receive failed\n");
	//	return 1;
	//}

	//// Verify Firmware Signature
	//if (verify_firmware_signature(sign) != 0)
	//{
	//	printf("Firmware_Signature decryption failed\n");
	//	return 1;
	//}

	//if (generate_signature(sign) != 0)
	//{
	//	printf("Signature generation failed\n");
	//	return 1;
	//}

	return 0;
}
