#include <stdio.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 5, 16}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

int generate_Signature(unsigned char* str)
{
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HKEY hSRK;
	TSS_HPOLICY hSRKPolicy, hNVPolicy;
	TSS_UUID MY_UUID = SIGN_KEY_UUID;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	TSS_HKEY hSigning_key;
	TSS_FLAG initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
	TSS_HHASH hHash;
	TSS_HNVSTORE hNVStore;
	BYTE *pubkey, *sig;
	UINT32 pubKeySize, srk_authusage, sigLen;

	result = Tspi_Context_Create(&hContext);
#if DEBUG
	DBG("Create a context\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_Connect(hContext, NULL);
#if DEBUG
	DBG("Connect to TPM\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_key);
#if DEBUG
	DBG("Create the key object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
#if DEBUG
	DBG("Get SRK handle\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage);
#if DEBUG
	DBG("Get Attribute\n", result);
#endif
	if (result != 0) return 1;

	if (srk_authusage)
	{
		result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
#if DEBUG
		DBG("Tspi_GetPolicyObject\n", result);
#endif
		if (result != 0) return 1;

		result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD);
#if DEBUG
		DBG("Set Secret\n", result);
#endif
		if (result != 0) return 1;
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
#if DEBUG
	DBG("Create Object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Hash_SetHashValue(hHash, 20, str);
#if DEBUG
	DBG("Set Hash\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Hash_Sign(hHash, hSigning_key, &sigLen, &sig);
#if DEBUG
	DBG("Hash Sign\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
#if DEBUG
	DBG("Create NV object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 0x00011101);
#if DEBUG
	DBG("Set index\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_NV_ReleaseSpace(hNVStore);
#if DEBUG
	DBG("Release\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, TPM_NV_PER_OWNERWRITE);
#if DEBUG
	DBG("Set Policy\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 0x100);
#if DEBUG
	DBG("Set size\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNVPolicy);
#if DEBUG
	DBG("Create Context\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Policy_AssignToObject(hNVPolicy, hNVStore);
#if DEBUG
	DBG("Policy Assign\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_NV_DefineSpace(hNVStore, 0, 0);
#if DEBUG
	DBG("NVRAM DefineSpace\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_NV_WriteValue(hNVStore, 0, sigLen, sig);
#if DEBUG
	DBG("Write NVRAM\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Policy_FlushSecret(hSigning_key);
#if DEBUG
	DBG("Flush Secret\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_FreeMemory(hContext, NULL);
#if DEBUG
	DBG("Free Memory\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_Close(hContext);
#if DEBUG
	DBG("Close TPM\n", result);
#endif
	if (result != 0) return 1;

	return 0;
}

int verify_firmware_version_Signature(unsigned char* str)
{
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HKEY hSRK;
	TSS_HPOLICY hSRKPolicy, hNVPolicy;
	TSS_UUID MY_UUID = SIGN_KEY_UUID;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	TSS_HKEY hSigning_key;
	TSS_FLAG initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
	TSS_HHASH hHash;
	TSS_HNVSTORE hNVStore;
	BYTE *pubkey, *sig, *data;
	UINT32 pubKeySize = 256, srk_authusage, sigLen, datasize = 256;

	result = Tspi_Context_Create(&hContext);
#if DEBUG
	DBG("Create a Context\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_Connect(hContext, NULL);
#if DEBUG
	DBG("Connect to TPM\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
#if DEBUG
	DBG("Create NV Object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 0x00011101);
#if DEBUG
	DBG("Set index\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 0x100);
#if DEBUG
	DBG("Set Size\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_NV_ReadValue(hNVStore, 0, &datasize, &data);
#if DEBUG
	DBG("Read value\n", result);
#endif
	if (result != 0) return 1;

	if (data == NULL)
	{
		printf("NVRAM read failed\n");
		return 1;
	}

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
#if DEBUG
	DBG("Get SRK handle\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage);
#if DEBUG
	DBG("Get Attribute\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
#if DEBUG
	DBG("Set Secret\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
	DBG("Set Secret\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_key);
#if DEBUG
	DBG("Context create\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, MY_UUID, &hSigning_key);
#if DEBUG
	DBG("Load key\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
#if DEBUG
	DBG("Create Object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Hash_SetHashValue(hHash, 20, str);
#if DEBUG
	DBG("Set Hash\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Hash_VerifySignature(hHash, hSigning_key, 256, data);
#if DEBUG
	DBG("Verify\n", result);
#endif
	if (result == 0) return 1;

	result = Tspi_Policy_FlushSecret(hSigning_key);
#if DEBUG
	DBG("Flush Secret\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_Close(hContext);
#if DEBUG
	DBG("Close TPM\n", result);
#endif
	if (result != 0) return 1;

	return 0;
}

int receive_firmware(BIO *sbio)
{
	FILE* fp;
	char buf[1024];
	int len = 1;

	/// firmware rececive start ///
	if (!(fp = fopen("Firmware", "wb")))
	{
		printf("File open error\n");
		return 1;
	}
	while (len>0)
	{
		if ((len = BIO_read(sbio, buf, 1024)) < 0)
		{
			printf("BIO_read failed\n");
			return 1;
		}

		fwrite((void*)buf, 1, len, fp);
	}
	fclose(fp);

	/// firmware signature receive start ///
	len = 1;
	if (!(fp = fopen("Signature", "wb")))
	{
		printf("File open failed\n");
		return 1;
	}
	while (len>0)
	{
		if ((len = BIO_read(sbio, buf, 1024)) < 0)
		{
			printf("BIO_read faile\n");
			return 1;
		}

		fwrite((void*)buf, 1, len, fp);
	}
	fclose(fp);

	return 0;
}

int decrypt_firmware_Signature(unsigned char* decrypt_sign)
{
	FILE* fp;
	char buf[256];
	int len, decrypt_sign_len;
	X509* user_x509 = NULL;
	RSA* pub_key = NULL;
	EVP_PKEY* e_pub_key = NULL;

	if (!(fp = fopen("Cert", "rb")))
	{
		printf("File open error\n");
		return 1;
	}

	user_x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	e_pub_key = X509_get_pubkey(user_x509);
	pub_key = EVP_PKEY_get1_RSA(e_pub_key);

	fclose(fp);

	if (!(fp = fopen("Signature", "rb")))
	{
		printf("File open error\n");
		return 1;
	}

	len = fread((void*)buf, 1, 256, fp);
	fclose(fp);

	decrypt_sign_len = RSA_public_decrypt(len, buf, decrypt_sign, pub_key, RSA_PKCS1_PADDING);

	if (decrypt_sign_len < 1)
	{
		printf("RSA decryption failed\n");
	}

	return 0;
}

int receiveData(BIO* sbio, char* recvData)
{
	BIO_read(sbio, recvData, 10);
}

int main()
{
	char decrypt_sign[20];
	char recvData[10];

	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *sbio, *out;
	BIO *bio_err = 0;

	if (!bio_err) {
		SSL_library_init();
		SSL_load_error_strings();
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);
	sbio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(sbio, &ssl);
	if (!ssl) {
		fprintf(stderr, "Can't locate SSL pointer\n");
		exit(1);
	}
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(sbio, "serverIP:Port");
	out = BIO_new_fp(stdout, BIO_NOCLOSE);
	res = BIO_do_connect(sbio);
	if (res <= 0) {
		fprintf(stderr, "Error connecting to server\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	res = BIO_do_handshake(sbio);
	if (res <= 0) {
		fprintf(stderr, "Error establishing SSL connection \n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (receive_firmware(sbio) != 0)
	{
		printf("Data receive failed\n");
		return 1;
	}

	if (decrypt_firmware_Signature(decrypt_sign) != 0)
	{
		printf("Firmware_Signature decryption failed\n");
		return 1;
	}

	//NVRAM all data verify using while or for
	if (verify_firmware_version_Signature(decrypt_sign) != 0)
	{
		printf("Firmware_version_Signature verify failed\n");
		return 1;
	}

	if (generate_Signature(decrypt_sign) != 0)
	{
		printf("Signature generation failed\n");
		return 1;
	}

	return 0;
}
