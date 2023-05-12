/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   corsair.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rzamolo- <rzamolo-@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/05/04 12:10:54 by rzamolo-          #+#    #+#             */
/*   Updated: 2023/05/12 10:22:09 by rzamolo-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "corsair.h"

// Buscar as Funcoes
// ERR_load_bio_strings
// ERR_load_crypto_strings
// BIO_new_file
// PEM_read_bio_PUBKEY
// EVP_PKEY_get1_RSA
// RSA_get0_key
// BN_bn2hex

void	specific_function(const char* filename)
{
	read_public_key(filename);
}


void read_public_key(char *file)
{
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	BIO *bio = NULL;
	bio = BIO_new_file(file, "r");
	if (bio == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	EVP_PKEY *evp_key = NULL;
	evp_key = PEM_read_bio_PUBKEY(bio, NULL, 0, NULL);
	if (evp_key == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	RSA *rsa_key = NULL;
	rsa_key = EVP_PKEY_get1_RSA(evp_key);
	if (rsa_key == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	const BIGNUM *n, *e;
	RSA_get0_key(rsa_key, &n, &e, NULL);
	char *n_hex = BN_bn2hex(n);
	char *e_hex = BN_bn2hex(e);
	BN_CTX *ctx = BN_CTX_new();
	char *dec_str = BN_bn2dec(n);
	if (dec_str == NULL) {
		printf("Error converting BIGNUM to decimal string\n");
	}
    printf("BIGNUM in decimal: %s\n", dec_str);


	printf("Public key (%s)\n", file);
	printf("n: %s\n", n_hex);
	printf("e: %s\n", e_hex);

	OPENSSL_free(n_hex);
	OPENSSL_free(e_hex);

	RSA_free(rsa_key);
	EVP_PKEY_free(evp_key);
	BIO_free_all(bio);
	ERR_free_strings();

}

void read_private_key(char *file)
{
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	BIO *bio = NULL;
	const char *filename = file;
	bio = BIO_new_file(filename, "r");
	if (bio == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	EVP_PKEY *private_key = NULL;
	private_key = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
	if (private_key == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	int key_type = EVP_PKEY_base_id(private_key);
	if (key_type != EVP_PKEY_RSA) {
		fprintf(stderr, "The key is not an RSA key.\n");
		exit(EXIT_FAILURE);
	}

	RSA *rsa_key = EVP_PKEY_get1_RSA(private_key);

	const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	RSA_get0_key(rsa_key, &n, &e, &d);
	RSA_get0_factors(rsa_key, &p, &q);
	RSA_get0_crt_params(rsa_key, &dmp1, &dmq1, &iqmp);

	char *n_hex = BN_bn2hex(n);
	char *e_hex = BN_bn2hex(e);
	char *d_hex = BN_bn2hex(d);
	char *p_hex = BN_bn2hex(p);
	char *q_hex = BN_bn2hex(q);
	char *dmp1_hex = BN_bn2hex(dmp1);
	char *dmq1_hex = BN_bn2hex(dmq1);
	char *iqmp_hex = BN_bn2hex(iqmp);

	printf("Private key\n");
	printf("n: %s\n", n_hex);
	printf("e: %s\n", e_hex);
	printf("d: %s\n", d_hex);
	printf("p: %s\n", p_hex);
	printf("q: %s\n", q_hex);
	printf("dmp1: %s\n", dmp1_hex);
	printf("dmq1: %s\n", dmq1_hex);
	printf("iqmp: %s\n", iqmp_hex);

	OPENSSL_free(n_hex);
	OPENSSL_free(e_hex);
	OPENSSL_free(d_hex);
	OPENSSL_free(p_hex);
	OPENSSL_free(q_hex);
	OPENSSL_free(dmp1_hex);
	OPENSSL_free(dmq1_hex);
	OPENSSL_free(iqmp_hex);

	RSA_free(rsa_key);
	EVP_PKEY_free(private_key);
	BIO_free_all(bio);
	EVP_cleanup();
	ERR_free_strings();
}

int	compare_n(BIGNUM *n_1, BIGNUM *n_2)
{

	BN_CTX *ctx = BN_CTX_new();

	c = BN_gdc(n_1, n_2, ctx);
	print(c);
}

int main(void) {
	const char *folder = "./challenge_corsair/";
	DIR *dir_ptr;
	struct dirent *entry;

	dir_ptr = opendir(folder);

	if (dir_ptr == NULL) 
	{
		perror("Unable to read directory");
		return (1);
	}

	while ((entry = readdir(dir_ptr)) != NULL)
	{
		if (entry->d_type == DT_REG)
		{
			char *ext = strrchr(entry->d_name, '.');

			if (ext != NULL && strcmp(ext, ".pem") == 0)
			{
				char filepath[512];
				snprintf(filepath, sizeof(filepath), "%s/%s", folder, \
				entry->d_name);
				specific_function(filepath);
			}
		}
	}

	closedir(dir_ptr);
	return (0);
}
