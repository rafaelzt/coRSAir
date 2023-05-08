/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   corsair.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rzamolo- <rzamolo-@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/05/04 12:10:54 by rzamolo-          #+#    #+#             */
/*   Updated: 2023/05/08 17:35:10 by rzamolo-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "corsair.h"


// void read_public_key(char *file)
// {
// 	int 			key_type = EVP_PKEY_base_id(private_key);
// 	const char		*filename = "private.pem";
// 	char 			*n_hex = BN_bn2hex(n);
// 	char 			*e_hex = BN_bn2hex(e);
// 	const BIGNUM	*n;
// 	const BIGNUM	*e;
// 	BIO				*bio = NULL;
// 	EVP_PKEY		*public_key = NULL;
// 	RSA 			*rsa_key = NULL;

// 	OpenSSL_add_all_algorithms();
// 	ERR_load_BIO_strings();
// 	ERR_load_crypto_strings();
// 	bio = BIO_new_file(filename, "r");
// 	if (bio == NULL) 
// 	{
// 		ERR_print_errors_fp(stderr);
// 		exit(EXIT_FAILURE);
// 	}
// 	if (key_type != EVP_PKEY_RSA)
// 	{
// 		fprintf(stderr, "The key is not an RSA key.\n");
// 		exit(EXIT_FAILURE);
// 	}
// 	rsa_key = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
// 	if (rsa_key == NULL)
// 	{
// 		ERR_print_errors_fp(stderr);
// 		exit(EXIT_FAILURE);
// 	}
// 	RSA_get0_key(rsa_key, &n, &e, NULL);
// 	printf("n: %s\n", n_hex);
// 	printf("e: %s\n", e_hex);
// 	OPENSSL_free(n_hex);
// 	OPENSSL_free(e_hex);
// 	RSA_free(rsa_key);
// 	BIO_free_all(bio);
// 	EVP_cleanup();
// 	ERR_free_strings();
// }

void	read_private_key(char *file)
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

int main(void) 
{
	read_private_key("private.pem");
	// read_public_key("public.pem");

	return (0);
}
