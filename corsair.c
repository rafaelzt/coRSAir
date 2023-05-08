/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   corsair.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rzamolo- <rzamolo-@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/05/04 12:10:54 by rzamolo-          #+#    #+#             */
/*   Updated: 2023/05/08 14:10:01 by rzamolo-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "corsair.h"


int main() {
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	BIO *bio = NULL;
	const char *filename = "private.pem";
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
	int	key_size = EVP_PKEY_size(private_key);

	printf("Key type: %s\n", (key_type == EVP_PKEY_RSA) ? "RSA" : "Not RSA");
	printf("Key size: %s\n", (key_size == 2048) ? "2048" : "Not 2048");


	EVP_PKEY_free(private_key);
	BIO_free_all(bio);
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}
