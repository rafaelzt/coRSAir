/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   corsair.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rzamolo- <rzamolo-@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/04/24 11:44:38 by rzamolo-          #+#    #+#             */
/*   Updated: 2023/05/09 19:17:31 by rzamolo-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef CORSAIR_H
#define CORSAIR_H

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <math.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

void specific_function(const char* filename);
void read_public_key(char *file);
void read_private_key(char *file);


#endif