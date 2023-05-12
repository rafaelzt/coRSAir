#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>


void print_decrypted_content(const char *file_path) {
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        printf("Error al abrir el archivo: %s\n", file_path);
        return;
    }
    printf("Contenido del archivo desencriptado:\n");
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("%s", buffer);
    }
    printf("\n");
    fclose(file);
}
int decrypt_file(const char *input_file, const char *output_file, RSA *rsa) {
    FILE *in = fopen(input_file, "rb");
    if (in == NULL) {
        perror("Error al abrir el archivo de entrada");
        return 0;
    }
    FILE *out = fopen(output_file, "wb");
    if (out == NULL) {
        perror("Error al abrir el archivo de salida");
        fclose(in);
        return 0;
    }
    int rsa_size = RSA_size(rsa);
    unsigned char *encrypted_buffer = malloc(rsa_size);
    unsigned char *decrypted_buffer = malloc(rsa_size);
    int bytes_read;
    while ((bytes_read = fread(encrypted_buffer, 1, rsa_size, in)) > 0) {
        int decrypted_size = RSA_private_decrypt(bytes_read, encrypted_buffer, decrypted_buffer, rsa, RSA_PKCS1_PADDING);
        if (decrypted_size == -1) {
            fprintf(stderr, "Error al desencriptar el archivo:\n");
            ERR_print_errors_fp(stderr);
            fclose(in);
            fclose(out);
            free(encrypted_buffer);
            free(decrypted_buffer);
            return 0;
        }
        fwrite(decrypted_buffer, 1, decrypted_size, out);
    }
    fclose(in);
    fclose(out);
    free(encrypted_buffer);
    free(decrypted_buffer);
    return 1;
}
BIGNUM *calculate_private_key(const BIGNUM *p, const BIGNUM *q, const BIGNUM *e) {
    BIGNUM *phi = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BIGNUM *d = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    // Calcular φ(n) = (p - 1) * (q - 1)
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_mul(phi, p_minus_1, q_minus_1, ctx);
    // Calcular el inverso multiplicativo de e mod φ(n)
    BN_mod_inverse(d, e, phi, ctx);
    BN_free(phi);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_CTX_free(ctx);
    return d;
}
void get_rsa_modulus_and_exponent(RSA *rsa, const BIGNUM **n, const BIGNUM **e) {
    RSA_get0_key(rsa, n, e, NULL);
}
RSA *read_rsa_public_key_from_file(const char *file_path) {
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        printf("Error al abrir el archivo: %s\n", file_path);
        return NULL;
    }
    RSA *rsa_pub_key = NULL;
    rsa_pub_key = PEM_read_RSA_PUBKEY(file, &rsa_pub_key, NULL, NULL);
    fclose(file);
    return rsa_pub_key;
}
void create_private(const BIGNUM *prime, const BIGNUM *n, const BIGNUM *e, const char *input_file) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *q = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *d = BN_new();
    // Calcular q = n / p
    BN_div(q, rem, n, prime, ctx);
    if (!BN_is_zero(rem)) {
        printf("Error, el certificado no comparte un numero primo\n");
        return;
    }
    // Calcular phi = (p - 1) * (q - 1)
    BN_sub(rem, prime, BN_value_one());
    BN_sub(phi, q, BN_value_one());
    BN_mul(phi, rem, phi, ctx);
    // Calcular d = e^(-1) mod phi
    BN_mod_inverse(d, e, phi, ctx);
    // Crear clave privada RSA
    RSA *rsa_private_key = RSA_new();
    RSA_set0_key(rsa_private_key, BN_dup(n), BN_dup(e), d);
    // Construir el nombre del archivo .bin basado en el número del archivo de la clave pública
    char encrypted_file[1024];
    strncpy(encrypted_file, input_file, strlen(input_file) - 4);  // Copiar todo excepto la extensión .pem
    encrypted_file[strlen(input_file) - 4] = '\0'; // Asegurarse de que la cadena termine correctamente
    strcat(encrypted_file, ".bin");  // Agregar la extensión .bin
    // Desencriptar archivo
    char output_file[1024];
    snprintf(output_file, sizeof(output_file), "%s.decrypted", encrypted_file);
    if (decrypt_file(encrypted_file, output_file, rsa_private_key)) {
        printf("Archivo desencriptado: %s\n", output_file);
        print_decrypted_content(output_file);
    } else {
        printf("Error al desencriptar el archivo: %s\n", encrypted_file);
    }
    // Liberar memoria
    RSA_free(rsa_private_key);
    BN_CTX_free(ctx);
    BN_free(q);
    BN_free(rem);
    BN_free(phi);
}
int main(int argc, char *argv[]) {
    const BIGNUM    *n1;
    const BIGNUM    *n2;
    const BIGNUM *e1;
    const BIGNUM *e2;
    BIGNUM          *gcd = BN_new();
    BN_CTX          *ctx = BN_CTX_new();
    RSA             *rsa_pub_key1;
    RSA             *rsa_pub_key2;
    if (argc < 3) {
        printf("Uso: %s <lista de archivos.pem>\n", argv[0]);
        return 1;
    }
    for (int i = 1; i < argc; ++i) {
        for (int j = i + 1; j < argc - 1; ++j) {
            rsa_pub_key1 = read_rsa_public_key_from_file(argv[i]);
            rsa_pub_key2 = read_rsa_public_key_from_file(argv[j]);
           if (rsa_pub_key1 == NULL || rsa_pub_key2 == NULL) {
                printf("Error al leer las claves públicas RSA.\n");
                return 1;
            }
            get_rsa_modulus_and_exponent(rsa_pub_key1, &n1, &e1);
            get_rsa_modulus_and_exponent(rsa_pub_key2, &n2, &e2);
            BN_gcd(gcd, n1, n2, ctx);
            if (!BN_is_one(gcd)) {
                printf("Primos coincidentes con %s y %s\n", argv[i], argv[j]);
                create_private(gcd, n1, e1, argv[i]);
                create_private(gcd, n2, e2,  argv[j]);
            }
            RSA_free(rsa_pub_key1);
            RSA_free(rsa_pub_key2);
        }
    }
    BN_free(gcd);
    BN_CTX_free(ctx);
    return 0;
}