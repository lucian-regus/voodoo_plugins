#include "signature_scanner/helpers.h"
#include <openssl/evp.h>
#include <stdio.h>

int hash_file(char *filepath, char hash[65]) {
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        return 0;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(file);
        return 0;
    }

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return 0;
    }

    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(ctx, buffer, bytes_read);
    }

    if (ferror(file)) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return 0;
    }

    unsigned char hash_bin[32];
    EVP_DigestFinal_ex(ctx, hash_bin, NULL);

    for (int i = 0; i < 32; i++) {
        sprintf(&hash[i * 2], "%02x", hash_bin[i]);
    }

    hash[65] = '\0';

    EVP_MD_CTX_free(ctx);
    fclose(file);
    return 1;
}
