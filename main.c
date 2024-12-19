#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/decoder.h>

#define MAX_SHELLCODE_SIZE 32

#define RSA_PRIVATE_KEY "-----BEGIN PRIVATE KEY-----\n"              \
"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC7X6/PRTqaU2wo\n" \
"ykPqsV9bHnMfR88qLykCZn1T8wj16hZspZea75lznPFg8SfCVLxbkMNT+jVMA7Ia\n" \
"UuCY9moocxPfmnfPzOHsfmgwORuSmgpUXopI5oReuyPLqiLvqM1LpxAkvLN61I0i\n" \
"7s/Ls70OWHPvjj2iXtysnFV9+7U8Rx4+EHGIubhZv17ovcUKRRAMyoPgkUScNPmQ\n" \
"0t5fMfGfX48kWEhD73UzeSJytQi3rmEHISmm29W/bRaRRNBj9CCC2RUT5SYix00D\n" \
"VLAcwecSvyzb1Fg6OLvBGybJEnRenKKw17/FpMxKlmaZdf2sKh2BJUITDPVdxqJc\n" \
"uSGaGK9tAgMBAAECggEAQCTwN0kwWC+R2d7wZDJHfhaM+5rmKT9OzzMN2YTcPu9d\n" \
"sOD5ZwF6K1GBcpnr7gN7He+PZrrDrxuex5MyrzrAOcu3dHdZZ8pwVzko6sVKEqRo\n" \
"P9zDg1Ri4Vk4VlsOrbPAYBM3nBP7b2O/U0Ok4EvOP1B5k/tCT0khS3gTblcSgqkR\n" \
"9ROiRDclEAdHj3bkzFCWSwpU6by9LlZIQUDeFFusWnhnVEdTQ2GZMrLURkpgiybd\n" \
"TI9PkqCZwHL824/FsTENAchwkRE3tIwIentP3/51YAH9zP3GsQ+Kg+R4YANY4xtx\n" \
"Tx+YkPbju8Cy0CUs/Ou1rzilbihsoKoRzmkgOVepkwKBgQDkMUudHLSenDAIiStk\n" \
"vr16i7y+uBGA5tYo6OdqEqAA76f4UYhJ84ra7npnwvpwURwPwOnX1yl60aRtRXJf\n" \
"UqreKyPH73kO95ZDn7ZH+lKfIRwZInvy1BIDcXjgNEuRout+ELG5JurUMIyXtxQY\n" \
"bZ0e2HKNeS48DpX0QfARJtO3twKBgQDSNQHE7xZmwOqY82O0Snyj3lPQX7lfC1Zg\n" \
"Pr91FXdIag8TXevy2Y9eQ5pG/n/cmc+3xor60Yau1GAqkKYL2HKgJ+Smn4yv6YV/\n" \
"L2U2nX41GwY9+LZqmqR9v1we+EeOo230D9GAIS7ck/dCd/fj+gdNdelzhgjXqQRY\n" \
"UKqgECLp+wKBgD2HSTMg1VbbGFyE1+1/PMn5ObhXG2kdVOuM+TDxurDl7e2X1l7S\n" \
"S0ODAABQY4S7agyZYLQxMN8L/gD0s8UeHjJvgWNcn9C4U40CWH0J8xMzM0dXtAIi\n" \
"yoShKQ2TLDklq8e/KpyY8MKsIIyb8dAwZig2BpU88omBCU/mI5wMUxP7AoGAUM8D\n" \
"0RtAd1vuU8ItMB/6blyHx/Ekp/8Jw5Ibs/z+kB4FkaJnlEJCtTAz3Nr1eG7AxZtT\n" \
"zjxCFG+cUICu9JrO5fawFcX8JZwWL+CefjJpVC0BZ013gt/UIGsyFM3JZHI7ULnM\n" \
"Bf+7rhxLz4ejCkcSC5sqlbiPKajV/MV18naBlYUCgYAHleNkNeT5pWrGFkGB5HPe\n" \
"dL4sEJX0GuL20EELpoK0+F36FmUreu1A6dXVkycr5NGc3nglXYEewQkyJaWCFW+f\n" \
"NYWAtfyRR8/FWwMhnM1EwZuHB5LjoRcxiIea4CYCEsKj9z78dywybGcw1H7pyCbf\n" \
"p4GQUoA2GsoYeZlJywd3WA==\n"                                         \
"-----END PRIVATE KEY-----\n"

const unsigned char f[] = {
    0x66, 0x6c, 0x61, 0x67, 0x3a, 0x20, 0x7b,
    0x37, 0x2d, 0x33, 0x63, 0x32, 0x61, 0x30,
    0x37, 0x33, 0x33, 0x66, 0x37, 0x65, 0x37,
    0x38, 0x62, 0x64, 0x32, 0x62, 0x33, 0x38,
    0x32, 0x66, 0x66, 0x34, 0x31, 0x63, 0x35,
    0x36, 0x61, 0x30, 0x37, 0x61, 0x64, 0x37,
    0x32, 0x62, 0x62, 0x37, 0x66, 0x37, 0x38,
    0x7d
};

void hello(void);

bool change_page_permissions_of_address(void *addr);

size_t base64_decode(const char *base64_str, unsigned char **out);

EVP_PKEY *newPKEY(const char *key);

size_t decrypt(EVP_PKEY *pkey, const unsigned char *in, size_t in_len, unsigned char **out);

int hex_char_to_int(unsigned char hex_char);

bool parse_shellcode(const unsigned char *input, size_t input_len, unsigned char *output);

int main(const int argc, char *argv[]) {
    void *hello_addr = (void *) hello;

    if (!change_page_permissions_of_address(hello_addr))
        return EXIT_FAILURE;

    hello();

    if (argc != 2)
        return EXIT_SUCCESS;

    const char *encrypted_base64_input = argv[1];

    unsigned char *encrypted_input = NULL;
    const size_t encrypted_input_len = base64_decode(encrypted_base64_input, &encrypted_input);

    if (encrypted_input_len == 0)
        goto cleanup;

    EVP_PKEY *key = newPKEY(RSA_PRIVATE_KEY);

    if (!key)
        goto cleanup;

    unsigned char *input = NULL;
    const size_t input_len = decrypt(key, encrypted_input, encrypted_input_len, &input);

    if (input_len == 0)
        goto cleanup;

    if (input_len % 4 != 0 || input_len > MAX_SHELLCODE_SIZE * 4)
        goto cleanup;

    unsigned char shellcode[MAX_SHELLCODE_SIZE] = {0x90};
    if (!parse_shellcode(input, input_len, shellcode))
        goto cleanup;

    memcpy(hello_addr, shellcode, MAX_SHELLCODE_SIZE);

    const __uid_t euid = geteuid();
    const __uid_t ruid = geteuid();
    setreuid(ruid,euid);

    hello();

cleanup:
    if (encrypted_input)
        OPENSSL_free(encrypted_input);

    if (key)
        EVP_PKEY_free(key);

    if (input)
        OPENSSL_free(input);

    return EXIT_SUCCESS;
}

void hello(void) {
    char buffer[MAX_SHELLCODE_SIZE] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64};
    fprintf(stdout, "%s\n", buffer);
}

// https://ephemeral.cx/2013/12/writing-a-self-mutating-x86_64-c-program/
bool change_page_permissions_of_address(void *addr) {
    const int page_size = getpagesize();
    addr -= (unsigned long) addr % page_size;
    return mprotect(addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

size_t base64_decode(const char *base64_str, unsigned char **out) {
    bool ret = false;

    size_t out_len = 0;

    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (!ctx)
        goto cleanup;

    EVP_DecodeInit(ctx);

    const size_t base64_len = strlen(base64_str);
    const size_t approximate_len = (base64_len * 3) / 4;

    *out = (unsigned char *) OPENSSL_malloc(approximate_len);
    if (!*out)
        goto cleanup;

    int len, final_len = 0;

    EVP_DecodeInit(ctx);

    if (EVP_DecodeUpdate(ctx, *out, &len, (unsigned char *) base64_str, base64_len) < 0)
        goto cleanup;

    if (EVP_DecodeFinal(ctx, *out + len, &final_len) == 1) {
        out_len = len + final_len;
        ret = true;
    }

cleanup:
    EVP_ENCODE_CTX_free(ctx);

    if (*out && (!ret || out_len == 0)) {
        OPENSSL_free(*out);
        *out = NULL;
    }

    if (!ret)
        out_len = 0;

    return out_len;
}

EVP_PKEY *newPKEY(const char *key) {
    bool ret = false;

    EVP_PKEY *pkey = NULL;

    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, "RSA", OSSL_KEYMGMT_SELECT_KEYPAIR, NULL,
                                                          NULL);
    if (!ctx)
        goto cleanup;

    BIO *bio = BIO_new_mem_buf(key, -1);
    if (!bio)
        goto cleanup;

    if (OSSL_DECODER_from_bio(ctx, bio) == 1)
        ret = true;

cleanup:
    OSSL_DECODER_CTX_free(ctx);
    BIO_free_all(bio);

    if (!ret) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    return pkey;
}

size_t decrypt(EVP_PKEY *pkey, const unsigned char *in, const size_t in_len, unsigned char **out) {
    bool ret = false;

    size_t out_len = 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        goto cleanup;

    if (EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        goto cleanup;

    if (EVP_PKEY_decrypt(ctx, NULL, &out_len, in, in_len) <= 0)
        goto cleanup;

    *out = (unsigned char *) OPENSSL_malloc(out_len);
    if (!*out)
        goto cleanup;

    if (EVP_PKEY_decrypt(ctx, *out, &out_len, in, in_len) == 1)
        ret = true;

cleanup:
    EVP_PKEY_CTX_free(ctx);

    if (*out && (!ret || out_len == 0)) {
        OPENSSL_free(*out);
        *out = NULL;
    }

    if (!ret)
        out_len = 0;

    return out_len;
}

int hex_char_to_int(const unsigned char hex_char) {
    if (hex_char >= 0x30 && hex_char <= 0x39)
        return hex_char - 0x30;

    if (hex_char >= 0x61 && hex_char <= 0x66)
        return hex_char - 0x61 + 10;

    if (hex_char >= 0x41 && hex_char <= 0x46)
        return hex_char - 0x41 + 10;

    return -1;
}

bool parse_shellcode(const unsigned char *input, const size_t input_len, unsigned char *output) {
    const unsigned char *in_pos = input;
    unsigned char *out_pos = output;

    for (size_t i = 0; i < input_len; i += 4) {
        if (*in_pos != 0x5C || *(in_pos + 1) != 0x78 ||
            !isxdigit(*(in_pos + 2)) || !isxdigit(*(in_pos + 3)))
            return false;

        const int high_nibble = hex_char_to_int(*(in_pos + 2));
        const int low_nibble = hex_char_to_int(*(in_pos + 3));

        if (high_nibble == -1 || low_nibble == -1)
            return false;

        *out_pos++ = (unsigned char) (high_nibble << 4 | low_nibble);

        in_pos += 4;
    }

    return true;
}