#include "mbedtls/mbedtls_config.h"
#include "mbedtls/platform.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/sha256.h"
#include "esp_timer.h"
#include "esp_log.h"

#include <string.h>
#include <stdio.h>

#define TAG "RSA_APP"



void app_main() {
    int ret;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_encrypt_decrypt";
    unsigned char text[] = "Hello, World!";
    unsigned char buf[512];
    unsigned char decrypted[512];
    size_t olen = 0;
    unsigned char hash[32];
    int64_t start_time, end_time;

    mbedtls_rsa_init(&rsa);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned -0x%x", -ret);
        goto exit;
    }

    start_time = esp_timer_get_time();
    if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537)) != 0) {
        ESP_LOGE(TAG, "mbedtls_rsa_gen_key returned -0x%x", -ret);
        goto exit;
    }
    end_time = esp_timer_get_time();
    ESP_LOGI(TAG, "RSA key generation took %lld microseconds", end_time - start_time);

    // Assuming rsa is set with a public key
    start_time = esp_timer_get_time();
    if ((ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, sizeof(text) - 1, text, buf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_rsa_pkcs1_encrypt returned -0x%x", -ret);
        goto exit;
    }
    end_time = esp_timer_get_time();
    ESP_LOGI(TAG, "Encryption took %lld microseconds", end_time - start_time);

    // Assuming rsa is set with a private key
    start_time = esp_timer_get_time();
    if ((ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, &olen, buf, decrypted, sizeof(decrypted))) != 0) {
        ESP_LOGE(TAG, "mbedtls_rsa_rsaes_pkcs1_v15_decrypt returned -0x%x", -ret);
        goto exit;
    }
    decrypted[olen] = '\0';  // Ensure null termination
    end_time = esp_timer_get_time();
    ESP_LOGI(TAG, "Decryption took %lld microseconds", end_time - start_time);

    mbedtls_sha256(text, sizeof(text) - 1, hash, 0);  // Hash the message

    // Further operations...
  // Signing
    start_time = esp_timer_get_time();
    if ((ret = mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_MD_SHA256, 32, hash, buf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_rsa_pkcs1_sign returned %d", ret);
        goto exit;
    }
    end_time = esp_timer_get_time();
    ESP_LOGI(TAG, "Signing took %lld microseconds", end_time - start_time);

    // Verifying
    start_time = esp_timer_get_time();
    if ((ret = mbedtls_rsa_pkcs1_verify(&rsa, MBEDTLS_MD_SHA256, 32, hash, buf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_rsa_pkcs1_verify returned %d", ret);
        goto exit;
    }
    end_time = esp_timer_get_time();
    ESP_LOGI(TAG, "Verification took %lld microseconds", end_time - start_time);



exit:
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}