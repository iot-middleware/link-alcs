#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "iot_import.h"
#include "iot_import_aes.h"

#include "mbedtls/aes.h"
#define AES_BLOCK_SIZE 16

typedef struct {
    mbedtls_aes_context ctx;
    uint8_t iv[33];
} platform_aes_t;

p_HAL_Aes128_t HAL_Aes128_Init(
            _IN_ const uint8_t *key,
            _IN_ const uint8_t *iv,
            _IN_ AES_DIR_t dir)
{

    int ret = 0;
    platform_aes_t *p_aes128 = NULL;
    p_aes128 = (platform_aes_t *)calloc(1, sizeof(platform_aes_t));
    memset (p_aes128, 0, sizeof(platform_aes_t));

    mbedtls_aes_init(&p_aes128->ctx);

    if (dir == HAL_AES_ENCRYPTION) {
        ret = mbedtls_aes_setkey_enc(&p_aes128->ctx, key, 128);
    } else {
        ret = mbedtls_aes_setkey_dec(&p_aes128->ctx, key, 128);
    }

    memcpy(p_aes128->iv, iv, 16);

    if (ret != 0) {
        free(p_aes128);
        p_aes128 = NULL;
    }

    return (p_HAL_Aes128_t *)p_aes128;
}

int HAL_Aes128_Cbc_Encrypt(
            _IN_ p_HAL_Aes128_t aes,
            _IN_ const void *src,
            _IN_ size_t blockNum,
            _OU_ void *dst)
{
    int ret = 0;
    platform_aes_t *p_aes128 = (platform_aes_t *)aes;

    int i;
    for (i = 0; i < blockNum; ++i) {
        ret = mbedtls_aes_crypt_cbc(&p_aes128->ctx, MBEDTLS_AES_ENCRYPT, AES_BLOCK_SIZE,
                                    p_aes128->iv, src, dst);
        src += 16;
        dst += 16;
    }

    return ret;
}

int HAL_Aes128_Cbc_Decrypt(
            _IN_ p_HAL_Aes128_t aes,
            _IN_ const void *src,
            _IN_ size_t blockNum,
            _OU_ void *dst)
{
    int ret = 0;
    platform_aes_t *p_aes128 = (platform_aes_t *)aes;

    int i = 0;
    for (i = 0; i < blockNum; ++i) {
        ret = mbedtls_aes_crypt_cbc(&p_aes128->ctx, MBEDTLS_AES_DECRYPT, AES_BLOCK_SIZE,
                                    p_aes128->iv, src, dst);
        src += 16;
        dst += 16;
    }

    return ret;
}

int HAL_Aes128_Destroy(_IN_ p_HAL_Aes128_t aes)
{
    mbedtls_aes_free(&((platform_aes_t *)aes)->ctx);
    free(aes);

    return 0;
}


