#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "kv.h"
#include "cJSON.h"
#include "utils_base64.h"
#include "iot_import.h"

struct kv_file_s {
    char filename[128];
    cJSON *json_root;

    void* lock;
};

/*
 * update KV file atomically:
 *   step 1. save data in temporary file
 *   step 2. rename temporary file to the orignal one
 */
static int kv_sync(kv_file_t *file)
{
    char *json = cJSON_Print(file->json_root);
    if (!json)
        return -1;

    /* create temporary file in the same directory as orignal KV file */
    char fullpath[128] = {0};
    strncpy(fullpath, file->filename, sizeof(fullpath) - 1);

    char *dname = dirname(fullpath);
    char *template = "/tmpfile.XXXXXX";

    int pathlen = strlen(dname) + strlen(template) + 1;
    if (pathlen > sizeof(fullpath)) {
        HAL_Free(json);
        return -1;
    }

    if (dname == fullpath) {    /* see dirname man-page for more detail */
        strcat(fullpath, template);
    } else {
        strcpy(fullpath, dname);
        strcat(fullpath, template);
    }

    int tmpfd = mkstemp(fullpath);
    if (tmpfd < 0) {
        perror("kv_sync open");
        HAL_Free(json);
        return -1;
    }

    /* write json data into temporary file */
    int len = strlen(json) + 1;
    if (write(tmpfd, json, len) != len) {
        perror("kv_sync write");
        close(tmpfd);
        HAL_Free(json);
        return -1;
    }

    fsync(tmpfd);
    close(tmpfd);
    HAL_Free(json);

    /* save KV file atomically */
    if (rename(fullpath, file->filename) < 0) {
        perror("rename");
        return -1;
    }

    return 0;
}

static char *read_file(char *filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        return NULL;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }

    char *buf = HAL_Malloc (st.st_size);
    if (!buf) {
        close(fd);
        return NULL;
    }

    if (read(fd, buf, st.st_size) != st.st_size) {
        HAL_Free(buf);
        close(fd);
        return NULL;
    }

    close(fd);

    return buf;
}

static int create_json_file(char *filename)
{
    int fd = open(filename, O_CREAT | O_RDWR, 0644);
    if (fd < 0)
        return -1;

    if (write(fd, "{}", 3) != 3) {  /* 3 = '{}' + null terminator */
        close(fd);
        return -1;
    }

    if (fsync(fd) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

kv_file_t *kv_open(char *filename)
{
    kv_file_t *file = HAL_Malloc (sizeof(kv_file_t));
    if (!file)
        return NULL;
    memset(file, 0, sizeof(kv_file_t));

    if (strlen(filename) > sizeof(file->filename) - 1) {
        printf("filename %s is too long\n", filename);
        goto fail;
    }

    strncpy(file->filename, filename, sizeof(file->filename) - 1);

    if (access(file->filename, F_OK) < 0) {
        /* create KV file when not exist */
        if (create_json_file(file->filename) < 0)
            goto fail;
    }

    char *json = read_file(filename);
    if (!json)
        goto fail;

    file->json_root = cJSON_Parse(json);
    if (!file->json_root) {
        HAL_Free(json);
        goto fail;
    }

    file->lock = HAL_MutexCreate ();
    HAL_Free(json);

    return file;

fail:
    if (file->json_root)
        cJSON_Delete(file->json_root);
    HAL_Free(file);

    return NULL;
}

int kv_close(kv_file_t *file)
{
    if (!file)
        return -1;

    HAL_MutexDestroy (file->lock);

    if (file->json_root)
        cJSON_Delete(file->json_root);
    HAL_Free(file);

    return 0;
}

int kv_get(kv_file_t *file, char *key, char *value, int value_len)
{
    if (!file || !file->json_root || !key || !value || value_len <= 0)
        return -1;

    HAL_MutexLock (file->lock);

    cJSON *obj = cJSON_GetObjectItem(file->json_root, key);
    if (!obj) {
        HAL_MutexUnlock (file->lock);
        return -1;
    }

    strncpy(value, obj->valuestring, value_len - 1);
    value[value_len - 1] = '\0';

    HAL_MutexUnlock (file->lock);

    return 0;
}

int kv_set(kv_file_t *file, char *key, char *value)
{
    if (!file || !file->json_root || !key || !value)
        return -1;

    HAL_MutexLock(file->lock);
    /* remove old value if exist */
    cJSON_DeleteItemFromObject(file->json_root, key);
    cJSON_AddItemToObject(file->json_root, key, cJSON_CreateString(value));

    int ret = kv_sync(file);
    HAL_MutexUnlock(file->lock);

    return ret;
}

int kv_del(kv_file_t *file, char *key)
{
    if (!file || !file->json_root || !key)
        return -1;

    /* remove old value if exist */
    HAL_MutexLock(file->lock);
    cJSON_DeleteItemFromObject(file->json_root, key);
    int ret = kv_sync(file);
    HAL_MutexUnlock(file->lock);

    return ret;
}

#define BASE64_ENCODE_SIZE(x)  (((x)+2) / 3 * 4 + 1)
#define BASE64_DECODE_SIZE(x) ((x) * 3LL / 4)
int kv_set_blob(kv_file_t *file, char *key, void *value, int value_len)
{
    uint32_t encoded_len = BASE64_ENCODE_SIZE(value_len);

    char *encoded = HAL_Malloc (encoded_len);
    if (!encoded)
        return -1;

    utils_base64encode (value, value_len, encoded_len, (uint8_t *)encoded, &encoded_len);
    encoded[encoded_len] = 0;
    int ret = kv_set(file, key, encoded);

    HAL_Free (encoded);

    return ret;
}

int kv_get_blob(kv_file_t *file, char *key, void *value, int *value_len)
{
    if (!file || !file->json_root || !key || !value || !value_len || *value_len <= 0)
        return -1;

    HAL_MutexLock (file->lock);

    cJSON *obj = cJSON_GetObjectItem(file->json_root, key);
    do {
        if (!obj) {
            break;
        }
        uint32_t data_len = strlen(obj->valuestring);
        uint32_t decode_len = BASE64_DECODE_SIZE(data_len);
        uint8_t *decoded = HAL_Malloc (decode_len);
        if (!decoded) {
            break;
        }
        if (utils_base64decode((uint8_t*)obj->valuestring, data_len, decode_len, decoded, &decode_len) < 0) {
            HAL_Free(decoded);
            break;
        }
        if (decode_len > *value_len) {
            HAL_Free(decoded);
            break;
        }

        memset (value, 0, *value_len);
        strncpy(value, (char*)decoded, decode_len);
        HAL_Free(decoded);
        *value_len = decode_len;

        HAL_MutexUnlock(file->lock);
        return 0;
    } while (0);

    printf ("\nkv_get_blob return -1\n");
    HAL_MutexUnlock(file->lock);
    return -1;
}

