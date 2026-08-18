#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netdb.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "mbedtls/sha256.h"
#include "cJSON.h"
#include "miner_config.h"

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

// Job data
typedef struct {
    char job_id[64];
    uint8_t prev_hash[32];
    uint8_t coinb1[256];
    size_t coinb1_len;
    uint8_t coinb2[256];
    size_t coinb2_len;
    uint8_t merkle_branches[32][32];
    int merkle_branch_count;
    uint32_t version;
    uint32_t nbits;
    uint32_t ntime;
    bool clean_jobs;
    uint8_t extranonce1[32];
    size_t extranonce1_len;
    size_t extranonce2_size;
    double difficulty;
    bool valid;
} stratum_job_t;

// Block header
typedef struct __attribute__((packed)) {
    uint32_t version;
    uint8_t prev_hash[32];
    uint8_t merkle_root[32];
    uint32_t ntime;
    uint32_t nbits;
    uint32_t nonce;
} block_header_t;

// State variables
static int s_sock = -1;
static SemaphoreHandle_t s_job_mutex;
static SemaphoreHandle_t s_sock_mutex;
static stratum_job_t s_job = {0};
static int s_msg_id = 1;

static int hex_decode(const char *hex_str, uint8_t *out, size_t out_max) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) return -1;
    size_t out_len = len / 2;
    if (out_len > out_max) return -1;
    for (size_t i = 0; i < out_len; i++) {
        char hi_c = hex_str[i * 2], lo_c = hex_str[i * 2 + 1];
        int hi = (hi_c >= '0' && hi_c <= '9') ? hi_c - '0' : (hi_c >= 'a' && hi_c <= 'f') ? hi_c - 'a' + 10 : (hi_c >= 'A' && hi_c <= 'F') ? hi_c - 'A' + 10 : -1;
        int lo = (lo_c >= '0' && lo_c <= '9') ? lo_c - '0' : (lo_c >= 'a' && lo_c <= 'f') ? lo_c - 'a' + 10 : (lo_c >= 'A' && lo_c <= 'F') ? lo_c - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)out_len;
}

static void sha256d(const uint8_t *data, size_t len, uint8_t out_hash[32]) {
    uint8_t first_pass[32];
    mbedtls_sha256(data, len, first_pass, 0);
    mbedtls_sha256(first_pass, 32, out_hash, 0);
}

static bool send_line(int sock, cJSON *msg) {
    char *str = cJSON_PrintUnformatted(msg);
    if (!str) return false;
    size_t len = strlen(str);
    bool ok = (send(sock, str, len, 0) == (ssize_t)len) && (send(sock, "\n", 1, 0) == 1);
    cJSON_free(str);
    return ok;
}

static bool send_line_locked(cJSON *msg) {
    bool ok = false;
    xSemaphoreTake(s_sock_mutex, portMAX_DELAY);
    if (s_sock >= 0) {
        ok = send_line(s_sock, msg);
    }
    xSemaphoreGive(s_sock_mutex);
    return ok;
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_DISCONNECTED) esp_wifi_connect();
    else if (id == IP_EVENT_STA_GOT_IP) xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
}

static void wifi_init_and_connect(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_flash_init();
    }
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL);

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, WIFI_SSID, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, WIFI_PASS, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
        
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
}

static void stratum_client_task(void *pvParameters) {
    (void)pvParameters;

    while (1) {
        // DNS lookup and TCP connection
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", POOL_PORT);
        struct addrinfo hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo *res = NULL;

        if (getaddrinfo(POOL_HOST, port_str, &hints, &res) != 0 || res == NULL) {
            // Could not resolve host address, spin for 5s
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        xSemaphoreTake(s_sock_mutex, portMAX_DELAY);
        s_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s_sock < 0 || connect(s_sock, res->ai_addr, res->ai_addrlen) != 0) {
            if (s_sock >= 0) close(s_sock);
            s_sock = -1;
            xSemaphoreGive(s_sock_mutex);
            freeaddrinfo(res);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        xSemaphoreGive(s_sock_mutex);
        freeaddrinfo(res);

        // New job published, discard previous job
        xSemaphoreTake(s_job_mutex, portMAX_DELAY);
        s_job.valid = false;
        xSemaphoreGive(s_job_mutex);

        // Subscribe as esp-32/1.0
        cJSON *sub_msg = cJSON_CreateObject();
        cJSON_AddNumberToObject(sub_msg, "id", s_msg_id++);
        cJSON_AddStringToObject(sub_msg, "method", "mining.subscribe");
        cJSON *sub_params = cJSON_CreateArray();
        cJSON_AddItemToArray(sub_params, cJSON_CreateString("esp-32/1.0"));
        cJSON_AddItemToObject(sub_msg, "params", sub_params);
        bool sub_ok = send_line_locked(sub_msg);
        cJSON_Delete(sub_msg);

        // Authorize
        cJSON *auth_msg = cJSON_CreateObject();
        cJSON_AddNumberToObject(auth_msg, "id", s_msg_id++);
        cJSON_AddStringToObject(auth_msg, "method", "mining.authorize");
        cJSON *auth_params = cJSON_CreateArray();
        cJSON_AddItemToArray(auth_params, cJSON_CreateString(POOL_USERNAME));
        cJSON_AddItemToArray(auth_params, cJSON_CreateString(POOL_PASSWORD));
        cJSON_AddItemToObject(auth_msg, "params", auth_params);
        bool auth_ok = send_line_locked(auth_msg);
        cJSON_Delete(auth_msg);

        if (!sub_ok || !auth_ok) {
            // Network failure, retry
            xSemaphoreTake(s_sock_mutex, portMAX_DELAY);
            close(s_sock);
            s_sock = -1;
            xSemaphoreGive(s_sock_mutex);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        char chunk[512];
        char s_line_buf[4096];
        size_t s_line_len = 0;

        while (1) {
            int n = recv(s_sock, chunk, sizeof(chunk), 0);
            if (n <= 0) break;
            
            // Re-assemble lines
            for (int i = 0; i < n; i++) {
                char c = chunk[i];
                if (c == '\n') {
                    s_line_buf[s_line_len] = '\0';
                    if (s_line_len > 0) {
                        cJSON *msg = cJSON_Parse(s_line_buf);
                        if (msg) {
                            cJSON *method = cJSON_GetObjectItem(msg, "method");
                            if (method && cJSON_IsString(method)) {
                                cJSON *params = cJSON_GetObjectItem(msg, "params");
                                if (strcmp(method->valuestring, "mining.notify") == 0 && cJSON_IsArray(params) && cJSON_GetArraySize(params) >= 9) {

                                    stratum_job_t job = {0};
                                    strncpy(job.job_id, cJSON_GetArrayItem(params, 0)->valuestring, sizeof(job.job_id) - 1);
                                    hex_decode(cJSON_GetArrayItem(params, 1)->valuestring, job.prev_hash, sizeof(job.prev_hash));
                                    int cb1_len = hex_decode(cJSON_GetArrayItem(params, 2)->valuestring, job.coinb1, sizeof(job.coinb1));
                                    job.coinb1_len = cb1_len > 0 ? (size_t)cb1_len : 0;
                                    int cb2_len = hex_decode(cJSON_GetArrayItem(params, 3)->valuestring, job.coinb2, sizeof(job.coinb2));
                                    job.coinb2_len = cb2_len > 0 ? (size_t)cb2_len : 0;

                                    cJSON *branches = cJSON_GetArrayItem(params, 4);
                                    job.merkle_branch_count = cJSON_GetArraySize(branches);

                                    if (job.merkle_branch_count > 32) job.merkle_branch_count = 32;
                                    for (int j = 0; j < job.merkle_branch_count; j++) {
                                        hex_decode(cJSON_GetArrayItem(branches, j)->valuestring, job.merkle_branches[j], 32);
                                    }

                                    job.version = (uint32_t)strtoul(cJSON_GetArrayItem(params, 5)->valuestring, NULL, 16);
                                    job.nbits = (uint32_t)strtoul(cJSON_GetArrayItem(params, 6)->valuestring, NULL, 16);
                                    job.ntime = (uint32_t)strtoul(cJSON_GetArrayItem(params, 7)->valuestring, NULL, 16);
                                    job.clean_jobs = cJSON_IsTrue(cJSON_GetArrayItem(params, 8));
                                    job.valid = true;

                                    xSemaphoreTake(s_job_mutex, portMAX_DELAY);
                                    job.extranonce1_len = s_job.extranonce1_len;
                                    memcpy(job.extranonce1, s_job.extranonce1, sizeof(job.extranonce1));
                                    job.extranonce2_size = s_job.extranonce2_size;
                                    job.difficulty = s_job.difficulty > 0 ? s_job.difficulty : 1.0;
                                    s_job = job;
                                    xSemaphoreGive(s_job_mutex);
                                } else if (strcmp(method->valuestring, "mining.set_difficulty") == 0 && cJSON_IsArray(params) && cJSON_GetArraySize(params) >= 1) {
                                    xSemaphoreTake(s_job_mutex, portMAX_DELAY);
                                    s_job.difficulty = cJSON_GetArrayItem(params, 0)->valuedouble;
                                    xSemaphoreGive(s_job_mutex);
                                }
                            } else {
                                cJSON *result = cJSON_GetObjectItem(msg, "result");
                                if (result && cJSON_IsArray(result) && cJSON_GetArraySize(result) >= 3) {
                                    xSemaphoreTake(s_job_mutex, portMAX_DELAY);
                                    int len = hex_decode(cJSON_GetArrayItem(result, 1)->valuestring, s_job.extranonce1, sizeof(s_job.extranonce1));
                                    s_job.extranonce1_len = len > 0 ? (size_t)len : 0;
                                    s_job.extranonce2_size = (size_t)cJSON_GetArrayItem(result, 2)->valueint;
                                    xSemaphoreGive(s_job_mutex);
                                }
                            }
                            cJSON_Delete(msg);
                        }
                        s_line_len = 0;
                    }
                } 
                
                else if (s_line_len < 4095) s_line_buf[s_line_len++] = c;
                else s_line_len = 0;
            }
        }
        
        // Network failure
        xSemaphoreTake(s_sock_mutex, portMAX_DELAY);
        close(s_sock);
        s_sock = -1;
        xSemaphoreGive(s_sock_mutex);
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

static void miner_task(void *pvParameters) {
    (void)pvParameters;
    uint32_t extranonce2_counter = 0;
    char current_job_id[64] = {0};
    block_header_t header = {0};
    uint8_t target[32] = {0};
    stratum_job_t job_snapshot = {0};

    while (1) {
        xSemaphoreTake(s_job_mutex, portMAX_DELAY);
        bool have_job = s_job.valid;
        if (have_job) job_snapshot = s_job;
        xSemaphoreGive(s_job_mutex);

        if (!have_job) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        if (strcmp(current_job_id, job_snapshot.job_id) != 0) {

            strncpy(current_job_id, job_snapshot.job_id, sizeof(current_job_id) - 1);
            extranonce2_counter = 0;
            double diff = job_snapshot.difficulty > 0 ? job_snapshot.difficulty : 1.0;

            static const uint8_t diff1_target[32] = {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0};
            uint64_t high64 = 0;
            for (int i = 0; i < 8; i++) high64 = (high64 << 8) | diff1_target[i];
            uint64_t scaled = (uint64_t)((double)high64 / diff);
            memset(target, 0, 32);
            for (int i = 7; i >= 0; i--) {
                target[i] = scaled & 0xff;
                scaled >>= 8;
            }
        }

        uint8_t extranonce2[8] = {0};
        size_t e2_size = job_snapshot.extranonce2_size;
        if (e2_size > sizeof(extranonce2)) e2_size = sizeof(extranonce2);
        for (size_t i = 0; i < e2_size && i < 4; i++) {
            extranonce2[e2_size - 1 - i] = (uint8_t)(extranonce2_counter >> (8 * i));
        }

        uint8_t coinbase[512];
        size_t pos = 0;
        memcpy(coinbase + pos, job_snapshot.coinb1, job_snapshot.coinb1_len);
        pos += job_snapshot.coinb1_len;
        memcpy(coinbase + pos, job_snapshot.extranonce1, job_snapshot.extranonce1_len);
        pos += job_snapshot.extranonce1_len;
        memcpy(coinbase + pos, extranonce2, e2_size);
        pos += e2_size;
        memcpy(coinbase + pos, job_snapshot.coinb2, job_snapshot.coinb2_len);
        pos += job_snapshot.coinb2_len;

        uint8_t acc[32];
        sha256d(coinbase, pos, acc);
        uint8_t pair[64];
        for (int i = 0; i < job_snapshot.merkle_branch_count; i++) {
            memcpy(pair, acc, 32);
            memcpy(pair + 32, job_snapshot.merkle_branches[i], 32);
            sha256d(pair, 64, acc);
        }

        // Assemble header
        header.version = job_snapshot.version;
        memcpy(header.prev_hash, job_snapshot.prev_hash, 32);
        memcpy(header.merkle_root, acc, 32);
        header.ntime = job_snapshot.ntime;
        header.nbits = job_snapshot.nbits;

        for (uint32_t n = 0; n < 200000; n++) {
            header.nonce = n;
            uint8_t hash[32];
            sha256d((const uint8_t *)&header, sizeof(header), hash);

            uint8_t hash_display[32];
            for (int i = 0; i < 32; i++) {
                hash_display[i] = hash[31 - i];
            }

            bool meets_target = true;
            for (int i = 0; i < 32; i++) {
                if (hash_display[i] < target[i]) break;
                if (hash_display[i] > target[i]) { meets_target = false; break; }
            }

            if (meets_target && s_sock >= 0) {
                char extranonce2_hex[17];
                static const char digits[] = "0123456789abcdef";
                for (size_t i = 0; i < e2_size; i++) {
                    extranonce2_hex[i * 2] = digits[(extranonce2[i] >> 4) & 0xf];
                    extranonce2_hex[i * 2 + 1] = digits[extranonce2[i] & 0xf];
                }
                extranonce2_hex[e2_size * 2] = '\0';

                char ntime_hex[9], nonce_hex[9];
                snprintf(ntime_hex, sizeof(ntime_hex), "%08" PRIx32, header.ntime);
                snprintf(nonce_hex, sizeof(nonce_hex), "%08" PRIx32, n);

                cJSON *msg = cJSON_CreateObject();
                cJSON_AddNumberToObject(msg, "id", s_msg_id++);
                cJSON_AddStringToObject(msg, "method", "mining.submit");
                cJSON *params = cJSON_CreateArray();
                cJSON_AddItemToArray(params, cJSON_CreateString(POOL_USERNAME));
                cJSON_AddItemToArray(params, cJSON_CreateString(job_snapshot.job_id));
                cJSON_AddItemToArray(params, cJSON_CreateString(extranonce2_hex));
                cJSON_AddItemToArray(params, cJSON_CreateString(ntime_hex));
                cJSON_AddItemToArray(params, cJSON_CreateString(nonce_hex));
                cJSON_AddItemToObject(msg, "params", params);
                send_line_locked(msg);
                cJSON_Delete(msg);
            }
        }
        extranonce2_counter++;
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

void app_main(void) {
    wifi_init_and_connect();

    s_job_mutex = xSemaphoreCreateMutex();
    s_sock_mutex = xSemaphoreCreateMutex();

    xTaskCreatePinnedToCore(stratum_client_task, "stratum", 8192, NULL, 5, NULL, 0);
    xTaskCreatePinnedToCore(miner_task, "miner", 8192, NULL, 5, NULL, 1);
}
