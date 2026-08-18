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
#include "esp_log.h"
#include "nvs_flash.h"
#include "mbedtls/sha256.h"
#include "cJSON.h"
#include "miner_config.h"

static const char *TAG = "esp-32";

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

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

typedef struct __attribute__((packed)) {
    uint32_t version;
    uint8_t prev_hash[32];
    uint8_t merkle_root[32];
    uint32_t ntime;
    uint32_t nbits;
    uint32_t nonce;
} block_header_t;

static int s_sock = -1;
static SemaphoreHandle_t s_job_mutex;
static SemaphoreHandle_t s_sock_mutex;
static stratum_job_t s_job = {0};
static int s_msg_id = 1;

static int HexDecode(const char *hex_str, uint8_t *out, size_t out_max) {
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

static void Sha256d(const uint8_t *data, size_t len, uint8_t out_hash[32]) {
    uint8_t first_pass[32];
    mbedtls_sha256(data, len, first_pass, 0);
    mbedtls_sha256(first_pass, 32, out_hash, 0);
}

static bool SendLine(int sock, cJSON *msg) {
    char *str = cJSON_PrintUnformatted(msg);
    if (!str) return false;
    size_t len = strlen(str);
    bool ok = (send(sock, str, len, 0) == (ssize_t)len) && (send(sock, "\n", 1, 0) == 1);
    cJSON_free(str);
    return ok;
}

static bool SendLineLocked(cJSON *msg) {
    bool ok = false;
    xSemaphoreTake(s_sock_mutex, portMAX_DELAY);
    if (s_sock >= 0) {
        ok = SendLine(s_sock, msg);
    }
    xSemaphoreGive(s_sock_mutex);
    return ok;
}

static void WifiEventHandler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "wifi: station started, connecting...");
        esp_wifi_connect();
    } else if (id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "wifi: disconnected, retrying...");
        esp_wifi_connect();
    } else if (id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *evt = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "wifi: got IP " IPSTR, IP2STR(&evt->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void WifiInitAndConnect(void) {
    ESP_LOGI(TAG, "wifi: bringing up SSID \"%s\"", WIFI_SSID);
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

    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &WifiEventHandler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &WifiEventHandler, NULL);

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, WIFI_SSID, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, WIFI_PASS, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "wifi: connected, proceeding to pool connection");
}

static void StratumClientTask(void *pvParameters) {
    (void)pvParameters;

    while (1) {
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", POOL_PORT);
        struct addrinfo hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo *res = NULL;

        ESP_LOGI(TAG, "pool: resolving %s:%d", POOL_HOST, POOL_PORT);
        if (getaddrinfo(POOL_HOST, port_str, &hints, &res) != 0 || res == NULL) {
            ESP_LOGW(TAG, "pool: DNS lookup failed, retrying in 5s");
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        xSemaphoreTake(s_sock_mutex, portMAX_DELAY);
        s_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s_sock < 0 || connect(s_sock, res->ai_addr, res->ai_addrlen) != 0) {
            ESP_LOGW(TAG, "pool: connect() failed (errno=%d), retrying in 5s", errno);
            if (s_sock >= 0) close(s_sock);
            s_sock = -1;
            xSemaphoreGive(s_sock_mutex);
            freeaddrinfo(res);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        xSemaphoreGive(s_sock_mutex);
        freeaddrinfo(res);
        ESP_LOGI(TAG, "pool: TCP connected, starting handshake");

        xSemaphoreTake(s_job_mutex, portMAX_DELAY);
        s_job.valid = false;
        xSemaphoreGive(s_job_mutex);

        cJSON *sub_msg = cJSON_CreateObject();
        cJSON_AddNumberToObject(sub_msg, "id", s_msg_id++);
        cJSON_AddStringToObject(sub_msg, "method", "mining.subscribe");
        cJSON *sub_params = cJSON_CreateArray();
        cJSON_AddItemToArray(sub_params, cJSON_CreateString("esp32-stratum-miner/1.0"));
        cJSON_AddItemToObject(sub_msg, "params", sub_params);
        bool sub_ok = SendLineLocked(sub_msg);
        cJSON_Delete(sub_msg);
        ESP_LOGI(TAG, "pool: sent mining.subscribe (ok=%d)", sub_ok);

        cJSON *auth_msg = cJSON_CreateObject();
        cJSON_AddNumberToObject(auth_msg, "id", s_msg_id++);
        cJSON_AddStringToObject(auth_msg, "method", "mining.authorize");
        cJSON *auth_params = cJSON_CreateArray();
        cJSON_AddItemToArray(auth_params, cJSON_CreateString(POOL_USERNAME));
        cJSON_AddItemToArray(auth_params, cJSON_CreateString(POOL_PASSWORD));
        cJSON_AddItemToObject(auth_msg, "params", auth_params);
        bool auth_ok = SendLineLocked(auth_msg);
        cJSON_Delete(auth_msg);
        ESP_LOGI(TAG, "pool: sent mining.authorize as \"%s\" (ok=%d)", POOL_USERNAME, auth_ok);

        if (!sub_ok || !auth_ok) {
            ESP_LOGW(TAG, "pool: handshake send failed, tearing down and retrying");
            xSemaphoreTake(s_sock_mutex, portMAX_DELAY);
            close(s_sock);
            s_sock = -1;
            xSemaphoreGive(s_sock_mutex);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        ESP_LOGI(TAG, "pool: handshake sent, listening for pool messages");

        char chunk[512];
        char s_line_buf[4096];
        size_t s_line_len = 0;

        while (1) {
            int n = recv(s_sock, chunk, sizeof(chunk), 0);
            if (n <= 0) {
                ESP_LOGW(TAG, "pool: recv() returned %d, connection lost", n);
                break; 
            }

            for (int i = 0; i < n; i++) {
                char c = chunk[i];
                if (c == '\n') {
                    s_line_buf[s_line_len] = '\0';
                    if (s_line_len > 0) {
                        ESP_LOGD(TAG, "pool: <- %s", s_line_buf);
                        cJSON *msg = cJSON_Parse(s_line_buf);
                        if (!msg) {
                            ESP_LOGW(TAG, "pool: failed to parse line as JSON: %s", s_line_buf);
                        }
                        if (msg) {
                            cJSON *method = cJSON_GetObjectItem(msg, "method");
                            if (method && cJSON_IsString(method)) {
                                cJSON *params = cJSON_GetObjectItem(msg, "params");
                                if (strcmp(method->valuestring, "mining.notify") == 0 && cJSON_IsArray(params) && cJSON_GetArraySize(params) >= 9) {
                                    stratum_job_t job = {0};
                                    strncpy(job.job_id, cJSON_GetArrayItem(params, 0)->valuestring, sizeof(job.job_id) - 1);

                                    for (int j = 0; j < 32; j += 4) {
                                        uint8_t tmp = job.prev_hash[j];
                                        job.prev_hash[j] = job.prev_hash[j + 3];
                                        job.prev_hash[j + 3] = tmp;
                                        tmp = job.prev_hash[j + 1];
                                        job.prev_hash[j + 1] = job.prev_hash[j + 2];
                                        job.prev_hash[j + 2] = tmp;
                                    }

                                    HexDecode(cJSON_GetArrayItem(params, 1)->valuestring, job.prev_hash, sizeof(job.prev_hash));
                                    int cb1_len = HexDecode(cJSON_GetArrayItem(params, 2)->valuestring, job.coinb1, sizeof(job.coinb1));
                                    job.coinb1_len = cb1_len > 0 ? (size_t)cb1_len : 0;
                                    int cb2_len = HexDecode(cJSON_GetArrayItem(params, 3)->valuestring, job.coinb2, sizeof(job.coinb2));
                                    job.coinb2_len = cb2_len > 0 ? (size_t)cb2_len : 0;

                                    cJSON *branches = cJSON_GetArrayItem(params, 4);
                                    job.merkle_branch_count = cJSON_GetArraySize(branches);
                                    if (job.merkle_branch_count > 32) job.merkle_branch_count = 32;
                                    for (int j = 0; j < job.merkle_branch_count; j++) {
                                        HexDecode(cJSON_GetArrayItem(branches, j)->valuestring, job.merkle_branches[j], 32);
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
                                    ESP_LOGI(TAG, "pool: new job \"%s\" (version=%08" PRIx32 " nbits=%08" PRIx32
                                                  " ntime=%08" PRIx32 " clean_jobs=%d, %d merkle branches)",
                                                  job.job_id, job.version, job.nbits, job.ntime,
                                                  job.clean_jobs, job.merkle_branch_count);
                                } else if (strcmp(method->valuestring, "mining.set_difficulty") == 0 && cJSON_IsArray(params) && cJSON_GetArraySize(params) >= 1) {
                                    double new_diff = cJSON_GetArrayItem(params, 0)->valuedouble;
                                    xSemaphoreTake(s_job_mutex, portMAX_DELAY);
                                    s_job.difficulty = new_diff;
                                    xSemaphoreGive(s_job_mutex);
                                    ESP_LOGI(TAG, "pool: difficulty set to %g", new_diff);
                                } else {
                                    ESP_LOGD(TAG, "pool: unhandled method \"%s\"", method->valuestring);
                                }
                                } else {
                                    cJSON *result = cJSON_GetObjectItem(msg, "result");
                                    if (result && cJSON_IsArray(result)) {
                                        int r_size = cJSON_GetArraySize(result);
                                        if (r_size >= 2) {
                                            cJSON *first_item = cJSON_GetArrayItem(result, 0);
                                            const char *extranonce1_hex = NULL;
                                            int e2_size = 0;

                                            if (cJSON_IsArray(first_item) && r_size >= 3) {
                                                extranonce1_hex = cJSON_GetArrayItem(result, 1)->valuestring;
                                                e2_size = cJSON_GetArrayItem(result, 2)->valueint;
                                            } else if (cJSON_IsString(first_item)) {
                                                extranonce1_hex = first_item->valuestring;
                                                e2_size = cJSON_GetArrayItem(result, 1)->valueint;
                                            }

                                            if (extranonce1_hex) {
                                                xSemaphoreTake(s_job_mutex, portMAX_DELAY);
                                                int len = HexDecode(extranonce1_hex, s_job.extranonce1, sizeof(s_job.extranonce1));
                                                s_job.extranonce1_len = len > 0 ? (size_t)len : 0;
                                                s_job.extranonce2_size = (size_t)e2_size;
                                                xSemaphoreGive(s_job_mutex);
                                                ESP_LOGI(TAG, "pool: subscribed, extranonce1=%s extranonce2_size=%d",
                                                        extranonce1_hex, e2_size);
                                            }
                                        }
                                    } else if (result) {
                                        ESP_LOGD(TAG, "pool: reply result received (likely authorize/submit ack)");
                                    }
                                    
                                    cJSON *error = cJSON_GetObjectItem(msg, "error");
                                    if (error && !cJSON_IsNull(error)) {
                                        char *err_str = cJSON_PrintUnformatted(error);
                                        ESP_LOGW(TAG, "pool: error reply: %s", err_str ? err_str : "(unprintable)");
                                        cJSON_free(err_str);
                                    }
                                }
                        }
                        cJSON_Delete(msg);
                    }
                    s_line_len = 0;
                } else if (s_line_len < 4095) {
                    s_line_buf[s_line_len++] = c;
                } else {
                    s_line_len = 0;
                }
            }
        }
        xSemaphoreTake(s_sock_mutex, portMAX_DELAY);
        close(s_sock);
        s_sock = -1;
        xSemaphoreGive(s_sock_mutex);
        ESP_LOGI(TAG, "pool: reconnecting in 3s");
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

static void MinerTask(void *pvParameters) {
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
            static bool logged_waiting = false;
            if (!logged_waiting) {
                ESP_LOGI(TAG, "miner: no job yet, waiting for pool...");
                logged_waiting = true;
            }
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        if (strcmp(current_job_id, job_snapshot.job_id) != 0) {
            strncpy(current_job_id, job_snapshot.job_id, sizeof(current_job_id) - 1);
            extranonce2_counter = 0;
            double diff = job_snapshot.difficulty > 0 ? job_snapshot.difficulty : 1.0;
            ESP_LOGI(TAG, "miner: switching to job \"%s\" (difficulty=%g)", job_snapshot.job_id, diff);

            static const uint8_t diff1_target[32] = {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0};
            uint64_t high64 = 0;
            for (int i = 0; i < 8; i++) high64 = (high64 << 8) | diff1_target[i];
            uint64_t scaled = (uint64_t)((double)high64 / diff);
            memset(target, 0, 32);
            for (int i = 7; i >= 0; i--) {
                target[i] = scaled & 0xff;
                scaled >>= 8;
            }
            char target_hex[65];
            static const char hexd[] = "0123456789abcdef";
            for (int i = 0; i < 32; i++) {
                target_hex[i * 2] = hexd[(target[i] >> 4) & 0xf];
                target_hex[i * 2 + 1] = hexd[target[i] & 0xf];
            }
            target_hex[64] = '\0';
            ESP_LOGI(TAG, "miner: target for this job = %s", target_hex);
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
        Sha256d(coinbase, pos, acc);
        uint8_t pair[64];
        for (int i = 0; i < job_snapshot.merkle_branch_count; i++) {
            memcpy(pair, acc, 32);
            memcpy(pair + 32, job_snapshot.merkle_branches[i], 32);
            Sha256d(pair, 64, acc);
        }

        header.version = job_snapshot.version;
        memcpy(header.prev_hash, job_snapshot.prev_hash, 32);
        memcpy(header.merkle_root, acc, 32);
        header.ntime = job_snapshot.ntime;
        header.nbits = job_snapshot.nbits;

        const uint32_t BATCH = 200000;
        const uint32_t YIELD_EVERY = 2000;

        for (uint32_t n = 0; n < BATCH; n++) {
            if ((n % YIELD_EVERY) == 0) {
                vTaskDelay(1);
            }
            header.nonce = n;
            uint8_t hash[32];
            Sha256d((const uint8_t *)&header, sizeof(header), hash);

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
                SendLineLocked(msg);
                cJSON_Delete(msg);
            }
        }
        extranonce2_counter++; 
        vTaskDelay(pdMS_TO_TICKS(1)); 
    }
}

void app_main(void) {
    WifiInitAndConnect();

    s_job_mutex = xSemaphoreCreateMutex();
    s_sock_mutex = xSemaphoreCreateMutex();

    xTaskCreatePinnedToCore(StratumClientTask, "stratum", 8192 * 2, NULL, 5, NULL, 0);
    xTaskCreatePinnedToCore(MinerTask, "miner", 8192, NULL, 5, NULL, 1);
}
