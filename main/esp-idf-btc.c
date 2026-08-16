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

static int hex_decode (const char *hex_str, uint8_t *out, size_t out_max) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) return -1;
    size_t out_len = len / 2;
    if (out_len > out_max) return -1;

    for (size_t i = 0; i < out_len; i++) {
        char hi_c = hex_str[i * 2], lo_c = hex_str[i * 2 + 1];
        int hi = (hi_c >= '0' && hi_c <= '9') ? hi_c - '0' :
                 (hi_c >= 'a' && hi_c <= 'f') ? hi_c - 'a' + 10 :
                 (hi_c >= 'A' && hi_c <= 'F') ? hi_c - 'A' + 10 : -1;
        int lo = (lo_c >= '0' && lo_c <= '9') ? lo_c - '0' :
                 (lo_c >= 'a' && lo_c <= 'f') ? lo_c - 'a' + 10 :
                 (lo_c >= 'A' && lo_c <= 'F') ? lo_c - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int) out_len;
}

static void hex_encode (const uint8_t *data, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = digits[(data[i] >> 4) & 0xf];
        out[i * 2 + 1] = digits[data[i] & 0xf];
    }
    out[len * 2] = '\0';
}

static void sha256d (const uint8_t *data, size_t len, uint8_t out_hash[32]) {
    uint8_t first_pass[32];
    mbedtls_sha256(data, len, first_pass, 0);
    mbedtls_sha256(first_pass, 32, out_hash, 0);
}

static void reverse_bytes (uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        uint8_t tmp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }
}

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static void wifi_event_handler (void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "wifi disconnected, retrying...");
        xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_connect_blocking (void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, WIFI_SSID, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, WIFI_PASS, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "connecting to SSID: %s", WIFI_SSID);
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "WiFi connected");
}

#define MAX_COINBASE_PART_LEN   256
#define MAX_MERKLE_BRANCHES     32
#define MAX_JOB_ID_LEN          64
#define MAX_EXTRANONCE1_LEN     32

typedef struct {
    char     job_id[MAX_JOB_ID_LEN];
    uint8_t  prev_hash[32];

    uint8_t  coinb1[MAX_COINBASE_PART_LEN];
    size_t   coinb1_len;
    uint8_t  coinb2[MAX_COINBASE_PART_LEN];
    size_t   coinb2_len;
    uint8_t  merkle_branches[MAX_MERKLE_BRANCHES][32];
    int      merkle_branch_count;
    uint32_t version;
    uint32_t nbits;
    uint32_t ntime;
    bool     clean_jobs;
    uint8_t  extranonce1[MAX_EXTRANONCE1_LEN];
    size_t   extranonce1_len;
    size_t   extranonce2_size;
    double   difficulty;
    bool     valid;
} stratum_job_t;

static int s_sock = -1;
static SemaphoreHandle_t s_job_mutex;
static stratum_job_t s_job = {0};
static int s_msg_id = 1;

#define LINE_BUF_SIZE 4096
static char s_line_buf[LINE_BUF_SIZE];
static size_t s_line_len = 0;

static stratum_job_t *stratum_job_lock (void)   { xSemaphoreTake(s_job_mutex, portMAX_DELAY); return &s_job; }
static void stratum_job_unlock (void)           { xSemaphoreGive(s_job_mutex); }

static int connect_to_pool (void) {
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", POOL_PORT);

    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int err = getaddrinfo(POOL_HOST, port_str, &hints, &res);
    if (err != 0 || res == NULL) {
        ESP_LOGE(TAG, "DNS lookup failed for %s: %d", POOL_HOST, err);
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket() failed: errno %d", errno);
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        ESP_LOGE(TAG, "connect() to %s:%d failed: errno %d", POOL_HOST, POOL_PORT, errno);
        close(sock);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    ESP_LOGI(TAG, "connected to pool %s:%d", POOL_HOST, POOL_PORT);
    return sock;
}

static bool send_line (int sock, cJSON *msg) {
    char *str = cJSON_PrintUnformatted(msg);
    if (!str) return false;
    size_t len = strlen(str);
    bool ok = (send(sock, str, len, 0) == (ssize_t)len) && (send(sock, "\n", 1, 0) == 1);
    ESP_LOGD(TAG, "-> %s", str);
    cJSON_free(str);
    return ok;
}

static bool send_subscribe (int sock) {
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddNumberToObject(msg, "id", s_msg_id++);
    cJSON_AddStringToObject(msg, "method", "mining.subscribe");
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString("esp32-stratum-miner/1.0"));
    cJSON_AddItemToObject(msg, "params", params);
    bool ok = send_line(sock, msg);
    cJSON_Delete(msg);
    return ok;
}

static bool send_authorize (int sock) {
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddNumberToObject(msg, "id", s_msg_id++);
    cJSON_AddStringToObject(msg, "method", "mining.authorize");
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(POOL_USERNAME));
    cJSON_AddItemToArray(params, cJSON_CreateString(POOL_PASSWORD));
    cJSON_AddItemToObject(msg, "params", params);
    bool ok = send_line(sock, msg);
    cJSON_Delete(msg);
    return ok;
}

static bool stratum_submit_share(
    const char *job_id,
    const uint8_t *extranonce2,
    size_t extranonce2_len,
    uint32_t ntime,
    uint32_t nonce) {

    if (s_sock < 0) return false;

    char extranonce2_hex[MAX_EXTRANONCE1_LEN * 2 + 1];
    hex_encode(extranonce2, extranonce2_len, extranonce2_hex);
    char ntime_hex[9], nonce_hex[9];
    snprintf(ntime_hex, sizeof(ntime_hex), "%08" PRIx32, ntime);
    snprintf(nonce_hex, sizeof(nonce_hex), "%08" PRIx32, nonce);

    cJSON *msg = cJSON_CreateObject();
    cJSON_AddNumberToObject(msg, "id", s_msg_id++);
    cJSON_AddStringToObject(msg, "method", "mining.submit");
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(POOL_USERNAME));
    cJSON_AddItemToArray(params, cJSON_CreateString(job_id));
    cJSON_AddItemToArray(params, cJSON_CreateString(extranonce2_hex));
    cJSON_AddItemToArray(params, cJSON_CreateString(ntime_hex));
    cJSON_AddItemToArray(params, cJSON_CreateString(nonce_hex));
    cJSON_AddItemToObject(msg, "params", params);

    ESP_LOGI(TAG, "submitting share: job=%s extranonce2=%s ntime=%s nonce=%s",
             job_id, extranonce2_hex, ntime_hex, nonce_hex);

    bool ok = send_line(s_sock, msg);
    cJSON_Delete(msg);
    return ok;
}

static void handle_notify (cJSON *params) {
    if (!cJSON_IsArray(params) || cJSON_GetArraySize(params) < 9) {
        ESP_LOGW(TAG, "malformed mining.notify, ignoring");
        return;
    }

    stratum_job_t job = {0};
    strncpy(job.job_id, cJSON_GetArrayItem(params, 0)->valuestring, sizeof(job.job_id) - 1);
    hex_decode(cJSON_GetArrayItem(params, 1)->valuestring, job.prev_hash, sizeof(job.prev_hash));

    int coinb1_len = hex_decode(cJSON_GetArrayItem(params, 2)->valuestring, job.coinb1, sizeof(job.coinb1));
    job.coinb1_len = coinb1_len > 0 ? (size_t)coinb1_len : 0;
    int coinb2_len = hex_decode(cJSON_GetArrayItem(params, 3)->valuestring, job.coinb2, sizeof(job.coinb2));
    job.coinb2_len = coinb2_len > 0 ? (size_t)coinb2_len : 0;

    cJSON *branches = cJSON_GetArrayItem(params, 4);
    int branch_count = cJSON_GetArraySize(branches);
    if (branch_count > MAX_MERKLE_BRANCHES) branch_count = MAX_MERKLE_BRANCHES;
    for (int i = 0; i < branch_count; i++) {
        hex_decode(cJSON_GetArrayItem(branches, i)->valuestring, job.merkle_branches[i], 32);
    }
    job.merkle_branch_count = branch_count;

    job.version = (uint32_t)strtoul(cJSON_GetArrayItem(params, 5)->valuestring, NULL, 16);
    job.nbits   = (uint32_t)strtoul(cJSON_GetArrayItem(params, 6)->valuestring, NULL, 16);
    job.ntime   = (uint32_t)strtoul(cJSON_GetArrayItem(params, 7)->valuestring, NULL, 16);
    job.clean_jobs = cJSON_IsTrue(cJSON_GetArrayItem(params, 8));
    job.valid = true;

    xSemaphoreTake(s_job_mutex, portMAX_DELAY);
    job.extranonce1_len = s_job.extranonce1_len;
    memcpy(job.extranonce1, s_job.extranonce1, sizeof(job.extranonce1));
    job.extranonce2_size = s_job.extranonce2_size;
    job.difficulty = s_job.difficulty > 0 ? s_job.difficulty : 1.0;
    s_job = job;
    xSemaphoreGive(s_job_mutex);

    ESP_LOGI(TAG, "new job %s (clean_jobs=%d, %d merkle branches)",
             job.job_id, job.clean_jobs, job.merkle_branch_count);
}

static void handle_set_difficulty (cJSON *params) {
    if (!cJSON_IsArray(params) || cJSON_GetArraySize(params) < 1) return;
    double diff = cJSON_GetArrayItem(params, 0)->valuedouble;
    xSemaphoreTake(s_job_mutex, portMAX_DELAY);
    s_job.difficulty = diff;
    xSemaphoreGive(s_job_mutex);
    ESP_LOGI(TAG, "pool set difficulty: %g", diff);
}

static void handle_subscribe_result (cJSON *result) {
    if (!cJSON_IsArray(result) || cJSON_GetArraySize(result) < 3) {
        ESP_LOGW(TAG, "malformed subscribe result");
        return;
    }
    const char *extranonce1_hex = cJSON_GetArrayItem(result, 1)->valuestring;
    int extranonce2_size = cJSON_GetArrayItem(result, 2)->valueint;

    xSemaphoreTake(s_job_mutex, portMAX_DELAY);
    int len = hex_decode(extranonce1_hex, s_job.extranonce1, sizeof(s_job.extranonce1));
    s_job.extranonce1_len = len > 0 ? (size_t)len : 0;
    s_job.extranonce2_size = (size_t)extranonce2_size;
    xSemaphoreGive(s_job_mutex);

    ESP_LOGI(TAG, "subscribed: extranonce1=%s extranonce2_size=%d", extranonce1_hex, extranonce2_size);
}

static void handle_line (const char *line) {
    cJSON *msg = cJSON_Parse(line);
    if (!msg) {
        ESP_LOGW(TAG, "failed to parse line: %s", line);
        return;
    }

    cJSON *method = cJSON_GetObjectItem(msg, "method");
    if (method && cJSON_IsString(method)) {
        cJSON *params = cJSON_GetObjectItem(msg, "params");
        if (strcmp(method->valuestring, "mining.notify") == 0) {
            handle_notify(params);
        } else if (strcmp(method->valuestring, "mining.set_difficulty") == 0) {
            handle_set_difficulty(params);
        } else {
            ESP_LOGD(TAG, "unhandled method: %s", method->valuestring);
        }
    } else {
        cJSON *result = cJSON_GetObjectItem(msg, "result");
        if (result && cJSON_IsArray(result)) {
            handle_subscribe_result(result);
        } else if (result) {
            char *s = cJSON_PrintUnformatted(result);
            ESP_LOGI(TAG, "<- result: %s", s ? s : "(null)");
            cJSON_free(s);
        }
        cJSON *error = cJSON_GetObjectItem(msg, "error");
        if (error && !cJSON_IsNull(error)) {
            char *s = cJSON_PrintUnformatted(error);
            ESP_LOGW(TAG, "<- error: %s", s ? s : "(null)");
            cJSON_free(s);
        }
    }
    cJSON_Delete(msg);
}

static bool pump_socket (int sock) {
    char chunk[512];
    int n = recv(sock, chunk, sizeof(chunk), 0);
    if (n <= 0) return false;

    for (int i = 0; i < n; i++) {
        char c = chunk[i];
        if (c == '\n') {
            s_line_buf[s_line_len] = '\0';
            if (s_line_len > 0) handle_line(s_line_buf);
            s_line_len = 0;
        } else if (s_line_len < LINE_BUF_SIZE - 1) {
            s_line_buf[s_line_len++] = c;
        } else {
            ESP_LOGW(TAG, "line buffer overflow, dropping line");
            s_line_len = 0;
        }
    }
    return true;
}

static void stratum_client_task (void *pvParameters) {
    (void)pvParameters;
    s_job_mutex = xSemaphoreCreateMutex();

    while (1) {
        s_sock = connect_to_pool();
        if (s_sock < 0) {
            ESP_LOGW(TAG, "retrying pool connection in 5s");
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        xSemaphoreTake(s_job_mutex, portMAX_DELAY);
        s_job.valid = false;
        xSemaphoreGive(s_job_mutex);

        if (!send_subscribe(s_sock) || !send_authorize(s_sock)) {
            ESP_LOGW(TAG, "subscribe/authorize send failed, reconnecting");
            close(s_sock);
            s_sock = -1;
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        s_line_len = 0;
        while (pump_socket(s_sock)) { /* keep pumping until the socket dies */ }

        ESP_LOGW(TAG, "pool connection lost, reconnecting");
        close(s_sock);
        s_sock = -1;
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

typedef struct __attribute__((packed)) {
    uint32_t version;
    uint8_t  prev_hash[32];
    uint8_t  merkle_root[32];
    uint32_t ntime;
    uint32_t nbits;
    uint32_t nonce;
} block_header_t;

_Static_assert(sizeof(block_header_t) == 80, "block header must be 80 bytes");

static void pool_difficulty_to_target (double difficulty, uint8_t target[32]) {
    static const uint8_t diff1_target[32] = {
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    if (difficulty <= 0) difficulty = 1.0;

    uint64_t high64 = 0;
    for (int i = 0; i < 8; i++) high64 = (high64 << 8) | diff1_target[i];
    uint64_t scaled = (uint64_t)((double)high64 / difficulty);

    memset(target, 0, 32);
    for (int i = 7; i >= 0; i--) {
        target[i] = scaled & 0xff;
        scaled >>= 8;
    }
}

static bool hash_meets_target (const uint8_t hash[32], const uint8_t target[32]) {
    for (int i = 0; i < 32; i++) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true;
}

static void compute_merkle_root(
    const uint8_t coinbase_txid[32],
    const uint8_t branches[][32],
    uint8_t out_root[32]) {

    uint8_t acc[32];
    memcpy(acc, coinbase_txid, 32);
    uint8_t pair[64];
    for (int i = 0; i < branch_count; i++) {
        memcpy(pair, acc, 32);
        memcpy(pair + 32, branches[i], 32);
        sha256d(pair, 64, acc);
    }
    memcpy(out_root, acc, 32);
}

static void build_coinbase_txid (
    const stratum_job_t *job,
    const uint8_t *extranonce2,
    uint8_t out_txid[32]) {

    uint8_t coinbase[512];
    size_t pos = 0;
    memcpy(coinbase + pos, job->coinb1, job->coinb1_len);
    pos += job->coinb1_len;

    memcpy(coinbase + pos, job->extranonce1, job->extranonce1_len);
    pos += job->extranonce1_len;

    memcpy(coinbase + pos, extranonce2, job->extranonce2_size);
    pos += job->extranonce2_size;

    memcpy(coinbase + pos, job->coinb2, job->coinb2_len);
    pos += job->coinb2_len;

    sha256d(coinbase, pos, out_txid);
}

static void miner_task (void *pvParameters) {
    (void)pvParameters;

    uint32_t extranonce2_counter = 0;
    uint64_t hashes_this_window = 0;
    int64_t window_start_us = esp_timer_get_time();

    char current_job_id[MAX_JOB_ID_LEN] = {0};
    block_header_t header = {0};
    uint8_t target[32] = {0};
    stratum_job_t job_snapshot = {0};

    while (1) {
        stratum_job_t *job = stratum_job_lock();
        bool have_job = job->valid;
        if (have_job) job_snapshot = *job;
        stratum_job_unlock();

        if (!have_job) {
            ESP_LOGI(TAG, "waiting for a job from the pool...");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        bool new_job = strcmp(current_job_id, job_snapshot.job_id) != 0;
        if (new_job) {
            strncpy(current_job_id, job_snapshot.job_id, sizeof(current_job_id) - 1);
            extranonce2_counter = 0;
            ESP_LOGI(TAG, "switching to job %s (pool diff=%g)", job_snapshot.job_id, job_snapshot.difficulty);
            pool_difficulty_to_target(job_snapshot.difficulty, target);
        }

        uint8_t extranonce2[8] = {0};
        size_t e2_size = job_snapshot.extranonce2_size;
        if (e2_size > sizeof(extranonce2)) e2_size = sizeof(extranonce2);
        for (size_t i = 0; i < e2_size && i < 4; i++) {
            extranonce2[e2_size - 1 - i] = (uint8_t)(extranonce2_counter >> (8 * i));
        }

        uint8_t coinbase_txid[32];
        build_coinbase_txid(&job_snapshot, extranonce2, coinbase_txid);

        uint8_t merkle_root[32];
        compute_merkle_root(coinbase_txid, job_snapshot.merkle_branches,
                             job_snapshot.merkle_branch_count, merkle_root);

        header.version = job_snapshot.version;
        memcpy(header.prev_hash, job_snapshot.prev_hash, 32);
        memcpy(header.merkle_root, merkle_root, 32);
        header.ntime = job_snapshot.ntime;
        header.nbits = job_snapshot.nbits;

        const uint32_t BATCH = 200000;
        for (uint32_t n = 0; n < BATCH; n++) {
            header.nonce = n;

            uint8_t hash[32];
            sha256d((const uint8_t *)&header, sizeof(header), hash);

            uint8_t hash_display[32];
            memcpy(hash_display, hash, 32);
            reverse_bytes(hash_display, 32);

            if (hash_meets_target(hash_display, target)) {
                ESP_LOGI(TAG, "share found! job=%s nonce=%" PRIu32 " extranonce2_ctr=%" PRIu32,
                         job_snapshot.job_id, n, extranonce2_counter);
                ESP_LOG_BUFFER_HEX(TAG, hash_display, 32);
                stratum_submit_share(job_snapshot.job_id, extranonce2, e2_size, header.ntime, n);
            }
            hashes_this_window++;
        }
        extranonce2_counter++;

        int64_t now_us = esp_timer_get_time();
        if (now_us - window_start_us >= 2 * 1000 * 1000) {
            double elapsed_s = (now_us - window_start_us) / 1e6;
            ESP_LOGI(TAG, "hashrate: %.1f H/s  job=%s", hashes_this_window / elapsed_s, current_job_id);
            hashes_this_window = 0;
            window_start_us = now_us;
        }

        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

void app_main (void) {
    ESP_LOGI(TAG, "esp32-stratum-miner starting");
    wifi_connect_blocking();

    xTaskCreatePinnedToCore(stratum_client_task, "stratum", 8192, NULL, 5, NULL, 0); // Core 0

    vTaskDelay(pdMS_TO_TICKS(500));
    xTaskCreatePinnedToCore(miner_task, "miner", 8192, NULL, 5, NULL, 1); // Core 1
}
