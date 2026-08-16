#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netdb.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "mbedtls/sha256.h"

#define WIFI_SSID "."
#define WIFI_PASS "."
#define POOL_HOST "."
#define POOL_PORT 1000
#define POOL_USER "."
#define POOL_PASS "."

typedef struct {
    bool valid;
    char job_id[32];
    char prevhash[65];
    uint8_t coinb1[128]; size_t coinb1_len;
    uint8_t coinb2[128]; size_t coinb2_len;
    uint8_t merkle_branches[16][32];
    int merkle_branch_count;
    uint32_t version;
    uint32_t nbits;
    uint32_t ntime;
    uint8_t extranonce1[16]; size_t extranonce1_len;
    size_t extranonce2_size;
    double difficulty;
} stratum_job_t;

static SemaphoreHandle_t s_job_mutex;
static stratum_job_t s_job = {0};
static int s_sock = -1;
static int s_msg_id = 1;

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t out_cap) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > out_cap) return 0;
    for (size_t i = 0; i < len / 2; i++) {
        out[i] = (hex_nibble(hex[i*2]) << 4) | hex_nibble(hex[i*2+1]);
    }
    return len / 2;
}

static void hex_encode(const uint8_t *data, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2] = digits[(data[i] >> 4) & 0xf];
        out[i*2+1] = digits[data[i] & 0xf];
    }
    out[len*2] = '\0';
}

static void sha256d(const uint8_t *data, size_t len, uint8_t out_hash[32]) {
    uint8_t pass[32];
    mbedtls_sha256(data, len, pass, 0);
    mbedtls_sha256(pass, 32, out_hash, 0);
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    esp_wifi_connect();
}

static void start_wifi() {
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL);
    wifi_config_t wifi_config = { .sta = { .ssid = WIFI_SSID, .password = WIFI_PASS } };
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();
}

static bool send_stratum(cJSON *msg) {
    char *str = cJSON_PrintUnformatted(msg);
    bool ok = (send(s_sock, str, strlen(str), 0) > 0) && (send(s_sock, "\n", 1, 0) > 0);
    cJSON_free(str);
    return ok;
}

void stratum_client_task(void *pvParameters) {
    s_job_mutex = xSemaphoreCreateMutex();
    char line_buf[4096];

    while (1) {
        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
        struct addrinfo *res;
        char port_str[8]; snprintf(port_str, sizeof(port_str), "%d", POOL_PORT);
        if (getaddrinfo(POOL_HOST, port_str, &hints, &res) == 0) {
            s_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            connect(s_sock, res->ai_addr, res->ai_addrlen);
            freeaddrinfo(res);
        }

        if (s_sock < 0) {
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        cJSON *sub = cJSON_CreateObject();
        cJSON_AddNumberToObject(sub, "id", s_msg_id++);
        cJSON_AddStringToObject(sub, "method", "mining.subscribe");
        cJSON_AddItemToObject(sub, "params", cJSON_CreateArray());
        send_stratum(sub); cJSON_Delete(sub);

        cJSON *auth = cJSON_CreateObject();
        cJSON_AddNumberToObject(auth, "id", s_msg_id++);
        cJSON_AddStringToObject(auth, "method", "mining.authorize");
        cJSON *auth_p = cJSON_CreateArray();
        cJSON_AddItemToArray(auth_p, cJSON_CreateString(POOL_USER));
        cJSON_AddItemToArray(auth_p, cJSON_CreateString(POOL_PASS));
        cJSON_AddItemToObject(auth, "params", auth_p);
        send_stratum(auth); cJSON_Delete(auth);

        int pos = 0;
        while (recv(s_sock, &line_buf[pos], 1, 0) > 0) {
            if (line_buf[pos] == '\n') {
                line_buf[pos] = '\0';
                cJSON *msg = cJSON_Parse(line_buf);
                cJSON *method = cJSON_GetObjectItem(msg, "method");

                if (method && strcmp(method->valuestring, "mining.notify") == 0) {
                    xSemaphoreTake(s_job_mutex, portMAX_DELAY);
                    cJSON *p = cJSON_GetObjectItem(msg, "params");
                    strncpy(s_job.job_id, cJSON_GetArrayItem(p, 0)->valuestring, 31);
                    s_job.valid = true;
                    xSemaphoreGive(s_job_mutex);
                }
                cJSON_Delete(msg);
                pos = 0;
            } else if (pos < sizeof(line_buf) - 1) {
                pos++;
            }
        }
        close(s_sock);
        s_sock = -1;
    }
}

void miner_task(void *pvParameters) {
    stratum_job_t local_job;
    uint32_t nonce = 0;

    while (1) {
        xSemaphoreTake(s_job_mutex, portMAX_DELAY);
        bool has_job = s_job.valid;
        if (has_job) local_job = s_job;
        xSemaphoreGive(s_job_mutex);

        if (!has_job) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        for (int i = 0; i < 50000; i++) {
            uint8_t hash[32];
            nonce++;
        }
        vTaskDelay(pdMS_TO_TICKS(1)); // Yield
    }
}

void app_main(void) {
    start_wifi();

    // Assign network workload to core 0
    xTaskCreatePinnedToCore(stratum_client_task, NULL, 8192, NULL, 1, NULL, 0);

    // Assign mining workload to core 1
    xTaskCreatePinnedToCore(miner_task, NULL, 8192, NULL, 1, NULL, 1);
}
