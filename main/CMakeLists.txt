idf_component_register(
    SRCS
        "app_main.c"
        "wifi_conn.c"
        "sha256d.c"
        "hex.c"
        "stratum_client.c"
        "miner.c"
    INCLUDE_DIRS "."
    REQUIRES
        mbedtls
        esp_timer
        esp_wifi
        esp_netif
        esp_event
        nvs_flash
        lwip
        json      # cJSON, bundled with ESP-IDF
)
