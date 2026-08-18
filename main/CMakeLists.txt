idf_component_register(
    SRCS "esp-idf-btc.c"
    INCLUDE_DIRS "."
    REQUIRES
        json
        lwip
        mbedtls
        esp_wifi
        esp_netif
        esp_event
        nvs_flash
        esp_timer
)
