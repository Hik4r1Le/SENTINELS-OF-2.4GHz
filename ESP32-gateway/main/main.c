#include <stdio.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h" 
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"

#include "esp-now.h"
#include "sniffer.h"

#define GATEWAY_CHANNEL 11

QueueHandle_t espnow_rx_queue;

typedef struct {
    uint8_t mac_addr[6];
    esp_now_payload_t payload;
} espnow_rx_event_t;

static void espnow_recv_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (len != sizeof(esp_now_payload_t)) {
        ESP_LOGW("ESP-NOW", "Received data of unexpected length: %d", len);
        return;
    }

    espnow_rx_event_t rx_event;
    memcpy(rx_event.mac_addr, info->src_addr, 6);
    memcpy(&rx_event.payload, data, len);

    xQueueSendFromISR(espnow_rx_queue, &rx_event, NULL);
}

void espnow_rx_task(void *pvParameter) {
    espnow_rx_event_t rx_event;

    while (1) {
        if (xQueueReceive(espnow_rx_queue, &rx_event, portMAX_DELAY)) {
            ESP_LOGI("ESP-NOW", "Received data from node %d", rx_event.payload.node_id);
            for (int i = 0; i < 3; i++) {
                sniffer_data_t *data = &rx_event.payload.on_channel[i];
                 ESP_LOGI("ESP-NOW", "Channel: %d, Total: %d, Beacon: %d, Deauth: %d, Probe Req: %d, Probe Resp: %d, Data: %d, Ctrl: %d, CRC Err: %d, RSSI Avg: %d, RSSI Max: %d, RSSI Min: %d, Unique MACs: %d, Unique BSSIDs: %d, Unique SSIDs: %d",
                    data->channel, data->total, data->beacon, data->deauth, data->probe_req, data->probe_resp, data->data, data->ctrl,
                    data->crc_err, data->rssi_avg, data->rssi_max, data->rssi_min, data->unique_macs, data->unique_bssids, data->unique_ssids);
            }
        }
    }
}

void app_main(void)
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize Wi-Fi
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    // Start Wi-Fi
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_wifi_set_channel(GATEWAY_CHANNEL, WIFI_SECOND_CHAN_NONE);

    ESP_ERROR_CHECK(esp_now_init());

    espnow_rx_queue = xQueueCreate(10, sizeof(espnow_rx_event_t));

    ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));

    xTaskCreate(espnow_rx_task, "espnow_rx_task", 4096, NULL, 5, NULL);
}
