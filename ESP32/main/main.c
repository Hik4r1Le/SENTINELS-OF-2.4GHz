#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h" 
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"

int channelList[3] = {1, 6, 11};
static sniffer_data_t stats = {0};
static int rssi_sum = 0;

static const char *snifferTAG = "sniffer";

static portMUX_TYPE sniffer_mux = portMUX_INITIALIZER_UNLOCKED;

QueueHandle_t sniffer_queue;

typedef struct {
    int channel;
    int rssi_avg;
    int rssi_max;
    int rssi_min;

    uint32_t total;
    uint32_t beacon;
    uint32_t deauth;
    uint32_t probe_req;
    uint32_t probe_resp;
    uint32_t data;
    uint32_t ctrl;
    uint32_t crc_err;

    uint32_t timestamp_ms;
    uint8_t node_id;
} sniffer_data_t;

void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t *ctrl = &pkt->rx_ctrl;

    stats.channel = ctrl->channel;
    stats.sig_len = ctrl->sig_len;

    portENTER_CRITICAL(&sniffer_mux);
    stats.total++;
    int rssi = ctrl -> rssi;
    if(rssi > stats.rssi_max) {
        stats.rssi_max = rssi;
    }
    if(rssi < stats.rssi_min) {
        stats.rssi_min = rssi;
    }
    rssi_sum += rssi; 
    port_EXIT_CRITICAL(&sniffer_mux);
    //uint8_t subtype = (ctrl->sig_mode == 0) ? ((pkt->payload[0] & 0xF0) >> 4) : 0; // For non-HT packets, the subtype is in the first byte of the payload
    uint8_t control_frame = pkt->payload[0];
    uint8_t subtype = (control_frame & 0xF0) >> 4;
    if (type == WIFI_PKT_MGMT) {
        switch(subtype) {
            case 8: // Beacon
                stats.beacon++;
                break;
            case 12: // Deauthentication
                stats.deauth++;
                break;
            case 4: // Probe Request
                stats.probe_req++;
                break;
            case 5: // Probe Response
                stats.probe_resp++;
                break;
            default:
                break;
        }
    } else if (type == WIFI_PKT_DATA) {
        stats.data++;
    } else if (type == WIFI_PKT_CTRL) {
        stats.ctrl++;
    } else if (ctrl->rx_state != 0) {
        stats.crc_err++;
    }
}

void channel_hopping_task(void *pvParameter) {
    uint8_t channel = channelList[0]; 
    int channelIndex = 0;
    while(1) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(300));

        portENTER_CRITICAL(&sniffer_mux);
        sniffer_data_t snapshot = stats; 
        if (stats.total >0) {
            snapshot.rssi_avg = rssi_sum / stats.total;
        }
        memset(&stats, 0, sizeof(stats));
        rssi_sum = 0;
        stats.rssi_max = -128;
        stats.rssi_min = 127;
        portEXIT_CRITICAL(&sniffer_mux);
        xQueueSend(sniffer_queue, &snapshot, 0);
        channelIndex = (channelIndex + 1) % 3;
        channel = channelList[channelIndex];
    }
}

void log_sniffer_data_task(void *pvParameter) {
    sniffer_data_t data;
    while(1) {
        if(xQueueReceive(sniffer_queue, &data, portMAX_DELAY)) {
           ESP_LOGI(snifferTAG, "Channel: %d, Total: %d, Beacon: %d, Deauth: %d, Probe Req: %d, Probe Resp: %d, Data: %d, Ctrl: %d, CRC Err: %d, RSSI Avg: %d, RSSI Max: %d, RSSI Min: %d", 
                    data.channel, data.total, data.beacon, data.deauth, data.probe_req, data.probe_resp, data.data, data.ctrl, data.crc_err,
                    data.rssi_avg, data.rssi_max, data.rssi_min);
        }
    }
}

void app_main(void) {
    //Init NVS
    esp_err_t ret = nvs_flash_init();
    if(ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }

    ESP_ERROR_CHECK(ret);
    //Init TCP/IP stack and WiFi default 
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    //Set mode for WiFi
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());

    //Activate sniffer
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&sniffer_cb)); //Each time a packet is received, the registered callback function will be called.

    wifi_promiscuous_filter_t filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                   WIFI_PROMIS_FILTER_MASK_DATA |
                   WIFI_PROMIS_FILTER_MASK_CTRL
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    sniffer_queue = xQueueCreate(20, sizeof(sniffer_data_t));
    
    xTaskCreate(channel_hopping_task, "channel_hopping_task", 2048, NULL, 5, NULL);
    xTaskCreate(log_sniffer_data_task, "log_sniffer_data_task", 2048, NULL, 4, NULL);
}


/* note: follow this packet
{
  "node_id": "sensor_01",
  "timestamp": 1710000000,
  "channel": 1,

  "frames": {
    "total": 250,
    "beacon": 40,
    "deauth": 8,
    "probe_req": 22,
    "probe_resp": 10,
    "data": 150,
    "ctrl": 20,
    "crc_err": 15
  },

  "signal": {
    "rssi_avg": -72,
    "rssi_max": -45,
    "rssi_min": -88
  },

  "devices": {
    "unique_macs": 12,
    "unique_ssids": 6,
    "unique_bssids": 4
  }
}
*/