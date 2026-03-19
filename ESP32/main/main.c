#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h" 
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "sniffer.h"
#include "esp-now.h"

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
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_ERROR_CHECK(esp_now_init());

  // Add peer AFTER init
  esp_now_peer_info_t peer = {0};
  memcpy(peer.peer_addr, GATEWAY_MAC, 6);
  peer.channel = GATEWAY_CHANNEL;
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false;

  ESP_ERROR_CHECK(esp_now_add_peer(&peer));

  //Activate sniffer
  sniffer_init();
    
  xTaskCreate(channel_hopping_task, "channel_hopping_task", 2048, NULL, 5, NULL);
  xTaskCreate(log_sniffer_data_task, "log_sniffer_data_task", 4096, NULL, 6, NULL);
  xTaskCreate(sending_data_task, "sending_data_task", 4096, NULL, 7, NULL);
}


/*note 1:
ESP32 gateway: that one yellow ESP32-WROOM, MAC: CC:DB:A7:96:D8:FC, channel 11
ESP32 sniffer:
1. ESP32-WROOM (black 30 pins): living room
2. ESP32C3 super mini: bedroom
3. ESP32-CAM: the other room idk
*/

/* note 2: follow this packet
{
  "node_id": "sensor_01",
  "timestamp": 1710000000,//may be not
  "channel": 1,//remove

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