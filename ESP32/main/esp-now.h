#ifndef ESP_NOW_H
#define ESP_NOW_H

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include <stdint.h>
#include "sniffer.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "esp_log.h"


#define GATEWAY_CHANNEL 11
#define NODE_ID 3 // Set your node ID here - 1: WROOM, 2: CAM, 3: c3 supermini
static uint8_t GATEWAY_MAC[6] = {0xCC, 0xDB, 0xA7, 0x96, 0xD8, 0xFC}; //that one yellow ESP32-WROOM

typedef struct {
  uint8_t node_id;
  sniffer_data_t on_channel[3];
} esp_now_payload_t;


void sending_data_task(void *pvParameter);

#endif