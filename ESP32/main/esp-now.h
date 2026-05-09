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
#define NODE_ID 1 // Set your node ID here - 1: black WROOM, 2: yellow WROOM, 3: CAM
static uint8_t GATEWAY_MAC[6] = {0xE0, 0x72, 0xA1, 0xD5, 0xD9, 0x94}; //that one ESP32S3

typedef struct {
  uint8_t node_id;
  sniffer_data_t on_channel[3];
} esp_now_payload_t;


void sending_data_task(void *pvParameter);

#endif