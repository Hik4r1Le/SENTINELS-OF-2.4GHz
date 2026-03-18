#include "esp_wifi.h"
#include "esp_log.h"
#include <string.h>
#include "sniffer.h"
#include "esp-now.h"


void sending_data_task(void *pvParameter) {
    esp_now_payload_t payload;
    payload.node_id = NODE_ID; 

    sniffer_data_t data;
    int count = 0;

    while(1) {
        if (xQueueReceive(sniffer_queue, &data, portMAX_DELAY)) {
            payload.on_channel[count] = data;
            ESP_LOGI("ESP-NOW", "Data for channel %d received", data.channel);
            count++;
            if (count == 3) {
              //enter critical section
              sniffer_pause();
              esp_wifi_set_channel(GATEWAY_CHANNEL, WIFI_SECOND_CHAN_NONE); 
              esp_err_t result = esp_now_send(GATEWAY_MAC, (uint8_t *)&payload, sizeof(payload));
              if (result == ESP_OK) {
                  ESP_LOGI("ESP-NOW", "Data sent successfully");
              }
              else {
                ESP_LOGE("ESP-NOW", "Send failed: %s", esp_err_to_name(result));
              }
              sniffer_resume();
              count = 0;
              vTaskDelay(pdMS_TO_TICKS(50));
            }
        }
    }
}