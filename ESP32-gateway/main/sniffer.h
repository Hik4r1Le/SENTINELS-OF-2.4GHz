#ifndef SNIFFER_H
#define SNIFFER_H

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include <stdint.h>

typedef struct {
    //uint8_t node_id;
    //uint32_t timestamp_ms; //remove for now
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

    uint16_t unique_macs;
    uint16_t unique_bssids;
    uint16_t unique_ssids;
} sniffer_data_t;

// Expose the queue
extern QueueHandle_t sniffer_queue;

void sniffer_init(void);
void channel_hopping_task(void *pvParameter);
void log_sniffer_data_task(void *pvParameter);

void sniffer_pause(void);
void sniffer_resume(void);

#endif