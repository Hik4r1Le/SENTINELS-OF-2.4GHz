#include "sniffer.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include <string.h>

#define MAX_MACS 50
#define MAX_SSIDS 20
#define MAX_BSSIDS 20
#define SSID_MAX_LEN 32

int channelList[3] = {1, 6, 11};

static sniffer_data_t stats = {0};
static int rssi_sum = 0;
static uint8_t mac_list [MAX_MACS][6];
static uint8_t bssid_list [MAX_BSSIDS][6];
static uint8_t ssid_list [MAX_SSIDS][SSID_MAX_LEN];
static int mac_count = 0;
static int bssid_count = 0;
static int ssid_count = 0;

static const char *snifferTAG = "sniffer";

static portMUX_TYPE sniffer_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool espnow_active = false;

QueueHandle_t sniffer_queue; 

bool mac_exists(uint8_t * mac, uint8_t list [][6], int count) {
    for (int i = 0; i < count; i++) {
        if (memcmp(list[i], mac, 6) == 0) {
            return true;
        }
    }
    return false;
}

bool bssid_exists(uint8_t * bssid, uint8_t list [][6], int count) {
    for (int i = 0; i < count; i++) {
        if (memcmp(list[i], bssid, 6) == 0) {
            return true;
        }
    }
    return false;
}

bool ssid_exists(char *ssid, uint8_t list[][SSID_MAX_LEN], int count) {
    for(int i = 0; i < count; i++) {
        if(memcmp(list[i], ssid, SSID_MAX_LEN) == 0) {
            return true;
        }
    }
    return false;
}

void add_mac (uint8_t * mac) {
    if (!mac_exists(mac, mac_list, mac_count) && mac_count < MAX_MACS) {
        memcpy(mac_list[mac_count], mac, 6);
        mac_count++;
    }
}

void add_bssid (uint8_t * bssid) {
    if (!bssid_exists(bssid, bssid_list, bssid_count) && bssid_count < MAX_BSSIDS) {
        memcpy(bssid_list[bssid_count], bssid, 6);
        bssid_count++;
    }
}

void add_ssid (char *ssid) {
    if (!ssid_exists(ssid, ssid_list, ssid_count) && ssid_count < MAX_SSIDS) {
        memcpy(ssid_list[ssid_count], ssid, SSID_MAX_LEN);
        ssid_count++;
    }
}

void extract_ssid(uint8_t *payload, int len) {
    if (len < 38) {
        return;
    }
    uint8_t *ie = payload + 36; 

    while (ie + 2 < payload + len) {
        uint8_t tag = ie[0];
        uint8_t tag_len = ie[1];
        if (ie + tag_len +2 > payload + len) {
            break;
        }
        if (tag == 0) { // SSID tag
            if (tag_len <= 32 && tag_len > 0) {
                char ssid[SSID_MAX_LEN + 1];
                memcpy(ssid, &ie[2], tag_len);
                ssid[tag_len] = '\0';
                add_ssid(ssid);
            }
            return;
        }
        ie += tag_len +2;
    }
}

void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type){
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t *ctrl = &pkt->rx_ctrl;
    uint8_t *payload = pkt->payload;
    int sig_len = ctrl->sig_len;


    if(sig_len < 1) return;

    uint8_t frame_ctrl = payload[0];
    uint8_t subtype = (frame_ctrl & 0xF0) >> 4;


    bool is_mgmt = (type == WIFI_PKT_MGMT);
    bool is_data = (type == WIFI_PKT_DATA);
    bool is_ctrl = (type == WIFI_PKT_CTRL);

    bool is_beacon = (is_mgmt && subtype == 8);
    bool is_probe_resp = (is_mgmt && subtype == 5);
    bool is_probe_req = (is_mgmt && subtype == 4);
    bool is_deauth = (is_mgmt && subtype == 12);

    bool has_mac_header = (sig_len >= 24) ;
    bool need_ssid_parse = (is_beacon || is_probe_resp);

    uint8_t *addr2 = NULL;
    uint8_t *addr3 = NULL;

    if(has_mac_header && (is_mgmt || is_data)){
        addr2 = payload + 10;   //transmitter MAC
        addr3 = payload + 16;   //BSSID
    }

    portENTER_CRITICAL(&sniffer_mux);

    if(ctrl->rx_state != 0){
        stats.crc_err++;
        portEXIT_CRITICAL(&sniffer_mux);
        return;
    }

    //stats.channel = ctrl->channel;
    stats.total++;
    int rssi = ctrl->rssi;
    if(rssi > stats.rssi_max) stats.rssi_max = rssi;
    if(rssi < stats.rssi_min) stats.rssi_min = rssi;
    rssi_sum += rssi;

    if(is_ctrl){
        stats.ctrl++;
    }
    else if(is_data){
        stats.data++;
    }
    else if(is_mgmt){
        if(is_beacon) stats.beacon++;
        else if(is_deauth) stats.deauth++;
        else if(is_probe_req) stats.probe_req++;
        else if(is_probe_resp) stats.probe_resp++;

        if(need_ssid_parse){
            extract_ssid(payload, sig_len);
        }
    }

    if(has_mac_header && (is_mgmt || is_data)){
        if(memcmp(addr2,"\xff\xff\xff\xff\xff\xff",6) != 0){
            add_mac(addr2);
        }
        add_bssid(addr3);
    }
    portEXIT_CRITICAL(&sniffer_mux);
}


void sniffer_init(void) {
    sniffer_queue = xQueueCreate(20, sizeof(sniffer_data_t));
    
    // Set up WiFi Promiscuous mode configuration
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&sniffer_cb));
    
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       WIFI_PROMIS_FILTER_MASK_DATA |
                       WIFI_PROMIS_FILTER_MASK_CTRL
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    stats.rssi_max = -128;
    stats.rssi_min = 127;
}

void channel_hopping_task(void *pvParameter) {
    uint8_t channel = channelList[0]; 
    int channelIndex = 0;
    while(1) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(300));

        portENTER_CRITICAL(&sniffer_mux);
        sniffer_data_t snapshot = stats;
        if (stats.total > 0) {
            snapshot.rssi_avg = rssi_sum / (int)stats.total;
        } else {
            snapshot.rssi_avg = 0;
        }
        snapshot.channel = channel;
        snapshot.unique_macs = mac_count;
        snapshot.unique_bssids = bssid_count;
        snapshot.unique_ssids = ssid_count;
        memset(&stats, 0, sizeof(stats));
        rssi_sum = 0;
        stats.rssi_max = -128;
        stats.rssi_min = 127;
        mac_count = 0;
        bssid_count = 0;
        ssid_count = 0;
        portEXIT_CRITICAL(&sniffer_mux);
        xQueueSend(sniffer_queue, &snapshot, pdMS_TO_TICKS(10));
        channelIndex = (channelIndex + 1) % 3;
        channel = channelList[channelIndex];
    }
}

void log_sniffer_data_task(void *pvParameter) {
    sniffer_data_t data;
    while(1) {
        if(xQueueReceive(sniffer_queue, &data, portMAX_DELAY)) {
           ESP_LOGI(snifferTAG, "Channel: %d, Total: %d, Beacon: %d, Deauth: %d, Probe Req: %d, Probe Resp: %d, Data: %d, Ctrl: %d, CRC Err: %d, RSSI Avg: %d, RSSI Max: %d, RSSI Min: %d, Unique MACs: %d, Unique BSSIDs: %d, Unique SSIDs: %d",
                    data.channel, data.total, data.beacon, data.deauth, data.probe_req, data.probe_resp, data.data, data.ctrl, data.crc_err,
                    data.rssi_avg, data.rssi_max, data.rssi_min, data.unique_macs, data.unique_bssids, data.unique_ssids);
        }
    }
}

void sniffer_pause(void)
{
    espnow_active = false;
    esp_wifi_set_promiscuous(false);
}

void sniffer_resume(void)
{
    esp_wifi_set_promiscuous(true);
    espnow_active = true;
}