#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "serial-pcap"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
#define PCAP_PREFIX "#"
/*-------------------------------------------------------------------------------------------------------------------*/
void pcap_log_input(const void *payload, unsigned short payload_len)
{
    LOG_PRINT_(PCAP_PREFIX "In|%hu|", payload_len);
    LOG_PRINT_BYTES(payload, payload_len);
    LOG_PRINT_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void pcap_log_output(const void *payload, unsigned short payload_len)
{
    LOG_PRINT_(PCAP_PREFIX "Out|%hu|", payload_len);
    LOG_PRINT_BYTES(payload, payload_len);
    LOG_PRINT_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void pcap_log_output_result(unsigned short payload_len, int res)
{
    LOG_PRINT_(PCAP_PREFIX "OutRes|%hu|%d\n", payload_len, res);
}
/*-------------------------------------------------------------------------------------------------------------------*/
