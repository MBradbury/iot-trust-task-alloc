#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "serial-pcap"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
#define PCAP_PREFIX "#"
/*-------------------------------------------------------------------------------------------------------------------*/
void pcap_log_input(const void *payload, unsigned short payload_len)
{
    LOG_PRINT_(PCAP_PREFIX "In|%u|", payload_len);
    LOG_PRINT_BYTES(payload, payload_len);
    LOG_PRINT_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void pcap_log_output(const void *payload, unsigned short payload_len)
{
    LOG_PRINT_(PCAP_PREFIX "Out|%u|", payload_len);
    LOG_PRINT_BYTES(payload, payload_len);
    LOG_PRINT_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void pcap_log_output_result(unsigned short payload_len, int res)
{
    LOG_PRINT_(PCAP_PREFIX "OutRes|%u|%d\n", payload_len, res);
}
/*-------------------------------------------------------------------------------------------------------------------*/
#if 0
// This code is based off the ipv6-hooks example in Contiki-NG
#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uipbuf.h"
#include "net/ipv6/uip-ds6.h"

#include "packetbuf.h"
/*-------------------------------------------------------------------------------------------------------------------*/
static void pcap_sniffer_input(void)
{
    LOG_INFO("[SN] Incoming packet (len=%u) from ", uip_len);
    LOG_INFO_6ADDR(&UIP_IP_BUF->srcipaddr);
    LOG_INFO_("\n\tuip_buf(%u): ", uip_len);
    LOG_INFO_BYTES(uip_buf, uip_len);
    LOG_INFO_("\n\tpacketbuf(%u): ", packetbuf_datalen());
    LOG_INFO_BYTES(packetbuf_dataptr(), packetbuf_datalen());
    LOG_INFO_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void pcap_sniffer_output(int mac_status)
{
    LOG_INFO("[SN] Outgoing packet (len=%u) to ", uip_len);
    LOG_INFO_6ADDR(&UIP_IP_BUF->destipaddr);
    LOG_INFO_("\n\tuip_buf(%u): ", uip_len);
    LOG_INFO_BYTES(uip_buf, uip_len);
    LOG_INFO_("\n\tpacketbuf(%u): ", packetbuf_datalen());
    LOG_INFO_BYTES(packetbuf_dataptr(), packetbuf_datalen());
    LOG_INFO_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
NETSTACK_SNIFFER(pcap_sniffer, pcap_sniffer_input, pcap_sniffer_output);
/*-------------------------------------------------------------------------------------------------------------------*/
static enum netstack_ip_action
input_handler(void)
{
    uint8_t proto = UINT8_MAX;
    uipbuf_get_last_header(uip_buf, uip_len, &proto);

    LOG_INFO("[PP] Incoming packet (len=%u) proto: %d from ", uip_len, proto);
    LOG_INFO_6ADDR(&UIP_IP_BUF->srcipaddr);
    LOG_INFO_("\n\tuip_buf(%u): ", uip_len);
    LOG_INFO_BYTES(uip_buf, uip_len);
    LOG_INFO_("\n\tpacketbuf(%u): ", packetbuf_datalen());
    LOG_INFO_BYTES(packetbuf_dataptr(), packetbuf_datalen());
    LOG_INFO_("\n");

    return NETSTACK_IP_PROCESS;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static enum netstack_ip_action
output_handler(const linkaddr_t *localdest)
{
    uint8_t proto = UINT8_MAX;
    uipbuf_get_last_header(uip_buf, uip_len, &proto);

    const bool is_me = uip_ds6_is_my_addr(&UIP_IP_BUF->srcipaddr);

    LOG_INFO("[PP] Outgoing packet (len=%u) (%s) proto: %d to ", uip_len, is_me ? "send" : "fwd ", proto);
    LOG_INFO_6ADDR(&UIP_IP_BUF->destipaddr);
    LOG_INFO_("\n\tuip_buf(%u): ", uip_len);
    LOG_INFO_BYTES(uip_buf, uip_len);
    LOG_INFO_("\n\tpacketbuf(%u): ", packetbuf_datalen());
    LOG_INFO_BYTES(packetbuf_dataptr(), packetbuf_datalen());
    LOG_INFO_("\n");

    // TODO: uip_buf only gets the IPv6 frame, how to get the 802.15.4 frame

    return NETSTACK_IP_PROCESS;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static struct netstack_ip_packet_processor packet_processor = {
    .process_input = input_handler,
    .process_output = output_handler
};
/*-------------------------------------------------------------------------------------------------------------------*/
void
pcap_init(void)
{
    netstack_ip_packet_processor_add(&packet_processor);
    netstack_sniffer_add(&pcap_sniffer);
}
/*-------------------------------------------------------------------------------------------------------------------*/
#endif
