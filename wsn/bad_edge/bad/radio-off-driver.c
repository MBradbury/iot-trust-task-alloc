#include "radio-off-driver.h"

#include "os/dev/radio.h"
#include "os/net/netstack.h"
/*---------------------------------------------------------------------------*/
static bool emulate_is_off;
/*---------------------------------------------------------------------------*/
void
radio_off_driver_set(bool state)
{
    emulate_is_off = state;
}
/*---------------------------------------------------------------------------*/
#ifdef NETSTACK_CONF_WITH_PCAP
#define PARENT_RADIO_DRIVER pcapradio_driver
#else
#define PARENT_RADIO_DRIVER NETSTACK_CONF_RADIO
#endif

extern const struct radio_driver PARENT_RADIO_DRIVER;
/*---------------------------------------------------------------------------*/
static int
init(void)
{
    // Start off as if the radio was enabled
    emulate_is_off = false;

    return PARENT_RADIO_DRIVER.init();
}
/*---------------------------------------------------------------------------*/
static int
prepare(const void *payload, unsigned short payload_len)
{
    return PARENT_RADIO_DRIVER.prepare(payload, payload_len);
}
/*---------------------------------------------------------------------------*/
static int
transmit(unsigned short transmit_len)
{
    return PARENT_RADIO_DRIVER.transmit(transmit_len);
}
/*---------------------------------------------------------------------------*/
static int
send(const void *payload, unsigned short payload_len)
{
    prepare(payload, payload_len);
    return transmit(payload_len);
}
/*---------------------------------------------------------------------------*/
static int
read(void *buf, unsigned short bufsize)
{
    if (emulate_is_off)
    {
        // Drop rx
        return 0;
    }
    else
    {
        return PARENT_RADIO_DRIVER.read(buf, bufsize);
    }
}
/*---------------------------------------------------------------------------*/
static int
channel_clear(void)
{
    return PARENT_RADIO_DRIVER.channel_clear();
}
/*---------------------------------------------------------------------------*/
static int
receiving_packet(void)
{
    return PARENT_RADIO_DRIVER.receiving_packet();
}
/*---------------------------------------------------------------------------*/
static int
pending_packet(void)
{
    return PARENT_RADIO_DRIVER.pending_packet();
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
    return PARENT_RADIO_DRIVER.on();
}
/*---------------------------------------------------------------------------*/
static int
off(void)
{
    return PARENT_RADIO_DRIVER.off();
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_value(radio_param_t param, radio_value_t *value)
{
    return PARENT_RADIO_DRIVER.get_value(param, value);
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_value(radio_param_t param, radio_value_t value)
{
    return PARENT_RADIO_DRIVER.set_value(param, value);
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_object(radio_param_t param, void *dest, size_t size)
{
    return PARENT_RADIO_DRIVER.get_object(param, dest, size);
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_object(radio_param_t param, const void *src, size_t size)
{
    return PARENT_RADIO_DRIVER.set_object(param, src, size);
}
/*---------------------------------------------------------------------------*/
const struct radio_driver radio_off_driver = {
    init,
    prepare,
    transmit,
    send,
    read,
    channel_clear,
    receiving_packet,
    pending_packet,
    on,
    off,
    get_value,
    set_value,
    get_object,
    set_object
};
/*---------------------------------------------------------------------------*/
