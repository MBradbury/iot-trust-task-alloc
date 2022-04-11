#include "radio-off-driver.h"

#include "os/dev/radio.h"
#include "os/net/netstack.h"
/*---------------------------------------------------------------------------*/
static bool emulate_is_off;
/*---------------------------------------------------------------------------*/
void
radio_off_driver_init(void)
{
    emulate_is_off = false;
}
/*---------------------------------------------------------------------------*/
void
radio_off_driver_set(bool state)
{
    emulate_is_off = state;
}
/*---------------------------------------------------------------------------*/
extern const struct radio_driver NETSTACK_CONF_RADIO;
/*---------------------------------------------------------------------------*/
static int
init(void)
{
    return NETSTACK_CONF_RADIO.init();
}
/*---------------------------------------------------------------------------*/
static int
prepare(const void *payload, unsigned short payload_len)
{
    if (emulate_is_off)
    {
      // Drop tx
      return RADIO_TX_OK;
    }
    else
    {
        return NETSTACK_CONF_RADIO.prepare(payload, payload_len);
    }
}
/*---------------------------------------------------------------------------*/
static int
transmit(unsigned short transmit_len)
{
    if (emulate_is_off)
    {
      // Drop tx
      return RADIO_TX_OK;
    }
    else
    {
        return NETSTACK_CONF_RADIO.transmit(transmit_len);
    }
}
/*---------------------------------------------------------------------------*/
static int
send(const void *payload, unsigned short payload_len)
{
    if (emulate_is_off)
    {
      // Drop tx
      return RADIO_TX_OK;
    }
    else
    {
      prepare(payload, payload_len);
      return transmit(payload_len);
    }
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
        return NETSTACK_CONF_RADIO.read(buf, bufsize);
    }
}
/*---------------------------------------------------------------------------*/
static int
channel_clear(void)
{
    return NETSTACK_CONF_RADIO.channel_clear();
}
/*---------------------------------------------------------------------------*/
static int
receiving_packet(void)
{
    return NETSTACK_CONF_RADIO.receiving_packet();
}
/*---------------------------------------------------------------------------*/
static int
pending_packet(void)
{
    return NETSTACK_CONF_RADIO.pending_packet();
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
    return NETSTACK_CONF_RADIO.on();
}
/*---------------------------------------------------------------------------*/
static int
off(void)
{
    return NETSTACK_CONF_RADIO.off();
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_value(radio_param_t param, radio_value_t *value)
{
    return NETSTACK_CONF_RADIO.get_value(param, value);
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_value(radio_param_t param, radio_value_t value)
{
    return NETSTACK_CONF_RADIO.set_value(param, value);
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_object(radio_param_t param, void *dest, size_t size)
{
    return NETSTACK_CONF_RADIO.get_object(param, dest, size);
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_object(radio_param_t param, const void *src, size_t size)
{
    return NETSTACK_CONF_RADIO.set_object(param, src, size);
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
