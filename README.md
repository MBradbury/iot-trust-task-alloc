# Evaluating Trustworthiness of Edge-Based Multi-Tenanted IoT Devices


## Edge MQTT


## Edge


## Sensor Node


## Observer


# Setup

1. Install dependancies

```bash
sudo apt-get install git
```

2. Download Contiki-NG

```bash
mkdir ~/wsn
cd ~/wsn
git clone https://github.com/contiki-ng/contiki-ng.git
git submodule update --init
```

Edit `~/.bashrc` to add the path to Contiki-NG before the interactivity check:
```bash
export CONTIKING_DIR="~/wsn/contiki-ng"
export COOJA_DIR="$CONTIKING_DIR/tools/cooja"
```



# Instructions to Deploy

## On Observer for Sensor Nodes

```bash
cd pi-client
pipenv shell
```

Find the device
```bash
./tools/motelist-zolertia
-------------- ---------------- ---------------------------------------------
Reference      Device           Description
-------------- ---------------- ---------------------------------------------
ZOL-RM02-B1002325 /dev/ttyUSB0     Silicon Labs Zolertia RE-Mote platform
```

Flash and run the terminal
```bash
./flash.py "/dev/ttyUSB0" node.bin zolertia contiki &&  ./tools/pyterm -b 115200 -p /dev/ttyUSB0
```

## On Root Observer

### Border Router

Set up tun0 interface

```bash
cd ~/contiki-ng/tools/serial-io
sudo ./tunslip6 -s /dev/ttyUSB0 fd00::1/64
```

### MQTT

```bash
sudo apt-get install mosquitto mosquitto-clients
```

Once `tunslip` is running, mosquitto needs to be restarted:
```bash
sudo service mosquitto restart
```

### MQTT-CoAP Bridge

```bash
sudo apt-get install libcoap2-bin
python3 -m pip install asyncio-mqtt aiocoap
```

# Related Resources

 - https://link.springer.com/content/pdf/10.1007%2F978-981-13-2324-9_28.pdf
 - https://tools.ietf.org/id/draft-ietf-core-object-security-04.html#rfc.appendix.C.3 
    - https://tools.ietf.org/id/draft-ietf-core-object-security-16.html
    - https://github.com/contiki-ng/contiki-ng/issues/285
    - https://github.com/core-wg/oscore
    - https://github.com/Gunzter/contiki-ng
