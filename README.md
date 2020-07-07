# Evaluating Trustworthiness of Edge-Based Multi-Tenanted IoT Devices

# Setup

## Development

1. Install dependancies

```bash
sudo apt-get install git build-essential gcc-arm-none-eabi python3
```

2. Download Contiki-NG

```bash
mkdir ~/wsn
cd ~/wsn
git clone -b petras https://github.com/MBradbury/contiki-ng.git
git submodule update --init
```

Edit `~/.bashrc` to add the path to Contiki-NG before the interactivity check:
```bash
export CONTIKING_DIR="~/wsn/contiki-ng"
export COOJA_DIR="$CONTIKING_DIR/tools/cooja"
```

3. Clone this repository

```bash
cd ~/wsn
git clone https://github.com/MBradbury/iot-trust-task-alloc.git
cd iot-trust-task-alloc && git submodule update --init
```


## Root Node

1. Install dependancies

```bash
sudo apt-get install mosquitto mosquitto-clients
sudo apt-get install libcoap2-bin
sudo apt-get install build-essential git
python3 -m pip install asyncio-mqtt cryptography
python3 -m pip install --upgrade "git+https://github.com/chrysn/aiocoap#egg=aiocoap[all]"
```

2. Clone Contiki-NG

```bash
cd ~
git clone -b petras https://github.com/MBradbury/contiki-ng.git
cd contiki-ng && git submodule update --init
```

Build the tunslip6 executable
```bash
cd ~/contiki-ng/tools/serial-io
make
```

3. Clone this repository

```bash
cd ~
git clone https://github.com/MBradbury/iot-trust-task-alloc.git
cd iot-trust-task-alloc && git submodule update --init
```

## Resource Rich Nodes (Edges) and Resource Constrained Nodes (Monitors)

```bash
sudo apt-get install git python3-pip python3-dev pipenv
```

```bash
cd  ~
git clone https://gitlab.com/cs407-idiots/pi-client.git
cd pi-client
pipenv install
```

## Resource Rich Nodes (Edges)

1. Install dependancies

```bash
python3 -m pip install cbor2 pyroutelib3
python3 -m pip install --upgrade "git+https://github.com/chrysn/aiocoap#egg=aiocoap[all]"
```

2. Clone this repository

```bash
cd ~
git clone https://github.com/MBradbury/iot-trust-task-alloc.git
cd iot-trust-task-alloc && git submodule update --init
```


# Instructions to Deploy

1. Configure and build

Edit `~/wsn/iot-trust-task-alloc/tools/setup.py` to specify the nodes used in the network then run it.


```bash
cd ~/wsn/iot-trust-task-alloc
./tools/setup.py <trust-model>
```

2. On Root

Set up tun0 interface.
```bash
cd ~/contiki-ng/tools/serial-io
sudo ./tunslip6 -s /dev/ttyUSB0 fd00::1/64
```

Once `tunslip` is running, mosquitto needs to be restarted:
```bash
sudo service mosquitto restart
```

The keyserver and mqtt-coap-bridge now needs to be started:
```bash
cd ~/iot-trust-task-alloc/resource_rich/root
./root_server.py -k keystore
```

3. On Observer for Sensor Nodes

```bash
cd pi-client && pipenv shell
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

3. On Observer for Edge Nodes

```bash
cd pi-client && pipenv shell
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
./flash.py "/dev/ttyUSB0" edge.bin zolertia contiki
```

Now start up the Edge bridge:
```bash
~/iot-trust-task-alloc/resource_rich/applications
./edge_bridge.py
```

Plus any applications that are desired:
```bash
./monitoring.py
./routing.py
```


# Related Resources

 - https://link.springer.com/content/pdf/10.1007%2F978-981-13-2324-9_28.pdf
 - https://tools.ietf.org/id/draft-ietf-core-object-security-04.html#rfc.appendix.C.3 
    - https://tools.ietf.org/id/draft-ietf-core-object-security-16.html
    - https://github.com/contiki-ng/contiki-ng/issues/285
    - https://github.com/core-wg/oscore
    - https://github.com/Gunzter/contiki-ng and https://github.com/Gunzter/contiki-ng/tree/group_oscore
    - https://arxiv.org/pdf/2001.08023.pdf

 - https://github.com/contiki-ng/contiki-ng/issues/863

 - https://github.com/contiki-ng/contiki-ng/wiki/Tutorial:-RPL-border-router#native-border-router
