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

## On Observer for Border Router

Set up tun0 interface

```bash
cd ~/contiki-ng/tools/serial-io
sudo ./tunslip6 -s /dev/ttyUSB0 fd00::1/64
```

## On Edge MQTT

```bash
sudo apt-get install mosquitto mosquitto-clients
```

Once `tunslip` is running, mosquitto needs to be restarted:
```bash
sudo service mosquitto restart
```

## On Edge MQTT-CoAP Bridge

See (https://docs.emqx.io/broker/latest/en/getting-started/installation.html#packages)

NO
```bash
sudo apt install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common
curl -fsSL https://repos.emqx.io/gpg.pub | sudo apt-key add -
sudo su -c "echo 'deb [arch=armhf] https://repos.emqx.io/emqx-ce/deb/raspbian/ ./$(lsb_release -cs) stable' > /etc/apt/sources.list.d/emqx.list"
sudo apt-get update
sudo apt install emqx
```

```bash
sudo apt-get install -y erlang libcoap2-bin

mkdir mqtt-coap
git clone https://github.com/erlang/rebar3.git
cd rebar3
./bootstrap
./rebar3 local install
cd ..
```

Add `export PATH=/home/pi/.cache/rebar3/bin:$PATH` to `~/.bashrc` before the interactivity check.

```bash
source ~/.bashrc

git clone https://github.com/emqx/emqx-rel.git -b release-4.1
cd emqx-rel
make emqx-pkg
./_build/emqx/rel/emqx/bin/emqx start
./_build/emqx/rel/emqx/bin/emqx_ctl plugins load emqx_coap
```


# Related Resources

 - https://link.springer.com/content/pdf/10.1007%2F978-981-13-2324-9_28.pdf
