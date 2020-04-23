# Evaluating Trustworthiness of Edge-Based Multi-Tenanted IoT Devices


## Edge MQTT


## Edge


## Sensor Node


## Observer


# Setup


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




# Related Resources

 - https://link.springer.com/content/pdf/10.1007%2F978-981-13-2324-9_28.pdf
