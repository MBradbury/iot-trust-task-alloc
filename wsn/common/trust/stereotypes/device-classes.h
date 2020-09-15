#pragma once

#define DEVICE_CLASS_MINIMUM 1
#define DEVICE_CLASS_MAXIMUM 8

#define DEVICE_CLASS_RASPBERRY_PI 1
#define DEVICE_CLASS_PHONE 2
#define DEVICE_CLASS_LAPTOP 3
#define DEVICE_CLASS_DESKTOP 4
#define DEVICE_CLASS_SERVER 5

// e.g., TelosB
#define DEVICE_CLASS_IOT_LOW 6

// e.g., Zolertia RE-Mote
#define DEVICE_CLASS_IOT_MEDIUM 7

// e.g., nRF52840
#define DEVICE_CLASS_IOT_HIGH 8

_Static_assert(DEVICE_CLASS_MINIMUM > 0, "Zero is a reserved device class");
_Static_assert(DEVICE_CLASS_MAXIMUM < 23, "Can't allow 23 or more classes to fit in a single CBOR uint");
