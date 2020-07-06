#pragma once

//#include "assert.h"

#define DEVICE_CLASS_MINIMUM 1
#define DEVICE_CLASS_MAXIMUM 5

#define DEVICE_CLASS_RASPBERRY_PI 1
#define DEVICE_CLASS_PHONE 2
#define DEVICE_CLASS_LAPTOP 3
#define DEVICE_CLASS_DESKTOP 4
#define DEVICE_CLASS_SERVER 5

//CTASSERT(DEVICE_CLASS_MINIMUM > 0); // Zero is a reserved device class
//CTASSERT(DEVICE_CLASS_MAXIMUM < 23); // Can't allow 23 or more classes to fit in a single CBOR uint
