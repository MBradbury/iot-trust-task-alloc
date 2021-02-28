CONTIKI_PROJECT = profile
all: $(CONTIKI_PROJECT)

CONTIKI = $(CONTIKING_OSCORE_DIR)

ifeq ($(CONTIKI),)
    $(error "Contiki directory not set")
endif

# Include Contiki-NG Make variables
include $(CONTIKI)/Makefile.dir-variables

ifdef BUILD_NUMBER
    CFLAGS += -DBUILD_NUMBER=$(BUILD_NUMBER)
endif

#CFLAGS += -Wconversion

ifeq ($(PROFILE_ECC),1)
    CFLAGS += -DPROFILE_ECC
else ifeq ($(PROFILE_AES),1)
    CFLAGS += -DPROFILE_AES
else
    $(error "Unknown profile option please specify either PROFILE_ECC=1 or PROFILE_AES=1")
endif

# Add additional CFLAGS
CFLAGS += -DCRYPTO_SUPPORT_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DKEYSTORE_LOG_LEVEL=LOG_LEVEL_DBG

# Include application modules
MODULES_REL += ../common ${addprefix ../common/,crypto crypto/platforms/cc2538 trust/stereotypes}

include ../common/nanocbor/Makefile.include

# CoAP configuration
MAKE_WITH_OSCORE = 1
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap

# Set MAC protocol
#MAKE_MAC = MAKE_MAC_TSCH

CFLAGS += -DCRYPTO_SUPPORT_TIME_METRICS=1

# Main Contiki-NG compile
include $(CONTIKI)/Makefile.include
