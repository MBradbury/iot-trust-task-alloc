CONTIKI_PROJECT = edge
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

# Add additional CFLAGS
CFLAGS += -DMQTT_CLIENT_CONF_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DTRUST_MODEL_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DAPP_MONITORING_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DCRYPTO_SUPPORT_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DKEYSTORE_LOG_LEVEL=LOG_LEVEL_DBG

ifeq ($(TRUST_MODEL),)
    $(error "TRUST_MODEL not set")
else
    CFLAGS += -DTRUST_MODEL=TRUST_MODEL_$(shell echo $(TRUST_MODEL) | tr '[:lower:]' '[:upper:]')
endif

# Include Contiki-NG system modules
#MODULES += os/services/shell

# Include application modules
MODULES_REL += ../common ${addprefix ../common/,mqtt-over-coap trust crypto}
MODULES_REL += ./capability
MODULES_REL += ../common/trust/models/$(TRUST_MODEL)

include ../common/nanocbor/Makefile.include

# MQTT configuration
CFLAGS += -DTOPICS_TO_SUBSCRIBE_LEN=4

# CoAP configuration
MAKE_WITH_OSCORE = 1
#MAKE_WITH_DTLS = 1
#MAKE_COAP_DTLS_KEYSTORE := MAKE_COAP_DTLS_KEYSTORE_SIMPLE
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap
#CFLAGS += -DDTLS_PEER_MAX=10 -DDTLS_HANDSHAKE_MAX=5

# Set MAC protocol
#MAKE_MAC = MAKE_MAC_TSCH

# Applications to include
APPLICATIONS = monitoring
include ../applications/Makefile.include

# Main Contiki-NG compile
include $(CONTIKI)/Makefile.include
