CONTIKI_PROJECT = node
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

# Add additional CFLAGS
CFLAGS += -DMQTT_CLIENT_CONF_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DTRUST_MODEL_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DAPP_MONITORING_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DAPP_ROUTING_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DAPP_CHALLENGE_RESPONSE_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DCRYPTO_SUPPORT_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DKEYSTORE_LOG_LEVEL=LOG_LEVEL_DBG

ifeq ($(TRUST_MODEL),)
    $(error "TRUST_MODEL not set")
else
    CFLAGS += -DTRUST_MODEL=TRUST_MODEL_$(shell echo $(TRUST_MODEL) | tr '[:lower:]' '[:upper:]' | tr '-' '_')
endif

ifeq ($(TRUST_CHOOSE),)
    $(error "TRUST_CHOOSE not set")
else
    CFLAGS += -DTRUST_CHOOSE=TRUST_CHOOSE_$(shell echo $(TRUST_CHOOSE) | tr '[:lower:]' '[:upper:]' | tr '-' '_')
endif

# Include Contiki-NG system modules
#MODULES += os/services/shell

# Include application modules
MODULES_REL += ../common ${addprefix ../common/,mqtt-over-coap trust trust/stereotypes crypto}
MODULES_REL += ./trust
MODULES_REL += ../common/trust/models/$(TRUST_MODEL)
MODULES_REL += ../common/trust/choose/$(TRUST_CHOOSE) ../common/trust/choose/

include ../common/nanocbor/Makefile.include

ifeq ($(MAKE_WITH_PCAP),1)
    CFLAGS += -DMAKE_WITH_PCAP=1
    MODULES_REL += ../common/pcap
endif

# MQTT configuration
CFLAGS += -DTOPICS_TO_SUBSCRIBE_LEN=4

# CoAP configuration
MAKE_WITH_OSCORE = 1
#MAKE_WITH_DTLS = 1
# We want to provide our own keystore
#MAKE_COAP_DTLS_KEYSTORE := MAKE_COAP_DTLS_KEYSTORE_SIMPLE
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap
#MODULES_REL += ${addprefix ../common/tinydtls/cc2538/,sha2 ecc}
#CFLAGS += -DDTLS_PEER_MAX=10 -DDTLS_HANDSHAKE_MAX=5

# Set MAC protocol
#MAKE_MAC = MAKE_MAC_TSCH

# Applications to include
APPLICATIONS = monitoring routing challenge-response
include ../applications/Makefile.include

# Enable when automatic job submission for routing is required
MODULES_REL += ../applications/routing/node/test
CFLAGS += -DROUTING_PERIODIC_TEST

# Main Contiki-NG compile
include $(CONTIKI)/Makefile.include
