CONTIKI_PROJECT = node
all: $(CONTIKI_PROJECT)

# Include Contiki-NG Make variables
include $(CONTIKING_DIR)/Makefile.dir-variables

# Add additional CFLAGS
CFLAGS += -DMQTT_CLIENT_CONF_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DTRUST_MODEL_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DAPP_MONITORING_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DDTLS_LOG_LEVEL=LOG_LEVEL_DBG

# Include Contiki-NG system modules
#MODULES += os/services/shell
MODULES += os/lib/json

# tinyDTLS
MAKE_WITH_DTLS ?= 0
ifeq ($(MAKE_WITH_DTLS),1)
  TINYDTLS_PATH := os/net/security/tinydtls

  ifeq (${wildcard $(CONTIKING_DIR)/$(TINYDTLS_PATH)/Makefile},)
    ${error Could not find the tinyDTLS submodule. Please run "git submodule update --init" and try again}
  endif

  CFLAGS += -DWITH_DTLS=1

  #MODULES += os/net/app-layer/coap/tinydtls-support
  MODULES += $(TINYDTLS_PATH) ${addprefix $(TINYDTLS_PATH)/,aes sha2 ecc contiki-support}

  # Provide a sha2 implementation that uses the HW acceleration features of the cc2538
  #MODULES_REL += ../common/tinydtls/sha2/cc2538

  #MAKE_COAP_DTLS_KEYSTORE_NONE   := 0
  #MAKE_COAP_DTLS_KEYSTORE_SIMPLE := 1
  #MAKE_COAP_DTLS_KEYSTORE_LWM2M  := 2

  #MAKE_COAP_DTLS_KEYSTORE ?= MAKE_COAP_DTLS_KEYSTORE_LWM2M

  #ifeq ($(MAKE_COAP_DTLS_KEYSTORE),MAKE_COAP_DTLS_KEYSTORE_SIMPLE)
  #  CFLAGS += -DCOAP_DTLS_KEYSTORE_CONF_WITH_SIMPLE=1
  #else ifeq ($(MAKE_COAP_DTLS_KEYSTORE),MAKE_COAP_DTLS_KEYSTORE_LWM2M)
  #  CFLAGS += -DCOAP_DTLS_KEYSTORE_CONF_WITH_LWM2M=1
  #else ifeq ($(MAKE_COAP_DTLS_KEYSTORE),MAKE_COAP_DTLS_KEYSTORE_NONE)
  #  # No C flag needed for no keystore
  #else
  #  ${error Unsupported CoAP DTLS keystore: $(MAKE_COAP_DTLS_KEYSTORE)}
  #endif
endif

# Include application modules
MODULES_REL += ../common ${addprefix ../common/,mqtt-over-coap trust}
MODULES_REL += ./trust

# MQTT configuration
CFLAGS += -DTOPICS_TO_SUBSCRIBE_LEN=3
#CFLAGS += -DMQTT_CONF_VERSION=MQTT_PROTOCOL_VERSION_3_1_1

#MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/mqtt

# CoAP configuration
#MAKE_WITH_DTLS = 1
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap

# Set MAC protocol
#MAKE_MAC = MAKE_MAC_TSCH

# Applications to include
APPLICATIONS = monitoring 
include ../applications/Makefile.include

# Main Contiki-NG compile
CONTIKI = $(CONTIKING_DIR)
include $(CONTIKI)/Makefile.include
