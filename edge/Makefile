CONTIKI_PROJECT = edge
all: $(CONTIKI_PROJECT)

# Include Contiki-NG Make variables
include $(CONTIKING_DIR)/Makefile.dir-variables

# Add additional CFLAGS
CFLAGS += -DMQTT_CLIENT_CONF_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DTRUST_MODEL_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DAPP_MONITORING_LOG_LEVEL=LOG_LEVEL_DBG

# Include Contiki-NG system modules
MODULES += os/services/shell

# Include application modules
MODULES_REL += ../common/mqtt
MODULES_REL += ../common/trust
MODULES_REL += ./trust

# MQTT configuration
CFLAGS += -DTOPICS_TO_SUBSCRIBE_LEN=2

MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/mqtt

# CoAP configuration
#MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap

# Set MAC protocol
#MAKE_MAC = MAKE_MAC_TSCH

# Applications to include
MODULES_REL += ../applications/monitoring/edge

# Main Contiki-NG compile
CONTIKI = $(CONTIKING_DIR)
include $(CONTIKI)/Makefile.include
