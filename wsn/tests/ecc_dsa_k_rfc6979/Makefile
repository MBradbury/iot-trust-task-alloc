CONTIKI_PROJECT = main
all: $(CONTIKI_PROJECT)

CONTIKI = $(CONTIKING_OSCORE_DIR)

ifeq ($(CONTIKI),)
    $(error "Contiki directory not set")
endif

# Include Contiki-NG Make variables
include $(CONTIKI)/Makefile.dir-variables

# Include Contiki-NG system modules
#MODULES += os/services/shell

# Include application modules
MODULES_REL += ../../common #${addprefix ../../common/,crypto}

CFLAGS += -I../../common/crypto

CFLAGS += -DCRYPTO_SUPPORT_LOG_LEVEL=LOG_LEVEL_DBG

# CoAP configuration
MAKE_WITH_OSCORE = 1
#MAKE_WITH_DTLS = 1
# We want to provide our own keystore
#MAKE_COAP_DTLS_KEYSTORE := MAKE_COAP_DTLS_KEYSTORE_SIMPLE
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap
#MODULES_REL += ${addprefix ../common/tinydtls/cc2538/,sha2 ecc}
#CFLAGS += -DDTLS_PEER_MAX=10 -DDTLS_HANDSHAKE_MAX=5

# Main Contiki-NG compile
include $(CONTIKI)/Makefile.include
