CONTIKI_PROJECT = node
all: $(CONTIKI_PROJECT)

include ../Makefile.common

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

# Include application modules
MODULES_REL += ./trust
MODULES_REL += ../common/trust/models/$(TRUST_MODEL)
MODULES_REL += ../common/trust/choose/$(TRUST_CHOOSE) ../common/trust/choose/

# Applications to include
APPLICATIONS = monitoring routing challenge-response
include ../applications/Makefile.include

# Enable when automatic job submission for routing is required
MODULES_REL += ../applications/routing/node/test
CFLAGS += -DROUTING_PERIODIC_TEST

# Main Contiki-NG compile
include $(CONTIKI)/Makefile.include
