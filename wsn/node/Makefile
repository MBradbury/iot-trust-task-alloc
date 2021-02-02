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
ifndef APPLICATIONS
	# Set default applications if not requesting specifics
	APPLICATIONS = monitoring routing challenge-response
endif
include ../applications/Makefile.include

# Enable when automatic job submission for routing is required
ifneq (,$(findstring routing,$(APPLICATIONS)))
    MODULES_REL += ../applications/routing/node/test
	CFLAGS += -DROUTING_PERIODIC_TEST
endif

# Main Contiki-NG compile
include $(CONTIKI)/Makefile.include
