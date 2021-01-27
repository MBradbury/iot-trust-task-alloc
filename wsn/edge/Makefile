CONTIKI_PROJECT = edge
all: $(CONTIKI_PROJECT)

include ../Makefile.common

ifeq ($(TRUST_MODEL),)
    $(error "TRUST_MODEL not set")
else
    CFLAGS += -DTRUST_MODEL=TRUST_MODEL_$(shell echo $(TRUST_MODEL) | tr '[:lower:]' '[:upper:]' | tr '-' '_')
endif

# Include application modules
MODULES_REL += ./capability
MODULES_REL += ../common/trust/models/$(TRUST_MODEL)

# Applications to include
APPLICATIONS = monitoring routing challenge-response
include ../applications/Makefile.include

# Main Contiki-NG compile
include $(CONTIKI)/Makefile.include
