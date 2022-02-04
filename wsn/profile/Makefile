CONTIKI_PROJECT = profile
all: $(CONTIKI_PROJECT)

include ../Makefile.common

#CFLAGS += -Wconversion

ifeq ($(PROFILE_ECC),1)
    CFLAGS += -DPROFILE_ECC
else ifeq ($(PROFILE_AES),1)
    CFLAGS += -DPROFILE_AES
else
    $(error "Unknown profile option please specify either PROFILE_ECC=1 or PROFILE_AES=1")
endif

ifeq ($(TRUST_MODEL),)
    $(error "TRUST_MODEL not set")
else
    CFLAGS += -DTRUST_MODEL=TRUST_MODEL_$(shell echo $(TRUST_MODEL) | tr '[:lower:]' '[:upper:]' | tr '-' '_')
endif

MODULES_REL += ./trust
MODULES_REL += ../common/trust/models/$(TRUST_MODEL)

# Applications to include
ifndef APPLICATIONS
	# Set default applications if not requesting specifics
	APPLICATIONS = monitoring
endif
include ../applications/Makefile.include

# Add additional CFLAGS
CFLAGS += -DCRYPTO_SUPPORT_LOG_LEVEL=LOG_LEVEL_DBG
CFLAGS += -DKEYSTORE_LOG_LEVEL=LOG_LEVEL_DBG

CFLAGS += -DCRYPTO_SUPPORT_TIME_METRICS=1

# Main Contiki-NG compile
include $(CONTIKI)/Makefile.include
