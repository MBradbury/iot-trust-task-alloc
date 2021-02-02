CONTIKI_PROJECT = adversary
all: $(CONTIKI_PROJECT)

include ../Makefile.common

ifeq ($(TRUST_MODEL),)
    $(error "TRUST_MODEL not set")
else
    CFLAGS += -DTRUST_MODEL=TRUST_MODEL_$(shell echo $(TRUST_MODEL) | tr '[:lower:]' '[:upper:]' | tr '-' '_')
endif

#ifeq ($(TRUST_CHOOSE),)
#    $(error "TRUST_CHOOSE not set")
#else
#    CFLAGS += -DTRUST_CHOOSE=TRUST_CHOOSE_$(shell echo $(TRUST_CHOOSE) | tr '[:lower:]' '[:upper:]' | tr '-' '_')
#endif

# Include application modules
MODULES_REL += ./trust
MODULES_REL += ../common/trust/models/$(TRUST_MODEL)
#MODULES_REL += ../common/trust/choose/$(TRUST_CHOOSE) ../common/trust/choose/

# Applications to include
ifndef APPLICATIONS
	# Set default applications if not requesting specifics
	APPLICATIONS = monitoring routing challenge-response
endif
include ../applications/Makefile.include

# Attack configuration
ifeq ($(MAKE_ATTACKS),)
    $(error "Please specify at least one attack")
endif

$(info Building these attacks: $(MAKE_ATTACKS))

MODULES_REL += ./attacks

# From: https://stackoverflow.com/questions/1541844/joining-elements-of-a-list-in-gnu-make
noop:=
space := $(noop) $(noop)
comma := ,

ATTACK_NAMES := $(subst $(comma),$(space),$(MAKE_ATTACKS))

ATTACK_PROCESSES := ${addprefix &,$(ATTACK_NAMES)}
ATTACK_PROCESSES := $(subst $(space),$(comma),$(ATTACK_PROCESSES))
CFLAGS += -DATTACK_PROCESSES='$(ATTACK_PROCESSES)'

prefix := PROCESS_NAME(
suffix := );
ATTACK_PROCESSES_DECL := ${addprefix $(prefix),$(ATTACK_NAMES)}
ATTACK_PROCESSES_DECL := ${addsuffix $(suffix),$(ATTACK_PROCESSES_DECL)}
CFLAGS += -DATTACK_PROCESSES_DECL='$(ATTACK_PROCESSES_DECL)'

# Certain attacks require code to be pulled in from different areas
ifneq (,$(findstring dos_certificate_verification,$(MAKE_ATTACKS)))
    CFLAGS += -I../node/trust
endif

# Main Contiki-NG compile
include $(CONTIKI)/Makefile.include
