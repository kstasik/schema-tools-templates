.PHONY: all install-dependencies clean

API_VERSION := $(shell cat spec/api/api.yaml | grep '^  version' | cut -d' ' -f4)

SCHEMATOOLS_VERSION := v0.3.0
SCHEMATOOLS_BIN = dependencies/schematools-$(SCHEMATOOLS_VERSION)
FORMAT = 
SCHEMATOOLS_PLATFORM = 

openapi: install-dependencies format
	mkdir -p spec/publish/

	$(SCHEMATOOLS_BIN) chain -vv \
		-c 'process dereference spec/api/api.yaml --skip-root-internal-references --skip-references json.schemas.registry.com --create-internal-references' \
		-c 'process merge-all-of - --leave-invalid-properties --filter "x-skip!=true"' \
		-c 'validate openapi -' \
		-c 'output -o json --to-file spec/publish/v${API_VERSION}.json'

	cp spec/publish/v${API_VERSION}.json spec/publish/latest.json

codegen: install-dependencies format
	@echo generating code ...

	$(SCHEMATOOLS_BIN) chain -vvvv \
		-c 'process dereference spec/message/all.yaml --skip-root-internal-references --create-internal-references' \
		-c 'codegen json-schema - --template ../../rust/_common/ --template ../../rust/rabbitmq/ -o apm=tracing-opentelemetry -o "log=log" -o "client=actix" ${FORMAT} --target-dir src/' \
		\
		-c 'process dereference spec/api/api.yaml --skip-root-internal-references --create-internal-references' \
		-c 'process merge-all-of - --leave-invalid-properties --filter "x-skip!=true"' \
		-c 'process name - --overwrite --resource-method-version' \
		-c 'codegen openapi - --template ../../rust/_common/ --template ../../rust/server-actix/ ${FORMAT} --target-dir src/' \
		-c 'codegen openapi - --template ../../rust/_common/ --template ../../rust/client/ --format "rustfmt --edition 2021" --target-dir src/client/ -o apm=tracing-opentelemetry -o namespace=devices -o name=DevicesClient'
 
install-dependencies: platform
	@echo installing dependencies ...

	mkdir -p dependencies/

	if [ ! -f ./dependencies/schematools-$(SCHEMATOOLS_VERSION) ]; then \
		curl -Lo dependencies/schematools.tar.gz https://github.com/kstasik/schema-tools/releases/download/$(SCHEMATOOLS_VERSION)/schematools-$(SCHEMATOOLS_PLATFORM).tar.gz; \
		tar -xvf dependencies/schematools.tar.gz -C dependencies/; \
		mv dependencies/schematools-$(SCHEMATOOLS_PLATFORM) dependencies/schematools-$(SCHEMATOOLS_VERSION); \
		chmod u+x dependencies/schematools-$(SCHEMATOOLS_VERSION); \
		rm dependencies/schematools.tar.gz; \
	fi

format:
	$(info Trying to find rustfmt)
ifneq (, $(shell which rustfmt))
    $(eval FORMAT := --format "rustfmt --edition 2021")
endif

platform:
	$(info Detecting platform)
    $(eval SCHEMATOOLS_PLATFORM := )

ifeq ($(OS),Windows_NT)
	$(error Windows not yet supported)
endif

    UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    SCHEMATOOLS_PLATFORM = linux
else ifeq ($(UNAME_S),Darwin)
    SCHEMATOOLS_PLATFORM = darwin
else
    $(error Cannot detect os ${UNAME_S})
endif

    UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	SCHEMATOOLS_PLATFORM := $(addsuffix -amd64,$(SCHEMATOOLS_PLATFORM))
else ifneq ($(filter arm%,$(UNAME_M)),)
	SCHEMATOOLS_PLATFORM := $(addsuffix -arm64,$(SCHEMATOOLS_PLATFORM))
else
	$(error Cannot detect architecture ${UNAME_M})
endif

    $(info Platform detected: ${SCHEMATOOLS_PLATFORM})

clean:
	@echo cleaning ...