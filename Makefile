BINPATH := $(PWD)/bin
SEMGREP_VERSION := 1.166.0
ZAP_IMAGE := ghcr.io/zaproxy/zaproxy:stable
GOVULNCHECK_VERSION := v1.3.0
TARGET ?= http://host.docker.internal:8080/healthz

export PATH := $(BINPATH):$(PATH)

all: tools

tools:
	cd tools && go mod tidy && go mod verify && go generate -tags tools

generate:
	go generate ./...

security: security-sast security-dast security-sca

security-sast:
	uvx --from "semgrep==$(SEMGREP_VERSION)" semgrep scan \
		--config p/golang \
		--config p/gosec \
		.

security-sca:
	GOPROXY=https://proxy.golang.org,direct go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

security-dast:
	docker run --rm \
		--add-host=host.docker.internal:host-gateway \
		"$(ZAP_IMAGE)" \
		zap-baseline.py \
		-t "$(TARGET)" \
		-m 1 \
		-I

.PHONY: all tools generate security security-sast security-sca security-dast
