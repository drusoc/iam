BINPATH = $(PWD)/bin
export PATH := $(BINPATH):$(PATH)

all: tools
tools:
	cd tools && go mod tidy && go mod verify && go generate -tags tools

generate:
	go generate ./...

.PHONY: tools