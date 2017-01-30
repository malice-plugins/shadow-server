REPO=malice
NAME=shadow-server
VERSION=$(shell cat VERSION)

all: build size test

build:
	docker build -t $(REPO)/$(NAME):$(VERSION) .

size:
	sed -i.bu 's/docker image-.*-blue/docker image-$(shell docker images --format "{{.Size}}" $(REPO)/$(NAME):$(VERSION))-blue/' README.md

tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(REPO)/$(NAME)

test:
	docker run --init --rm $(REPO)/$(NAME):$(VERSION)
	docker run --init --rm $(REPO)/$(NAME):$(VERSION) -V 669f87f2ec48dce3a76386eec94d7e3b > results.json
	cat results.json | jq .

.PHONY: build size tags test
