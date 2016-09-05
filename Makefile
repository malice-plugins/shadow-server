NAME=shadow-server
VERSION=$(shell cat VERSION)
DEV_RUN_OPTS ?= 669f87f2ec48dce3a76386eec94d7e3b

dev:
	docker build -f Dockerfile -t $(NAME):dev .
	docker run --rm $(NAME):dev $(DEV_RUN_OPTS)

build:
	rm -rf build && mkdir build
	docker build -t $(NAME):$(VERSION) .
	sed -i.bu 's/docker image-.*-blue/docker image-$(shell docker images --format "{{.Size}}" $(NAME):$(VERSION))-blue/g' README.md
	docker save $(NAME):$(VERSION) | gzip -9 > build/$(NAME)_$(VERSION).tgz

release:
	rm -rf release && mkdir release
	go get github.com/progrium/gh-release/...
	cp build/* release
	gh-release create maliceio/malice-$(NAME) $(VERSION) \
		$(shell git rev-parse --abbrev-ref HEAD) $(VERSION)
	# glu hubtag maliceio/malice-$(NAME) $(VERSION)

circleci:
	rm -f ~/.gitconfig
	go get -u github.com/gliderlabs/glu
	glu circleci

.PHONY: build release
