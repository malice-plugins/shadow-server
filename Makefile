REPO=malice-plugins/shadow-server
ORG=malice
NAME=shadow-server
VERSION=$(shell cat VERSION)

all: build size test

build:
	docker build -t $(ORG)/$(NAME):$(VERSION) .

size:
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(ORG)/$(NAME)

ssh:
	@docker run --init -it --rm --entrypoint=bash $(ORG)/$(NAME):$(VERSION)

tar:
	docker save $(ORG)/$(NAME):$(VERSION) -o $(NAME).tar

test:
	@docker run --rm $(ORG)/$(NAME):$(VERSION) --help
	@docker run --rm $(ORG)/$(NAME):$(VERSION) -V 669f87f2ec48dce3a76386eec94d7e3b | jq . > docs/results.json
	cat docs/results.json | jq .
	@echo "===> Test lookup sandbox"
	@docker run --rm $(ORG)/$(NAME):$(VERSION) -t 669f87f2ec48dce3a76386eec94d7e3b| tee docs/SAMPLE.md
	@echo "===> Test lookup whitelist"
	@docker run --rm $(ORG)/$(NAME):$(VERSION) -t 7a90f8b051bc82cc9cadbcc9ba345ced02891a6c | tee -a docs/SAMPLE.md

circle: ci-size
	@sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell cat .circleci/SIZE)-blue/' README.md
	@echo "===> Image size is: $(shell cat .circleci/SIZE)"

ci-build:
	@echo "===> Getting CircleCI build number"
	@http https://circleci.com/api/v1.1/project/github/${REPO} | jq '.[0].build_num' > .circleci/build_num

ci-size: ci-build
	@echo "===> Getting image build size from CircleCI"
	@http "$(shell http https://circleci.com/api/v1.1/project/github/${REPO}/$(shell cat .circleci/build_num)/artifacts${CIRCLE_TOKEN} | jq '.[].url')" > .circleci/SIZE

clean:
	docker-clean stop
	docker rmi $(ORG)/$(NAME):$(VERSION)

.PHONY: build size tags test
