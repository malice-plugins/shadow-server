REPO=malice-plugins/shadow-server
ORG=malice
NAME=shadow-server
CATEGORY=intel
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
	@docker rm -f elasticsearch || true
	@docker run --init -d --name elasticsearch -p 9200:9200 blacktop/elasticsearch
	@sleep 10;docker run --rm $(ORG)/$(NAME):$(VERSION) --help
	@echo "===> Test sandbox"
	@docker run --rm --link elasticsearch $(ORG)/$(NAME):$(VERSION) -V 669f87f2ec48dce3a76386eec94d7e3b | jq . > docs/sandbox.json
	cat docs/sandbox.json | jq .
	@http localhost:9200/malice/_search | jq . > docs/elastic.json
	@cat docs/elastic.json | jq -r '.hits.hits[] ._source.plugins.${CATEGORY}.shadow_server.markdown' | tee docs/SAMPLE.md
	@echo "===> Test whitelist"
	@docker run --rm --link elasticsearch $(ORG)/$(NAME):$(VERSION) -V 7a90f8b051bc82cc9cadbcc9ba345ced02891a6c | jq . > docs/whitelist.json
	cat docs/whitelist.json | jq .
	@http localhost:9200/malice/_search | jq . > docs/elastic.json
	@cat docs/elastic.json | jq -r '.hits.hits[1] ._source.plugins.${CATEGORY}.shadow_server.markdown' | tee -a docs/SAMPLE.md
	@docker rm -f elasticsearch

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
