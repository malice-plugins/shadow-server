REPO=malice-plugins/shadow-server
ORG=malice
NAME=shadow-server
CATEGORY=intel
VERSION=$(shell cat VERSION)


all: build size tag test test_markdown

.PHONY: build
build:
	cd $(VERSION); docker build -t $(ORG)/$(NAME):$(VERSION) .

.PHONY: size
size:
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

.PHONY: tag
tag:
	docker tag $(ORG)/$(NAME):$(VERSION) $(ORG)/$(NAME):latest

.PHONY: tags
tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(ORG)/$(NAME)

.PHONY: ssh
ssh:
	@docker run --init -it --rm --entrypoint=bash $(ORG)/$(NAME):$(VERSION)

.PHONY: tar
tar:
	docker save $(ORG)/$(NAME):$(VERSION) -o $(NAME).tar

.PHONY: start_elasticsearch
start_elasticsearch:
ifeq ("$(shell docker inspect -f {{.State.Running}} elasticsearch)", "true")
	@echo "===> elasticsearch already running"
else
	@echo "===> Starting elasticsearch"
	@docker rm -f elasticsearch || true
	@docker run --init -d --name elasticsearch -p 9200:9200 malice/elasticsearch:6.3; sleep 10
endif

.PHONY: test
test:
	@docker run --rm $(ORG)/$(NAME):$(VERSION) --help
	@echo "===> Test sandbox"
	@docker run --rm $(ORG)/$(NAME):$(VERSION) -V 669f87f2ec48dce3a76386eec94d7e3b | jq . > docs/sandbox.json
	cat docs/sandbox.json | jq .
	@echo "===> Test whitelist"
	@docker run --rm $(ORG)/$(NAME):$(VERSION) -V 7a90f8b051bc82cc9cadbcc9ba345ced02891a6c | jq . > docs/whitelist.json
	cat docs/whitelist.json | jq .

.PHONY: test_elastic
test_elastic: start_elasticsearch
	@echo "===> ${NAME} test_elastic"
	@docker run --rm --link elasticsearch -e MALICE_ELASTICSEARCH=elasticsearch -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) -V 669f87f2ec48dce3a76386eec94d7e3b
	@docker run --rm --link elasticsearch -e MALICE_ELASTICSEARCH=elasticsearch -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) -V 7a90f8b051bc82cc9cadbcc9ba345ced02891a6c
	http localhost:9200/malice/_search | jq . > docs/elastic.json

.PHONY: test_markdown
test_markdown: test_elastic
	@echo "===> ${NAME} test_markdown"
	# http localhost:9200/malice/_search query:=@docs/query.json | jq . > docs/elastic.json
	cat docs/elastic.json | jq -r '.hits.hits[] ._source.plugins.${CATEGORY}.shadow_server.markdown' > docs/SAMPLE.md

.PHONY: circle
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

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := all
