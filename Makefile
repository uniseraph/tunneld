# Copyright (c) 2015-2017, ANT-FINANCE CORPORATION. All rights reserved.

SHELL = /bin/bash

GOLANG = golang:1.7.5

TUNNELD = github.com/zanecloud/tunneld

VERSION = $(shell cat VERSION)
GITCOMMIT = $(shell git log -1 --pretty=format:%h)
BUILD_TIME = $(shell date --rfc-3339 ns 2>/dev/null | sed -e 's/ /T/')

IMAGE_NAME = registry.cn-hangzhou.aliyuncs.com/zanecloud/tunneld

build:
	docker run -v $(shell pwd):/go/src/${TUNNELD} -w /go/src/${TUNNELD} --rm ${GOLANG} make build-local

binary: build

build-local:
	@rm -rf bundles/${VERSION}
	mkdir -p bundles/${VERSION}/binary
	CGO_ENABLED=0 go build -v -ldflags "-X main.Version=${VERSION} -X main.GitCommit=${GITCOMMIT} -X main.BuildTime=${BUILD_TIME}" -o bundles/${VERSION}/binary/tunneld ${TUNNELD}

image:
	docker build -t ${IMAGE_NAME} .
	docker tag ${IMAGE_NAME} ${IMAGE_NAME}:${VERSION}-${GITCOMMIT}

publish:
	docker tag ${IMAGE_NAME}:${VERSION}-${GITCOMMIT} ${IMAGE_NAME}:${VERSION}
	docker tag ${IMAGE_NAME}:${VERSION}-${GITCOMMIT} ${IMAGE_NAME}
	docker push ${IMAGE_NAME}:${VERSION}-${GITCOMMIT}
	docker push ${IMAGE_NAME}:${VERSION}
	docker push ${IMAGE_NAME}

.PHONY: build binary build-local image release
