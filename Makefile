DOCKER_REGISTRY	?= radixdev.azurecr.io

BINS	= radix-github-webhook
IMAGES	= radix-github-webhook

GIT_TAG		= $(shell git describe --tags --always 2>/dev/null)
VERSION		?= ${GIT_TAG}
IMAGE_TAG 	?= ${VERSION}
LDFLAGS		+= -s -w

CX_OSES		= linux windows
CX_ARCHS	= amd64

.PHONY: build
build: $(BINS)

.PHONY: test
test:
	go test -cover `go list ./...`

.PHONY: lint
lint: bootstrap
	golangci-lint run --max-same-issues 0

.PHONY: $(BINS)
$(BINS):
	go build -ldflags '$(LDFLAGS)' -o bin/$@ .

.PHONY: docker-build
docker-build: $(addsuffix -image,$(IMAGES))

%-image:
	docker build $(DOCKER_BUILD_FLAGS) -t $(DOCKER_REGISTRY)/$*:$(IMAGE_TAG) .

.PHONY: docker-push
docker-push: $(addsuffix -push,$(IMAGES))

%-push:
	az acr login --name $(DOCKER_REGISTRY)
	docker push $(DOCKER_REGISTRY)/$*:$(IMAGE_TAG)

.PHONY: deploy
deploy: docker-build docker-push

.PHONY: mocks
mocks: bootstrap
	mockgen -source ./radix/api_server.go -destination ./radix/api_server_mock.go -package radix

.PHONY: generate
generate: mocks

.PHONY: verify-generate
verify-generate: generate
	git diff --exit-code

HAS_GOLANGCI_LINT := $(shell command -v golangci-lint;)
HAS_MOCKGEN       := $(shell command -v mockgen;)

.PHONY: bootstrap
bootstrap:
ifndef HAS_GOLANGCI_LINT
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.7.2
endif
ifndef HAS_MOCKGEN
	go install go.uber.org/mock/mockgen@v0.6.0
endif
