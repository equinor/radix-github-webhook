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
	go test -cover `go list ./...

.PHONY: deploy
deploy:
	# Download deploy key + webhook shared secret
	az keyvault secret download -f values.yaml -n radix-github-radixregistration --vault-name radix-boot-dev-vault
	# Install RR referring to the downloaded secrets
	helm upgrade --install radix-reg-github-webhook -f values.yaml radixdev/radix-registration 
	# Delete secret file to avvoid being checked in
	rm values.yaml
	# Allow operator to pick up RR. TODO should be handled with waiting for app namespace
	sleep 5
	# Create pipeline job
	helm upgrade --install radix-pipeline-github-webhook radixdev/radix-pipeline-invocation \
	    --set name="radix-github-webhook" \
		--set cloneURL="git@github.com:Statoil/radix-github-webhook.git" \
		--set cloneBranch="master"

.PHONY: undeploy
undeploy:
	helm delete --purge radix-pipeline-github-webhook
	helm delete --purge radix-reg-github-webhook

.PHONY: $(BINS)
$(BINS): vendor
	go build -ldflags '$(LDFLAGS)' -o bin/$@ .

.PHONY: docker-build
docker-build: $(addsuffix -image,$(IMAGES))

%-image:
	docker build $(DOCKER_BUILD_FLAGS) -t $(DOCKER_REGISTRY)/$*:$(IMAGE_TAG) .

.PHONY: docker-push
docker-push: $(addsuffix -push,$(IMAGES))

%-push:
	docker push $(DOCKER_REGISTRY)/$*:$(IMAGE_TAG)

HAS_GOMETALINTER := $(shell command -v gometalinter;)
HAS_DEP          := $(shell command -v dep;)
HAS_GIT          := $(shell command -v git;)

vendor:
ifndef HAS_GIT
	$(error You must install git)
endif
ifndef HAS_DEP
	go get -u github.com/golang/dep/cmd/dep
endif
ifndef HAS_GOMETALINTER
	go get -u github.com/alecthomas/gometalinter
	gometalinter --install
endif
	dep ensure

.PHONY: bootstrap
bootstrap: vendor