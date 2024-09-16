TEST?=./...
PRODUCT=xray
GO_ARCH=$(shell go env GOARCH)
TARGET_ARCH=$(shell go env GOOS)_${GO_ARCH}
GORELEASER_ARCH=${TARGET_ARCH}

ifeq ($(GO_ARCH), amd64)
GORELEASER_ARCH=${TARGET_ARCH}_$(shell go env GOAMD64)
endif
PKG_NAME=pkg/xray
# if this path ever changes, you need to also update the 'ldflags' value in .goreleaser.yml
PKG_VERSION_PATH=github.com/jfrog/terraform-provider-${PRODUCT}/${PKG_NAME}
VERSION := $(shell git tag --sort=-creatordate | head -1 | sed  -n 's/v\([0-9]*\).\([0-9]*\).\([0-9]*\)/\1.\2.\3/p')
NEXT_VERSION := $(shell echo ${VERSION}| awk -F '.' '{print $$1 "." $$2 "." $$3 +1 }' )

TERRAFORM_CLI?=terraform

REGISTRY_HOST=registry.terraform.io

ifeq ($(TERRAFORM_CLI), tofu)
REGISTRY_HOST=registry.opentofu.org
TF_ACC_TERRAFORM_PATH="$(which tofu)"
TF_ACC_PROVIDER_HOST="registry.opentofu.org"
endif

BUILD_PATH=terraform.d/plugins/${REGISTRY_HOST}/jfrog/${PRODUCT}/${NEXT_VERSION}/${TARGET_ARCH}
SONAR_SCANNER_VERSION?=4.7.0.2747
SONAR_SCANNER_HOME?=${HOME}/.sonar/sonar-scanner-${SONAR_SCANNER_VERSION}-macosx

default: build

install: clean build
	mkdir -p ${BUILD_PATH} && \
		mv -v dist/terraform-provider-${PRODUCT}_${GORELEASER_ARCH}/terraform-provider-${PRODUCT}_v${NEXT_VERSION}* ${BUILD_PATH} && \
		rm -f .terraform.lock.hcl && \
		sed -i.bak 's/version = ".*"/version = "${NEXT_VERSION}"/' sample.tf && rm sample.tf.bak && \
		${TERRAFORM_CLI} init

clean:
	rm -fR dist terraform.d/ .terraform terraform.tfstate* .terraform.lock.hcl

update_pkg_cache:
	GOPROXY=https://proxy.golang.org GO111MODULE=on go get github.com/jfrog/terraform-provider-${PRODUCT}@v${VERSION}

build: fmt
	GORELEASER_CURRENT_TAG=${NEXT_VERSION} goreleaser build --single-target --clean --snapshot

test:
	@echo "==> Starting unit tests"
	go test $(TEST) -timeout=30s -parallel=4

attach:
	dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient attach $$(pgrep terraform-provider-${PRODUCT})

acceptance: fmt
	export TF_ACC=true && \
		go test -cover -coverprofile=coverage.txt -ldflags="-X '${PKG_VERSION_PATH}/provider.Version=${NEXT_VERSION}-test'" -v -p 1 -parallel 20 -timeout 35m ./pkg/...

# To generate coverage.txt run `make acceptance` first
coverage:
	go tool cover -html=coverage.txt

# SONAR_TOKEN (project token) must be set to run `make scan`. Check file sonar-project.properties for the configuration.
scan:
	${SONAR_SCANNER_HOME}/bin/sonar-scanner -Dsonar.projectVersion=${VERSION} -Dsonar.go.coverage.reportPaths=coverage.txt

fmt:
	@echo "==> Fixing source code with gofmt..."
	@go fmt ./pkg/...

doc:
	rm -f docs/debug.md
	go generate

.PHONY: build fmt
