SHELL=/bin/bash -o pipefail

export GO111MODULE := on
export PATH := .bin:${PATH}
export PWD := $(shell pwd)

GO_DEPENDENCIES = github.com/ory/go-acc \
				  golang.org/x/tools/cmd/goimports \
				  github.com/go-swagger/go-swagger/cmd/swagger \
				  github.com/ory/cli \
				  github.com/gobuffalo/packr/v2/packr2 \
				  github.com/go-bindata/go-bindata/go-bindata

define make-go-dependency
  # go install is responsible for not re-building when the code hasn't changed
  .bin/$(notdir $1): go.sum go.mod
		GOBIN=$(PWD)/.bin/ go install $1
endef
$(foreach dep, $(GO_DEPENDENCIES), $(eval $(call make-go-dependency, $(dep))))

node_modules: package.json package-lock.json
		npm i

.bin/clidoc: go.mod
		go build -o .bin/clidoc ./cmd/clidoc/.

# Formats the code
.PHONY: format
format: .bin/goimports node_modules
		goimports -w --local github.com/ory .
		gofmt -l -s -w .
		npm run format

.bin/ory: Makefile
		bash <(curl https://raw.githubusercontent.com/ory/meta/master/install.sh) -b .bin ory v0.1.22
		touch -a -m .bin/ory

# Generates the SDK
.PHONY: sdk
sdk: .bin/swagger .bin/ory node_modules
		swagger generate spec -m -o spec/swagger.json \
			-c github.com/ory/oathkeeper \
			-c github.com/ory/x/healthx
		ory dev swagger sanitize ./spec/swagger.json
		swagger validate ./spec/swagger.json
		CIRCLE_PROJECT_USERNAME=ory CIRCLE_PROJECT_REPONAME=oathkeeper \
				ory dev openapi migrate \
					--health-path-tags metadata \
					-p https://raw.githubusercontent.com/ory/x/master/healthx/openapi/patch.yaml \
					-p file://.schema/openapi/patches/meta.yaml \
					spec/swagger.json spec/api.json

		rm -rf internal/httpclient
		mkdir -p internal/httpclient
		swagger generate client -f ./spec/swagger.json -t internal/httpclient -A Ory_Oathkeeper

		make format

.PHONY: install-stable
install-stable: .bin/packr2
		OATHKEEPER_LATEST=$$(git describe --abbrev=0 --tags)
		git checkout $$OATHKEEPER_LATEST
		packr2
		GO111MODULE=on go install \
				-ldflags "-X github.com/ory/oathkeeper/x.Version=$$OATHKEEPER_LATEST -X github.com/ory/oathkeeper/x.Date=`TZ=UTC date -u '+%Y-%m-%dT%H:%M:%SZ'` -X github.com/ory/oathkeeper/x.Commit=`git rev-parse HEAD`" \
				.
		packr2 clean
		git checkout master

.PHONY: install
install: .bin/packr2
		packr2 || (GO111MODULE=on go install github.com/gobuffalo/packr/v2/packr2 && packr2)
		GO111MODULE=on go install .
		packr2 clean

.PHONY: docker
docker: .bin/packr2
		packr2 || (GO111MODULE=on go install github.com/gobuffalo/packr/v2/packr2 && packr2)
		CGO_ENABLED=0 GO111MODULE=on GOOS=linux GOARCH=amd64 go build
		packr2 clean
		docker build -t oryd/oathkeeper:dev .
		docker build -t oryd/oathkeeper:dev-alpine -f Dockerfile-alpine .
		rm oathkeeper

build: .bin/packr2
		packr2 || (GO111MODULE=on go install github.com/gobuffalo/packr/v2/packr2 && packr2)
		CGO_ENABLED=0 GO111MODULE=on GOOS=linux GOARCH=amd64 go build
		packr2 clean

docs/cli: .bin/clidoc
		clidoc .

.PHONY: post-release
post-release:
		echo "nothing to do"
