# Everything runs in containers; only Docker is needed on the host.
IMAGE   ?= secret-mask:dev
VERSION ?= dev
ARCH    := $(shell docker version -f '{{.Server.Arch}}')

.PHONY: test image binaries e2e demo scan all

all: test image binaries e2e

test: ## go vet + unit and integration tests
	docker build --target test .

image: ## runtime image $(IMAGE)
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

binaries: ## static binaries + SHA256SUMS in dist/
	docker build --target binaries --build-arg VERSION=$(VERSION) -o dist .

e2e: image binaries ## end-to-end tests against the release binary and the image
	docker run --rm -v "$(CURDIR)/test/e2e:/e2e:ro" -v "$(CURDIR)/install.sh:/installer/install.sh:ro" -v "$(CURDIR)/dist:/dist:ro" \
		-e SECRET_MASK_INSTALLER=/installer/install.sh alpine:3.24.3 sh -c 'apk add --no-cache git curl busybox-extras bash zsh util-linux-misc >/dev/null && sh /e2e/e2e.sh /dist/secret-mask_linux_$(ARCH)'
	docker run --rm --entrypoint sh -v "$(CURDIR)/test/e2e:/e2e:ro" $(IMAGE) \
		/e2e/e2e.sh /usr/local/bin/secret-mask

demo: binaries ## guided demo of every feature (release binary, in a container with git)
	docker run --rm -t -v "$(CURDIR)/demo:/demo:ro" -v "$(CURDIR)/dist:/dist:ro" alpine:3.24.3 \
		sh -c 'apk add --no-cache git >/dev/null && sh /demo/demo.sh /dist/secret-mask_linux_$(ARCH) /tmp/demo'

scan: image ## Trivy scan of the image
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.76.2 image \
		--scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 $(IMAGE)
