# syntax=docker/dockerfile:1
#
# Targets:
#   (default)  runtime image:  docker build -t secret-mask .
#   test       vet + unit/integration tests:  docker build --target test .
#   binaries   static binaries for every platform in /dist:  docker build --target binaries -o dist .

ARG GO_IMAGE=golang:1.27.3-alpine
ARG RUNTIME_IMAGE=alpine:3.24.3

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0 LDFLAGS="-s -w -X github.com/benakaben10/secret-mask/internal/version.Version=${VERSION}"
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "$LDFLAGS" -o /out/secret-mask ./cmd/secret-mask

FROM build AS test
RUN go vet ./... && go test -count=1 ./...

FROM build AS cross
RUN set -e; for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
      os=${p%/*}; arch=${p#*/}; ext=; [ "$os" = windows ] && ext=.exe; \
      GOOS=$os GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o /dist/secret-mask_${os}_${arch}${ext} ./cmd/secret-mask; \
    done; cd /dist && sha256sum secret-mask_* > SHA256SUMS

FROM scratch AS binaries
COPY --from=cross /dist/ /

FROM ${RUNTIME_IMAGE}
# Pick up Alpine security fixes released after the base image; stty is used for the password prompt.
RUN apk upgrade --no-cache
COPY --from=build /out/secret-mask /usr/local/bin/secret-mask
# Run with -u "$(id -u):$(id -g)" so masked files keep your ownership.
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["secret-mask"]
CMD ["help"]
