# syntax=docker/dockerfile:1
#
# Builds the agent into a distroless, non-root, static image. The vendored
# tree is the source of truth (-mod=vendor): the image contains exactly the
# third-party code committed to this repository, nothing fetched at build time.
#
#   docker build --build-arg VERSION=$(git describe --tags --always) \
#     -t <registry>/kube-diagnose-agent:<tag> .
#
# In production pin both base images to a digest.

FROM golang:1.26.9-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY cmd/ cmd/
COPY internal/ internal/
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor \
    go build -trimpath -ldflags="-s -w -X main.agentVersion=${VERSION}" \
    -o /out/agent ./cmd/agent

# distroless/static: no shell, no package manager, no libc — nothing for a
# compromised process to exec. The nonroot variant runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agent /agent
USER 65532:65532
ENTRYPOINT ["/agent"]
