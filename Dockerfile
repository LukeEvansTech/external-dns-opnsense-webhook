ARG GO_VERSION
FROM golang:${GO_VERSION}-alpine AS builder
ARG VERSION=dev
ARG REVISION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.Gitsha=${REVISION}" \
    -trimpath -o /out/external-dns-opnsense-webhook ./cmd/external-dns-opnsense-webhook

FROM gcr.io/distroless/static:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
COPY --from=builder /out/external-dns-opnsense-webhook /external-dns-opnsense-webhook
EXPOSE 8888/tcp
ENTRYPOINT ["/external-dns-opnsense-webhook"]
