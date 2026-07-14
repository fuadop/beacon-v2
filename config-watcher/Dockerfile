FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/config-watcher ./config-watcher

FROM alpine:3.20
# docker CLI is needed so the watcher can `docker exec` a SIGHUP into the telegraf
# container (or restart it) when devices/settings change; distroless has no shell/CLI.
RUN apk add --no-cache docker-cli
COPY --from=build /out/config-watcher /config-watcher
ENTRYPOINT ["/config-watcher"]
