FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/trap-receiver ./trap-receiver

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/trap-receiver /trap-receiver
EXPOSE 162/udp
ENTRYPOINT ["/trap-receiver"]
