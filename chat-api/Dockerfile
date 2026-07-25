FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/chat-api ./chat-api

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/chat-api /chat-api
EXPOSE 8082
ENTRYPOINT ["/chat-api"]
