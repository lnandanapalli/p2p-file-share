# Build stage: ACR builds on linux/amd64, so Go compiles natively for it.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o relay .

FROM scratch
COPY --from=build /src/relay /relay
USER 65534:65534
EXPOSE 8080
ENV RELAY_ADDR=:8080
ENTRYPOINT ["/relay"]
