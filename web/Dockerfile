# The build stage always runs on the machine doing the build (no emulation);
# Go cross-compiles to whatever --platform you ask for.
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod main.go ./
COPY site ./site
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o web .

# Nothing is executed in this stage, so it needs no emulation either.
FROM scratch
COPY --from=build /src/web /web
USER 65534:65534
EXPOSE 8080
ENV WEB_ADDR=:8080
ENTRYPOINT ["/web"]
