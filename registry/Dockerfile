FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/sealim-registry ./cmd/sealim-registry

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sealim-registry /usr/local/bin/sealim-registry
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sealim-registry"]