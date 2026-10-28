FROM golang:1.27 AS build-stage
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.Version=${VERSION} -X main.VersionDate=$(date +%Y-%m-%d\ %H:%M:%S)" -o certmaker ./cmd/certmaker
FROM scratch AS final-stage
WORKDIR /app
COPY --from=build-stage /app/certmaker .
EXPOSE 8880
ENTRYPOINT ["/app/certmaker"]