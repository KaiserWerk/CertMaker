FROM golang:1.27 AS build-stage
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o certmaker ./cmd/certmaker
FROM scratch AS final-stage
WORKDIR /app
COPY --from=build-stage /app/certmaker .
EXPOSE 8880
ENTRYPOINT ["/app/certmaker"]