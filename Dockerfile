FROM golang:1.24-alpine AS build

ARG SERVICE=core-api

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/service ./cmd/${SERVICE}

FROM alpine:3.20

WORKDIR /app
RUN addgroup -S app && adduser -S app -G app

COPY --from=build --chown=app:app /out/service /app/service

USER app

EXPOSE 8080 8081

ENTRYPOINT ["/app/service"]
