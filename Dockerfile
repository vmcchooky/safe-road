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

ENV SAFE_ROAD_HEALTHCHECK_PORT=8080
ENV SAFE_ROAD_HEALTHCHECK_PATH=/healthz

HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD sh -c 'wget -qO- "http://127.0.0.1:${SAFE_ROAD_HEALTHCHECK_PORT}${SAFE_ROAD_HEALTHCHECK_PATH}" >/dev/null 2>&1 || exit 1'

EXPOSE 8080 8081

ENTRYPOINT ["/app/service"]
