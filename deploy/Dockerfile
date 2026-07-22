# syntax=docker/dockerfile:1

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/cmd/discord-auth/admin ./cmd/discord-auth/admin
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/discord-auth ./cmd/discord-auth

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
  && adduser -D -H -u 65532 nonroot
USER nonroot
COPY --from=build /out/discord-auth /usr/local/bin/discord-auth
EXPOSE 4181
ENTRYPOINT ["/usr/local/bin/discord-auth"]
