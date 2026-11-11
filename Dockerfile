FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service ./cmd/app

FROM alpine:3.22

# Отдельный пользователь: сервису с приватным ключом не нужен root
RUN adduser -D -H -u 10001 app
WORKDIR /app

COPY --from=builder /app/auth-service /app/auth-service
COPY --from=builder /app/config /app/config

USER app
EXPOSE 8090

CMD ["/app/auth-service"]
