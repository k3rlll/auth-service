-include .env

ifeq ($(OS),Windows_NT)
SHELL := bash.exe
endif

GOLANGCI_LINT_VERSION := v2.15.0

.PHONY: run keys test test-integration lint up down

## Запуск локально (нужен PostgreSQL из DATABASE_URL)
run:
	go run ./cmd/app

## Пара RSA-ключей для подписи токенов
keys:
	go run ./cmd/keygen

test:
	go test -race -count=1 ./...

## Против настоящего PostgreSQL (нужен Docker)
test-integration:
	go test -tags integration -race -count=1 ./internal/storage/...

lint:
	docker run --rm -v "$(CURDIR):/src" -w /src golangci/golangci-lint:$(GOLANGCI_LINT_VERSION) golangci-lint run ./...

up:
	docker compose up -d --build
down:
	docker compose down
