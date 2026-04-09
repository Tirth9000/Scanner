FROM golang:1.26.1-alpine AS builder

RUN apk add --no-cache \
    git \
    gcc \
    g++ \
    musl-dev \
    libpcap-dev \
    make \
    pkgconfig \
    libstdc++

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o scanner ./cmd/worker


FROM alpine:latest 

WORKDIR /root/

COPY --from=builder /app/scanner .

CMD ["./scanner"]

