# -------- BUILDER --------
FROM golang:1.26.1-alpine AS builder

RUN apk add --no-cache \
    git \
    gcc \
    g++ \
    musl-dev \
    libpcap-dev \
    make \
    pkgconfig \
    build-base \
    libstdc++

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o scanner ./cmd/worker

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest


# -------- RUNTIME --------
FROM alpine:latest

RUN apk add --no-cache \
    git \
    gcc \
    g++ \
    musl-dev \
    libpcap-dev \
    make \
    pkgconfig \
    build-base \
    libstdc++

WORKDIR /root/

COPY --from=builder /app/scanner .

COPY --from=builder /go/bin/ /usr/local/bin/

CMD ["./scanner"]