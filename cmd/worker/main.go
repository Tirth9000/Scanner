package main

import (
    "context"
    "log"
    "fmt"
    "os"

    "scanner-platform/internal/queue"
    "scanner-platform/internal/worker"
)

func main() {
    ctx := context.Background()
    addr := os.Getenv("REDIS_ADDR")
    if addr == "" {
        addr = "redis:6379"
    }

    q := queue.New(addr)

    log.Println("Scanner worker started")

    for {
        job, err := q.Pop(ctx)
        if err != nil {
            log.Println("Queue error:", err)
            continue
        }

        result, err := worker.Run(ctx, job)
        if err != nil {
            log.Println("Worker error:", err)
            continue
        }

        fmt.Printf("Webhook response: %v\n", result)
    }
}