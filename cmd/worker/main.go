package main

import (
    "context"
    "log"
    "fmt"

    "scanner-platform/internal/queue"
    "scanner-platform/internal/worker"
)

func main() {
    ctx := context.Background()
    q := queue.New("localhost:6379")

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

        fmt.Printf("Scan completed: %s (%d results)\n", job.ScanID, len(result))
    }
}