package main

import (
    "context"
    "log"

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

        worker.Run(ctx, job)
    }
}