package main

import (
	"context"
	"fmt"
	"log"
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
	scan_type := os.Getenv("WORKER_TYPE")
	if scan_type == "" {
		scan_type = "main"
	}

	fq := queue.NewFixQueue(addr)
	mq := queue.NewMainQueue(addr)

	log.Println("Scanner worker started")

	for {
		if scan_type == "fix" {
			log.Println("Running fix worker")

			job, err := fq.PopFixQueue(ctx)
			if err != nil {
				log.Println("Queue error:", err)
			}

			result, err := worker.RunFix(ctx, job)
			if err != nil {
				log.Println("Worker error:", err)
			}

			fmt.Printf("Webhook response: %v\n", result)
			
		} else {

			job, err := mq.PopMainQueue(ctx)
			if err != nil {
				log.Println("Queue error:", err)
				continue
			}

			result, err := worker.RunMain(ctx, job)
			if err != nil {
				log.Println("Worker error:", err)
				continue
			}
			fmt.Printf("Webhook response: %v\n", result)
		}
	}
}
