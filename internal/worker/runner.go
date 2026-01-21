package worker

import (
    "context"
    "log"

    "scanner-platform/internal/models"
    // "scanner-platform/internal/webhook"
    // "scanner-platform/scanner-engine"
)

func Run(ctx context.Context, job *models.ScanJob) {
    log.Printf("Scan started: %s (%s)", job.ScanID, job.Domain)

    // webhook.Send(job.ScanID, "scan_started", nil)

    // pipeline := scanner.NewPipeline(job.Domain)

    // for stage := range pipeline.Execute(ctx) {
    //     webhook.Send(job.ScanID, stage.Name, stage.Data)
    // }

    // webhook.Send(job.ScanID, "scan_completed", nil)
}