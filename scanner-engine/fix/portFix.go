package fix

import (
	"context"
	"fmt"
	"os/exec"
	"bytes"
	"strings"

	"scanner-platform/internal/models"
)

func PortFix(ctx context.Context, job *models.FixScanJob) (models.FixScanResult, error){
	null := models.FixScanResult{}
	port := job.Data.(map[string]int)["port"]

	cmd := exec.CommandContext(ctx, "naabu", 
		"-host", job.Domain,
		"-p", fmt.Sprintf("%d", port),
		"-silent",
	)

	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return null, err
	}

	result := strings.TrimSpace(out.String())
	
	PortFixResult := models.FixScanResult{
		UserID: job.UserID,
		Domain: job.Domain,
		FixType: job.FixType,
		Result : result,
	}
	return PortFixResult, nil
}