package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"quicktransfer/internal/app"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("quicktransfer-migrate-storage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	controlDataDir := flags.String("control-data-dir", "", "stopped control-plane data copy")
	sourceObjectsDir := flags.String("source-objects-dir", "", "explicit legacy objects directory")
	storageDataDir := flags.String("storage-data-dir", "", "initialized storage-node data directory")
	nodeID := flags.String("node-id", "", "destination storage node ID")
	apply := flags.Bool("apply", false, "apply the audited migration plan")
	copyOnly := flags.Bool("copy-only", false, "create independently copied objects and never use hard links")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "quicktransfer-migrate-storage: positional arguments are not supported")
		return 2
	}
	for name, value := range map[string]string{
		"--control-data-dir":   *controlDataDir,
		"--source-objects-dir": *sourceObjectsDir,
		"--storage-data-dir":   *storageDataDir,
		"--node-id":            *nodeID,
	} {
		if strings.TrimSpace(value) == "" {
			fmt.Fprintf(stderr, "quicktransfer-migrate-storage: %s is required\n", name)
			return 2
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	report, err := app.RunStorageMigration(ctx, app.StorageMigrationOptions{
		ControlDataDir:   *controlDataDir,
		SourceObjectsDir: *sourceObjectsDir,
		StorageDataDir:   *storageDataDir,
		NodeID:           *nodeID,
		Apply:            *apply,
		CopyOnly:         *copyOnly,
	})
	if err != nil {
		fmt.Fprintf(stderr, "quicktransfer-migrate-storage: %v\n", err)
		return 1
	}
	mode := "audit"
	if *apply {
		mode = "apply"
	}
	fmt.Fprintf(stdout, "mode=%s copy_only=%t candidate=%d imported=%d reused=%d bytes=%d skipped=%d quarantined=%d blocked=%d deleted=%d control_quick_check=%t storage_quick_check=%t\n",
		mode, *copyOnly, report.Candidate, report.Imported, report.Reused, report.Bytes, report.Skipped,
		report.Quarantined, report.Blocked, report.Deleted, report.ControlQuickCheck, report.StorageQuickCheck)
	return 0
}
