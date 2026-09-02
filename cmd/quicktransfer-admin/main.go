package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"quicktransfer/internal/app"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("quicktransfer-admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data-dir", "./data", "QuickTransfer data directory")
	email := flags.String("email", "admin@quicktransfer.local", "dedicated administrator email")
	rotate := flags.Bool("rotate", false, "rotate the password of an existing administrator")
	disableCaptcha := flags.Bool("disable-captcha", false, "disable CAPTCHA as a local recovery operation")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "quicktransfer-admin: positional arguments are not supported")
		return 2
	}
	if *disableCaptcha && *rotate {
		fmt.Fprintln(stderr, "quicktransfer-admin: --disable-captcha cannot be combined with --rotate")
		return 2
	}

	cleanDataDir := strings.TrimSpace(*dataDir)
	if cleanDataDir == "" {
		fmt.Fprintln(stderr, "quicktransfer-admin: --data-dir must not be empty")
		return 2
	}
	cleanDataDir = filepath.Clean(cleanDataDir)
	if err := os.MkdirAll(filepath.Join(cleanDataDir, "db"), 0o700); err != nil {
		fmt.Fprintf(stderr, "quicktransfer-admin: prepare data directory: %v\n", err)
		return 1
	}

	store, err := app.OpenStore(cleanDataDir)
	if err != nil {
		fmt.Fprintf(stderr, "quicktransfer-admin: open database: %v\n", err)
		return 1
	}
	defer store.Close()
	if *disableCaptcha {
		revision, err := store.DisableCaptchaRecovery(context.Background())
		if err != nil {
			fmt.Fprintf(stderr, "quicktransfer-admin: disable CAPTCHA recovery: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "CAPTCHA disabled in settings revision %d; restart QuickTransfer to apply recovery.\n", revision)
		return 0
	}

	password, err := app.GenerateAdminPassword()
	if err != nil {
		fmt.Fprintf(stderr, "quicktransfer-admin: generate password: %v\n", err)
		return 1
	}

	user, err := store.ProvisionAdmin(context.Background(), *email, password, *rotate)
	if err != nil {
		if errors.Is(err, app.ErrConflict) {
			fmt.Fprintln(stderr, "quicktransfer-admin: account conflict; --rotate is allowed only for an existing administrator")
		} else {
			fmt.Fprintf(stderr, "quicktransfer-admin: provision administrator: %v\n", err)
		}
		return 1
	}
	fmt.Fprintf(stdout, "email: %s\npassword: %s\n", user.Email, password)
	return 0
}
