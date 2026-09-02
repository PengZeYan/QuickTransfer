package app

import (
	"context"
	"net/url"
	"strings"
)

func (server *Server) verificationMode() string {
	server.senderMu.RLock()
	defer server.senderMu.RUnlock()
	return server.verificationSender.Mode()
}

func (server *Server) sendVerification(ctx context.Context, email, code string, purpose verificationPurpose) error {
	server.senderMu.RLock()
	sender := server.verificationSender
	server.senderMu.RUnlock()
	return sender.Send(ctx, email, code, purpose)
}

func (server *Server) registrationAvailable() bool {
	if server.cfg.RegistrationForceClosed {
		return false
	}
	settings, secrets := server.settings.snapshot()
	if !settings.Registration.Open {
		return false
	}
	return (settings.SMTP.Enabled && server.verificationMode() == "email" && settings.SMTP.LastTestSucceeded &&
		smtpConfigurationFingerprint(settings.SMTP, secrets.SMTPPassword) == server.activeSMTPFingerprint) ||
		(server.cfg.ExposeLocalCode && server.verificationMode() == "local-sandbox")
}

func (server *Server) contentSecurityPolicy() string {
	settings, _ := server.settings.snapshot()
	scriptSources := []string{"'self'"}
	connectSources := []string{"'self'"}
	frameSources := []string{"'none'"}
	if server.cfg.UsesRemoteStorage() {
		if parsed, err := url.Parse(server.cfg.StoragePublicURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			connectSources = append(connectSources, parsed.Scheme+"://"+parsed.Host)
		}
	}
	if settings.Captcha.Enabled {
		switch settings.Captcha.Provider {
		case "turnstile":
			scriptSources = append(scriptSources, "https://challenges.cloudflare.com")
			connectSources = append(connectSources, "https://challenges.cloudflare.com")
			frameSources = []string{"https://challenges.cloudflare.com"}
		case "tencent":
			scriptSources = append(scriptSources, "https://turing.captcha.qcloud.com")
			connectSources = append(connectSources, "https://turing.captcha.qcloud.com", "https://*.captcha.qcloud.com")
			frameSources = []string{"https://turing.captcha.qcloud.com", "https://*.captcha.qcloud.com"}
		}
	}
	return "default-src 'self'; img-src 'self' data:; font-src 'self'; style-src 'self'; script-src " +
		strings.Join(scriptSources, " ") + "; connect-src " + strings.Join(connectSources, " ") +
		"; frame-src " + strings.Join(frameSources, " ") +
		"; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
}
