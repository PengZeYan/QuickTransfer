package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	errEmailDomainNotAllowed = errors.New("email domain not allowed")
	emailDomainPattern       = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

type verificationPurpose string

const (
	verificationPurposeRegister verificationPurpose = "register"
	verificationPurposeReset    verificationPurpose = "reset"
	verificationPurposeTest     verificationPurpose = "test"
)

type verificationSender interface {
	Send(context.Context, string, string, verificationPurpose) error
	Mode() string
}

type localVerificationSender struct{}

func (localVerificationSender) Send(context.Context, string, string, verificationPurpose) error {
	return nil
}
func (localVerificationSender) Mode() string { return "local-sandbox" }

type failingVerificationSender struct{ err error }

func (sender failingVerificationSender) Send(context.Context, string, string, verificationPurpose) error {
	return sender.err
}
func (failingVerificationSender) Mode() string { return "unavailable" }

type smtpVerificationSender struct {
	host     string
	port     int
	username string
	password string
	from     mail.Address
	tlsMode  string
	authMode string
	timeout  time.Duration
	codeTTL  time.Duration
	slots    chan struct{}
}

func normalizeEmailDomains(values []string) ([]string, error) {
	trustedProviders := map[string]bool{"qq.com": true, "163.com": true, "gmail.com": true}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		domain := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(value, "@")))
		if !emailDomainPattern.MatchString(domain) {
			return nil, fmt.Errorf("invalid QT_EMAIL_ALLOWED_DOMAINS entry %q", value)
		}
		if !trustedProviders[domain] {
			return nil, fmt.Errorf("unsupported registration email provider %q", domain)
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	if len(result) == 0 {
		return nil, errors.New("QT_EMAIL_ALLOWED_DOMAINS must not be empty")
	}
	return result, nil
}

func normalizeEmailAddress(value string) (string, string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 254 || strings.ContainsAny(value, "\r\n") {
		return "", "", errors.New("invalid email")
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return "", "", errors.New("invalid email")
	}
	separator := strings.LastIndexByte(value, '@')
	if separator < 1 || separator == len(value)-1 {
		return "", "", errors.New("invalid email")
	}
	local, domain := value[:separator], value[separator+1:]
	if len(local) > 64 || strings.Contains(local, "+") || strings.HasPrefix(local, ".") ||
		strings.HasSuffix(local, ".") || strings.Contains(local, "..") || !emailDomainPattern.MatchString(domain) {
		return "", "", errors.New("invalid email")
	}
	for _, character := range local {
		if character > 127 || character <= 32 {
			return "", "", errors.New("invalid email")
		}
	}
	if domain == "gmail.com" {
		local = strings.ReplaceAll(local, ".", "")
	}
	return local + "@" + domain, domain, nil
}

func normalizeAllowedEmail(value string, allowed []string) (string, string, error) {
	email, domain, err := normalizeEmailAddress(value)
	if err != nil {
		return "", "", err
	}
	for _, candidate := range allowed {
		if domain == candidate {
			return email, domain, nil
		}
	}
	return "", domain, errEmailDomainNotAllowed
}

func privateRateKey(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validateSMTPConfig(cfg Config) error {
	if cfg.SMTPHost == "" || strings.ContainsAny(cfg.SMTPHost, "\r\n") || cfg.SMTPPort < 1 || cfg.SMTPPort > 65535 {
		return errors.New("QT_SMTP_HOST and a valid QT_SMTP_PORT are required when email verification is enabled")
	}
	if cfg.SMTPFrom == "" {
		return errors.New("QT_SMTP_FROM is required when email verification is enabled")
	}
	if strings.ContainsAny(cfg.SMTPFrom, "\r\n") || strings.ContainsAny(cfg.SMTPFromName, "\r\n") {
		return errors.New("QT_SMTP_FROM and QT_SMTP_FROM_NAME must not contain line breaks")
	}
	address, err := mail.ParseAddress(cfg.SMTPFrom)
	if err != nil || address.Address == "" || strings.ContainsAny(address.Address, "\r\n") {
		return errors.New("QT_SMTP_FROM is invalid")
	}
	if cfg.SMTPTLSMode != "implicit" && cfg.SMTPTLSMode != "starttls" {
		return errors.New("QT_SMTP_TLS_MODE must be implicit or starttls; unencrypted SMTP is forbidden")
	}
	if cfg.SMTPAuthMode != "login" && cfg.SMTPAuthMode != "plain" {
		return errors.New("QT_SMTP_AUTH_MODE must be login or plain")
	}
	if cfg.SMTPUsername == "" || cfg.SMTPPassword == "" {
		return errors.New("QT_SMTP_USERNAME and an SMTP password source are required")
	}
	return nil
}

func verificationSenderForConfig(cfg Config) verificationSender {
	if cfg.LocalVerification {
		return localVerificationSender{}
	}
	if err := validateSMTPConfig(cfg); err != nil {
		return failingVerificationSender{err: err}
	}
	from, err := mail.ParseAddress(cfg.SMTPFrom)
	if err != nil {
		return failingVerificationSender{err: err}
	}
	if cfg.SMTPFromName != "" {
		from.Name = cfg.SMTPFromName
	}
	return &smtpVerificationSender{
		host: cfg.SMTPHost, port: cfg.SMTPPort, username: cfg.SMTPUsername,
		password: cfg.SMTPPassword, from: *from, tlsMode: cfg.SMTPTLSMode,
		authMode: cfg.SMTPAuthMode, timeout: 12 * time.Second, codeTTL: cfg.VerificationCodeTTL,
		slots: make(chan struct{}, cfg.SMTPConcurrency),
	}
}

func (sender *smtpVerificationSender) Mode() string { return "email" }

func (sender *smtpVerificationSender) Send(ctx context.Context, recipient, code string, purpose verificationPurpose) error {
	if _, _, err := normalizeEmailAddress(recipient); err != nil {
		return err
	}
	message, err := buildVerificationMessage(sender.from, recipient, code, purpose, sender.codeTTL)
	if err != nil {
		return fmt.Errorf("build smtp message: %w", err)
	}
	select {
	case sender.slots <- struct{}{}:
		defer func() { <-sender.slots }()
	default:
		return errors.New("SMTP delivery capacity reached")
	}
	ctx, cancel := context.WithTimeout(ctx, sender.timeout)
	defer cancel()
	address := net.JoinHostPort(sender.host, strconv.Itoa(sender.port))
	dialer := &net.Dialer{Timeout: sender.timeout}
	tlsConfig := &tls.Config{ServerName: sender.host, MinVersion: tls.VersionTLS12}

	var connection net.Conn
	err = nil
	if sender.tlsMode == "implicit" {
		connection, err = tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("connect smtp: %w", err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(connection, sender.host)
	if err != nil {
		return fmt.Errorf("open smtp client: %w", err)
	}
	defer client.Close()
	if sender.tlsMode == "starttls" {
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("start smtp tls: %w", err)
		}
	}
	var auth smtp.Auth
	if sender.authMode == "plain" {
		auth = smtp.PlainAuth("", sender.username, sender.password, sender.host)
	} else {
		auth = &smtpLoginAuth{username: sender.username, password: sender.password}
	}
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("authenticate smtp: %w", err)
	}
	if err := client.Mail(sender.from.Address); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return fmt.Errorf("smtp recipient: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write smtp message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish smtp message: %w", err)
	}
	// DATA completion means the SMTP server accepted responsibility for delivery.
	// A later QUIT failure must not cause issuance of a second valid code.
	_ = client.Quit()
	return nil
}

type smtpLoginAuth struct {
	username string
	password string
}

func (auth *smtpLoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("LOGIN authentication requires TLS")
	}
	return "LOGIN", nil, nil
}

func (auth *smtpLoginAuth) Next(challenge []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	prompt := strings.ToLower(strings.TrimSpace(string(challenge)))
	if strings.Contains(prompt, "user") || prompt == "" {
		return []byte(auth.username), nil
	}
	if strings.Contains(prompt, "pass") {
		return []byte(auth.password), nil
	}
	return nil, fmt.Errorf("unsupported SMTP LOGIN challenge %q", prompt)
}

func buildVerificationMessage(from mail.Address, recipient, code string, purpose verificationPurpose, ttl time.Duration) ([]byte, error) {
	action := "完成账户注册"
	title := "验证你的邮箱"
	description := "输入下方验证码，继续完成快传账户注册。"
	if purpose == verificationPurposeReset {
		action = "重置账户密码"
		title = "重置账户密码"
		description = "输入下方验证码，继续设置新的账户密码。"
	}
	if purpose == verificationPurposeTest {
		action = "验证管理员 SMTP 配置"
		title = "SMTP 配置正常"
		description = "服务器已经通过加密连接完成本次测试邮件投递。"
	}
	minutes := max(1, int((ttl+time.Minute-1)/time.Minute))
	plain := fmt.Sprintf("您的快传验证码是：%s\n\n该验证码用于%s，%d 分钟内有效。请勿把验证码转发给任何人。\n\n如果不是您本人操作，请忽略此邮件。", code, action, minutes)
	subject := "【快传】邮箱验证码"
	if purpose == verificationPurposeTest {
		plain = fmt.Sprintf("快传 SMTP 配置测试成功。\n\n本次测试编号：%s\n\n该邮件由管理员在安全设置中主动发送，不包含账户验证码。", code)
		subject = "【快传】SMTP 配置测试"
	}
	htmlBody := buildVerificationHTML(title, description, action, code, minutes, purpose == verificationPurposeTest)
	messageID, err := randomToken(12)
	if err != nil {
		return nil, fmt.Errorf("generate message id: %w", err)
	}
	domain := strings.SplitN(from.Address, "@", 2)
	messageDomain := "quicktransfer.local"
	if len(domain) == 2 {
		messageDomain = domain[1]
	}
	headers := []string{
		"From: " + from.String(),
		"To: " + (&mail.Address{Address: recipient}).String(),
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		fmt.Sprintf("Message-ID: <%s@%s>", messageID, messageDomain),
		"Subject: " + mime.BEncoding.Encode("UTF-8", subject),
		"MIME-Version: 1.0",
		fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"qt-%s\"", messageID),
		"Auto-Submitted: auto-generated",
		"X-Auto-Response-Suppress: All",
	}
	boundary := "qt-" + messageID
	parts := []string{
		"--" + boundary,
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: base64",
		"",
		wrapBase64([]byte(plain)),
		"--" + boundary,
		"Content-Type: text/html; charset=UTF-8",
		"Content-Transfer-Encoding: base64",
		"",
		wrapBase64([]byte(htmlBody)),
		"--" + boundary + "--",
		"",
	}
	return []byte(strings.Join(headers, "\r\n") + "\r\n\r\n" + strings.Join(parts, "\r\n")), nil
}

func buildVerificationHTML(title, description, action, code string, minutes int, smtpTest bool) string {
	label := "一次性验证码"
	expiry := fmt.Sprintf("%d 分钟内有效", minutes)
	safety := "请勿将验证码转发给任何人。快传工作人员不会向你索要验证码。"
	if smtpTest {
		label = "测试编号"
		expiry = "此编号仅用于确认本次 SMTP 测试"
		safety = "该邮件由管理员在系统设置中主动发送，不包含账户验证码。"
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title></head>
<body style="margin:0;padding:0;background:#050816;color:#F7F8FF;font-family:'PingFang SC','Microsoft YaHei',Arial,sans-serif;">
  <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="width:100%%;background:#050816;">
    <tr><td align="center" style="padding:40px 16px;">
      <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="width:100%%;max-width:620px;border:1px solid #28345F;border-radius:24px;background:#080D1F;box-shadow:0 24px 80px rgba(68,70,255,.22);overflow:hidden;">
        <tr><td style="height:5px;background:#6D4AFF;background-image:linear-gradient(90deg,#A33DFF,#4E63FF,#2A8CFF);"></td></tr>
        <tr><td style="padding:34px 40px 18px;">
          <table role="presentation" cellspacing="0" cellpadding="0" border="0"><tr>
            <td style="width:42px;height:42px;border-radius:13px;background:#171B42;border:1px solid #4354A1;text-align:center;color:#8E7CFF;font-size:22px;font-weight:700;">Q</td>
            <td style="padding-left:13px;"><strong style="display:block;color:#FFFFFF;font-size:20px;line-height:1.2;">快传</strong><span style="display:block;margin-top:4px;color:#7F8AAD;font-size:12px;letter-spacing:1.2px;">安全文件传输</span></td>
          </tr></table>
        </td></tr>
        <tr><td style="padding:16px 40px 12px;">
          <div style="color:#8D9DFF;font-size:13px;font-weight:600;letter-spacing:1px;">安全验证</div>
          <h1 style="margin:12px 0 10px;color:#FFFFFF;font-size:30px;line-height:1.3;font-weight:700;">%s</h1>
          <p style="margin:0;color:#AAB3D0;font-size:16px;line-height:1.8;">%s</p>
        </td></tr>
        <tr><td style="padding:18px 40px;">
          <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="width:100%%;border:1px solid #4B4DB0;border-radius:18px;background:#0D1432;">
            <tr><td align="center" style="padding:23px 20px 8px;color:#8791B5;font-size:12px;letter-spacing:1.6px;">%s</td></tr>
            <tr><td align="center" style="padding:0 20px 10px;color:#FFFFFF;font-family:Arial,sans-serif;font-size:36px;line-height:1.2;font-weight:700;letter-spacing:8px;">%s</td></tr>
            <tr><td align="center" style="padding:4px 20px 22px;color:#8D9DFF;font-size:13px;">%s</td></tr>
          </table>
        </td></tr>
        <tr><td style="padding:10px 40px 34px;">
          <div style="padding:15px 17px;border-radius:14px;background:#0A1028;border:1px solid #222E57;color:#9EA8C8;font-size:13px;line-height:1.7;">%s</div>
          <p style="margin:22px 0 0;color:#667194;font-size:12px;line-height:1.7;">本邮件用于%s。如果不是你本人操作，可以安全忽略。</p>
        </td></tr>
      </table>
      <p style="margin:20px 0 0;color:#596483;font-size:12px;line-height:1.7;">QuickTransfer 快传 · 自动发送，请勿直接回复</p>
    </td></tr>
  </table>
</body></html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(description),
		html.EscapeString(label), html.EscapeString(code), html.EscapeString(expiry), html.EscapeString(safety), html.EscapeString(action))
}

func wrapBase64(value []byte) string {
	encoded := base64.StdEncoding.EncodeToString(value)
	var builder strings.Builder
	for len(encoded) > 76 {
		builder.WriteString(encoded[:76])
		builder.WriteString("\r\n")
		encoded = encoded[76:]
	}
	builder.WriteString(encoded)
	return builder.String()
}
