package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultTermsContent = `一、服务范围
本服务提供临时文件发送、收集、提取、上传流量、VIP 权益和站内积分等功能。账户不设置存储容量配额，但文件仍按任务有效期临时保存，并可因到期、发送者撤销、安全处置或达到下载限制而失效。用户应自行保留原始文件和必要备份，本服务不作为永久存储或唯一备份工具。

二、账户与验证
注册人应使用本人合法控制且平台允许的邮箱，提供真实、准确的信息，妥善保管密码和验证凭据。禁止转售账户、批量注册、恶意占用邮箱、自动化撞库、绕过人机验证或帮助他人规避风控。平台可对注册、登录、找回密码、游客传输、兑换尝试以及异常流量或攻击行为进行频率限制及人机验证。

三、可接受使用规则
用户仅可处理自己有权处理的文件。严禁上传、收集或传播违反适用法律法规、危害国家安全或公共安全、侵犯知识产权和人格权益、泄露个人信息或商业秘密、包含恶意代码、诈骗、色情、赌博、暴力恐怖、骚扰、仇恨、违法交易、规避监管或破坏计算机系统的内容。不得扫描、攻击、压测、爬取、反向利用服务，或以任何方式干扰其他用户和基础设施。

四、内容授权与处置
文件权利仍归原权利人。用户仅在提供存储、完整性检查、安全扫描、传输、下载、删除和故障恢复所必需的范围内，授权平台处理其内容。平台收到有效投诉、发现安全风险或依法需要处置时，可以暂停传输、隔离或删除文件、限制账户，并依法保全必要证据或配合主管机关。

五、隐私与数据处理
为提供服务和保障安全，平台会处理邮箱地址、账户与验证状态、登录及操作时间、经保护的网络和设备标识、文件名称、大小、类型、哈希等技术元数据，以及用户主动上传的文件内容。数据仅用于履行服务、安全防护、滥用处置、审计和法定义务，不出售个人信息。文件按任务有效期保存，并在到期、撤销或清理后删除；账户、同意记录、安全日志和交易账本按履约、争议处理、安全及法定义务所需的合理期限保存。用户可通过运营方公布的联系渠道提出查询、更正、删除或注销请求，但法律要求保留或安全调查所必需的数据除外。

六、邮箱、人机验证与第三方服务
邮件投递和人机验证可能由已配置的邮箱服务商、Cloudflare Turnstile 或腾讯验证码提供。启用第三方能力时，必要的网络标识和验证数据会按其服务规则处理。平台仅在关键操作所必需的范围内调用这些服务，并对验证票据实施时效、动作、域名和防重放校验。

七、积分、流量、VIP 与支付
上传流量在文件上传时计费，下载及重复下载不消耗账户流量。流量、VIP、兑换码、积分和套餐仅代表站内使用权益，不是存款、证券或法定货币，不得套现、倒卖或场外交易。页面标明“暂未开放”的支付方式不会创建真实支付或扣款。支付渠道正式开放后，应以届时公布的价格、有效期、退款和开票规则为准；未经支付成功确认，不视为已购买。

八、服务变更、中断与责任边界
平台会采取合理措施维护可用性和安全性，但互联网、设备、第三方服务和不可抗力可能导致延迟、中断或数据损坏。除法律另有强制规定外，平台不对用户未备份、错误分享、凭据泄露、第三方行为或违法使用造成的损失承担责任。任何责任限制均不排除依法不得排除或限制的责任。

九、未成年人
未成年人应在监护人指导和同意下使用服务，不得上传不适合其年龄或涉及他人敏感信息的内容。监护人发现不当使用时应及时联系运营方处理。

十、暂停与终止
用户违反本规则、危害安全或依法需要处置时，平台可采取验证码升级、限流、暂停、封禁、撤销分享、删除违法内容等必要措施。用户可停止使用并申请注销；注销不影响此前依法形成的责任、账本、同意证据和必要安全记录。

十一、条款版本与同意证据
注册前必须阅读并勾选同意当前版本的服务条款、隐私政策和可接受使用规则。平台记录条款版本、正文哈希、同意时间及经保护的网络与设备信息。同一版本正文不得被替换；重大变更将发布新版本并在必要时重新征得同意。

十二、法律适用与争议处理
用户与运营方应先通过页面公布的正式联系渠道协商处理投诉和争议；协商不成的，按照适用法律规定向有管辖权的机构寻求解决。本条款任何部分无效不影响其余部分的效力，法律法规另有强制规定的，从其规定。`

type RegistrationSettings struct {
	Open                     bool     `json:"open"`
	RequireTerms             bool     `json:"requireTerms"`
	AllowedDomains           []string `json:"allowedDomains"`
	EmailCooldownSeconds     int      `json:"emailCooldownSeconds"`
	EmailHourly              int      `json:"emailHourly"`
	EmailDaily               int      `json:"emailDaily"`
	IPHourly                 int      `json:"ipHourly"`
	IPDaily                  int      `json:"ipDaily"`
	DomainHourly             int      `json:"domainHourly"`
	DomainDaily              int      `json:"domainDaily"`
	SuccessfulPerIPDaily     int      `json:"successfulPerIPDaily"`
	SuccessfulPerSubnetDaily int      `json:"successfulPerSubnetDaily"`
}

type DefaultQuotaSettings struct {
	GuestMaxFileBytes     int64 `json:"guestMaxFileBytes"`
	GuestMaxTransferBytes int64 `json:"guestMaxTransferBytes"`
	GuestMaxFiles         int   `json:"guestMaxFiles"`
	GuestMaxDownloads     int   `json:"guestMaxDownloads"`
	GuestDailyBytes       int64 `json:"guestDailyBytes"`
	GuestDailyTasks       int   `json:"guestDailyTasks"`
	// Legacy compatibility only. Account storage is unlimited and this value is
	// neither returned as a user resource nor enforced during upload.
	UserStorageBytes int64 `json:"userStorageBytes,omitempty"`
	// The field name is retained for stored-settings/API compatibility. It is
	// a one-time permanent initial grant and is never reset monthly.
	UserMonthlyTraffic int64 `json:"userMonthlyTrafficBytes"`
	DefaultExpiryHours int   `json:"defaultExpiryHours"`
	MaximumExpiryHours int   `json:"maximumExpiryHours"`
}

type SMTPSettings struct {
	Enabled            bool   `json:"enabled"`
	Provider           string `json:"provider"`
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Username           string `json:"username"`
	From               string `json:"from"`
	FromName           string `json:"fromName"`
	TLSMode            string `json:"tlsMode"`
	AuthMode           string `json:"authMode"`
	PasswordConfigured bool   `json:"passwordConfigured"`
	LastTestedAt       int64  `json:"lastTestedAt"`
	LastTestSucceeded  bool   `json:"lastTestSucceeded"`
}

type CaptchaSettings struct {
	Enabled                      bool            `json:"enabled"`
	Provider                     string          `json:"provider"`
	SiteKey                      string          `json:"siteKey"`
	AllowedHostnames             []string        `json:"allowedHostnames"`
	TencentCaptchaAppID          int64           `json:"tencentCaptchaAppId"`
	Actions                      map[string]bool `json:"actions"`
	SecretConfigured             bool            `json:"secretConfigured"`
	TencentCredentialsConfigured bool            `json:"tencentCredentialsConfigured"`
}

type PaymentSettings struct {
	PointsEnabled          bool   `json:"pointsEnabled"`
	WechatEnabled          bool   `json:"wechatEnabled"`
	WechatMerchantID       string `json:"wechatMerchantId"`
	WechatAppID            string `json:"wechatAppId"`
	WechatSecretConfigured bool   `json:"wechatSecretConfigured"`
	AlipayEnabled          bool   `json:"alipayEnabled"`
	AlipayAppID            string `json:"alipayAppId"`
	AlipaySecretConfigured bool   `json:"alipaySecretConfigured"`
}

type TermsSettings struct {
	Version     string `json:"version"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	EffectiveAt int64  `json:"effectiveAt"`
}

type ConsentEvidence struct {
	Version       string
	DocumentHash  string
	AcceptedAt    int64
	IPHash        string
	UserAgentHash string
}

func termsDocumentHash(terms TermsSettings) string {
	digest := sha256.Sum256([]byte(terms.Version + "\n" + terms.Title + "\n" +
		strconv.FormatInt(terms.EffectiveAt, 10) + "\n" + terms.Content))
	return hex.EncodeToString(digest[:])
}

type ServiceSettings struct {
	Revision     int64                `json:"revision"`
	Registration RegistrationSettings `json:"registration"`
	Defaults     DefaultQuotaSettings `json:"defaults"`
	SMTP         SMTPSettings         `json:"smtp"`
	Captcha      CaptchaSettings      `json:"captcha"`
	Payment      PaymentSettings      `json:"payment"`
	Terms        TermsSettings        `json:"terms"`
	UpdatedAt    int64                `json:"updatedAt"`
	UpdatedBy    string               `json:"updatedBy,omitempty"`
}

type ServiceSecrets struct {
	SMTPPassword        string
	TurnstileSecret     string
	TencentAppSecretKey string
	TencentSecretID     string
	TencentSecretKey    string
	WechatAPIv3Key      string
	AlipayPrivateKey    string
}

type SecretSettingsUpdate struct {
	SMTPPassword         string `json:"smtpPassword"`
	ClearSMTPPassword    bool   `json:"clearSmtpPassword"`
	TurnstileSecret      string `json:"turnstileSecret"`
	ClearTurnstileSecret bool   `json:"clearTurnstileSecret"`
	TencentAppSecretKey  string `json:"tencentAppSecretKey"`
	TencentSecretID      string `json:"tencentSecretId"`
	TencentSecretKey     string `json:"tencentSecretKey"`
	ClearTencentSecrets  bool   `json:"clearTencentSecrets"`
	WechatAPIv3Key       string `json:"wechatApiV3Key"`
	ClearWechatSecret    bool   `json:"clearWechatSecret"`
	AlipayPrivateKey     string `json:"alipayPrivateKey"`
	ClearAlipaySecret    bool   `json:"clearAlipaySecret"`
}

type settingsState struct {
	mu       sync.RWMutex
	settings ServiceSettings
	secrets  ServiceSecrets
}

func defaultServiceSettings(cfg Config) ServiceSettings {
	smtpProvider := smtpProviderFromHost(cfg.SMTPHost)
	smtpEnabled := !cfg.LocalVerification && smtpProvider != "" && cfg.SMTPUsername != "" && cfg.SMTPPassword != ""
	return ServiceSettings{
		Registration: RegistrationSettings{
			Open: cfg.RegistrationOpen, RequireTerms: true, AllowedDomains: append([]string(nil), cfg.EmailAllowedDomains...),
			EmailCooldownSeconds: int(cfg.VerificationCooldown.Seconds()), EmailHourly: cfg.VerificationEmailHourly,
			EmailDaily: cfg.VerificationEmailDaily, IPHourly: cfg.VerificationIPHourly, IPDaily: cfg.VerificationIPDaily,
			DomainHourly: cfg.VerificationDomainHourly, DomainDaily: cfg.VerificationDomainDaily,
			SuccessfulPerIPDaily: 3, SuccessfulPerSubnetDaily: 20,
		},
		Defaults: DefaultQuotaSettings{
			GuestMaxFileBytes: cfg.GuestMaxFileBytes, GuestMaxTransferBytes: cfg.GuestMaxTaskBytes,
			GuestMaxFiles: cfg.GuestMaxFiles, GuestMaxDownloads: cfg.GuestMaxDownloads,
			GuestDailyBytes: cfg.GuestDailyBytes, GuestDailyTasks: cfg.GuestDailyTasks,
			UserStorageBytes: 0, UserMonthlyTraffic: cfg.UserMonthlyTraffic,
			DefaultExpiryHours: int(cfg.DefaultExpiry.Hours()), MaximumExpiryHours: int(cfg.MaxExpiry.Hours()),
		},
		SMTP: SMTPSettings{Enabled: smtpEnabled, Provider: smtpProvider, Host: cfg.SMTPHost, Port: cfg.SMTPPort,
			Username: cfg.SMTPUsername, From: cfg.SMTPFrom, FromName: cfg.SMTPFromName,
			TLSMode: cfg.SMTPTLSMode, AuthMode: cfg.SMTPAuthMode, PasswordConfigured: cfg.SMTPPassword != ""},
		Captcha: CaptchaSettings{Provider: "disabled", Actions: map[string]bool{
			"login": true, "register": true, "password_reset": true, "guest_transfer": true, "redeem": true,
		}},
		Payment: PaymentSettings{PointsEnabled: true},
		// The version and effective time are part of the immutable document hash.
		// Keep them stable until the bundled legal text is deliberately revised.
		Terms: TermsSettings{Version: "2026-08-30", Title: "快传服务条款、隐私政策与可接受使用规则",
			Content: defaultTermsContent, EffectiveAt: 1788048000},
	}
}

func smtpProviderFromHost(host string) string {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "smtp.qq.com":
		return "qq"
	case "smtp.163.com":
		return "163"
	case "smtp.gmail.com":
		return "gmail"
	default:
		return ""
	}
}

func (state *settingsState) snapshot() (ServiceSettings, ServiceSecrets) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	settings := state.settings
	settings.Registration.AllowedDomains = append([]string(nil), settings.Registration.AllowedDomains...)
	settings.Captcha.AllowedHostnames = append([]string(nil), settings.Captcha.AllowedHostnames...)
	settings.Captcha.Actions = cloneBoolMap(settings.Captcha.Actions)
	return settings, state.secrets
}

func (state *settingsState) replace(settings ServiceSettings, secrets ServiceSecrets) {
	state.mu.Lock()
	state.settings, state.secrets = settings, secrets
	state.mu.Unlock()
}

func cloneBoolMap(input map[string]bool) map[string]bool {
	result := make(map[string]bool, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func applySecretUpdate(current ServiceSecrets, update SecretSettingsUpdate) ServiceSecrets {
	set := func(current *string, incoming string, clearValue bool) {
		if clearValue {
			*current = ""
		} else if incoming = strings.TrimSpace(incoming); incoming != "" {
			*current = incoming
		}
	}
	set(&current.SMTPPassword, update.SMTPPassword, update.ClearSMTPPassword)
	set(&current.TurnstileSecret, update.TurnstileSecret, update.ClearTurnstileSecret)
	if update.ClearTencentSecrets {
		current.TencentAppSecretKey, current.TencentSecretID, current.TencentSecretKey = "", "", ""
	} else {
		set(&current.TencentAppSecretKey, update.TencentAppSecretKey, false)
		set(&current.TencentSecretID, update.TencentSecretID, false)
		set(&current.TencentSecretKey, update.TencentSecretKey, false)
	}
	// Cash payment adapters are not enabled yet; never retain merchant secrets
	// until callback verification and refund flows are implemented.
	current.WechatAPIv3Key, current.AlipayPrivateKey = "", ""
	return current
}

func normalizeServiceSettings(settings ServiceSettings, secrets ServiceSecrets) (ServiceSettings, error) {
	var err error
	settings.Registration.AllowedDomains, err = normalizeEmailDomains(settings.Registration.AllowedDomains)
	if err != nil || len(settings.Registration.AllowedDomains) == 0 {
		return ServiceSettings{}, errors.New("at least one valid email domain is required")
	}
	settings.Registration.RequireTerms = true
	settings.Terms.Version = cleanText(settings.Terms.Version, 40)
	settings.Terms.Title = cleanText(settings.Terms.Title, 160)
	settings.Terms.Content = strings.TrimSpace(settings.Terms.Content)
	if settings.Terms.Version == "" || settings.Terms.Title == "" || len(settings.Terms.Content) < 200 || len(settings.Terms.Content) > 60000 {
		return ServiceSettings{}, errors.New("a versioned legal document between 200 and 60000 characters is required")
	}
	if settings.Terms.EffectiveAt <= 0 {
		settings.Terms.EffectiveAt = time.Now().Unix()
	}
	const guestCap = int64(100 * 1024 * 1024)
	if settings.Defaults.GuestMaxFileBytes <= 0 || settings.Defaults.GuestMaxFileBytes > guestCap ||
		settings.Defaults.GuestMaxTransferBytes < settings.Defaults.GuestMaxFileBytes || settings.Defaults.GuestMaxTransferBytes > guestCap ||
		settings.Defaults.GuestMaxFiles < 1 || settings.Defaults.GuestMaxFiles > 100 || settings.Defaults.GuestMaxDownloads < 1 ||
		settings.Defaults.GuestDailyBytes < settings.Defaults.GuestMaxTransferBytes || settings.Defaults.GuestDailyTasks < 1 ||
		settings.Defaults.UserStorageBytes < 0 || settings.Defaults.UserMonthlyTraffic < guestCap ||
		settings.Defaults.DefaultExpiryHours < 1 || settings.Defaults.MaximumExpiryHours < settings.Defaults.DefaultExpiryHours ||
		settings.Defaults.MaximumExpiryHours > 720 {
		return ServiceSettings{}, errors.New("invalid default quota settings")
	}
	registration := settings.Registration
	if registration.EmailCooldownSeconds < 60 || registration.EmailCooldownSeconds > 3600 ||
		registration.EmailHourly < 1 || registration.EmailDaily < registration.EmailHourly ||
		registration.IPHourly < 1 || registration.IPDaily < registration.IPHourly ||
		registration.DomainHourly < registration.IPHourly || registration.DomainDaily < registration.DomainHourly ||
		registration.SuccessfulPerIPDaily < 1 || registration.SuccessfulPerSubnetDaily < registration.SuccessfulPerIPDaily {
		return ServiceSettings{}, errors.New("invalid registration risk limits")
	}
	settings.SMTP.Provider = strings.ToLower(strings.TrimSpace(settings.SMTP.Provider))
	settings.SMTP.Username = strings.TrimSpace(settings.SMTP.Username)
	settings.SMTP.From = strings.TrimSpace(settings.SMTP.From)
	settings.SMTP.FromName = cleanText(settings.SMTP.FromName, 80)
	if settings.SMTP.Enabled {
		host, port, tlsMode, providerErr := smtpProviderDefaults(settings.SMTP.Provider)
		if providerErr != nil {
			return ServiceSettings{}, providerErr
		}
		settings.SMTP.Host, settings.SMTP.Port, settings.SMTP.TLSMode = host, port, tlsMode
		settings.SMTP.AuthMode = "login"
		if settings.SMTP.Username == "" || settings.SMTP.From == "" || secrets.SMTPPassword == "" {
			return ServiceSettings{}, errors.New("SMTP username, sender, and authorization code are required")
		}
	}
	settings.Captcha.Provider = strings.ToLower(strings.TrimSpace(settings.Captcha.Provider))
	settings.Captcha.AllowedHostnames, err = normalizeAllowedHostnames(settings.Captcha.AllowedHostnames)
	if err != nil {
		return ServiceSettings{}, err
	}
	if settings.Captcha.Actions == nil {
		settings.Captcha.Actions = map[string]bool{}
	}
	allowedCaptchaActions := map[string]bool{
		"login": true, "register": true, "password_reset": true, "guest_transfer": true, "redeem": true,
	}
	for action := range settings.Captcha.Actions {
		if !allowedCaptchaActions[action] {
			delete(settings.Captcha.Actions, action)
		}
	}
	if !settings.Captcha.Enabled {
		settings.Captcha.Provider = "disabled"
	} else {
		switch settings.Captcha.Provider {
		case "turnstile":
			if strings.TrimSpace(settings.Captcha.SiteKey) == "" || secrets.TurnstileSecret == "" || len(settings.Captcha.AllowedHostnames) == 0 {
				return ServiceSettings{}, errors.New("Turnstile site key, secret, and allowed hostname are required")
			}
		case "tencent":
			if settings.Captcha.TencentCaptchaAppID <= 0 || secrets.TencentAppSecretKey == "" ||
				secrets.TencentSecretID == "" || secrets.TencentSecretKey == "" {
				return ServiceSettings{}, errors.New("Tencent CAPTCHA application and API credentials are required")
			}
		default:
			return ServiceSettings{}, errors.New("unsupported CAPTCHA provider")
		}
	}
	settings.Payment.WechatEnabled = false
	settings.Payment.AlipayEnabled = false
	settings.SMTP.PasswordConfigured = secrets.SMTPPassword != ""
	settings.Captcha.SecretConfigured = secrets.TurnstileSecret != ""
	settings.Captcha.TencentCredentialsConfigured = secrets.TencentAppSecretKey != "" && secrets.TencentSecretID != "" && secrets.TencentSecretKey != ""
	settings.Payment.WechatSecretConfigured = false
	settings.Payment.AlipaySecretConfigured = false
	return settings, nil
}

func smtpProviderDefaults(provider string) (string, int, string, error) {
	switch provider {
	case "qq":
		return "smtp.qq.com", 465, "implicit", nil
	case "163":
		return "smtp.163.com", 465, "implicit", nil
	case "gmail":
		return "smtp.gmail.com", 465, "implicit", nil
	default:
		return "", 0, "", fmt.Errorf("unsupported SMTP provider %q", provider)
	}
}

func normalizeAllowedHostnames(values []string) ([]string, error) {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		hostname, err := normalizeHumanVerificationHostname(value)
		if err != nil {
			return nil, errors.New("invalid CAPTCHA hostname")
		}
		if !seen[hostname] {
			seen[hostname] = true
			result = append(result, hostname)
		}
	}
	return result, nil
}
