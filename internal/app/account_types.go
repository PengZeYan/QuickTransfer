package app

const (
	VIPPlanNone     = "none"
	VIPPlanMonthly  = "monthly"
	VIPPlanYearly   = "yearly"
	VIPPlanLifetime = "lifetime"

	// SQLite keeps a concrete sortable value for permanent traffic balances.
	// Product APIs expose validDays=0 so clients never present this sentinel as a date.
	permanentTrafficEntitlementExpiry = int64(253402300799) // 9999-12-31T23:59:59Z.
	permanentBaseTrafficSource        = "permanent"
)

type User struct {
	ID                 string `json:"id"`
	Email              string `json:"email"`
	Username           string `json:"username"`
	PasswordHash       string `json:"-"`
	Status             string `json:"status"`
	Role               string `json:"role"`
	VIPPlan            string `json:"vipPlan"`
	VIPExpiresAt       int64  `json:"vipExpiresAt,omitempty"`
	MustChangePassword bool   `json:"mustChangePassword"`
	CreatedAt          int64  `json:"createdAt"`
	VerifiedAt         int64  `json:"verifiedAt"`
	LastLoginAt        int64  `json:"lastLoginAt"`
}

type Principal struct {
	Kind string
	ID   string
	User *User
}

func (principal Principal) Authenticated() bool {
	return principal.Kind == "user" && principal.User != nil
}

type Account struct {
	ID                    string `json:"id"`
	Email                 string `json:"email"`
	Username              string `json:"username"`
	Status                string `json:"status"`
	Role                  string `json:"role"`
	Level                 string `json:"level"`
	VIPPlan               string `json:"vipPlan"`
	VIPExpiresAt          int64  `json:"vipExpiresAt,omitempty"`
	TrafficRemainingBytes int64  `json:"remainingUploadTrafficBytes"`
}

type EffectivePolicy struct {
	Tier             string `json:"tier"`
	MaxFileBytes     int64  `json:"maxFileBytes"`
	MaxTransferBytes int64  `json:"maxTransferBytes"`
	MaxFiles         int    `json:"maxFiles"`
	MaxDownloads     int    `json:"maxDownloads"`
	MaxExpiryHours   int    `json:"maxExpiryHours"`
}

type AccountSummary struct {
	Username                string `json:"username"`
	Level                   string `json:"level"`
	VIPPlan                 string `json:"vipPlan"`
	VIPExpiresAt            int64  `json:"vipExpiresAt,omitempty"`
	TrafficRemainingBytes   int64  `json:"remainingUploadTrafficBytes"`
	StorageLimitBytes       int64  `json:"-"`
	StorageUsedBytes        int64  `json:"-"`
	FreeTrafficBytes        int64  `json:"-"`
	PaidTrafficBytes        int64  `json:"-"`
	TrafficReservedBytes    int64  `json:"-"`
	Points                  int64  `json:"points"`
	ActiveStorageBonusBytes int64  `json:"-"`
}

type Product struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Kind         string `json:"kind"`
	StorageBytes int64  `json:"-"`
	TrafficBytes int64  `json:"trafficBytes"`
	ValidDays    int    `json:"validDays"`
	VIPPlan      string `json:"vipPlan,omitempty"`
	VIPDays      int    `json:"vipDays,omitempty"`
	PriceCents   int64  `json:"priceCents"`
	PointsPrice  int64  `json:"pointsPrice"`
	Active       bool   `json:"active"`
	SortOrder    int    `json:"-"`
}

type Order struct {
	ID                    string `json:"id"`
	UserID                string `json:"-"`
	ProductID             string `json:"productId"`
	ProductName           string `json:"productName"`
	PriceCents            int64  `json:"priceCents"`
	PointsPrice           int64  `json:"pointsPrice"`
	PaymentMethod         string `json:"paymentMethod"`
	Status                string `json:"status"`
	ProviderTransactionID string `json:"providerTransactionId,omitempty"`
	CreatedAt             int64  `json:"createdAt"`
	PaidAt                int64  `json:"paidAt,omitempty"`
	RefundedAt            int64  `json:"refundedAt,omitempty"`
}

type DownloadReservation struct {
	ID                 string
	UploadID           string
	TransferID         string
	RetrievalSessionID string
	UserID             string
	ReservedBytes      int64
	Status             string
	ExpiresAt          int64
}

type RetrievalSession struct {
	ID            string
	TransferID    string
	RecipientKey  string
	Status        string
	CreatedAt     int64
	ExpiresAt     int64
	HardExpiresAt int64
	LastUsedAt    int64
	CompletedAt   int64
}

type UploadTrafficCharge struct {
	UploadID    string `json:"uploadId"`
	UserID      string `json:"userId"`
	AmountBytes int64  `json:"amountBytes"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"createdAt"`
	SettledAt   int64  `json:"settledAt,omitempty"`
}

type UploadTrafficAllocation struct {
	UploadID    string `json:"uploadId"`
	Ordinal     int    `json:"ordinal"`
	SourceKind  string `json:"sourceKind"`
	SourceID    string `json:"sourceId,omitempty"`
	AmountBytes int64  `json:"amountBytes"`
}

type AdminOverview struct {
	Stats        map[string]any `json:"stats"`
	Users        int64          `json:"users"`
	PaidOrders   int64          `json:"paidOrders"`
	OpenReports  int64          `json:"openReports"`
	BlockedUsers int64          `json:"blockedUsers"`
	RecentAudits []AuditEntry   `json:"recentAudits"`
}

type AuditEntry struct {
	ID         string `json:"id"`
	UserID     string `json:"userId,omitempty"`
	Action     string `json:"action"`
	TargetType string `json:"targetType,omitempty"`
	TargetID   string `json:"targetId,omitempty"`
	Detail     string `json:"detail,omitempty"`
	IP         string `json:"ip,omitempty"`
	CreatedAt  int64  `json:"createdAt"`
}

type ResourceEntitlement struct {
	ID             string `json:"id"`
	ResourceType   string `json:"resourceType"`
	AmountBytes    int64  `json:"amountBytes"`
	RemainingBytes int64  `json:"remainingBytes"`
	ExpiresAt      int64  `json:"expiresAt"`
	SourceType     string `json:"sourceType"`
	SourceID       string `json:"sourceId"`
	CreatedAt      int64  `json:"createdAt"`
}

type PointsEntry struct {
	ID           string `json:"id"`
	Delta        int64  `json:"delta"`
	BalanceAfter int64  `json:"balanceAfter"`
	Reason       string `json:"reason"`
	CreatedAt    int64  `json:"createdAt"`
}

type DailyCheckIn struct {
	Date        string `json:"date"`
	RewardBytes int64  `json:"rewardBytes"`
	CreatedAt   int64  `json:"createdAt"`
}

type WelfareStatus struct {
	Month            string         `json:"month"`
	Today            string         `json:"today"`
	TimeZone         string         `json:"timeZone"`
	ClaimedToday     bool           `json:"claimedToday"`
	TodayRewardBytes int64          `json:"todayRewardBytes"`
	CheckInDays      int            `json:"checkInDays"`
	MonthRewardBytes int64          `json:"monthRewardBytes"`
	CheckIns         []DailyCheckIn `json:"checkIns"`
}

type DailyCheckInResult struct {
	CheckIn    DailyCheckIn `json:"checkIn"`
	Idempotent bool         `json:"idempotent"`
}

// VIPDailyLoginGrant is returned only when the current login created a new
// permanent upload-traffic entitlement for the Beijing calendar day.
type VIPDailyLoginGrant struct {
	Date        string `json:"date"`
	VIPPlan     string `json:"vipPlan"`
	RewardBytes int64  `json:"rewardBytes"`
	CreatedAt   int64  `json:"createdAt"`
}

type AdminUser struct {
	ID                               string `json:"id"`
	Email                            string `json:"email"`
	Username                         string `json:"username"`
	Status                           string `json:"status"`
	Role                             string `json:"role"`
	Level                            string `json:"level"`
	VIPPlan                          string `json:"vipPlan"`
	VIPExpiresAt                     int64  `json:"vipExpiresAt,omitempty"`
	CreatedAt                        int64  `json:"createdAt"`
	VerifiedAt                       int64  `json:"verifiedAt"`
	LastLoginAt                      int64  `json:"lastLoginAt"`
	Points                           int64  `json:"points"`
	TrafficRemainingBytes            int64  `json:"remainingUploadTrafficBytes"`
	BaseTrafficRemainingBytes        int64  `json:"baseTrafficRemainingBytes"`
	EntitlementTrafficRemainingBytes int64  `json:"entitlementTrafficRemainingBytes"`
	TrafficGrantedBytes              int64  `json:"trafficGrantedBytes"`
	TrafficConsumedBytes             int64  `json:"trafficConsumedBytes"`
	TrafficReservedBytes             int64  `json:"trafficReservedBytes"`
	OrderCount                       int64  `json:"orderCount"`
	PaidOrderCount                   int64  `json:"paidOrderCount"`
	RefundedOrderCount               int64  `json:"refundedOrderCount"`
	CashPaidCents                    int64  `json:"cashPaidCents"`
	PointsSpent                      int64  `json:"pointsSpent"`
	LastOrderAt                      int64  `json:"lastOrderAt"`
	RedemptionCount                  int64  `json:"redemptionCount"`
	TransferCount                    int64  `json:"transferCount"`
	ActiveTransferCount              int64  `json:"activeTransferCount"`
	CheckInDays                      int64  `json:"checkInDays"`
	CheckInTrafficBytes              int64  `json:"checkInTrafficBytes"`
	VIPDailyGrantDays                int64  `json:"vipDailyGrantDays"`
	VIPDailyTrafficBytes             int64  `json:"vipDailyTrafficBytes"`
}

type AdminUserTransfer struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Title        string `json:"title"`
	Status       string `json:"status"`
	TotalBytes   int64  `json:"totalBytes"`
	FileCount    int    `json:"fileCount"`
	Downloads    int    `json:"downloads"`
	MaxDownloads int    `json:"maxDownloads"`
	CreatedAt    int64  `json:"createdAt"`
	ExpiresAt    int64  `json:"expiresAt"`
}

type AdminUserDetail struct {
	User            AdminUser             `json:"user"`
	Orders          []Order               `json:"orders"`
	Entitlements    []ResourceEntitlement `json:"entitlements"`
	PointsLedger    []PointsEntry         `json:"pointsLedger"`
	Redemptions     []AdminRedemptionCode `json:"redemptions"`
	CheckIns        []DailyCheckIn        `json:"checkIns"`
	VIPDailyGrants  []VIPDailyLoginGrant  `json:"vipDailyGrants"`
	RecentTransfers []AdminUserTransfer   `json:"recentTransfers"`
}

type RedemptionBatch struct {
	ID            string                `json:"id"`
	Kind          string                `json:"kind"`
	Quantity      int                   `json:"quantity"`
	TrafficBytes  int64                 `json:"trafficBytes,omitempty"`
	VIPPlan       string                `json:"vipPlan,omitempty"`
	VIPDays       int                   `json:"vipDays,omitempty"`
	Status        string                `json:"status"`
	ExpiresAt     int64                 `json:"expiresAt,omitempty"`
	Note          string                `json:"note,omitempty"`
	CreatedBy     string                `json:"createdBy"`
	CreatedAt     int64                 `json:"createdAt"`
	DisabledAt    int64                 `json:"disabledAt,omitempty"`
	ActiveCodes   int64                 `json:"activeCodes"`
	RedeemedCodes int64                 `json:"redeemedCodes"`
	DisabledCodes int64                 `json:"disabledCodes"`
	Codes         []AdminRedemptionCode `json:"codes"`
}

type AdminRedemptionCode struct {
	ID               string `json:"id"`
	BatchID          string `json:"batchId"`
	Code             string `json:"code,omitempty"`
	CodeAvailable    bool   `json:"codeAvailable"`
	Status           string `json:"status"`
	RedeemedBy       string `json:"redeemedBy,omitempty"`
	RedeemedUsername string `json:"redeemedUsername,omitempty"`
	RedeemedEmail    string `json:"redeemedEmail,omitempty"`
	RedeemedAt       int64  `json:"redeemedAt,omitempty"`
	CreatedAt        int64  `json:"createdAt"`
}

type RedemptionCode struct {
	ID         string `json:"id"`
	BatchID    string `json:"batchId"`
	CodeHash   string `json:"-"`
	MaskedCode string `json:"maskedCode"`
	Status     string `json:"status"`
	RedeemedBy string `json:"redeemedBy,omitempty"`
	RedeemedAt int64  `json:"redeemedAt,omitempty"`
	CreatedAt  int64  `json:"createdAt"`
}

type Redemption struct {
	ID                    string `json:"id"`
	BatchID               string `json:"batchId"`
	Kind                  string `json:"kind"`
	MaskedCode            string `json:"maskedCode"`
	Status                string `json:"status"`
	Username              string `json:"username"`
	TrafficBytes          int64  `json:"trafficBytes,omitempty"`
	VIPPlan               string `json:"vipPlan,omitempty"`
	VIPDays               int    `json:"vipDays,omitempty"`
	VIPExpiresAt          int64  `json:"vipExpiresAt,omitempty"`
	TrafficRemainingBytes int64  `json:"remainingUploadTrafficBytes"`
	RedeemedAt            int64  `json:"redeemedAt"`
}

type AbuseReport struct {
	ID         string `json:"id"`
	ShareToken string `json:"shareToken"`
	Reason     string `json:"reason"`
	Detail     string `json:"detail"`
	IP         string `json:"ip"`
	Status     string `json:"status"`
	CreatedAt  int64  `json:"createdAt"`
	ResolvedAt int64  `json:"resolvedAt,omitempty"`
}
