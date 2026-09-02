package app

const (
	StorageKindLocal = "local"
	StorageKindNode  = "node"

	TransferStatusActive    = "active"
	TransferStatusExhausted = "exhausted"

	DownloadLimitModeLegacyFile         = "legacy_file"
	DownloadLimitModeRetrievalSessionV1 = "retrieval_session_v1"

	// StoragePlacementVersionV1 is the first explicit control-plane placement
	// contract. It is deliberately independent from the storage-node schema.
	StoragePlacementVersionV1 int64 = 1
)

type Transfer struct {
	ID                 string `json:"-"`
	Kind               string `json:"kind"`
	Title              string `json:"title"`
	ShareToken         string `json:"shareToken"`
	ManageHash         string `json:"-"`
	PickupCode         string `json:"pickupCode"`
	AccessHash         string `json:"-"`
	Status             string `json:"status"`
	ExpiresAt          int64  `json:"expiresAt"`
	CreatedAt          int64  `json:"createdAt"`
	MaxDownloads       int    `json:"maxDownloads"`
	Downloads          int    `json:"downloads"`
	TotalBytes         int64  `json:"totalBytes"`
	FileCount          int    `json:"fileCount"`
	RequiresCode       bool   `json:"requiresCode"`
	OwnerType          string `json:"-"`
	OwnerID            string `json:"-"`
	PolicyMaxFileBytes int64  `json:"-"`
	PolicyMaxTaskBytes int64  `json:"-"`
	PolicyMaxFiles     int    `json:"-"`
	DownloadLimitMode  string `json:"-"`
	DeleteOnExhaustion bool   `json:"-"`
}

type Upload struct {
	ID              string `json:"id"`
	TransferID      string `json:"-"`
	UploadHash      string `json:"-"`
	OriginalName    string `json:"name"`
	ContentType     string `json:"contentType"`
	Length          int64  `json:"size"`
	Offset          int64  `json:"offset"`
	Status          string `json:"status"`
	TempPath        string `json:"-"`
	ObjectPath      string `json:"-"`
	SHA256          string `json:"sha256,omitempty"`
	ScanDetail      string `json:"scanDetail,omitempty"`
	SubmitterName   string `json:"submitterName,omitempty"`
	CreatedAt       int64  `json:"createdAt"`
	CompletedAt     int64  `json:"completedAt,omitempty"`
	StorageReleased bool   `json:"-"`
	StorageKind     string `json:"-"`
	StorageNodeID   string `json:"-"`
	StorageKey      string `json:"-"`
	StorageVersion  int64  `json:"-"`
}

func (upload Upload) IsLocalStorage() bool {
	// Empty is accepted only as an in-memory compatibility value for callers
	// constructing legacy Upload values. Database rows are migrated to local.
	return upload.StorageKind == "" || upload.StorageKind == StorageKindLocal
}

func (upload Upload) IsNodeStorage() bool {
	return upload.StorageKind == StorageKindNode
}

type PublicTransfer struct {
	Kind         string   `json:"kind"`
	Title        string   `json:"title"`
	ShareToken   string   `json:"shareToken"`
	PickupCode   string   `json:"pickupCode"`
	Status       string   `json:"status"`
	ExpiresAt    int64    `json:"expiresAt"`
	CreatedAt    int64    `json:"createdAt"`
	MaxDownloads int      `json:"maxDownloads"`
	Downloads    int      `json:"downloads"`
	TotalBytes   int64    `json:"totalBytes"`
	FileCount    int      `json:"fileCount"`
	Locked       bool     `json:"locked"`
	Files        []Upload `json:"files,omitempty"`
	Scanning     bool     `json:"scanning"`
	BlockedFiles int      `json:"blockedFiles,omitempty"`
}
