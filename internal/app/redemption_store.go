package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	redemptionCodeAlphabet     = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	redemptionCodeCharacters   = 16
	maximumRedemptionBatchSize = 500
	maximumRedemptionTraffic   = int64(100) * 1024 * 1024 * 1024 * 1024
)

var (
	ErrInvalidRedemption     = errors.New("invalid redemption request")
	ErrRedemptionUnavailable = errors.New("redemption code is unavailable")
)

type RedemptionBatchSpec struct {
	Kind         string
	Count        int
	TrafficBytes int64
	VIPPlan      string
	VIPDays      int
	ExpiresAt    int64
	Note         string
}

type redemptionCodeRecord struct {
	codeID       string
	codeStatus   string
	redeemedBy   string
	redeemedAt   int64
	maskedCode   string
	batchID      string
	batchStatus  string
	kind         string
	trafficBytes int64
	vipPlan      string
	vipDays      int
	expiresAt    int64
}

func normalizeRedemptionBatchSpec(spec RedemptionBatchSpec, now int64) (RedemptionBatchSpec, error) {
	spec.Kind = strings.ToLower(strings.TrimSpace(spec.Kind))
	spec.VIPPlan = strings.ToLower(strings.TrimSpace(spec.VIPPlan))
	spec.Note = strings.Join(strings.Fields(cleanText(spec.Note, 200)), " ")
	if spec.Count < 1 || spec.Count > maximumRedemptionBatchSize {
		return RedemptionBatchSpec{}, ErrInvalidRedemption
	}
	if spec.ExpiresAt != 0 {
		if spec.ExpiresAt <= now || spec.ExpiresAt > time.Unix(now, 0).AddDate(10, 0, 0).Unix() {
			return RedemptionBatchSpec{}, ErrInvalidRedemption
		}
	}
	switch spec.Kind {
	case "traffic":
		if spec.TrafficBytes <= 0 || spec.TrafficBytes > maximumRedemptionTraffic ||
			spec.VIPPlan != "" || spec.VIPDays != 0 {
			return RedemptionBatchSpec{}, ErrInvalidRedemption
		}
	case "vip":
		if spec.TrafficBytes != 0 {
			return RedemptionBatchSpec{}, ErrInvalidRedemption
		}
		plan, days, err := normalizeVIPBenefit(spec.VIPPlan, spec.VIPDays)
		if err != nil {
			return RedemptionBatchSpec{}, err
		}
		spec.VIPPlan, spec.VIPDays = plan, days
	default:
		return RedemptionBatchSpec{}, ErrInvalidRedemption
	}
	return spec, nil
}

func normalizeVIPBenefit(plan string, days int) (string, int, error) {
	plan = strings.ToLower(strings.TrimSpace(plan))
	wantDays := 0
	switch plan {
	case "monthly":
		wantDays = 30
	case "yearly":
		wantDays = 365
	case "lifetime":
		wantDays = 0
	default:
		return "", 0, ErrInvalidRedemption
	}
	// Omitting days selects the canonical duration. A non-zero duration must
	// exactly match the named plan, preventing misleading administrator input.
	if days == 0 && plan != "lifetime" {
		days = wantDays
	}
	if days != wantDays {
		return "", 0, ErrInvalidRedemption
	}
	return plan, days, nil
}

func generateRedemptionCode() (string, error) {
	randomBytes := make([]byte, redemptionCodeCharacters)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	characters := make([]byte, redemptionCodeCharacters)
	// The alphabet has exactly 32 symbols, so masking five random bits is
	// unbiased and gives every generated code 80 bits of entropy.
	for index, value := range randomBytes {
		characters[index] = redemptionCodeAlphabet[int(value&31)]
	}
	return fmt.Sprintf("QT-%s-%s-%s-%s", characters[0:4], characters[4:8], characters[8:12], characters[12:16]), nil
}

func normalizeRedemptionCode(raw string) (string, error) {
	compact := strings.Map(func(character rune) rune {
		if character == '-' || character == ' ' || character == '\t' ||
			character == '\r' || character == '\n' {
			return -1
		}
		if character >= 'a' && character <= 'z' {
			return character - ('a' - 'A')
		}
		return character
	}, strings.TrimSpace(raw))
	if len(compact) != 2+redemptionCodeCharacters || !strings.HasPrefix(compact, "QT") {
		return "", ErrInvalidRedemption
	}
	for index := 2; index < len(compact); index++ {
		if !strings.ContainsRune(redemptionCodeAlphabet, rune(compact[index])) {
			return "", ErrInvalidRedemption
		}
	}
	return compact, nil
}

func maskRedemptionCode(normalized string) string {
	if len(normalized) != 2+redemptionCodeCharacters {
		return "QT-****-****-****-****"
	}
	return "QT-****-****-****-" + normalized[len(normalized)-4:]
}

// CreateRedemptionBatch returns raw codes to the administrator and persists an
// encrypted copy for later authenticated administration. Plaintext is never
// written to SQLite, logs, or audit details.
func (store *Store) CreateRedemptionBatch(ctx context.Context, actorUserID string, spec RedemptionBatchSpec,
	ip string, now int64,
) (RedemptionBatch, []string, error) {
	spec, err := normalizeRedemptionBatchSpec(spec, now)
	if err != nil || strings.TrimSpace(actorUserID) == "" {
		return RedemptionBatch{}, nil, ErrInvalidRedemption
	}
	batchID, err := randomToken(16)
	if err != nil {
		return RedemptionBatch{}, nil, err
	}
	auditID, err := auditIDGenerator(16)
	if err != nil {
		return RedemptionBatch{}, nil, err
	}
	type generatedCode struct {
		id, raw, hash, masked, protected string
	}
	generated := make([]generatedCode, 0, spec.Count)
	seen := make(map[string]struct{}, spec.Count)
	for len(generated) < spec.Count {
		raw, err := generateRedemptionCode()
		if err != nil {
			return RedemptionBatch{}, nil, err
		}
		normalized, err := normalizeRedemptionCode(raw)
		if err != nil {
			return RedemptionBatch{}, nil, err
		}
		hash := tokenHash(normalized)
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		id, err := randomToken(16)
		if err != nil {
			return RedemptionBatch{}, nil, err
		}
		protected, err := sealRedemptionCode(raw, store.redemptionProtectionKey)
		if err != nil {
			return RedemptionBatch{}, nil, fmt.Errorf("protect redemption code: %w", err)
		}
		seen[hash] = struct{}{}
		generated = append(generated, generatedCode{
			id: id, raw: raw, hash: hash, masked: maskRedemptionCode(normalized), protected: protected,
		})
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return RedemptionBatch{}, nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO redemption_batches
		(id,kind,traffic_bytes,vip_plan,vip_days,quantity,expires_at,note,status,created_by,created_at)
		VALUES(?,?,?,?,?,?,?,?, 'active',?,?)`, batchID, spec.Kind, spec.TrafficBytes, spec.VIPPlan,
		spec.VIPDays, spec.Count, spec.ExpiresAt, spec.Note, actorUserID, now); err != nil {
		return RedemptionBatch{}, nil, err
	}
	for _, code := range generated {
		if _, err := tx.ExecContext(ctx, `INSERT INTO redemption_codes
			(id,batch_id,code_hash,masked_code,protected_code,status,created_at)
			VALUES(?,?,?,?,?, 'active',?)`, code.id, batchID, code.hash, code.masked, code.protected, now); err != nil {
			return RedemptionBatch{}, nil, err
		}
	}
	detail := fmt.Sprintf("kind=%s;count=%d", spec.Kind, spec.Count)
	if spec.Kind == "vip" {
		detail += ";plan=" + spec.VIPPlan
	}
	if err := insertAuditTx(ctx, tx, auditID, actorUserID, "admin.redemption-batch.create", "redemption_batch",
		batchID, detail, ip, now); err != nil {
		return RedemptionBatch{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return RedemptionBatch{}, nil, err
	}
	rawCodes := make([]string, len(generated))
	for index := range generated {
		rawCodes[index] = generated[index].raw
	}
	return RedemptionBatch{
		ID: batchID, Kind: spec.Kind, TrafficBytes: spec.TrafficBytes, VIPPlan: spec.VIPPlan,
		VIPDays: spec.VIPDays, Quantity: spec.Count, ExpiresAt: spec.ExpiresAt, Note: spec.Note,
		Status: "active", CreatedBy: actorUserID, CreatedAt: now, ActiveCodes: int64(spec.Count),
	}, rawCodes, nil
}

func (store *Store) ListRedemptionBatches(ctx context.Context, limit int) ([]RedemptionBatch, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := store.db.QueryContext(ctx, `SELECT id,kind,quantity,traffic_bytes,vip_plan,vip_days,status,
		expires_at,note,created_by,created_at,disabled_at FROM redemption_batches
		ORDER BY created_at DESC,id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	batches := make([]RedemptionBatch, 0)
	batchIndexes := make(map[string]int)
	for rows.Next() {
		var batch RedemptionBatch
		if err := rows.Scan(&batch.ID, &batch.Kind, &batch.Quantity, &batch.TrafficBytes, &batch.VIPPlan,
			&batch.VIPDays, &batch.Status, &batch.ExpiresAt, &batch.Note, &batch.CreatedBy,
			&batch.CreatedAt, &batch.DisabledAt); err != nil {
			return nil, err
		}
		batch.Codes = []AdminRedemptionCode{}
		batchIndexes[batch.ID] = len(batches)
		batches = append(batches, batch)
	}
	if err := rows.Err(); err != nil || len(batches) == 0 {
		return batches, err
	}
	codeRows, err := store.db.QueryContext(ctx, `SELECT c.id,c.batch_id,c.protected_code,c.status,
		COALESCE(c.redeemed_by,''),COALESCE(u.username,''),COALESCE(u.email,''),c.redeemed_at,c.created_at
		FROM redemption_codes c
		LEFT JOIN users u ON u.id=c.redeemed_by
		WHERE c.batch_id IN (
			SELECT id FROM redemption_batches ORDER BY created_at DESC,id DESC LIMIT ?
		)
		ORDER BY c.created_at,c.id`, limit)
	if err != nil {
		return nil, err
	}
	defer codeRows.Close()
	for codeRows.Next() {
		var item AdminRedemptionCode
		var protected string
		if err := codeRows.Scan(&item.ID, &item.BatchID, &protected, &item.Status, &item.RedeemedBy,
			&item.RedeemedUsername, &item.RedeemedEmail, &item.RedeemedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		if protected != "" {
			item.Code, err = openRedemptionCode(protected, store.redemptionProtectionKey)
			if err != nil {
				return nil, fmt.Errorf("open redemption code %s: %w", item.ID, err)
			}
			item.CodeAvailable = true
		}
		index, ok := batchIndexes[item.BatchID]
		if !ok {
			continue
		}
		batches[index].Codes = append(batches[index].Codes, item)
		switch item.Status {
		case "active":
			batches[index].ActiveCodes++
		case "redeemed":
			batches[index].RedeemedCodes++
		case "disabled":
			batches[index].DisabledCodes++
		}
	}
	if err := codeRows.Err(); err != nil {
		return nil, err
	}
	return batches, nil
}

func (store *Store) DisableRedemptionBatch(ctx context.Context, batchID, actorUserID, ip string,
	now int64,
) (RedemptionBatch, error) {
	batchID = strings.TrimSpace(batchID)
	if batchID == "" || strings.TrimSpace(actorUserID) == "" {
		return RedemptionBatch{}, ErrInvalidRedemption
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return RedemptionBatch{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE redemption_batches
		SET status='disabled',disabled_at=? WHERE id=? AND status='active'`, now, batchID)
	if err != nil {
		return RedemptionBatch{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return RedemptionBatch{}, err
	}
	if changed == 1 {
		if _, err := tx.ExecContext(ctx, `UPDATE redemption_codes SET status='disabled'
			WHERE batch_id=? AND status='active'`, batchID); err != nil {
			return RedemptionBatch{}, err
		}
		auditID, err := auditIDGenerator(16)
		if err != nil {
			return RedemptionBatch{}, err
		}
		if err := insertAuditTx(ctx, tx, auditID, actorUserID, "admin.redemption-batch.disable",
			"redemption_batch", batchID, "disabled", ip, now); err != nil {
			return RedemptionBatch{}, err
		}
	}
	batch, err := redemptionBatchByIDTx(ctx, tx, batchID)
	if errors.Is(err, sql.ErrNoRows) {
		return RedemptionBatch{}, ErrNotFound
	}
	if err != nil {
		return RedemptionBatch{}, err
	}
	if changed == 0 && batch.Status != "disabled" {
		return RedemptionBatch{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return RedemptionBatch{}, err
	}
	return batch, nil
}

func redemptionBatchByIDTx(ctx context.Context, tx *sql.Tx, batchID string) (RedemptionBatch, error) {
	var batch RedemptionBatch
	err := tx.QueryRowContext(ctx, `SELECT id,kind,quantity,traffic_bytes,vip_plan,vip_days,status,
		expires_at,note,created_by,created_at,disabled_at FROM redemption_batches WHERE id=?`, batchID).
		Scan(&batch.ID, &batch.Kind, &batch.Quantity, &batch.TrafficBytes, &batch.VIPPlan, &batch.VIPDays,
			&batch.Status, &batch.ExpiresAt, &batch.Note, &batch.CreatedBy, &batch.CreatedAt, &batch.DisabledAt)
	return batch, err
}

// RedeemedRedemptionForUser is a narrow idempotency lookup. It only returns a
// result when the supplied code has already been redeemed by the same user.
func (store *Store) RedeemedRedemptionForUser(ctx context.Context, userID, rawCode string) (Redemption, bool, error) {
	normalized, err := normalizeRedemptionCode(rawCode)
	if err != nil {
		return Redemption{}, false, err
	}
	record, err := scanRedemptionCode(store.db.QueryRowContext(ctx, redemptionCodeSelect+` WHERE c.code_hash=?`,
		tokenHash(normalized)))
	if errors.Is(err, sql.ErrNoRows) {
		return Redemption{}, false, nil
	}
	if err != nil {
		return Redemption{}, false, err
	}
	if record.codeStatus != "redeemed" || record.redeemedBy != userID {
		return Redemption{}, false, nil
	}
	result, err := redemptionResultForRecord(ctx, store.db, userID, record, time.Now().Unix())
	return result, err == nil, err
}

const redemptionCodeSelect = `SELECT c.id,c.status,COALESCE(c.redeemed_by,''),c.redeemed_at,c.masked_code,
	b.id,b.status,b.kind,b.traffic_bytes,
	b.vip_plan,b.vip_days,b.expires_at FROM redemption_codes c
	JOIN redemption_batches b ON b.id=c.batch_id`

func scanRedemptionCode(row interface{ Scan(...any) error }) (redemptionCodeRecord, error) {
	var record redemptionCodeRecord
	err := row.Scan(&record.codeID, &record.codeStatus, &record.redeemedBy, &record.redeemedAt,
		&record.maskedCode, &record.batchID,
		&record.batchStatus, &record.kind, &record.trafficBytes, &record.vipPlan, &record.vipDays,
		&record.expiresAt)
	return record, err
}

// RedeemRedemptionCode atomically claims a code, applies its benefit, and
// records a non-sensitive audit event. A no-op write acquires SQLite's writer
// lock before reading state, so two concurrent redeemers cannot both win.
func (store *Store) RedeemRedemptionCode(ctx context.Context, userID, rawCode, ip string,
	now int64,
) (Redemption, error) {
	normalized, err := normalizeRedemptionCode(rawCode)
	if err != nil {
		return Redemption{}, err
	}
	hash := tokenHash(normalized)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Redemption{}, err
	}
	defer tx.Rollback()
	lockResult, err := tx.ExecContext(ctx, `UPDATE redemption_codes SET status=status WHERE code_hash=?`, hash)
	if err != nil {
		return Redemption{}, err
	}
	matched, err := lockResult.RowsAffected()
	if err != nil {
		return Redemption{}, err
	}
	if matched != 1 {
		return Redemption{}, ErrRedemptionUnavailable
	}
	record, err := scanRedemptionCode(tx.QueryRowContext(ctx, redemptionCodeSelect+` WHERE c.code_hash=?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return Redemption{}, ErrRedemptionUnavailable
	}
	if err != nil {
		return Redemption{}, err
	}
	if record.codeStatus == "redeemed" {
		if record.redeemedBy != userID {
			return Redemption{}, ErrRedemptionUnavailable
		}
		result, err := redemptionResultForRecord(ctx, tx, userID, record, now)
		if err != nil {
			return Redemption{}, err
		}
		if err := tx.Commit(); err != nil {
			return Redemption{}, err
		}
		return result, nil
	}
	if record.codeStatus != "active" || record.batchStatus != "active" ||
		(record.expiresAt != 0 && record.expiresAt <= now) {
		return Redemption{}, ErrRedemptionUnavailable
	}
	claim, err := tx.ExecContext(ctx, `UPDATE redemption_codes SET status='redeemed',redeemed_by=?,redeemed_at=?
		WHERE id=? AND status='active'`, userID, now, record.codeID)
	if err != nil {
		return Redemption{}, err
	}
	claimed, err := claim.RowsAffected()
	if err != nil {
		return Redemption{}, err
	}
	if claimed != 1 {
		return Redemption{}, ErrRedemptionUnavailable
	}
	switch record.kind {
	case "traffic":
		if record.trafficBytes <= 0 || record.trafficBytes > maximumRedemptionTraffic {
			return Redemption{}, ErrInvalidRedemption
		}
		entitlementID, err := randomToken(16)
		if err != nil {
			return Redemption{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO resource_entitlements
			(id,user_id,resource_type,amount_bytes,remaining_bytes,expires_at,source_type,source_id,created_at)
			VALUES(?,?,'traffic',?,?,?,'redemption',?,?)`, entitlementID, userID, record.trafficBytes,
			record.trafficBytes, permanentTrafficEntitlementExpiry, record.codeID, now); err != nil {
			return Redemption{}, err
		}
	case "vip":
		if err := applyVIPBenefitTx(ctx, tx, userID, record.vipPlan, record.vipDays, now); err != nil {
			return Redemption{}, err
		}
	default:
		return Redemption{}, ErrInvalidRedemption
	}
	auditID, err := auditIDGenerator(16)
	if err != nil {
		return Redemption{}, err
	}
	detail := record.kind
	if record.kind == "vip" {
		detail += ";plan=" + record.vipPlan
	}
	if err := insertAuditTx(ctx, tx, auditID, userID, "redemption.redeem", "redemption_batch",
		record.batchID, detail, ip, now); err != nil {
		return Redemption{}, err
	}
	record.codeStatus = "redeemed"
	record.redeemedBy = userID
	record.redeemedAt = now
	result, err := redemptionResultForRecord(ctx, tx, userID, record, now)
	if err != nil {
		return Redemption{}, err
	}
	if err := tx.Commit(); err != nil {
		return Redemption{}, err
	}
	return result, nil
}

type redemptionQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func redemptionResultForRecord(ctx context.Context, queryer redemptionQueryer, userID string,
	record redemptionCodeRecord, now int64,
) (Redemption, error) {
	result := Redemption{
		ID: record.codeID, BatchID: record.batchID, Kind: record.kind, MaskedCode: record.maskedCode,
		Status: "redeemed", TrafficBytes: record.trafficBytes, VIPPlan: record.vipPlan,
		VIPDays: record.vipDays, RedeemedAt: record.redeemedAt,
	}
	var email string
	var freeTraffic, reservedTraffic int64
	if err := queryer.QueryRowContext(ctx, `SELECT email,username,vip_plan,vip_expires_at FROM users WHERE id=?`, userID).
		Scan(&email, &result.Username, &result.VIPPlan, &result.VIPExpiresAt); err != nil {
		return Redemption{}, err
	}
	if strings.TrimSpace(result.Username) == "" {
		result.Username = defaultUsernameFromEmail(email)
	}
	if err := queryer.QueryRowContext(ctx, `SELECT free_traffic_remaining,traffic_reserved_bytes
		FROM resource_accounts WHERE user_id=?`, userID).Scan(&freeTraffic, &reservedTraffic); err != nil {
		return Redemption{}, err
	}
	var paidTraffic int64
	if err := queryer.QueryRowContext(ctx, `SELECT COALESCE(SUM(remaining_bytes),0) FROM resource_entitlements
		WHERE user_id=? AND resource_type='traffic' AND expires_at>?`, userID, now).Scan(&paidTraffic); err != nil {
		return Redemption{}, err
	}
	result.TrafficRemainingBytes = freeTraffic + paidTraffic - reservedTraffic
	if result.TrafficRemainingBytes < 0 {
		result.TrafficRemainingBytes = 0
	}
	return result, nil
}

// applyVIPBenefitTx is shared by redemption and paid-order completion. Monthly
// and yearly benefits extend from max(now,current expiry). A stronger active
// plan is never downgraded, and lifetime VIP can never be overwritten.
func applyVIPBenefitTx(ctx context.Context, tx *sql.Tx, userID, plan string, days int, now int64) error {
	plan, days, err := normalizeVIPBenefit(plan, days)
	if err != nil {
		return err
	}
	var currentPlan string
	var currentExpiresAt int64
	if err := tx.QueryRowContext(ctx, `SELECT vip_plan,vip_expires_at FROM users WHERE id=?`, userID).
		Scan(&currentPlan, &currentExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	currentPlan = strings.ToLower(strings.TrimSpace(currentPlan))
	if currentPlan == "lifetime" {
		return nil
	}
	if plan == "lifetime" {
		result, err := tx.ExecContext(ctx, `UPDATE users SET vip_plan='lifetime',vip_expires_at=0 WHERE id=?`, userID)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			if err != nil {
				return err
			}
			return ErrNotFound
		}
		return nil
	}
	base := now
	activeCurrent := currentExpiresAt > now
	if activeCurrent {
		base = currentExpiresAt
	}
	durationSeconds := int64(days) * int64(24*time.Hour/time.Second)
	if durationSeconds <= 0 || base > math.MaxInt64-durationSeconds {
		return ErrInvalidRedemption
	}
	targetPlan := plan
	if activeCurrent && vipPlanRank(currentPlan) > vipPlanRank(plan) {
		targetPlan = currentPlan
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET vip_plan=?,vip_expires_at=? WHERE id=?`,
		targetPlan, base+durationSeconds, userID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

func vipPlanRank(plan string) int {
	switch strings.ToLower(strings.TrimSpace(plan)) {
	case "monthly":
		return 1
	case "yearly":
		return 2
	case "lifetime":
		return 3
	default:
		return 0
	}
}
