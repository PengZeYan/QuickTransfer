package app

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

var (
	identityIDGenerator = randomToken
	sessionIDGenerator  = randomToken
	pointsIDGenerator   = randomToken
	auditIDGenerator    = randomToken
)

func (store *Store) UserCount(ctx context.Context) (int64, error) {
	var count int64
	err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

func (store *Store) CreatePendingUser(ctx context.Context, user User, verificationHash string, expiresAt int64, consents ...ConsentEvidence) error {
	if strings.TrimSpace(user.Username) == "" {
		user.Username = defaultUsernameFromEmail(user.Email)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO users
		(id,email,username,password_hash,status,role,created_at) VALUES(?,?,?,?,'pending',?,?)`,
		user.ID, user.Email, user.Username, user.PasswordHash, user.Role, user.CreatedAt); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrConflict
		}
		return err
	}
	codeID, err := identityIDGenerator(16)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO verification_codes
		(id,user_id,purpose,code_hash,created_at,expires_at) VALUES(?,?,'verify',?,?,?)`,
		codeID, user.ID, verificationHash, user.CreatedAt, expiresAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO resource_accounts
		(user_id,free_traffic_period,updated_at) VALUES(?,?,?)`, user.ID, "", user.CreatedAt); err != nil {
		return err
	}
	if len(consents) > 0 {
		if err := insertConsentTx(ctx, tx, user.ID, consents[0]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (store *Store) RefreshPendingUser(ctx context.Context, userID, verificationHash string, now, expiresAt int64, consents ...ConsentEvidence) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM users WHERE id=?`, userID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if status != "pending" {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE verification_codes SET consumed_at=?
		WHERE user_id=? AND purpose='verify' AND consumed_at=0`, now, userID); err != nil {
		return err
	}
	codeID, err := identityIDGenerator(16)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO verification_codes
		(id,user_id,purpose,code_hash,created_at,expires_at) VALUES(?,?,'verify',?,?,?)`,
		codeID, userID, verificationHash, now, expiresAt); err != nil {
		return err
	}
	if len(consents) > 0 {
		if err := insertConsentTx(ctx, tx, userID, consents[0]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func insertConsentTx(ctx context.Context, tx *sql.Tx, userID string, consent ConsentEvidence) error {
	var existingHash string
	err := tx.QueryRowContext(ctx, `SELECT document_hash FROM user_consents
		WHERE user_id=? AND document_type='combined-terms' AND document_version=?`, userID, consent.Version).
		Scan(&existingHash)
	if err == nil {
		if existingHash != consent.DocumentHash {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	id, err := identityIDGenerator(16)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO user_consents
		(id,user_id,document_type,document_version,document_hash,accepted_at,ip_hash,user_agent_hash)
		VALUES(?,?,'combined-terms',?,?,?,?,?)`,
		id, userID, consent.Version, consent.DocumentHash, consent.AcceptedAt, consent.IPHash, consent.UserAgentHash)
	return err
}

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var user User
	err := row.Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.Status, &user.Role,
		&user.CreatedAt, &user.VerifiedAt, &user.LastLoginAt, &user.MustChangePassword,
		&user.VIPPlan, &user.VIPExpiresAt)
	return user, err
}

func (store *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	user, err := scanUser(store.db.QueryRowContext(ctx, `SELECT id,email,username,password_hash,status,role,created_at,verified_at,last_login_at,must_change_password,vip_plan,vip_expires_at
		FROM users WHERE email=? COLLATE NOCASE`, email))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return user, err
}

func (store *Store) UserByID(ctx context.Context, id string) (User, error) {
	user, err := scanUser(store.db.QueryRowContext(ctx, `SELECT id,email,username,password_hash,status,role,created_at,verified_at,last_login_at,must_change_password,vip_plan,vip_expires_at
		FROM users WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return user, err
}

type RegistrationSuccessRisk struct {
	IPHash      string
	SubnetHash  string
	IPDaily     int
	SubnetDaily int
}

func (store *Store) VerifyUser(ctx context.Context, email, code, passwordHash string, now int64, risks ...RegistrationSuccessRisk) (User, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	user, err := scanUser(tx.QueryRowContext(ctx, `SELECT id,email,username,password_hash,status,role,created_at,verified_at,last_login_at,must_change_password,vip_plan,vip_expires_at
		FROM users WHERE email=? COLLATE NOCASE`, email))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	if user.Status != "pending" {
		return User{}, ErrConflict
	}
	var id, hash string
	var expiresAt int64
	var attempts int
	err = tx.QueryRowContext(ctx, `SELECT id,code_hash,expires_at,attempts FROM verification_codes
		WHERE user_id=? AND purpose='verify' AND consumed_at=0 ORDER BY created_at DESC LIMIT 1`, user.ID).
		Scan(&id, &hash, &expiresAt, &attempts)
	if errors.Is(err, sql.ErrNoRows) || expiresAt <= now || attempts >= 5 {
		return User{}, ErrConflict
	}
	if err != nil {
		return User{}, err
	}
	if !verifyAccessCode(hash, code) {
		_, _ = tx.ExecContext(ctx, `UPDATE verification_codes SET attempts=attempts+1 WHERE id=?`, id)
		_ = tx.Commit()
		return User{}, ErrUnauthorized
	}
	if len(risks) > 0 {
		risk := risks[0]
		for _, bucket := range []struct {
			key   string
			limit int
		}{
			{"registration-success-ip:" + risk.IPHash, risk.IPDaily},
			{"registration-success-subnet:" + risk.SubnetHash, risk.SubnetDaily},
		} {
			allowed, err := allowBucketTx(ctx, tx, bucket.key, bucket.limit, 24*time.Hour, 1, 0, 0, time.Unix(now, 0))
			if err != nil {
				return User{}, err
			}
			if !allowed {
				return User{}, ErrRateLimited
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE verification_codes SET consumed_at=? WHERE id=?`, now, id); err != nil {
		return User{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET status='active',verified_at=?,password_hash=? WHERE id=? AND status='pending'`, now, passwordHash, user.ID)
	if err != nil {
		return User{}, err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return User{}, ErrConflict
	}
	if err := addPointsTx(ctx, tx, user.ID, 100, "完成账户验证", "welcome:"+user.ID, now); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	user.Status = "active"
	user.VerifiedAt = now
	return user, nil
}

func (store *Store) CreatePasswordReset(ctx context.Context, userID, codeHash string, now, expiresAt int64) error {
	id, err := identityIDGenerator(16)
	if err != nil {
		return err
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO verification_codes
		(id,user_id,purpose,code_hash,created_at,expires_at) VALUES(?,?,'reset',?,?,?)`,
		id, userID, codeHash, now, expiresAt)
	return err
}

func (store *Store) ResetPassword(ctx context.Context, email, code, passwordHash string, now int64) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var userID, codeID, codeHash string
	var expiresAt int64
	var attempts int
	if err := tx.QueryRowContext(ctx, `SELECT u.id,v.id,v.code_hash,v.expires_at,v.attempts
		FROM users u JOIN verification_codes v ON v.user_id=u.id
		WHERE u.email=? COLLATE NOCASE AND v.purpose='reset' AND v.consumed_at=0
		ORDER BY v.created_at DESC LIMIT 1`, email).Scan(&userID, &codeID, &codeHash, &expiresAt, &attempts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if expiresAt <= now || attempts >= 5 {
		return ErrConflict
	}
	if !verifyAccessCode(codeHash, code) {
		_, _ = tx.ExecContext(ctx, `UPDATE verification_codes SET attempts=attempts+1 WHERE id=?`, codeID)
		_ = tx.Commit()
		return ErrUnauthorized
	}
	if _, err := tx.ExecContext(ctx, `UPDATE verification_codes SET consumed_at=? WHERE id=?`, now, codeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, passwordHash, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_sessions SET revoked_at=? WHERE user_id=? AND revoked_at=0`, now, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) CreateUserSession(ctx context.Context, userID, tokenHashValue, csrfToken, ipHash, userAgentHash string, now, expiresAt int64) error {
	_, err := store.createUserSession(ctx, userID, tokenHashValue, csrfToken, ipHash, userAgentHash,
		now, expiresAt, "", "", "", "", "", false)
	return err
}

func (store *Store) CreateUserSessionWithAudit(ctx context.Context, userID, tokenHashValue, csrfToken,
	ipHash, userAgentHash string, now, expiresAt int64, action, targetType, targetID, detail, ip string,
) error {
	if action == "" {
		return ErrConflict
	}
	_, err := store.createUserSession(ctx, userID, tokenHashValue, csrfToken, ipHash, userAgentHash,
		now, expiresAt, action, targetType, targetID, detail, ip, false)
	return err
}

func (store *Store) CreateLoginSessionWithAuditAndVIPDailyGrant(ctx context.Context, userID, tokenHashValue,
	csrfToken, ipHash, userAgentHash string, now, expiresAt int64, action, targetType, targetID, detail, ip string,
) (VIPDailyLoginGrant, error) {
	if action == "" {
		return VIPDailyLoginGrant{}, ErrConflict
	}
	return store.createUserSession(ctx, userID, tokenHashValue, csrfToken, ipHash, userAgentHash,
		now, expiresAt, action, targetType, targetID, detail, ip, true)
}

func (store *Store) createUserSession(ctx context.Context, userID, tokenHashValue, csrfToken,
	ipHash, userAgentHash string, now, expiresAt int64, auditAction, targetType, targetID, detail, ip string,
	grantVIPDailyTraffic bool,
) (VIPDailyLoginGrant, error) {
	id, err := sessionIDGenerator(16)
	if err != nil {
		return VIPDailyLoginGrant{}, err
	}
	var auditID string
	if auditAction != "" {
		auditID, err = auditIDGenerator(16)
		if err != nil {
			return VIPDailyLoginGrant{}, err
		}
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return VIPDailyLoginGrant{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_sessions
		(id,user_id,token_hash,csrf_token,created_at,expires_at,last_seen_at,ip_hash,user_agent_hash)
		VALUES(?,?,?,?,?,?,?,?,?)`, id, userID, tokenHashValue, csrfToken, now, expiresAt, now, ipHash, userAgentHash); err != nil {
		return VIPDailyLoginGrant{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET last_login_at=? WHERE id=?`, now, userID); err != nil {
		return VIPDailyLoginGrant{}, err
	}
	grant := VIPDailyLoginGrant{}
	if grantVIPDailyTraffic {
		grant, err = grantVIPDailyLoginTrafficTx(ctx, tx, userID, ip, time.Unix(now, 0))
		if err != nil {
			return VIPDailyLoginGrant{}, err
		}
	}
	if auditAction != "" {
		if err := insertAuditTx(ctx, tx, auditID, userID, auditAction, targetType, targetID, detail, ip, now); err != nil {
			return VIPDailyLoginGrant{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return VIPDailyLoginGrant{}, err
	}
	return grant, nil
}

func (store *Store) UserBySession(ctx context.Context, tokenHashValue string, now int64) (User, string, error) {
	var user User
	var csrf string
	err := store.db.QueryRowContext(ctx, `SELECT u.id,u.email,u.username,u.password_hash,u.status,u.role,u.created_at,u.verified_at,u.last_login_at,u.must_change_password,u.vip_plan,u.vip_expires_at,s.csrf_token
		FROM user_sessions s JOIN users u ON u.id=s.user_id
		WHERE s.token_hash=? AND s.revoked_at=0 AND s.expires_at>?`, tokenHashValue, now).
		Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.Status, &user.Role, &user.CreatedAt,
			&user.VerifiedAt, &user.LastLoginAt, &user.MustChangePassword, &user.VIPPlan, &user.VIPExpiresAt, &csrf)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrNotFound
	}
	if err == nil {
		_, _ = store.db.ExecContext(ctx, `UPDATE user_sessions SET last_seen_at=? WHERE token_hash=?`, now, tokenHashValue)
	}
	return user, csrf, err
}

func (store *Store) UpdateUsername(ctx context.Context, userID, username string) error {
	result, err := store.db.ExecContext(ctx, `UPDATE users SET username=? WHERE id=?`, username, userID)
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

func (store *Store) ClaimTransferWithoutStorageQuota(ctx context.Context, shareToken, manageToken, userID string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var transferID, manageHash, ownerType, ownerID string
	err = tx.QueryRowContext(ctx, `SELECT id,manage_hash,owner_type,owner_id FROM transfers WHERE share_token=?`, shareToken).
		Scan(&transferID, &manageHash, &ownerType, &ownerID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	if !secureEqual(tokenHash(manageToken), manageHash) {
		return ErrUnauthorized
	}
	if ownerType == "user" {
		if ownerID == userID {
			return tx.Commit()
		}
		return ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE transfers SET owner_type='user',owner_id=? WHERE id=? AND owner_type!='user'`, userID, transferID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (store *Store) RevokeUserSession(ctx context.Context, tokenHashValue string, now int64) error {
	_, err := store.db.ExecContext(ctx, `UPDATE user_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at=0`, now, tokenHashValue)
	return err
}

func (store *Store) CleanupIdentity(ctx context.Context, now int64) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []struct {
		query string
		args  []any
	}{
		{`DELETE FROM guest_sessions WHERE last_seen_at<?`, []any{now - 45*24*3600}},
		{`DELETE FROM user_sessions WHERE expires_at<? OR (revoked_at>0 AND revoked_at<?)`, []any{now - 7*24*3600, now - 7*24*3600}},
		{`DELETE FROM users WHERE status='pending' AND created_at<?`, []any{now - 48*3600}},
		{`DELETE FROM verification_codes WHERE expires_at<?`, []any{now - 7*24*3600}},
		{`DELETE FROM verification_delivery_limits WHERE day_window_start<?`, []any{now - 30*24*3600}},
		{`UPDATE orders SET status='closed' WHERE status='pending' AND created_at<?`, []any{now - 24*3600}},
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (store *Store) CreateGuestSession(ctx context.Context, id, tokenHashValue string, now int64) error {
	_, err := store.db.ExecContext(ctx, `INSERT INTO guest_sessions(id,token_hash,created_at,last_seen_at) VALUES(?,?,?,?)`,
		id, tokenHashValue, now, now)
	return err
}

func (store *Store) GuestByToken(ctx context.Context, tokenHashValue string, now int64) (string, error) {
	var id string
	err := store.db.QueryRowContext(ctx, `SELECT id FROM guest_sessions WHERE token_hash=?`, tokenHashValue).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err == nil {
		_, _ = store.db.ExecContext(ctx, `UPDATE guest_sessions SET last_seen_at=? WHERE id=?`, now, id)
	}
	return id, err
}

func (store *Store) AccountSummary(ctx context.Context, userID string, _ int64, monthlyTraffic int64, now time.Time) (AccountSummary, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return AccountSummary{}, err
	}
	defer tx.Rollback()
	if err := ensureTrafficAccountTx(ctx, tx, userID, monthlyTraffic, now); err != nil {
		return AccountSummary{}, err
	}
	var email, username string
	var freeTraffic, reservedTraffic, points int64
	var vipPlan string
	var vipExpiresAt int64
	if err := tx.QueryRowContext(ctx, `SELECT u.email,u.username,a.free_traffic_remaining,a.traffic_reserved_bytes,a.points_balance,u.vip_plan,u.vip_expires_at
		FROM resource_accounts a JOIN users u ON u.id=a.user_id WHERE a.user_id=?`, userID).
		Scan(&email, &username, &freeTraffic, &reservedTraffic, &points, &vipPlan, &vipExpiresAt); err != nil {
		return AccountSummary{}, err
	}
	var paidTraffic int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(remaining_bytes),0) FROM resource_entitlements
		WHERE user_id=? AND resource_type='traffic' AND expires_at>?`, userID, now.Unix()).Scan(&paidTraffic); err != nil {
		return AccountSummary{}, err
	}
	remaining := freeTraffic + paidTraffic - reservedTraffic
	if remaining < 0 {
		remaining = 0
	}
	canonicalPlan := canonicalVIPPlan(vipPlan)
	if strings.TrimSpace(username) == "" {
		username = defaultUsernameFromEmail(email)
	}
	summary := AccountSummary{
		Username:              username,
		Level:                 "normal",
		VIPPlan:               canonicalPlan,
		VIPExpiresAt:          vipExpiresAt,
		TrafficRemainingBytes: remaining,
		FreeTrafficBytes:      freeTraffic,
		PaidTrafficBytes:      paidTraffic,
		TrafficReservedBytes:  reservedTraffic,
		Points:                points,
	}
	if activeVIPPlan(vipPlan, vipExpiresAt, now.Unix()) != "" {
		summary.Level = "vip"
	}
	if err := tx.Commit(); err != nil {
		return AccountSummary{}, err
	}
	return summary, nil
}

func defaultUsernameFromEmail(email string) string {
	for _, value := range strings.TrimSpace(email) {
		return string(value)
	}
	return "用户"
}

func canonicalVIPPlan(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "month", VIPPlanMonthly:
		return VIPPlanMonthly
	case "year", VIPPlanYearly, "annual":
		return VIPPlanYearly
	case "life", VIPPlanLifetime, "permanent":
		return VIPPlanLifetime
	default:
		return VIPPlanNone
	}
}

func activeVIPPlan(value string, expiresAt, now int64) string {
	plan := canonicalVIPPlan(value)
	if plan == VIPPlanLifetime {
		return plan
	}
	if (plan == VIPPlanMonthly || plan == VIPPlanYearly) && expiresAt > now {
		return plan
	}
	return ""
}

func addPointsTx(ctx context.Context, tx *sql.Tx, userID string, delta int64, reason, eventKey string, now int64) error {
	var balance int64
	if err := tx.QueryRowContext(ctx, `SELECT points_balance FROM resource_accounts WHERE user_id=?`, userID).Scan(&balance); err != nil {
		return err
	}
	next := balance + delta
	if next < 0 {
		return ErrQuotaExceeded
	}
	id, err := pointsIDGenerator(16)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO points_ledger(id,user_id,delta,balance_after,reason,event_key,created_at)
		VALUES(?,?,?,?,?,?,?)`, id, userID, delta, next, reason, eventKey, now); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil
		}
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE resource_accounts SET points_balance=?,updated_at=? WHERE user_id=?`, next, now, userID)
	return err
}

func (store *Store) AddAudit(ctx context.Context, userID, action, targetType, targetID, detail, ip string) error {
	id, err := auditIDGenerator(16)
	if err != nil {
		return err
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO audit_logs
		(id,user_id,action,target_type,target_id,detail,ip,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		id, userID, action, targetType, targetID, detail, ip, time.Now().Unix())
	return err
}

func insertAuditTx(ctx context.Context, tx *sql.Tx, id, userID, action, targetType, targetID, detail, ip string,
	createdAt int64,
) error {
	if id == "" || action == "" {
		return ErrConflict
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(id,user_id,action,target_type,target_id,detail,ip,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		id, userID, action, targetType, targetID, detail, ip, createdAt)
	return err
}

func normalizeEmail(value string) (string, error) {
	email, _, err := normalizeEmailAddress(value)
	return email, err
}
