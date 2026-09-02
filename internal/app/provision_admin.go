package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const minProvisionedAdminPasswordLength = 24

var provisionTokenGenerator = randomToken

// GenerateAdminPassword returns a cryptographically random base64url password.
// Twenty-four random bytes encode to 32 characters without padding.
func GenerateAdminPassword() (string, error) {
	return provisionTokenGenerator(24)
}

// ProvisionAdmin creates a dedicated verified administrator. If the email is
// already in use, rotate must be true and the existing account must already be
// an administrator. Rotation never promotes a normal user.
func (store *Store) ProvisionAdmin(ctx context.Context, email, password string, rotate bool) (User, error) {
	if store == nil || store.db == nil {
		return User{}, errors.New("admin provisioning store is unavailable")
	}
	normalizedEmail, err := normalizeEmail(email)
	if err != nil {
		return User{}, fmt.Errorf("normalize admin email: %w", err)
	}
	if len(password) < minProvisionedAdminPasswordLength || len(password) > 128 {
		return User{}, errors.New("admin password must contain 24 to 128 characters")
	}
	passwordHash, err := hashAccessCode(password)
	if err != nil {
		return User{}, fmt.Errorf("hash admin password: %w", err)
	}
	userID, err := provisionTokenGenerator(16)
	if err != nil {
		return User{}, fmt.Errorf("generate admin identifier: %w", err)
	}
	auditID, err := provisionTokenGenerator(16)
	if err != nil {
		return User{}, fmt.Errorf("generate audit identifier: %w", err)
	}

	now := time.Now().Unix()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	existing, lookupErr := scanUser(tx.QueryRowContext(ctx, `SELECT id,email,username,password_hash,status,role,created_at,verified_at,last_login_at,must_change_password,vip_plan,vip_expires_at
		FROM users WHERE email=? COLLATE NOCASE`, normalizedEmail))
	switch {
	case lookupErr == nil:
		if !rotate || existing.Role != "admin" {
			return User{}, ErrConflict
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE users
			SET password_hash=?,status='active',must_change_password=1,verified_at=CASE WHEN verified_at=0 THEN ? ELSE verified_at END
			WHERE id=? AND role='admin'`, passwordHash, now, existing.ID)
		if updateErr != nil {
			return User{}, updateErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return User{}, rowsErr
		}
		if rows != 1 {
			return User{}, ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO resource_accounts
			(user_id,free_traffic_period,updated_at) VALUES(?,?,?)`, existing.ID, "", now); err != nil {
			return User{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_sessions SET revoked_at=?
			WHERE user_id=? AND revoked_at=0`, now, existing.ID); err != nil {
			return User{}, err
		}
		if err := addProvisioningAudit(ctx, tx, auditID, existing.ID, "admin.password_rotated", now); err != nil {
			return User{}, err
		}
		existing.PasswordHash = passwordHash
		existing.Status = "active"
		existing.MustChangePassword = true
		if existing.VerifiedAt == 0 {
			existing.VerifiedAt = now
		}
		if err := tx.Commit(); err != nil {
			return User{}, err
		}
		return existing, nil
	case !errors.Is(lookupErr, sql.ErrNoRows):
		return User{}, lookupErr
	}

	user := User{
		ID:                 userID,
		Email:              normalizedEmail,
		Username:           defaultUsernameFromEmail(normalizedEmail),
		PasswordHash:       passwordHash,
		Status:             "active",
		Role:               "admin",
		MustChangePassword: true,
		CreatedAt:          now,
		VerifiedAt:         now,
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO users
		(id,email,username,password_hash,status,role,created_at,verified_at,last_login_at,must_change_password)
		VALUES(?,?,?,?,'active','admin',?,?,0,1)`, user.ID, user.Email, user.Username, user.PasswordHash, user.CreatedAt, user.VerifiedAt); err != nil {
		if isProvisioningConflict(err) {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO resource_accounts
		(user_id,free_traffic_period,updated_at) VALUES(?,?,?)`, user.ID, "", now); err != nil {
		if isProvisioningConflict(err) {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	if err := addPointsTx(ctx, tx, user.ID, 100, "管理员账户初始化", "admin-provision:"+user.ID, now); err != nil {
		return User{}, err
	}
	if err := addProvisioningAudit(ctx, tx, auditID, user.ID, "admin.provisioned", now); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		if isProvisioningConflict(err) {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	return user, nil
}

func addProvisioningAudit(ctx context.Context, tx *sql.Tx, auditID, userID, action string, now int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(id,user_id,action,target_type,target_id,detail,ip,created_at)
		VALUES(?,?,?,'user',?,'local provisioning','',?)`, auditID, userID, action, userID, now)
	return err
}

func isProvisioningConflict(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique") || strings.Contains(message, "constraint failed")
}
