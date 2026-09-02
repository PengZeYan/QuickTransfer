package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var settingSecretNames = map[string]func(*ServiceSecrets) *string{
	"smtp_password":          func(value *ServiceSecrets) *string { return &value.SMTPPassword },
	"turnstile_secret":       func(value *ServiceSecrets) *string { return &value.TurnstileSecret },
	"tencent_app_secret_key": func(value *ServiceSecrets) *string { return &value.TencentAppSecretKey },
	"tencent_secret_id":      func(value *ServiceSecrets) *string { return &value.TencentSecretID },
	"tencent_secret_key":     func(value *ServiceSecrets) *string { return &value.TencentSecretKey },
}

func (store *Store) LoadServiceSettings(ctx context.Context, defaults ServiceSettings, appKey []byte) (ServiceSettings, ServiceSecrets, error) {
	settings := defaults
	var raw string
	err := store.db.QueryRowContext(ctx, `SELECT value_json,revision,updated_by,updated_at FROM service_settings WHERE id=1`).
		Scan(&raw, &settings.Revision, &settings.UpdatedBy, &settings.UpdatedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ServiceSettings{}, ServiceSecrets{}, err
	}
	if err == nil {
		if err := json.Unmarshal([]byte(raw), &settings); err != nil {
			return ServiceSettings{}, ServiceSecrets{}, fmt.Errorf("decode service settings: %w", err)
		}
		// Promote only the exact bundled legacy defaults. Administrator-authored
		// versions remain immutable and are never rewritten in place.
		if settings.Terms.Version == "2026-08-29" {
			settings.Terms = defaults.Terms
		}
		if settings.Defaults.GuestMaxFiles == 5 || settings.Defaults.GuestMaxFiles == 99 {
			settings.Defaults.GuestMaxFiles = defaults.Defaults.GuestMaxFiles
		}
		settings.Defaults.UserStorageBytes = 0
	}
	var secrets ServiceSecrets
	rows, err := store.db.QueryContext(ctx, `SELECT name,ciphertext FROM service_secrets`)
	if err != nil {
		return ServiceSettings{}, ServiceSecrets{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var name, ciphertext string
		if err := rows.Scan(&name, &ciphertext); err != nil {
			return ServiceSettings{}, ServiceSecrets{}, err
		}
		field, ok := settingSecretNames[name]
		if !ok {
			continue
		}
		value, err := openSettingSecret(ciphertext, appKey)
		if err != nil {
			return ServiceSettings{}, ServiceSecrets{}, fmt.Errorf("decrypt service secret %s: %w", name, err)
		}
		*field(&secrets) = value
	}
	if err := rows.Err(); err != nil {
		return ServiceSettings{}, ServiceSecrets{}, err
	}
	settings, err = normalizeServiceSettings(settings, secrets)
	if err != nil {
		return ServiceSettings{}, ServiceSecrets{}, fmt.Errorf("validate persisted settings: %w", err)
	}
	return settings, secrets, nil
}

func (store *Store) SaveServiceSettings(ctx context.Context, settings ServiceSettings, secrets ServiceSecrets,
	expectedRevision int64, updatedBy string, appKey []byte) (ServiceSettings, error) {
	settings, err := normalizeServiceSettings(settings, secrets)
	if err != nil {
		return ServiceSettings{}, err
	}
	now := time.Now().Unix()
	settings.Revision = expectedRevision + 1
	settings.UpdatedAt = now
	settings.UpdatedBy = updatedBy
	payload, err := json.Marshal(settings)
	if err != nil {
		return ServiceSettings{}, err
	}
	revisionID, err := randomToken(16)
	if err != nil {
		return ServiceSettings{}, fmt.Errorf("generate settings revision id: %w", err)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ServiceSettings{}, err
	}
	defer tx.Rollback()
	documentHash := termsDocumentHash(settings.Terms)
	var existingDocumentHash string
	documentErr := tx.QueryRowContext(ctx, `SELECT document_hash FROM legal_documents WHERE version=?`, settings.Terms.Version).
		Scan(&existingDocumentHash)
	if documentErr == nil && existingDocumentHash != documentHash {
		return ServiceSettings{}, fmt.Errorf("legal document version %q is immutable: %w", settings.Terms.Version, ErrConflict)
	}
	if documentErr != nil && !errors.Is(documentErr, sql.ErrNoRows) {
		return ServiceSettings{}, documentErr
	}
	if errors.Is(documentErr, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO legal_documents
			(version,title,content,document_hash,effective_at,published_at,created_by) VALUES(?,?,?,?,?,?,?)`,
			settings.Terms.Version, settings.Terms.Title, settings.Terms.Content, documentHash,
			settings.Terms.EffectiveAt, now, updatedBy); err != nil {
			return ServiceSettings{}, err
		}
	}
	if expectedRevision == 0 {
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO service_settings(id,value_json,revision,updated_by,updated_at)
			VALUES(1,?,?,?,?)`, string(payload), settings.Revision, updatedBy, now)
		if err != nil {
			return ServiceSettings{}, err
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return ServiceSettings{}, ErrConflict
		}
	} else {
		result, err := tx.ExecContext(ctx, `UPDATE service_settings SET value_json=?,revision=?,updated_by=?,updated_at=?
			WHERE id=1 AND revision=?`, string(payload), settings.Revision, updatedBy, now, expectedRevision)
		if err != nil {
			return ServiceSettings{}, err
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return ServiceSettings{}, ErrConflict
		}
	}
	for name, accessor := range settingSecretNames {
		value := *accessor(&secrets)
		if value == "" {
			if _, err := tx.ExecContext(ctx, `DELETE FROM service_secrets WHERE name=?`, name); err != nil {
				return ServiceSettings{}, err
			}
			continue
		}
		protected, err := sealSettingSecret(value, appKey)
		if err != nil {
			return ServiceSettings{}, fmt.Errorf("protect service secret %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO service_secrets(name,ciphertext,protector,updated_at)
			VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET ciphertext=excluded.ciphertext,
			protector=excluded.protector,updated_at=excluded.updated_at`, name, protected, secretProtectorName(protected), now); err != nil {
			return ServiceSettings{}, err
		}
	}
	digest := sha256.Sum256(payload)
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings_revisions(id,revision,value_hash,updated_by,updated_at)
		VALUES(?,?,?,?,?)`, revisionID, settings.Revision, hex.EncodeToString(digest[:]), updatedBy, now); err != nil {
		return ServiceSettings{}, err
	}
	if err := tx.Commit(); err != nil {
		return ServiceSettings{}, err
	}
	return settings, nil
}

func secretProtectorName(value string) string {
	if len(value) >= 6 && value[:6] == "dpapi:" {
		return "windows-dpapi-localmachine"
	}
	return "application-aesgcm"
}

// DisableCaptchaRecovery is a local break-glass operation for recovering from
// an invalid CAPTCHA credential. It deliberately leaves encrypted credentials
// untouched and requires a service restart before the in-memory snapshot changes.
func (store *Store) DisableCaptchaRecovery(ctx context.Context) (int64, error) {
	revisionID, err := randomToken(16)
	if err != nil {
		return 0, fmt.Errorf("generate recovery revision id: %w", err)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var raw string
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT value_json,revision FROM service_settings WHERE id=1`).Scan(&raw, &revision); err != nil {
		return 0, err
	}
	var settings ServiceSettings
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return 0, err
	}
	settings.Captcha.Enabled = false
	settings.Captcha.Provider = "disabled"
	settings.Captcha.Actions = map[string]bool{}
	settings.Revision = revision + 1
	settings.UpdatedAt = time.Now().Unix()
	settings.UpdatedBy = "local-captcha-recovery"
	payload, err := json.Marshal(settings)
	if err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE service_settings SET value_json=?,revision=?,updated_by=?,updated_at=?
		WHERE id=1 AND revision=?`, string(payload), settings.Revision, settings.UpdatedBy, settings.UpdatedAt, revision)
	if err != nil {
		return 0, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return 0, ErrConflict
	}
	digest := sha256.Sum256(payload)
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings_revisions(id,revision,value_hash,updated_by,updated_at)
		VALUES(?,?,?,?,?)`, revisionID, settings.Revision, hex.EncodeToString(digest[:]), settings.UpdatedBy, settings.UpdatedAt); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return settings.Revision, nil
}

func (store *Store) EnsureLegalDocument(ctx context.Context, terms TermsSettings, createdBy string) error {
	documentHash := termsDocumentHash(terms)
	now := time.Now().Unix()
	_, err := store.db.ExecContext(ctx, `INSERT OR IGNORE INTO legal_documents
		(version,title,content,document_hash,effective_at,published_at,created_by) VALUES(?,?,?,?,?,?,?)`,
		terms.Version, terms.Title, terms.Content, documentHash, terms.EffectiveAt, now, createdBy)
	if err != nil {
		return err
	}
	var persistedHash string
	if err := store.db.QueryRowContext(ctx, `SELECT document_hash FROM legal_documents WHERE version=?`, terms.Version).
		Scan(&persistedHash); err != nil {
		return err
	}
	if persistedHash != documentHash {
		return fmt.Errorf("legal document version %q is immutable: %w", terms.Version, ErrConflict)
	}
	return nil
}

func (store *Store) AddRiskEvent(ctx context.Context, action, decision, ruleCode, subjectHash, ipHash, detail string) error {
	id, err := randomToken(16)
	if err != nil {
		return fmt.Errorf("generate risk event id: %w", err)
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO risk_events
		(id,action,decision,rule_code,subject_hash,ip_hash,detail,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		id, action, decision, ruleCode, subjectHash, ipHash, cleanText(detail, 240), time.Now().Unix())
	return err
}

func (store *Store) ReserveSuccessfulRegistration(ctx context.Context, ipHash, subnetHash string, ipDaily, subnetDaily int) error {
	limits := []struct {
		key   string
		limit int
	}{
		{"registration-success-ip:" + ipHash, ipDaily},
		{"registration-success-subnet:" + subnetHash, subnetDaily},
	}
	for _, item := range limits {
		allowed, err := store.AllowPersistent(ctx, item.key, item.limit, 24*time.Hour, 0, 0)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrRateLimited
		}
	}
	return nil
}
