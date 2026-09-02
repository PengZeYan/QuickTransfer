package app

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type verificationDeliveryLimit struct {
	SubjectKey string
	Cooldown   time.Duration
	Hourly     int
	Daily      int
}

func (store *Store) ReserveVerificationDelivery(ctx context.Context, limits []verificationDeliveryLimit, now time.Time) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	nowUnix := now.Unix()
	hourStart := now.Truncate(time.Hour).Unix()
	dayStart := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC).Unix()
	for _, limit := range limits {
		result, updateErr := tx.ExecContext(ctx, `UPDATE verification_delivery_limits SET
			last_sent_at=?,
			hour_window_start=?,
			hour_count=CASE WHEN hour_window_start=? THEN hour_count+1 ELSE 1 END,
			day_window_start=?,
			day_count=CASE WHEN day_window_start=? THEN day_count+1 ELSE 1 END
			WHERE subject_key=? AND last_sent_at<=?
			AND (hour_window_start<>? OR hour_count<?)
			AND (day_window_start<>? OR day_count<?)`,
			nowUnix, hourStart, hourStart, dayStart, dayStart, limit.SubjectKey,
			nowUnix-int64(limit.Cooldown.Seconds()), hourStart, limit.Hourly, dayStart, limit.Daily)
		if updateErr != nil {
			return updateErr
		}
		rows, _ := result.RowsAffected()
		if rows == 1 {
			continue
		}
		var exists int
		lookupErr := tx.QueryRowContext(ctx, `SELECT 1 FROM verification_delivery_limits WHERE subject_key=?`, limit.SubjectKey).Scan(&exists)
		if lookupErr == nil {
			return ErrRateLimited
		}
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			return lookupErr
		}
		if _, insertErr := tx.ExecContext(ctx, `INSERT INTO verification_delivery_limits
			(subject_key,last_sent_at,hour_window_start,hour_count,day_window_start,day_count)
			VALUES(?,?,?,1,?,1)`, limit.SubjectKey, nowUnix, hourStart, dayStart); insertErr != nil {
			return insertErr
		}
	}
	return tx.Commit()
}

func (store *Store) InvalidateVerificationCodes(ctx context.Context, userID, purpose string, now int64) error {
	_, err := store.db.ExecContext(ctx, `UPDATE verification_codes SET consumed_at=?
		WHERE user_id=? AND purpose=? AND consumed_at=0`, now, userID, purpose)
	return err
}
