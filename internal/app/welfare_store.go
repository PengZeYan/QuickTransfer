package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	welfareTimeZone    = "Asia/Shanghai"
	welfareMinimumMiB  = int64(10)
	welfareMaximumMiB  = int64(200)
	welfareBytesPerMiB = int64(1024 * 1024)
)

var (
	welfareBusinessLocation   = time.FixedZone(welfareTimeZone, 8*60*60)
	welfareIDGenerator        = randomToken
	welfareRewardMiBGenerator = secureWelfareRewardMiB
)

func secureWelfareRewardMiB() (int64, error) {
	span := welfareMaximumMiB - welfareMinimumMiB + 1
	value, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return 0, err
	}
	return welfareMinimumMiB + value.Int64(), nil
}

func welfareDate(now time.Time) string {
	return now.In(welfareBusinessLocation).Format("2006-01-02")
}

func welfareMonth(now time.Time) string {
	return now.In(welfareBusinessLocation).Format("2006-01")
}

func sameWelfareDate(timestamp int64, now time.Time) bool {
	return timestamp > 0 && welfareDate(time.Unix(timestamp, 0)) == welfareDate(now)
}

func (store *Store) dailyCheckInByDate(ctx context.Context, userID, date string) (DailyCheckIn, error) {
	var checkIn DailyCheckIn
	err := store.db.QueryRowContext(ctx, `SELECT checkin_date,reward_bytes,created_at
		FROM daily_checkins WHERE user_id=? AND checkin_date=?`, userID, date).
		Scan(&checkIn.Date, &checkIn.RewardBytes, &checkIn.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DailyCheckIn{}, ErrNotFound
	}
	return checkIn, err
}

func (store *Store) HasDailyCheckIn(ctx context.Context, userID string, now time.Time) (bool, error) {
	if userID == "" {
		return false, ErrConflict
	}
	var exists int
	err := store.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM daily_checkins WHERE user_id=? AND checkin_date=?)`, userID, welfareDate(now)).Scan(&exists)
	return exists == 1, err
}

func (store *Store) WelfareStatus(ctx context.Context, userID string, now time.Time) (WelfareStatus, error) {
	if userID == "" {
		return WelfareStatus{}, ErrConflict
	}
	localNow := now.In(welfareBusinessLocation)
	monthStart := time.Date(localNow.Year(), localNow.Month(), 1, 0, 0, 0, 0, welfareBusinessLocation)
	monthKey := monthStart.Format("2006-01")
	todayKey := localNow.Format("2006-01-02")
	nextMonthKey := monthStart.AddDate(0, 1, 0).Format("2006-01-02")
	status := WelfareStatus{
		Month: monthKey, Today: todayKey, TimeZone: welfareTimeZone, CheckIns: []DailyCheckIn{},
	}
	rows, err := store.db.QueryContext(ctx, `SELECT checkin_date,reward_bytes,created_at
		FROM daily_checkins WHERE user_id=? AND checkin_date>=? AND checkin_date<? ORDER BY checkin_date`,
		userID, monthKey+"-01", nextMonthKey)
	if err != nil {
		return WelfareStatus{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var checkIn DailyCheckIn
		if err := rows.Scan(&checkIn.Date, &checkIn.RewardBytes, &checkIn.CreatedAt); err != nil {
			return WelfareStatus{}, err
		}
		status.CheckIns = append(status.CheckIns, checkIn)
		status.CheckInDays++
		status.MonthRewardBytes += checkIn.RewardBytes
		if checkIn.Date == todayKey {
			status.ClaimedToday = true
			status.TodayRewardBytes = checkIn.RewardBytes
		}
	}
	if err := rows.Err(); err != nil {
		return WelfareStatus{}, err
	}
	return status, nil
}

func (store *Store) ClaimDailyCheckIn(ctx context.Context, userID, ip string, now time.Time) (DailyCheckInResult, error) {
	if userID == "" {
		return DailyCheckInResult{}, ErrConflict
	}
	date := welfareDate(now)
	if existing, err := store.dailyCheckInByDate(ctx, userID, date); err == nil {
		return DailyCheckInResult{CheckIn: existing, Idempotent: true}, nil
	} else if !errors.Is(err, ErrNotFound) {
		return DailyCheckInResult{}, err
	}

	rewardMiB, err := welfareRewardMiBGenerator()
	if err != nil {
		return DailyCheckInResult{}, err
	}
	if rewardMiB < welfareMinimumMiB || rewardMiB > welfareMaximumMiB {
		return DailyCheckInResult{}, ErrConflict
	}
	rewardBytes := rewardMiB * welfareBytesPerMiB
	checkInID, err := welfareIDGenerator(16)
	if err != nil {
		return DailyCheckInResult{}, err
	}
	entitlementID, err := welfareIDGenerator(16)
	if err != nil {
		return DailyCheckInResult{}, err
	}
	auditID, err := welfareIDGenerator(16)
	if err != nil {
		return DailyCheckInResult{}, err
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return DailyCheckInResult{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO daily_checkins
		(id,user_id,checkin_date,reward_bytes,created_at) VALUES(?,?,?,?,?)`,
		checkInID, userID, date, rewardBytes, now.Unix())
	if err != nil {
		return DailyCheckInResult{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return DailyCheckInResult{}, err
	}
	if affected == 0 {
		_ = tx.Rollback()
		existing, existingErr := store.dailyCheckInByDate(ctx, userID, date)
		if existingErr != nil {
			return DailyCheckInResult{}, existingErr
		}
		return DailyCheckInResult{CheckIn: existing, Idempotent: true}, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO resource_entitlements
		(id,user_id,resource_type,amount_bytes,remaining_bytes,expires_at,source_type,source_id,created_at)
		VALUES(?,?,'traffic',?,?,?,'checkin',?,?)`, entitlementID, userID, rewardBytes, rewardBytes,
		permanentTrafficEntitlementExpiry, checkInID, now.Unix()); err != nil {
		return DailyCheckInResult{}, err
	}
	if err := insertAuditTx(ctx, tx, auditID, userID, "welfare.daily_checkin", "daily_checkin", checkInID,
		fmt.Sprintf("签到奖励 %d MiB", rewardMiB), ip, now.Unix()); err != nil {
		return DailyCheckInResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return DailyCheckInResult{}, err
	}
	return DailyCheckInResult{CheckIn: DailyCheckIn{
		Date: date, RewardBytes: rewardBytes, CreatedAt: now.Unix(),
	}}, nil
}
