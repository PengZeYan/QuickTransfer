package app

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const (
	vipMonthlyDailyLoginBytes  = int64(200 * 1024 * 1024)
	vipYearlyDailyLoginBytes   = int64(500 * 1024 * 1024)
	vipLifetimeDailyLoginBytes = int64(1024 * 1024 * 1024)
)

var vipDailyLoginIDGenerator = randomToken

func vipDailyLoginReward(plan string) (int64, string) {
	switch canonicalVIPPlan(plan) {
	case VIPPlanMonthly:
		return vipMonthlyDailyLoginBytes, "月度会员每日登录权益 200 MiB"
	case VIPPlanYearly:
		return vipYearlyDailyLoginBytes, "年度会员每日登录权益 500 MiB"
	case VIPPlanLifetime:
		return vipLifetimeDailyLoginBytes, "终身会员每日登录权益 1 GiB"
	default:
		return 0, ""
	}
}

func grantVIPDailyLoginTrafficTx(ctx context.Context, tx *sql.Tx, userID, ip string, now time.Time) (VIPDailyLoginGrant, error) {
	var storedPlan string
	var expiresAt int64
	if err := tx.QueryRowContext(ctx, `SELECT vip_plan,vip_expires_at FROM users WHERE id=?`, userID).
		Scan(&storedPlan, &expiresAt); err != nil {
		return VIPDailyLoginGrant{}, err
	}
	plan := activeVIPPlan(storedPlan, expiresAt, now.Unix())
	rewardBytes, detail := vipDailyLoginReward(plan)
	if rewardBytes == 0 {
		return VIPDailyLoginGrant{}, nil
	}

	date := welfareDate(now)
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM vip_daily_login_grants WHERE user_id=? AND grant_date=?)`, userID, date).
		Scan(&exists); err != nil {
		return VIPDailyLoginGrant{}, err
	}
	if exists == 1 {
		return VIPDailyLoginGrant{}, nil
	}

	grantID, err := vipDailyLoginIDGenerator(16)
	if err != nil {
		return VIPDailyLoginGrant{}, err
	}
	entitlementID, err := vipDailyLoginIDGenerator(16)
	if err != nil {
		return VIPDailyLoginGrant{}, err
	}
	auditID, err := vipDailyLoginIDGenerator(16)
	if err != nil {
		return VIPDailyLoginGrant{}, err
	}
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO vip_daily_login_grants
		(id,user_id,grant_date,vip_plan,reward_bytes,created_at) VALUES(?,?,?,?,?,?)`,
		grantID, userID, date, plan, rewardBytes, now.Unix())
	if err != nil {
		return VIPDailyLoginGrant{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return VIPDailyLoginGrant{}, err
	}
	if affected == 0 {
		return VIPDailyLoginGrant{}, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO resource_entitlements
		(id,user_id,resource_type,amount_bytes,remaining_bytes,expires_at,source_type,source_id,created_at)
		VALUES(?,?,'traffic',?,?,?,'vip_daily_login',?,?)`, entitlementID, userID, rewardBytes, rewardBytes,
		permanentTrafficEntitlementExpiry, grantID, now.Unix()); err != nil {
		return VIPDailyLoginGrant{}, err
	}
	if err := insertAuditTx(ctx, tx, auditID, userID, "membership.daily_login_traffic", "vip_daily_login_grant",
		grantID, fmt.Sprintf("%s，已加入永久上传流量", detail), ip, now.Unix()); err != nil {
		return VIPDailyLoginGrant{}, err
	}
	return VIPDailyLoginGrant{Date: date, VIPPlan: plan, RewardBytes: rewardBytes, CreatedAt: now.Unix()}, nil
}
