package app

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const adminUserSelect = `SELECT u.id,u.email,u.username,u.status,u.role,u.vip_plan,u.vip_expires_at,
	u.created_at,u.verified_at,u.last_login_at,COALESCE(r.points_balance,0),
	COALESCE(r.free_traffic_remaining,0),
	COALESCE((SELECT SUM(e.remaining_bytes) FROM resource_entitlements e
		WHERE e.user_id=u.id AND e.resource_type='traffic' AND e.expires_at>?1),0),
	COALESCE((SELECT SUM(e.amount_bytes) FROM resource_entitlements e
		WHERE e.user_id=u.id AND e.resource_type='traffic'),0),
	COALESCE((SELECT SUM(c.amount_bytes) FROM upload_traffic_charges c
		WHERE c.user_id=u.id AND c.status='settled'),0),
	COALESCE(r.traffic_reserved_bytes,0),
	(SELECT COUNT(*) FROM orders o WHERE o.user_id=u.id),
	(SELECT COUNT(*) FROM orders o WHERE o.user_id=u.id AND o.status='paid'),
	(SELECT COUNT(*) FROM orders o WHERE o.user_id=u.id AND o.status='refunded'),
	COALESCE((SELECT SUM(o.price_cents) FROM orders o
		WHERE o.user_id=u.id AND o.status='paid' AND o.payment_method!='points'),0),
	COALESCE((SELECT SUM(o.points_price) FROM orders o
		WHERE o.user_id=u.id AND o.status='paid' AND o.payment_method='points'),0),
	COALESCE((SELECT MAX(o.created_at) FROM orders o WHERE o.user_id=u.id),0),
	(SELECT COUNT(*) FROM redemption_codes c WHERE c.redeemed_by=u.id),
	(SELECT COUNT(*) FROM transfers t WHERE t.owner_type='user' AND t.owner_id=u.id),
	(SELECT COUNT(*) FROM transfers t WHERE t.owner_type='user' AND t.owner_id=u.id
		AND t.status='active' AND t.expires_at>?1),
	(SELECT COUNT(*) FROM daily_checkins d WHERE d.user_id=u.id),
	COALESCE((SELECT SUM(d.reward_bytes) FROM daily_checkins d WHERE d.user_id=u.id),0),
	(SELECT COUNT(*) FROM vip_daily_login_grants g WHERE g.user_id=u.id),
	COALESCE((SELECT SUM(g.reward_bytes) FROM vip_daily_login_grants g WHERE g.user_id=u.id),0)
	FROM users u LEFT JOIN resource_accounts r ON r.user_id=u.id`

type adminUserScanner interface{ Scan(...any) error }

func scanAdminUser(row adminUserScanner, now int64) (AdminUser, error) {
	var item AdminUser
	err := row.Scan(&item.ID, &item.Email, &item.Username, &item.Status, &item.Role,
		&item.VIPPlan, &item.VIPExpiresAt, &item.CreatedAt, &item.VerifiedAt, &item.LastLoginAt,
		&item.Points, &item.BaseTrafficRemainingBytes, &item.EntitlementTrafficRemainingBytes,
		&item.TrafficGrantedBytes, &item.TrafficConsumedBytes, &item.TrafficReservedBytes,
		&item.OrderCount, &item.PaidOrderCount, &item.RefundedOrderCount, &item.CashPaidCents,
		&item.PointsSpent, &item.LastOrderAt, &item.RedemptionCount, &item.TransferCount,
		&item.ActiveTransferCount, &item.CheckInDays, &item.CheckInTrafficBytes,
		&item.VIPDailyGrantDays, &item.VIPDailyTrafficBytes)
	if err != nil {
		return AdminUser{}, err
	}
	item.TrafficRemainingBytes = item.BaseTrafficRemainingBytes + item.EntitlementTrafficRemainingBytes
	item.Level = "normal"
	if item.VIPPlan == VIPPlanLifetime ||
		((item.VIPPlan == VIPPlanMonthly || item.VIPPlan == VIPPlanYearly) && item.VIPExpiresAt > now) {
		item.Level = "vip"
	}
	return item, nil
}

func (store *Store) AdminUsers(ctx context.Context) ([]AdminUser, error) {
	now := time.Now().Unix()
	rows, err := store.db.QueryContext(ctx, adminUserSelect+` ORDER BY u.created_at DESC LIMIT 500`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AdminUser{}
	for rows.Next() {
		item, err := scanAdminUser(rows, now)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (store *Store) AdminUserDetail(ctx context.Context, userID string) (AdminUserDetail, error) {
	now := time.Now().Unix()
	user, err := scanAdminUser(store.db.QueryRowContext(ctx, adminUserSelect+` WHERE u.id=?2`, now, userID), now)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminUserDetail{}, ErrNotFound
	}
	if err != nil {
		return AdminUserDetail{}, err
	}
	detail := AdminUserDetail{
		User: user, Orders: []Order{}, Entitlements: []ResourceEntitlement{}, PointsLedger: []PointsEntry{},
		Redemptions: []AdminRedemptionCode{}, CheckIns: []DailyCheckIn{}, VIPDailyGrants: []VIPDailyLoginGrant{},
		RecentTransfers: []AdminUserTransfer{},
	}

	orderRows, err := store.db.QueryContext(ctx, `SELECT id,user_id,product_id,product_name,price_cents,
		points_price,payment_method,status,provider_transaction_id,created_at,paid_at,refunded_at
		FROM orders WHERE user_id=? ORDER BY created_at DESC LIMIT 200`, userID)
	if err != nil {
		return AdminUserDetail{}, err
	}
	for orderRows.Next() {
		order, scanErr := scanOrder(orderRows)
		if scanErr != nil {
			_ = orderRows.Close()
			return AdminUserDetail{}, scanErr
		}
		detail.Orders = append(detail.Orders, order)
	}
	if err := orderRows.Err(); err != nil {
		_ = orderRows.Close()
		return AdminUserDetail{}, err
	}
	_ = orderRows.Close()

	entitlementRows, err := store.db.QueryContext(ctx, `SELECT id,resource_type,amount_bytes,remaining_bytes,
		expires_at,source_type,source_id,created_at FROM resource_entitlements
		WHERE user_id=? AND resource_type='traffic' ORDER BY created_at DESC LIMIT 200`, userID)
	if err != nil {
		return AdminUserDetail{}, err
	}
	for entitlementRows.Next() {
		var item ResourceEntitlement
		if err := entitlementRows.Scan(&item.ID, &item.ResourceType, &item.AmountBytes, &item.RemainingBytes,
			&item.ExpiresAt, &item.SourceType, &item.SourceID, &item.CreatedAt); err != nil {
			_ = entitlementRows.Close()
			return AdminUserDetail{}, err
		}
		detail.Entitlements = append(detail.Entitlements, item)
	}
	if err := entitlementRows.Err(); err != nil {
		_ = entitlementRows.Close()
		return AdminUserDetail{}, err
	}
	_ = entitlementRows.Close()

	pointsRows, err := store.db.QueryContext(ctx, `SELECT id,delta,balance_after,reason,created_at
		FROM points_ledger WHERE user_id=? ORDER BY created_at DESC LIMIT 200`, userID)
	if err != nil {
		return AdminUserDetail{}, err
	}
	for pointsRows.Next() {
		var item PointsEntry
		if err := pointsRows.Scan(&item.ID, &item.Delta, &item.BalanceAfter, &item.Reason, &item.CreatedAt); err != nil {
			_ = pointsRows.Close()
			return AdminUserDetail{}, err
		}
		detail.PointsLedger = append(detail.PointsLedger, item)
	}
	if err := pointsRows.Err(); err != nil {
		_ = pointsRows.Close()
		return AdminUserDetail{}, err
	}
	_ = pointsRows.Close()

	redemptionRows, err := store.db.QueryContext(ctx, `SELECT c.id,c.batch_id,c.protected_code,c.status,
		COALESCE(c.redeemed_by,''),u.username,u.email,c.redeemed_at,c.created_at
		FROM redemption_codes c JOIN users u ON u.id=c.redeemed_by
		WHERE c.redeemed_by=? ORDER BY c.redeemed_at DESC LIMIT 200`, userID)
	if err != nil {
		return AdminUserDetail{}, err
	}
	for redemptionRows.Next() {
		var item AdminRedemptionCode
		var protected string
		if err := redemptionRows.Scan(&item.ID, &item.BatchID, &protected, &item.Status, &item.RedeemedBy,
			&item.RedeemedUsername, &item.RedeemedEmail, &item.RedeemedAt, &item.CreatedAt); err != nil {
			_ = redemptionRows.Close()
			return AdminUserDetail{}, err
		}
		if protected != "" {
			item.Code, err = openRedemptionCode(protected, store.redemptionProtectionKey)
			if err != nil {
				_ = redemptionRows.Close()
				return AdminUserDetail{}, err
			}
			item.CodeAvailable = true
		}
		detail.Redemptions = append(detail.Redemptions, item)
	}
	if err := redemptionRows.Err(); err != nil {
		_ = redemptionRows.Close()
		return AdminUserDetail{}, err
	}
	_ = redemptionRows.Close()

	checkInRows, err := store.db.QueryContext(ctx, `SELECT checkin_date,reward_bytes,created_at
		FROM daily_checkins WHERE user_id=? ORDER BY checkin_date DESC LIMIT 370`, userID)
	if err != nil {
		return AdminUserDetail{}, err
	}
	for checkInRows.Next() {
		var item DailyCheckIn
		if err := checkInRows.Scan(&item.Date, &item.RewardBytes, &item.CreatedAt); err != nil {
			_ = checkInRows.Close()
			return AdminUserDetail{}, err
		}
		detail.CheckIns = append(detail.CheckIns, item)
	}
	if err := checkInRows.Err(); err != nil {
		_ = checkInRows.Close()
		return AdminUserDetail{}, err
	}
	_ = checkInRows.Close()

	grantRows, err := store.db.QueryContext(ctx, `SELECT grant_date,vip_plan,reward_bytes,created_at
		FROM vip_daily_login_grants WHERE user_id=? ORDER BY grant_date DESC LIMIT 370`, userID)
	if err != nil {
		return AdminUserDetail{}, err
	}
	for grantRows.Next() {
		var item VIPDailyLoginGrant
		if err := grantRows.Scan(&item.Date, &item.VIPPlan, &item.RewardBytes, &item.CreatedAt); err != nil {
			_ = grantRows.Close()
			return AdminUserDetail{}, err
		}
		detail.VIPDailyGrants = append(detail.VIPDailyGrants, item)
	}
	if err := grantRows.Err(); err != nil {
		_ = grantRows.Close()
		return AdminUserDetail{}, err
	}
	_ = grantRows.Close()

	transferRows, err := store.db.QueryContext(ctx, `SELECT id,kind,title,status,total_bytes,file_count,
		downloads,max_downloads,created_at,expires_at FROM transfers
		WHERE owner_type='user' AND owner_id=? ORDER BY created_at DESC LIMIT 200`, userID)
	if err != nil {
		return AdminUserDetail{}, err
	}
	for transferRows.Next() {
		var item AdminUserTransfer
		if err := transferRows.Scan(&item.ID, &item.Kind, &item.Title, &item.Status, &item.TotalBytes,
			&item.FileCount, &item.Downloads, &item.MaxDownloads, &item.CreatedAt, &item.ExpiresAt); err != nil {
			_ = transferRows.Close()
			return AdminUserDetail{}, err
		}
		detail.RecentTransfers = append(detail.RecentTransfers, item)
	}
	if err := transferRows.Err(); err != nil {
		_ = transferRows.Close()
		return AdminUserDetail{}, err
	}
	_ = transferRows.Close()
	return detail, nil
}

func (store *Store) AdminReports(ctx context.Context) ([]AbuseReport, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id,share_token,reason,detail,ip,status,created_at,resolved_at
		FROM abuse_reports ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END,created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AbuseReport{}
	for rows.Next() {
		var item AbuseReport
		if err := rows.Scan(&item.ID, &item.ShareToken, &item.Reason, &item.Detail, &item.IP,
			&item.Status, &item.CreatedAt, &item.ResolvedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (store *Store) AdminOrders(ctx context.Context) ([]Order, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id,user_id,product_id,product_name,price_cents,
		points_price,payment_method,status,provider_transaction_id,created_at,paid_at,refunded_at
		FROM orders ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Order{}
	for rows.Next() {
		order, scanErr := scanOrder(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, order)
	}
	return items, rows.Err()
}

func (store *Store) SetReportStatus(ctx context.Context, id, status string, now int64) (string, error) {
	if status != "resolved" && status != "rejected" {
		return "", ErrConflict
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var shareToken string
	if err := tx.QueryRowContext(ctx, `SELECT share_token FROM abuse_reports WHERE id=? AND status='open'`, id).Scan(&shareToken); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	result, err := tx.ExecContext(ctx, `UPDATE abuse_reports SET status=?,resolved_at=? WHERE id=? AND status='open'`, status, now, id)
	if err != nil {
		return "", err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return "", ErrNotFound
	}
	if status == "resolved" {
		if _, err := tx.ExecContext(ctx, `UPDATE transfers SET status='revoked' WHERE share_token=? AND status='active'`, shareToken); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return shareToken, nil
}

func (store *Store) RefundOrder(ctx context.Context, orderID string, _ int64, _ int64, now int64) (Order, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Order{}, err
	}
	defer tx.Rollback()
	order, err := scanOrder(tx.QueryRowContext(ctx, `SELECT id,user_id,product_id,product_name,price_cents,
		points_price,payment_method,status,provider_transaction_id,created_at,paid_at,refunded_at
		FROM orders WHERE id=?`, orderID))
	if errors.Is(err, sql.ErrNoRows) {
		return Order{}, ErrNotFound
	}
	if err != nil {
		return Order{}, err
	}
	if order.Status != "paid" || (order.PaymentMethod != "sandbox" && order.PaymentMethod != "points") {
		return Order{}, ErrConflict
	}
	var vipPlan string
	if err := tx.QueryRowContext(ctx, `SELECT vip_plan FROM products WHERE id=?`, order.ProductID).Scan(&vipPlan); err != nil {
		return Order{}, err
	}
	// Membership grants currently aggregate on the account. Until a revocable
	// grant ledger is introduced, automatic VIP refunds fail closed instead of
	// accidentally revoking another active purchase or redemption.
	if vipPlan != "" {
		return Order{}, ErrConflict
	}
	var consumed int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM resource_entitlements
		WHERE source_type='order' AND source_id=? AND resource_type='traffic' AND remaining_bytes!=amount_bytes`, order.ID).Scan(&consumed); err != nil {
		return Order{}, err
	}
	if consumed != 0 {
		return Order{}, ErrQuotaExceeded
	}
	var reserved int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
		FROM resource_entitlements e
		JOIN upload_traffic_allocations a ON a.source_kind='entitlement' AND a.source_id=e.id
		JOIN upload_traffic_charges c ON c.upload_id=a.upload_id AND c.status='reserved'
		WHERE e.source_type='order' AND e.source_id=? AND e.resource_type='traffic'`, order.ID).Scan(&reserved); err != nil {
		return Order{}, err
	}
	if reserved != 0 {
		return Order{}, ErrQuotaExceeded
	}
	if order.PaymentMethod == "points" {
		if err := addPointsTx(ctx, tx, order.UserID, order.PointsPrice, "积分订单退款 "+order.ProductName, "order-refund:"+order.ID, now); err != nil {
			return Order{}, err
		}
	} else if order.PriceCents > 0 {
		reward := max(int64(1), order.PriceCents/10)
		if err := addPointsTx(ctx, tx, order.UserID, -reward, "购买奖励撤回 "+order.ProductName, "order-reward-refund:"+order.ID, now); err != nil {
			return Order{}, ErrQuotaExceeded
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM resource_entitlements WHERE source_type='order' AND source_id=?`, order.ID); err != nil {
		return Order{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE orders SET status='refunded',refunded_at=? WHERE id=? AND status='paid'`, now, order.ID)
	if err != nil {
		return Order{}, err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return Order{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Order{}, err
	}
	order.Status = "refunded"
	order.RefundedAt = now
	return order, nil
}
