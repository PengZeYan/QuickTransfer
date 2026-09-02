package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	downloadReservationLeaseDuration = 2 * time.Minute
	downloadReservationMaxDuration   = 48 * time.Hour
)

var commerceIDGenerator = randomToken

type uploadTrafficAllocation struct {
	ordinal    int
	sourceKind string
	sourceID   string
	reserved   int64
}

type downloadReservationSchemaState struct {
	mu    sync.Mutex
	ready bool
}

var downloadReservationSchemaStates sync.Map

func scanProduct(row interface{ Scan(...any) error }) (Product, error) {
	var product Product
	err := row.Scan(&product.ID, &product.Name, &product.Description, &product.Kind, &product.StorageBytes,
		&product.TrafficBytes, &product.VIPPlan, &product.VIPDays, &product.ValidDays, &product.PriceCents, &product.PointsPrice,
		&product.Active, &product.SortOrder)
	return product, err
}

func (store *Store) ListProducts(ctx context.Context) ([]Product, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id,name,description,kind,storage_bytes,traffic_bytes,
		vip_plan,vip_days,valid_days,price_cents,points_price,active,sort_order
		FROM products WHERE active=1 ORDER BY sort_order,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	products := []Product{}
	for rows.Next() {
		product, scanErr := scanProduct(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		products = append(products, product)
	}
	return products, rows.Err()
}

func (store *Store) ProductByID(ctx context.Context, id string) (Product, error) {
	product, err := scanProduct(store.db.QueryRowContext(ctx, `SELECT id,name,description,kind,storage_bytes,traffic_bytes,
		vip_plan,vip_days,valid_days,price_cents,points_price,active,sort_order
		FROM products WHERE id=? AND active=1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Product{}, ErrNotFound
	}
	return product, err
}

func scanOrder(row interface{ Scan(...any) error }) (Order, error) {
	var order Order
	err := row.Scan(&order.ID, &order.UserID, &order.ProductID, &order.ProductName, &order.PriceCents,
		&order.PointsPrice, &order.PaymentMethod, &order.Status, &order.ProviderTransactionID,
		&order.CreatedAt, &order.PaidAt, &order.RefundedAt)
	return order, err
}

func (store *Store) CreateOrder(ctx context.Context, userID, productID, method, idempotencyKey string, now int64) (Order, error) {
	if method != "sandbox" && method != "points" && method != "wechat" && method != "alipay" {
		return Order{}, ErrConflict
	}
	if idempotencyKey == "" {
		return Order{}, ErrConflict
	}
	if existing, err := store.orderByIdempotencyKey(ctx, userID, idempotencyKey); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Order{}, err
	}
	product, err := store.ProductByID(ctx, productID)
	if err != nil {
		return Order{}, err
	}
	id, err := commerceIDGenerator(16)
	if err != nil {
		return Order{}, err
	}
	order := Order{ID: id, UserID: userID, ProductID: product.ID, ProductName: product.Name,
		PriceCents: product.PriceCents, PointsPrice: product.PointsPrice, PaymentMethod: method,
		Status: "pending", CreatedAt: now}
	_, err = store.db.ExecContext(ctx, `INSERT INTO orders
		(id,idempotency_key,user_id,product_id,product_name,price_cents,points_price,payment_method,status,created_at)
		VALUES(?,?,?,?,?,?,?,?,'pending',?)`, order.ID, idempotencyKey, order.UserID, order.ProductID, order.ProductName,
		order.PriceCents, order.PointsPrice, order.PaymentMethod, order.CreatedAt)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return store.orderByIdempotencyKey(ctx, userID, idempotencyKey)
	}
	return order, err
}

func (store *Store) orderByIdempotencyKey(ctx context.Context, userID, key string) (Order, error) {
	order, err := scanOrder(store.db.QueryRowContext(ctx, `SELECT id,user_id,product_id,product_name,price_cents,
		points_price,payment_method,status,provider_transaction_id,created_at,paid_at,refunded_at
		FROM orders WHERE user_id=? AND idempotency_key=?`, userID, key))
	if errors.Is(err, sql.ErrNoRows) {
		return Order{}, ErrNotFound
	}
	return order, err
}

func (store *Store) OrderByIDForUser(ctx context.Context, id, userID string) (Order, error) {
	order, err := scanOrder(store.db.QueryRowContext(ctx, `SELECT id,user_id,product_id,product_name,price_cents,
		points_price,payment_method,status,provider_transaction_id,created_at,paid_at,refunded_at
		FROM orders WHERE id=? AND user_id=?`, id, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return Order{}, ErrNotFound
	}
	return order, err
}

func (store *Store) OrdersForUser(ctx context.Context, userID string) ([]Order, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id,user_id,product_id,product_name,price_cents,
		points_price,payment_method,status,provider_transaction_id,created_at,paid_at,refunded_at
		FROM orders WHERE user_id=? ORDER BY created_at DESC LIMIT 100`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	orders := []Order{}
	for rows.Next() {
		order, scanErr := scanOrder(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		orders = append(orders, order)
	}
	return orders, rows.Err()
}

func (store *Store) CompleteSandboxOrder(ctx context.Context, orderID, userID, eventID, transactionID string, now int64) (Order, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Order{}, err
	}
	defer tx.Rollback()
	order, product, err := loadOrderProductTx(ctx, tx, orderID, userID)
	if err != nil {
		return Order{}, err
	}
	if order.PaymentMethod != "sandbox" {
		return Order{}, ErrUnauthorized
	}
	if order.Status == "paid" {
		return order, tx.Commit()
	}
	payloadHash := tokenHash(eventID + ":" + transactionID + ":" + orderID)
	if _, err := tx.ExecContext(ctx, `INSERT INTO payment_events(event_id,provider,order_id,payload_hash,created_at)
		VALUES(?,'sandbox',?,?,?)`, eventID, orderID, payloadHash, now); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return order, tx.Commit()
		}
		return Order{}, err
	}
	if err := completeOrderTx(ctx, tx, &order, product, transactionID, now, true); err != nil {
		return Order{}, err
	}
	if err := tx.Commit(); err != nil {
		return Order{}, err
	}
	return order, nil
}

func (store *Store) PayOrderWithPoints(ctx context.Context, orderID, userID string, now int64) (Order, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Order{}, err
	}
	defer tx.Rollback()
	order, product, err := loadOrderProductTx(ctx, tx, orderID, userID)
	if err != nil {
		return Order{}, err
	}
	if order.PaymentMethod != "points" {
		return Order{}, ErrUnauthorized
	}
	if order.Status == "paid" {
		return order, tx.Commit()
	}
	if err := addPointsTx(ctx, tx, userID, -order.PointsPrice, "积分兑换 "+order.ProductName, "order-spend:"+order.ID, now); err != nil {
		return Order{}, err
	}
	if err := completeOrderTx(ctx, tx, &order, product, "points-"+order.ID, now, false); err != nil {
		return Order{}, err
	}
	if err := tx.Commit(); err != nil {
		return Order{}, err
	}
	return order, nil
}

func loadOrderProductTx(ctx context.Context, tx *sql.Tx, orderID, userID string) (Order, Product, error) {
	order, err := scanOrder(tx.QueryRowContext(ctx, `SELECT id,user_id,product_id,product_name,price_cents,
		points_price,payment_method,status,provider_transaction_id,created_at,paid_at,refunded_at
		FROM orders WHERE id=? AND user_id=?`, orderID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return Order{}, Product{}, ErrNotFound
	}
	if err != nil {
		return Order{}, Product{}, err
	}
	product, err := scanProduct(tx.QueryRowContext(ctx, `SELECT id,name,description,kind,storage_bytes,traffic_bytes,
		vip_plan,vip_days,valid_days,price_cents,points_price,active,sort_order FROM products WHERE id=?`, order.ProductID))
	return order, product, err
}

func completeOrderTx(ctx context.Context, tx *sql.Tx, order *Order, product Product, transactionID string, now int64, rewardPoints bool) error {
	if order.Status != "pending" {
		return ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE orders SET status='paid',provider_transaction_id=?,paid_at=?
		WHERE id=? AND status='pending'`, transactionID, now, order.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrConflict
	}
	expiresAt := permanentTrafficEntitlementExpiry
	if product.ValidDays > 0 {
		expiresAt = time.Unix(now, 0).Add(time.Duration(product.ValidDays) * 24 * time.Hour).Unix()
	}
	if product.TrafficBytes > 0 {
		id, err := commerceIDGenerator(16)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO resource_entitlements
			(id,user_id,resource_type,amount_bytes,remaining_bytes,expires_at,source_type,source_id,created_at)
			VALUES(?,?,'traffic',?,?,?,'order',?,?)`, id, order.UserID, product.TrafficBytes,
			product.TrafficBytes, expiresAt, order.ID, now); err != nil {
			return err
		}
	}
	if product.VIPPlan != "" {
		if err := applyVIPBenefitTx(ctx, tx, order.UserID, product.VIPPlan, product.VIPDays, now); err != nil {
			return err
		}
	}
	if rewardPoints && order.PriceCents > 0 {
		reward := max(int64(1), order.PriceCents/10)
		if err := addPointsTx(ctx, tx, order.UserID, reward, "购买奖励 "+order.ProductName, "order-reward:"+order.ID, now); err != nil {
			return err
		}
	}
	order.Status = "paid"
	order.PaidAt = now
	order.ProviderTransactionID = transactionID
	return nil
}

func (store *Store) CreateUploadWithQuota(ctx context.Context, upload Upload, transfer Transfer, maxFiles int,
	maxBytes, baseStorage, monthlyTraffic, guestDailyBytes int64) error {
	_ = transfer
	_ = baseStorage
	var err error
	upload, err = normalizeUploadPlacement(upload)
	if err != nil {
		return err
	}
	if upload.Length <= 0 {
		return ErrConflict
	}
	// Retire any pre-v5 download-side traffic holds before upload billing
	// consults the shared reserved counter.
	if err := store.ensureDownloadReservationStateSchema(ctx); err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Obtain SQLite's writer lock before the idempotency lookup and balance
	// planning. This serializes concurrent uploads without relying on a stale
	// read transaction that later tries to upgrade to a writer.
	locked, err := tx.ExecContext(ctx, `UPDATE transfers SET file_count=file_count WHERE id=?`, upload.TransferID)
	if err != nil {
		return err
	}
	if rows, _ := locked.RowsAffected(); rows != 1 {
		return ErrNotFound
	}
	existing, err := scanUpload(tx.QueryRowContext(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE id=?`, upload.ID))
	if err == nil {
		if existing.Status == "deleted" || existing.TransferID != upload.TransferID ||
			existing.UploadHash != upload.UploadHash || existing.OriginalName != upload.OriginalName ||
			existing.ContentType != upload.ContentType || existing.Length != upload.Length ||
			existing.StorageKind != upload.StorageKind || existing.StorageNodeID != upload.StorageNodeID ||
			existing.StorageKey != upload.StorageKey || existing.StorageVersion != upload.StorageVersion {
			return ErrConflict
		}
		// The upload row and its charge are committed atomically. An exact retry
		// therefore reuses the original reservation instead of charging again.
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var files int
	var bytes, expiresAt int64
	var status, ownerType, ownerID string
	if err := tx.QueryRowContext(ctx, `SELECT file_count,total_bytes,status,expires_at,owner_type,owner_id
		FROM transfers WHERE id=?`, upload.TransferID).Scan(&files, &bytes, &status, &expiresAt, &ownerType, &ownerID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if status != "active" || expiresAt <= time.Now().Unix() {
		return ErrConflict
	}
	if files+1 > maxFiles || bytes+upload.Length > maxBytes {
		return ErrQuotaExceeded
	}
	now := time.Now()
	if ownerType == "guest" && ownerID != "" && guestDailyBytes > 0 {
		allowed, err := allowBucketTx(ctx, tx, "guest-bytes:"+ownerID, 0, 24*time.Hour, 0, upload.Length, guestDailyBytes, now)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrRateLimited
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uploads
		(id,transfer_id,upload_hash,original_name,content_type,length,offset,status,temp_path,submitter_name,created_at,
		 storage_released,storage_kind,storage_node_id,storage_key,storage_version)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?)`, upload.ID, upload.TransferID, upload.UploadHash,
		upload.OriginalName, upload.ContentType, upload.Length, 0, "uploading", upload.TempPath,
		upload.SubmitterName, upload.CreatedAt, upload.StorageKind, upload.StorageNodeID, upload.StorageKey,
		upload.StorageVersion); err != nil {
		return err
	}
	if ownerType == "user" && ownerID != "" {
		if err := reserveUploadTrafficTx(ctx, tx, upload.ID, ownerID, upload.Length, monthlyTraffic, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE transfers SET file_count=file_count+1,total_bytes=total_bytes+? WHERE id=?`,
		upload.Length, upload.TransferID); err != nil {
		return err
	}
	return tx.Commit()
}

func ensureTrafficAccountTx(ctx context.Context, tx *sql.Tx, userID string, initialTraffic int64, now time.Time) error {
	initialTraffic = max(initialTraffic, 0)
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO resource_accounts
		(user_id,free_traffic_remaining,free_traffic_period,updated_at) VALUES(?,?,?,?)`,
		userID, initialTraffic, permanentBaseTrafficSource, now.Unix()); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE resource_accounts SET
		free_traffic_remaining=CASE
			WHEN free_traffic_period='' AND free_traffic_remaining=0 THEN ?
			ELSE free_traffic_remaining END,
		free_traffic_period=?,updated_at=?
		WHERE user_id=? AND free_traffic_period!=?`, initialTraffic, permanentBaseTrafficSource,
		now.Unix(), userID, permanentBaseTrafficSource)
	return err
}

func planUploadTrafficAllocationsTx(ctx context.Context, tx *sql.Tx, userID string,
	required int64, now time.Time) ([]uploadTrafficAllocation, error) {
	var free, totalReserved int64
	var period string
	if err := tx.QueryRowContext(ctx, `SELECT free_traffic_remaining,free_traffic_period,traffic_reserved_bytes
		FROM resource_accounts WHERE user_id=?`, userID).Scan(&free, &period, &totalReserved); err != nil {
		return nil, err
	}
	allocatedBySource := make(map[string]int64)
	var snapshottedReserved int64
	rows, err := tx.QueryContext(ctx, `SELECT a.source_kind,a.source_id,COALESCE(SUM(a.amount_bytes),0)
		FROM upload_traffic_allocations a
		JOIN upload_traffic_charges c ON c.upload_id=a.upload_id
		WHERE c.user_id=? AND c.status='reserved'
		GROUP BY a.source_kind,a.source_id`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var kind, id string
		var amount int64
		if err := rows.Scan(&kind, &id, &amount); err != nil {
			_ = rows.Close()
			return nil, err
		}
		allocatedBySource[kind+"\x00"+id] = amount
		snapshottedReserved += amount
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// Any reserved bytes without a v5 upload allocation belong to an old
	// download hold or a partially migrated row. Account for them
	// conservatively so a rolling upgrade cannot overspend traffic.
	legacyReserved := max(totalReserved-snapshottedReserved, 0)
	type trafficSource struct {
		kind      string
		id        string
		available int64
	}
	sources := []trafficSource{{kind: "free", id: period,
		available: max(free-allocatedBySource["free\x00"+period], 0)}}
	rows, err = tx.QueryContext(ctx, `SELECT id,remaining_bytes FROM resource_entitlements
		WHERE user_id=? AND resource_type='traffic' AND expires_at>? AND remaining_bytes>0
		ORDER BY expires_at,id`, userID, now.Unix())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var source trafficSource
		source.kind = "entitlement"
		if err := rows.Scan(&source.id, &source.available); err != nil {
			_ = rows.Close()
			return nil, err
		}
		source.available = max(source.available-allocatedBySource["entitlement\x00"+source.id], 0)
		sources = append(sources, source)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range sources {
		usedByLegacy := min(sources[index].available, legacyReserved)
		sources[index].available -= usedByLegacy
		legacyReserved -= usedByLegacy
	}
	remaining := required
	allocations := make([]uploadTrafficAllocation, 0, len(sources))
	for _, source := range sources {
		amount := min(max(source.available, 0), remaining)
		if amount <= 0 {
			continue
		}
		allocations = append(allocations, uploadTrafficAllocation{
			ordinal: len(allocations), sourceKind: source.kind, sourceID: source.id, reserved: amount,
		})
		remaining -= amount
		if remaining == 0 {
			break
		}
	}
	if remaining > 0 {
		return nil, ErrTrafficExceeded
	}
	return allocations, nil
}

func reserveUploadTrafficTx(ctx context.Context, tx *sql.Tx, uploadID, userID string,
	required, monthlyTraffic int64, now time.Time) error {
	if required < 0 || uploadID == "" || userID == "" {
		return ErrConflict
	}
	if err := ensureTrafficAccountTx(ctx, tx, userID, monthlyTraffic, now); err != nil {
		return err
	}
	allocations, err := planUploadTrafficAllocationsTx(ctx, tx, userID, required, now)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO upload_traffic_charges
		(upload_id,user_id,amount_bytes,status,created_at,settled_at)
		VALUES(?,?,?,'reserved',?,0)`, uploadID, userID, required, now.Unix()); err != nil {
		return err
	}
	for _, allocation := range allocations {
		if allocation.sourceKind != "free" && allocation.sourceKind != "entitlement" {
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO upload_traffic_allocations
			(upload_id,ordinal,source_kind,source_id,amount_bytes)
			VALUES(?,?,?,?,?)`, uploadID, allocation.ordinal, allocation.sourceKind,
			allocation.sourceID, allocation.reserved); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE resource_accounts SET
		traffic_reserved_bytes=traffic_reserved_bytes+?,updated_at=? WHERE user_id=?`,
		required, now.Unix(), userID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrConflict
	}
	return nil
}

func settleUploadTrafficTx(ctx context.Context, tx *sql.Tx, uploadID string, now int64) error {
	result, err := tx.ExecContext(ctx, `UPDATE upload_traffic_charges SET
		status='settled',settled_at=? WHERE upload_id=? AND status='reserved'`, now, uploadID)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		var status string
		err := tx.QueryRowContext(ctx, `SELECT status FROM upload_traffic_charges WHERE upload_id=?`, uploadID).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			// Rows created before upload charging are grandfathered and never
			// charged retroactively.
			return nil
		}
		if err != nil {
			return err
		}
		if status == "settled" || status == "grandfathered" {
			return nil
		}
		return ErrConflict
	}
	var userID string
	var reserved int64
	if err := tx.QueryRowContext(ctx, `SELECT user_id,amount_bytes FROM upload_traffic_charges
		WHERE upload_id=?`, uploadID).Scan(&userID, &reserved); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT source_kind,source_id,amount_bytes
		FROM upload_traffic_allocations WHERE upload_id=? ORDER BY ordinal`, uploadID)
	if err != nil {
		return err
	}
	allocations := make([]uploadTrafficAllocation, 0, 2)
	var allocated int64
	for rows.Next() {
		var allocation uploadTrafficAllocation
		if err := rows.Scan(&allocation.sourceKind, &allocation.sourceID, &allocation.reserved); err != nil {
			_ = rows.Close()
			return err
		}
		allocations = append(allocations, allocation)
		allocated += allocation.reserved
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if allocated != reserved {
		return ErrConflict
	}
	var currentFreePeriod string
	if err := tx.QueryRowContext(ctx, `SELECT free_traffic_period FROM resource_accounts WHERE user_id=?`,
		userID).Scan(&currentFreePeriod); err != nil {
		return err
	}
	for _, allocation := range allocations {
		var sourceResult sql.Result
		switch allocation.sourceKind {
		case "free":
			if allocation.sourceID != currentFreePeriod {
				return ErrConflict
			}
			sourceResult, err = tx.ExecContext(ctx, `UPDATE resource_accounts SET
				free_traffic_remaining=free_traffic_remaining-? WHERE user_id=?
				AND free_traffic_period=? AND free_traffic_remaining>=?`, allocation.reserved,
				userID, allocation.sourceID, allocation.reserved)
		case "entitlement":
			sourceResult, err = tx.ExecContext(ctx, `UPDATE resource_entitlements SET
				remaining_bytes=remaining_bytes-? WHERE id=? AND user_id=? AND resource_type='traffic'
				AND remaining_bytes>=?`, allocation.reserved, allocation.sourceID, userID, allocation.reserved)
		default:
			return ErrConflict
		}
		if err != nil {
			return err
		}
		if affected, _ := sourceResult.RowsAffected(); affected != 1 {
			return ErrTrafficExceeded
		}
	}
	result, err = tx.ExecContext(ctx, `UPDATE resource_accounts SET
		traffic_reserved_bytes=traffic_reserved_bytes-?,updated_at=?
		WHERE user_id=? AND traffic_reserved_bytes>=?`, reserved, now, userID, reserved)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrConflict
	}
	return nil
}

func refundUploadTrafficTx(ctx context.Context, tx *sql.Tx, uploadID string, now int64) error {
	result, err := tx.ExecContext(ctx, `UPDATE upload_traffic_charges SET
		status='refunded',settled_at=? WHERE upload_id=? AND status='reserved'`, now, uploadID)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		var status string
		err := tx.QueryRowContext(ctx, `SELECT status FROM upload_traffic_charges WHERE upload_id=?`, uploadID).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) || status == "settled" || status == "refunded" || status == "grandfathered" {
			return nil
		}
		if err != nil {
			return err
		}
		return ErrConflict
	}
	var userID string
	var reserved int64
	if err := tx.QueryRowContext(ctx, `SELECT user_id,amount_bytes FROM upload_traffic_charges
		WHERE upload_id=?`, uploadID).Scan(&userID, &reserved); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT source_kind,source_id,amount_bytes
		FROM upload_traffic_allocations WHERE upload_id=? ORDER BY ordinal`, uploadID)
	if err != nil {
		return err
	}
	allocations := make([]uploadTrafficAllocation, 0, 2)
	var allocated int64
	for rows.Next() {
		var allocation uploadTrafficAllocation
		if err := rows.Scan(&allocation.sourceKind, &allocation.sourceID, &allocation.reserved); err != nil {
			_ = rows.Close()
			return err
		}
		allocations = append(allocations, allocation)
		allocated += allocation.reserved
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if allocated != reserved {
		return ErrConflict
	}
	// Source balances were only logically held. Marking the charge refunded
	// releases those immutable allocations without altering either source.
	result, err = tx.ExecContext(ctx, `UPDATE resource_accounts SET
		traffic_reserved_bytes=traffic_reserved_bytes-?,updated_at=?
		WHERE user_id=? AND traffic_reserved_bytes>=?`, reserved, now, userID, reserved)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrConflict
	}
	return nil
}

func (store *Store) ReleaseUploadStorage(ctx context.Context, uploadID string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := releaseUploadStorageTx(ctx, tx, uploadID); err != nil {
		return err
	}
	return tx.Commit()
}

func releaseUploadStorageTx(ctx context.Context, tx *sql.Tx, uploadID string) error {
	var released bool
	err := tx.QueryRowContext(ctx, `SELECT storage_released FROM uploads WHERE id=?`, uploadID).Scan(&released)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := refundUploadTrafficTx(ctx, tx, uploadID, time.Now().Unix()); err != nil {
		return err
	}
	if released {
		return nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE uploads SET storage_released=1 WHERE id=?`, uploadID)
	return err
}

func (store *Store) AllowPersistent(ctx context.Context, key string, limit int, window time.Duration, amount, maxAmount int64) (bool, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	allowed, err := allowBucketTx(ctx, tx, key, limit, window, 1, amount, maxAmount, time.Now())
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return allowed, nil
}

func allowBucketTx(ctx context.Context, tx *sql.Tx, key string, limit int, window time.Duration,
	countIncrement int, amountIncrement, maxAmount int64, now time.Time) (bool, error) {
	seconds := int64(window.Seconds())
	if seconds <= 0 {
		return false, fmt.Errorf("invalid rate window")
	}
	windowStart := now.Unix() / seconds * seconds
	var count int
	var amount int64
	err := tx.QueryRowContext(ctx, `SELECT request_count,amount FROM rate_limits WHERE bucket_key=? AND window_start=?`,
		key, windowStart).Scan(&count, &amount)
	if errors.Is(err, sql.ErrNoRows) {
		count, amount = 0, 0
	} else if err != nil {
		return false, err
	}
	if (limit > 0 && count+countIncrement > limit) || (maxAmount > 0 && amount+amountIncrement > maxAmount) {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO rate_limits(bucket_key,window_start,request_count,amount)
		VALUES(?,?,?,?) ON CONFLICT(bucket_key,window_start) DO UPDATE SET
		request_count=request_count+excluded.request_count,amount=amount+excluded.amount`,
		key, windowStart, countIncrement, amountIncrement); err != nil {
		return false, err
	}
	return true, nil
}

func (store *Store) ensureDownloadReservationStateSchema(ctx context.Context) error {
	value, _ := downloadReservationSchemaStates.LoadOrStore(store.db, &downloadReservationSchemaState{})
	state := value.(*downloadReservationSchemaState)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.ready {
		return nil
	}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS download_reservation_runtime (
			reservation_id TEXT PRIMARY KEY REFERENCES download_reservations(id) ON DELETE CASCADE,
			started_at INTEGER NOT NULL,
			lease_expires_at INTEGER NOT NULL,
			hard_expires_at INTEGER NOT NULL,
			last_progress_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS download_reservation_allocations (
			reservation_id TEXT NOT NULL REFERENCES download_reservations(id) ON DELETE CASCADE,
			ordinal INTEGER NOT NULL,
			source_kind TEXT NOT NULL CHECK(source_kind IN ('free','entitlement')),
			source_id TEXT NOT NULL,
			reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),
			consumed_bytes INTEGER NOT NULL DEFAULT 0 CHECK(consumed_bytes>=0),
			PRIMARY KEY(reservation_id,ordinal)
		)`,
		`CREATE TABLE IF NOT EXISTS download_reservation_state_meta (
			id INTEGER PRIMARY KEY CHECK(id=1),
			version INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_download_reservation_runtime_hard
			ON download_reservation_runtime(hard_expires_at,reservation_id)`,
		`CREATE INDEX IF NOT EXISTS idx_download_reservation_allocations_source
			ON download_reservation_allocations(source_kind,source_id,reservation_id)`,
	} {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("download reservation state schema: %w", err)
		}
	}
	if err := ensureSQLiteColumn(store.db, "download_reservations", "recipient_key",
		"TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("download reservation recipient migration: %w", err)
	}
	if err := ensureSQLiteColumn(store.db, "download_reservations", "monthly_traffic_bytes",
		"INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("download reservation traffic migration: %w", err)
	}
	if err := ensureSQLiteColumn(store.db, "download_reservations", "retrieval_session_id",
		"TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("download reservation retrieval migration: %w", err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_download_reservation_retrieval
		ON download_reservations(retrieval_session_id,upload_id,status)`); err != nil {
		return fmt.Errorf("download reservation retrieval index: %w", err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS
		idx_download_reservation_provisional_recipient
		ON download_reservations(transfer_id,upload_id,recipient_key)
		WHERE status='reserved' AND recipient_key!=''`); err != nil {
		return fmt.Errorf("download reservation idempotency index: %w", err)
	}
	if err := store.upgradeLegacyDownloadReservations(ctx); err != nil {
		return err
	}
	state.ready = true
	return nil
}

func (store *Store) upgradeLegacyDownloadReservations(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	err = tx.QueryRowContext(ctx, `SELECT version FROM download_reservation_state_meta WHERE id=1`).Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read download reservation state version: %w", err)
	}
	if version >= 3 {
		return tx.Commit()
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `UPDATE resource_accounts SET
		traffic_reserved_bytes=MAX(traffic_reserved_bytes-COALESCE((
			SELECT SUM(r.reserved_bytes) FROM download_reservations r
			WHERE r.status IN ('reserved','consuming') AND r.user_id=resource_accounts.user_id
		),0),0),updated_at=?
		WHERE EXISTS(SELECT 1 FROM download_reservations r
			WHERE r.status IN ('reserved','consuming') AND r.user_id=resource_accounts.user_id
			AND r.reserved_bytes>0)`, now); err != nil {
		return fmt.Errorf("release legacy download traffic: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM download_reservation_allocations
		WHERE reservation_id IN (SELECT id FROM download_reservations
		WHERE status IN ('reserved','consuming'))`); err != nil {
		return fmt.Errorf("remove legacy download allocations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE download_reservations SET
		user_id='',reserved_bytes=0 WHERE status IN ('reserved','consuming')`); err != nil {
		return fmt.Errorf("neutralize legacy download reservations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO download_reservation_state_meta(id,version)
		VALUES(1,3) ON CONFLICT(id) DO UPDATE SET version=excluded.version`); err != nil {
		return fmt.Errorf("record download reservation state version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit download reservation state upgrade: %w", err)
	}
	return nil
}

func releaseLegacyDownloadTrafficForReservationTx(ctx context.Context, tx *sql.Tx,
	reservationID string, now int64) error {
	var userID, status string
	var reserved int64
	err := tx.QueryRowContext(ctx, `SELECT user_id,reserved_bytes,status FROM download_reservations
		WHERE id=?`, reservationID).Scan(&userID, &reserved, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil || (userID == "" && reserved == 0) || status == "settled" {
		return err
	}
	if userID != "" && reserved > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE resource_accounts SET
			traffic_reserved_bytes=MAX(traffic_reserved_bytes-?,0),updated_at=? WHERE user_id=?`,
			reserved, now, userID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM download_reservation_allocations
		WHERE reservation_id=?`, reservationID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE download_reservations SET user_id='',reserved_bytes=0 WHERE id=?`,
		reservationID)
	return err
}

func (store *Store) CreateDownloadReservation(ctx context.Context, transfer Transfer, upload Upload,
	_ int64, monthlyTraffic int64, lifetime time.Duration) (DownloadReservation, error) {
	return store.CreateDownloadReservationForRecipient(ctx, transfer, upload, "", monthlyTraffic, lifetime)
}

func (store *Store) CreateDownloadReservationForRecipient(ctx context.Context, transfer Transfer, upload Upload,
	recipientKey string, monthlyTraffic int64, lifetime time.Duration) (DownloadReservation, error) {
	_ = monthlyTraffic
	if err := store.ensureDownloadReservationStateSchema(ctx); err != nil {
		return DownloadReservation{}, err
	}
	if len(recipientKey) > 256 || lifetime <= 0 {
		return DownloadReservation{}, ErrConflict
	}
	reservationID, err := randomToken(18)
	if err != nil {
		return DownloadReservation{}, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return DownloadReservation{}, err
	}
	defer tx.Rollback()
	now := time.Now()
	expiresAt := now.Add(lifetime).Unix()
	if recipientKey != "" {
		// This is deliberately the first statement in the transaction. It obtains
		// SQLite's write lock before the idempotency lookup so concurrent re-signs
		// cannot both observe an empty provisional slot.
		if _, err := tx.ExecContext(ctx, `UPDATE download_reservations SET expires_at=expires_at
			WHERE transfer_id=? AND upload_id=? AND recipient_key=?`, transfer.ID, upload.ID,
			recipientKey); err != nil {
			return DownloadReservation{}, err
		}
		var expiredID string
		err := tx.QueryRowContext(ctx, `SELECT id FROM download_reservations
			WHERE transfer_id=? AND upload_id=? AND recipient_key=? AND status='reserved' AND expires_at<=?`,
			transfer.ID, upload.ID, recipientKey, now.Unix()).Scan(&expiredID)
		if err == nil {
			if err := releaseLegacyDownloadTrafficForReservationTx(ctx, tx, expiredID, now.Unix()); err != nil {
				return DownloadReservation{}, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE download_reservations SET status='released',settled_at=?
				WHERE id=? AND status='reserved'`, now.Unix(), expiredID); err != nil {
				return DownloadReservation{}, err
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return DownloadReservation{}, err
		}
		var existing DownloadReservation
		err = tx.QueryRowContext(ctx, `SELECT id,upload_id,transfer_id,user_id,reserved_bytes,status,expires_at
			FROM download_reservations WHERE transfer_id=? AND upload_id=? AND recipient_key=?
			AND status='reserved'`, transfer.ID, upload.ID, recipientKey).Scan(&existing.ID,
			&existing.UploadID, &existing.TransferID, &existing.UserID, &existing.ReservedBytes,
			&existing.Status, &existing.ExpiresAt)
		if err == nil {
			if err := releaseLegacyDownloadTrafficForReservationTx(ctx, tx, existing.ID, now.Unix()); err != nil {
				return DownloadReservation{}, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE download_reservations SET
				expires_at=?,user_id='',reserved_bytes=0,monthly_traffic_bytes=0
				WHERE id=? AND status='reserved'`, expiresAt, existing.ID); err != nil {
				return DownloadReservation{}, err
			}
			existing.UserID = ""
			existing.ReservedBytes = 0
			existing.ExpiresAt = expiresAt
			if err := tx.Commit(); err != nil {
				return DownloadReservation{}, err
			}
			return existing, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return DownloadReservation{}, err
		}
	}
	reservation := DownloadReservation{ID: reservationID, UploadID: upload.ID, TransferID: transfer.ID,
		ReservedBytes: 0, Status: "reserved", ExpiresAt: expiresAt}
	if _, err := tx.ExecContext(ctx, `INSERT INTO download_reservations
		(id,upload_id,transfer_id,user_id,reserved_bytes,status,created_at,expires_at,recipient_key,
		 monthly_traffic_bytes)
		VALUES(?,?,?,'',0,'reserved',?,?,?,0)`, reservation.ID, upload.ID, transfer.ID,
		now.Unix(), reservation.ExpiresAt, recipientKey); err != nil {
		return DownloadReservation{}, err
	}
	if err := tx.Commit(); err != nil {
		return DownloadReservation{}, err
	}
	return reservation, nil
}

func (store *Store) BeginDownloadReservation(ctx context.Context, id string, now int64) (DownloadReservation, error) {
	return store.beginDownloadReservation(ctx, id, "", now)
}

func (store *Store) BeginDownloadReservationForUpload(ctx context.Context, id, uploadID string, now int64) (DownloadReservation, error) {
	if uploadID == "" {
		return DownloadReservation{}, ErrConflict
	}
	return store.beginDownloadReservation(ctx, id, uploadID, now)
}

func (store *Store) beginDownloadReservation(ctx context.Context, id, expectedUploadID string, now int64) (DownloadReservation, error) {
	if err := store.ensureDownloadReservationStateSchema(ctx); err != nil {
		return DownloadReservation{}, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return DownloadReservation{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE download_reservations SET status='consuming'
		WHERE id=? AND status='reserved' AND expires_at>? AND (?='' OR upload_id=?)`, id, now,
		expectedUploadID, expectedUploadID)
	if err != nil {
		return DownloadReservation{}, err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM download_reservations WHERE id=?`, id).
			Scan(&exists); err != nil {
			return DownloadReservation{}, err
		}
		if exists == 0 {
			return DownloadReservation{}, ErrNotFound
		}
		return DownloadReservation{}, ErrConflict
	}
	if err := releaseLegacyDownloadTrafficForReservationTx(ctx, tx, id, now); err != nil {
		return DownloadReservation{}, err
	}
	var reservation DownloadReservation
	err = tx.QueryRowContext(ctx, `SELECT r.id,r.upload_id,r.transfer_id,r.retrieval_session_id,
		r.user_id,r.reserved_bytes,r.status,r.expires_at FROM download_reservations r WHERE r.id=?`, id).
		Scan(&reservation.ID, &reservation.UploadID, &reservation.TransferID, &reservation.RetrievalSessionID,
			&reservation.UserID, &reservation.ReservedBytes, &reservation.Status, &reservation.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DownloadReservation{}, ErrNotFound
	}
	if err != nil {
		return DownloadReservation{}, err
	}
	if reservation.RetrievalSessionID == "" {
		result, err = tx.ExecContext(ctx, `UPDATE transfers SET downloads=downloads+1
			WHERE id=? AND status='active' AND expires_at>? AND downloads<max_downloads`, reservation.TransferID, now)
		if err != nil {
			return DownloadReservation{}, err
		}
		rows, _ = result.RowsAffected()
		if rows != 1 {
			if _, releaseErr := tx.ExecContext(ctx, `UPDATE download_reservations SET status='released',settled_at=?
				WHERE id=? AND status='consuming'`, now, id); releaseErr != nil {
				return DownloadReservation{}, releaseErr
			}
			if commitErr := tx.Commit(); commitErr != nil {
				return DownloadReservation{}, commitErr
			}
			return DownloadReservation{}, ErrQuotaExceeded
		}
	} else {
		var allowed int
		err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM retrieval_sessions s
			JOIN transfers t ON t.id=s.transfer_id
			WHERE s.id=? AND s.transfer_id=? AND s.status IN ('provisional','active')
			AND s.expires_at>? AND s.hard_expires_at>? AND t.status IN ('active','exhausted')
			AND t.expires_at>?`, reservation.RetrievalSessionID, reservation.TransferID, now, now, now).Scan(&allowed)
		if err != nil {
			return DownloadReservation{}, err
		}
		if allowed != 1 {
			if _, releaseErr := tx.ExecContext(ctx, `UPDATE download_reservations SET status='released',settled_at=?
				WHERE id=? AND status='consuming'`, now, id); releaseErr != nil {
				return DownloadReservation{}, releaseErr
			}
			if commitErr := tx.Commit(); commitErr != nil {
				return DownloadReservation{}, commitErr
			}
			return DownloadReservation{}, ErrQuotaExceeded
		}
		if _, err := tx.ExecContext(ctx, `UPDATE retrieval_sessions SET last_used_at=? WHERE id=?`,
			now, reservation.RetrievalSessionID); err != nil {
			return DownloadReservation{}, err
		}
		if err := activateRetrievalSessionTx(ctx, tx, reservation.RetrievalSessionID, now); err != nil {
			return DownloadReservation{}, err
		}
	}
	reservation.UserID = ""
	reservation.ReservedBytes = 0
	reservation.ExpiresAt = now + int64(downloadReservationMaxDuration/time.Second)
	result, err = tx.ExecContext(ctx, `UPDATE download_reservations SET
		user_id='',reserved_bytes=0,monthly_traffic_bytes=0,expires_at=?
		WHERE id=? AND status='consuming'`, reservation.ExpiresAt, id)
	if err != nil {
		return DownloadReservation{}, err
	}
	rows, _ = result.RowsAffected()
	if rows != 1 {
		return DownloadReservation{}, ErrConflict
	}
	leaseExpiresAt := min(now+int64(downloadReservationLeaseDuration/time.Second), reservation.ExpiresAt)
	if _, err := tx.ExecContext(ctx, `INSERT INTO download_reservation_runtime
		(reservation_id,started_at,lease_expires_at,hard_expires_at,last_progress_at)
		VALUES(?,?,?,?,?) ON CONFLICT(reservation_id) DO UPDATE SET
		started_at=excluded.started_at,lease_expires_at=excluded.lease_expires_at,
		hard_expires_at=excluded.hard_expires_at,last_progress_at=excluded.last_progress_at`,
		id, now, leaseExpiresAt, reservation.ExpiresAt, now); err != nil {
		return DownloadReservation{}, err
	}
	reservation.Status = "consuming"
	if err := tx.Commit(); err != nil {
		return DownloadReservation{}, err
	}
	return reservation, nil
}

func encodeFinalNodeDownloadBytes(expected, actual int64) (int64, error) {
	if expected <= 0 || actual <= 0 || actual >= expected || expected > (math.MaxInt64-1)/2 ||
		actual > math.MaxInt64-expected-1 {
		return 0, ErrConflict
	}
	return expected + 1 + actual, nil
}

func decodeNodeDownloadBytes(expected, reported int64) (actual int64, final bool, err error) {
	if expected <= 0 || reported < 0 {
		return 0, false, ErrConflict
	}
	if reported == 0 || reported == expected {
		return reported, true, nil
	}
	if reported < expected {
		return reported, false, nil
	}
	if expected > (math.MaxInt64-1)/2 || reported <= expected || reported > expected*2 {
		return 0, false, ErrConflict
	}
	actual = reported - expected - 1
	if actual <= 0 || actual >= expected {
		return 0, false, ErrConflict
	}
	return actual, true, nil
}

func (store *Store) SettleDownloadReservation(ctx context.Context, id string, actual, monthlyTraffic int64, now int64) error {
	return store.settleDownloadReservation(ctx, id, actual, monthlyTraffic, now, false)
}

func (store *Store) settleDownloadReservation(ctx context.Context, id string, reported,
	monthlyTraffic int64, now int64, forceFinal bool) error {
	_ = monthlyTraffic
	if err := store.ensureDownloadReservationStateSchema(ctx); err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	locked, err := tx.ExecContext(ctx, `UPDATE download_reservations SET reserved_bytes=reserved_bytes WHERE id=?`, id)
	if err != nil {
		return err
	}
	if affected, _ := locked.RowsAffected(); affected != 1 {
		return ErrNotFound
	}
	var transferID, retrievalSessionID, status, storageKind string
	var settledActual, expected int64
	if err := tx.QueryRowContext(ctx, `SELECT r.transfer_id,r.retrieval_session_id,r.actual_bytes,r.status,u.length,u.storage_kind
		FROM download_reservations r
		JOIN uploads u ON u.id=r.upload_id WHERE r.id=?`, id).
		Scan(&transferID, &retrievalSessionID, &settledActual, &status, &expected, &storageKind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if err := releaseLegacyDownloadTrafficForReservationTx(ctx, tx, id, now); err != nil {
		return err
	}
	actual, final := reported, true
	if !forceFinal && storageKind == StorageKindNode {
		actual, final, err = decodeNodeDownloadBytes(expected, reported)
		if err != nil {
			return err
		}
	}
	if actual < 0 || actual > expected {
		return ErrConflict
	}
	if status == "released" {
		// Late callbacks from a retired/expired pre-v5 reservation remain a
		// successful no-op so storage outboxes can drain during rolling upgrades.
		return tx.Commit()
	}
	if status == "settled" {
		if settledActual != actual {
			return ErrConflict
		}
		return tx.Commit()
	}
	if status != "consuming" {
		final = true
	}
	if status == "consuming" && !final {
		if actual < settledActual {
			return ErrConflict
		}
		var hardExpiresAt int64
		err := tx.QueryRowContext(ctx, `SELECT hard_expires_at FROM download_reservation_runtime
			WHERE reservation_id=?`, id).Scan(&hardExpiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			hardExpiresAt = now + int64(downloadReservationMaxDuration/time.Second)
			leaseExpiresAt := min(now+int64(downloadReservationLeaseDuration/time.Second), hardExpiresAt)
			if _, err := tx.ExecContext(ctx, `INSERT INTO download_reservation_runtime
				(reservation_id,started_at,lease_expires_at,hard_expires_at,last_progress_at)
				VALUES(?,?,?,?,?)`, id, now, leaseExpiresAt, hardExpiresAt, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE download_reservations SET expires_at=? WHERE id=?`,
				hardExpiresAt, id); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if now < hardExpiresAt {
			if actual > 0 && retrievalSessionID != "" {
				if err := touchRetrievalSessionTx(ctx, tx, retrievalSessionID, now); err != nil {
					return err
				}
			}
			leaseExpiresAt := min(now+int64(downloadReservationLeaseDuration/time.Second), hardExpiresAt)
			if _, err := tx.ExecContext(ctx, `UPDATE download_reservations SET actual_bytes=MAX(actual_bytes,?)
				WHERE id=? AND status='consuming'`, actual, id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE download_reservation_runtime SET
				lease_expires_at=?,last_progress_at=? WHERE reservation_id=?`, leaseExpiresAt, now, id); err != nil {
				return err
			}
			return tx.Commit()
		}
		actual = max(actual, settledActual)
		final = true
	}
	if !final {
		return ErrConflict
	}
	if status == "consuming" && actual == 0 && retrievalSessionID == "" {
		if _, err := tx.ExecContext(ctx, `UPDATE transfers SET downloads=MAX(downloads-1,0) WHERE id=?`, transferID); err != nil {
			return err
		}
	}
	if status == "consuming" && actual > 0 && retrievalSessionID != "" {
		if err := touchRetrievalSessionTx(ctx, tx, retrievalSessionID, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE download_reservations SET status='settled',actual_bytes=?,settled_at=? WHERE id=?`,
		actual, now, id); err != nil {
		return err
	}
	if status == "consuming" && actual > 0 {
		if err := closeCompletedRetrievalSessionTx(ctx, tx, retrievalSessionID, transferID, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (store *Store) ReleaseExpiredDownloadReservations(ctx context.Context, monthlyTraffic int64, now int64) error {
	if err := store.ensureDownloadReservationStateSchema(ctx); err != nil {
		return err
	}
	provisionalTx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer provisionalTx.Rollback()
	if _, err := provisionalTx.ExecContext(ctx, `UPDATE resource_accounts SET
		traffic_reserved_bytes=MAX(traffic_reserved_bytes-COALESCE((
			SELECT SUM(r.reserved_bytes) FROM download_reservations r
			WHERE r.status='reserved' AND r.expires_at<=? AND r.user_id=resource_accounts.user_id
		),0),0),updated_at=?
		WHERE EXISTS(SELECT 1 FROM download_reservations r WHERE r.status='reserved'
			AND r.expires_at<=? AND r.user_id=resource_accounts.user_id AND r.reserved_bytes>0)`,
		now, now, now); err != nil {
		_ = provisionalTx.Rollback()
		return err
	}
	if _, err := provisionalTx.ExecContext(ctx, `DELETE FROM download_reservation_allocations
		WHERE reservation_id IN (SELECT id FROM download_reservations
			WHERE status='reserved' AND expires_at<=?)`, now); err != nil {
		_ = provisionalTx.Rollback()
		return err
	}
	if _, err := provisionalTx.ExecContext(ctx, `UPDATE download_reservations SET
		status='released',user_id='',reserved_bytes=0,settled_at=?
		WHERE status='reserved' AND expires_at<=?`,
		now, now); err != nil {
		return err
	}
	if err := provisionalTx.Commit(); err != nil {
		return err
	}
	legacyHardExpiry := now + int64(downloadReservationMaxDuration/time.Second)
	legacyLeaseExpiry := now + int64(downloadReservationLeaseDuration/time.Second)
	if _, err := store.db.ExecContext(ctx, `INSERT OR IGNORE INTO download_reservation_runtime
		(reservation_id,started_at,lease_expires_at,hard_expires_at,last_progress_at)
		SELECT id,?,?,?,? FROM download_reservations WHERE status='consuming'`, now,
		legacyLeaseExpiry, legacyHardExpiry, now); err != nil {
		return err
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE download_reservations SET expires_at=(
		SELECT hard_expires_at FROM download_reservation_runtime runtime WHERE runtime.reservation_id=download_reservations.id)
		WHERE status='consuming' AND EXISTS(SELECT 1 FROM download_reservation_runtime runtime
		WHERE runtime.reservation_id=download_reservations.id)`); err != nil {
		return err
	}
	rows, err := store.db.QueryContext(ctx, `SELECT r.id,r.actual_bytes FROM download_reservations r
		JOIN download_reservation_runtime runtime ON runtime.reservation_id=r.id
		WHERE r.status='consuming' AND runtime.hard_expires_at<=? LIMIT 100`, now)
	if err != nil {
		return err
	}
	type expiredStream struct {
		id     string
		actual int64
	}
	streams := []expiredStream{}
	for rows.Next() {
		var stream expiredStream
		if err := rows.Scan(&stream.id, &stream.actual); err != nil {
			_ = rows.Close()
			return err
		}
		streams = append(streams, stream)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, stream := range streams {
		if err := store.settleDownloadReservation(ctx, stream.id, stream.actual, monthlyTraffic, now, true); err != nil &&
			!errors.Is(err, ErrConflict) {
			return err
		}
	}
	_, _ = store.db.ExecContext(ctx, `DELETE FROM rate_limits WHERE window_start<?`, now-7*24*3600)
	return nil
}

func (store *Store) EntitlementsForUser(ctx context.Context, userID string, now int64) ([]ResourceEntitlement, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id,resource_type,amount_bytes,remaining_bytes,expires_at,
		source_type,source_id,created_at FROM resource_entitlements
		WHERE user_id=? AND expires_at>? ORDER BY expires_at,created_at`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ResourceEntitlement{}
	for rows.Next() {
		var item ResourceEntitlement
		if err := rows.Scan(&item.ID, &item.ResourceType, &item.AmountBytes, &item.RemainingBytes,
			&item.ExpiresAt, &item.SourceType, &item.SourceID, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (store *Store) PointsForUser(ctx context.Context, userID string) ([]PointsEntry, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id,delta,balance_after,reason,created_at
		FROM points_ledger WHERE user_id=? ORDER BY created_at DESC,id DESC LIMIT 100`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []PointsEntry{}
	for rows.Next() {
		var item PointsEntry
		if err := rows.Scan(&item.ID, &item.Delta, &item.BalanceAfter, &item.Reason, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (store *Store) TransfersForOwner(ctx context.Context, ownerID string) ([]Transfer, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id,kind,title,share_token,manage_hash,pickup_code,access_hash,status,
		expires_at,created_at,max_downloads,downloads,total_bytes,file_count,owner_type,owner_id,
		policy_max_file_bytes,policy_max_task_bytes,policy_max_files,download_limit_mode,delete_on_exhaustion FROM transfers
		WHERE owner_type='user' AND owner_id=? ORDER BY created_at DESC LIMIT 100`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	transfers := []Transfer{}
	for rows.Next() {
		var transfer Transfer
		if err := rows.Scan(&transfer.ID, &transfer.Kind, &transfer.Title, &transfer.ShareToken,
			&transfer.ManageHash, &transfer.PickupCode, &transfer.AccessHash, &transfer.Status,
			&transfer.ExpiresAt, &transfer.CreatedAt, &transfer.MaxDownloads, &transfer.Downloads,
			&transfer.TotalBytes, &transfer.FileCount, &transfer.OwnerType, &transfer.OwnerID,
			&transfer.PolicyMaxFileBytes, &transfer.PolicyMaxTaskBytes, &transfer.PolicyMaxFiles,
			&transfer.DownloadLimitMode, &transfer.DeleteOnExhaustion); err != nil {
			return nil, err
		}
		transfer.RequiresCode = transfer.AccessHash != ""
		transfers = append(transfers, transfer)
	}
	return transfers, rows.Err()
}

func (store *Store) ClaimTransfer(ctx context.Context, shareToken, manageToken, userID string,
	baseStorage, monthlyTraffic int64) error {
	_ = baseStorage
	_ = monthlyTraffic
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var transfer Transfer
	err = tx.QueryRowContext(ctx, `SELECT id,manage_hash,owner_type,owner_id FROM transfers WHERE share_token=?`, shareToken).
		Scan(&transfer.ID, &transfer.ManageHash, &transfer.OwnerType, &transfer.OwnerID)
	if errors.Is(err, sql.ErrNoRows) || !secureEqual(tokenHash(manageToken), transfer.ManageHash) {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	if transfer.OwnerType == "user" {
		if transfer.OwnerID == userID {
			return tx.Commit()
		}
		return ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE transfers SET owner_type='user',owner_id=? WHERE id=? AND owner_type!='user'`, userID, transfer.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (store *Store) CreateAbuseReport(ctx context.Context, shareToken, reason, detail, ip string) error {
	id, err := commerceIDGenerator(16)
	if err != nil {
		return err
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO abuse_reports(id,share_token,reason,detail,ip,created_at)
		VALUES(?,?,?,?,?,?)`, id, shareToken, reason, detail, ip, time.Now().Unix())
	return err
}

func (store *Store) AdminOverview(ctx context.Context) (AdminOverview, error) {
	overview := AdminOverview{}
	stats, err := store.Stats(ctx)
	if err != nil {
		return overview, err
	}
	overview.Stats = stats
	queries := []struct {
		target *int64
		query  string
	}{
		{&overview.Users, `SELECT COUNT(*) FROM users`},
		{&overview.PaidOrders, `SELECT COUNT(*) FROM orders WHERE status='paid'`},
		{&overview.OpenReports, `SELECT COUNT(*) FROM abuse_reports WHERE status='open'`},
		{&overview.BlockedUsers, `SELECT COUNT(*) FROM users WHERE status='blocked'`},
	}
	for _, query := range queries {
		if err := store.db.QueryRowContext(ctx, query.query).Scan(query.target); err != nil {
			return overview, err
		}
	}
	rows, err := store.db.QueryContext(ctx, `SELECT id,user_id,action,target_type,target_id,detail,ip,created_at
		FROM audit_logs ORDER BY created_at DESC LIMIT 20`)
	if err != nil {
		return overview, err
	}
	defer rows.Close()
	overview.RecentAudits = []AuditEntry{}
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.ID, &entry.UserID, &entry.Action, &entry.TargetType, &entry.TargetID,
			&entry.Detail, &entry.IP, &entry.CreatedAt); err != nil {
			return overview, err
		}
		overview.RecentAudits = append(overview.RecentAudits, entry)
	}
	return overview, rows.Err()
}

type userStatusQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func validateUserStatusChange(ctx context.Context, queryer userStatusQueryer, actorUserID, userID, status string) error {
	if status != "active" && status != "blocked" {
		return ErrConflict
	}
	if status == "blocked" && actorUserID == userID {
		return ErrConflict
	}
	var role, currentStatus string
	if err := queryer.QueryRowContext(ctx, `SELECT role,status FROM users WHERE id=?`, userID).
		Scan(&role, &currentStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if status == "blocked" && role == "admin" && currentStatus == "active" {
		var activeAdmins int
		if err := queryer.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'`).
			Scan(&activeAdmins); err != nil {
			return err
		}
		if activeAdmins <= 1 {
			return ErrConflict
		}
	}
	return nil
}

func (store *Store) ValidateUserStatusChange(ctx context.Context, actorUserID, userID, status string) error {
	return validateUserStatusChange(ctx, store.db, actorUserID, userID, status)
}

func (store *Store) SetUserStatus(ctx context.Context, actorUserID, userID, status, ip string, now int64) error {
	if err := store.ValidateUserStatusChange(ctx, actorUserID, userID, status); err != nil {
		return err
	}
	auditID, err := auditIDGenerator(16)
	if err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Acquire SQLite's writer lock before re-checking the active-admin invariant.
	// This prevents two concurrent administrators from both observing a stale count.
	result, err := tx.ExecContext(ctx, `UPDATE users SET status=status WHERE id=?`, userID)
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
	if err := validateUserStatusChange(ctx, tx, actorUserID, userID, status); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `UPDATE users SET status=? WHERE id=?`, status, userID)
	if err != nil {
		return err
	}
	rows, err = result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrNotFound
	}
	if status == "blocked" {
		if _, err := tx.ExecContext(ctx, `UPDATE user_sessions SET revoked_at=? WHERE user_id=? AND revoked_at=0`, now, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE verification_codes SET consumed_at=? WHERE user_id=? AND consumed_at=0`, now, userID); err != nil {
			return err
		}
	}
	if err := insertAuditTx(ctx, tx, auditID, actorUserID, "admin.user-status", "user", userID, status, ip, now); err != nil {
		return err
	}
	return tx.Commit()
}
