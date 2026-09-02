package app

import (
	"database/sql"
	"fmt"
)

func migrateStore(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin database migration: %w", err)
	}
	defer tx.Rollback()
	columns := []struct {
		table      string
		name       string
		definition string
	}{
		{"transfers", "owner_type", "TEXT NOT NULL DEFAULT 'legacy'"},
		{"transfers", "owner_id", "TEXT NOT NULL DEFAULT ''"},
		{"transfers", "policy_max_file_bytes", "INTEGER NOT NULL DEFAULT 0"},
		{"transfers", "policy_max_task_bytes", "INTEGER NOT NULL DEFAULT 0"},
		{"transfers", "policy_max_files", "INTEGER NOT NULL DEFAULT 0"},
		{"transfers", "download_limit_mode", "TEXT NOT NULL DEFAULT 'legacy_file'"},
		{"transfers", "delete_on_exhaustion", "INTEGER NOT NULL DEFAULT 0"},
		{"uploads", "storage_released", "INTEGER NOT NULL DEFAULT 0"},
		{"uploads", "storage_kind", "TEXT NOT NULL DEFAULT 'local' CHECK(storage_kind IN ('local','node'))"},
		{"uploads", "storage_node_id", "TEXT NOT NULL DEFAULT ''"},
		{"uploads", "storage_key", "TEXT NOT NULL DEFAULT ''"},
		{"uploads", "storage_version", "INTEGER NOT NULL DEFAULT 1 CHECK(storage_version>0)"},
	}
	for _, column := range columns {
		if err := ensureSQLiteColumn(tx, column.table, column.name, column.definition); err != nil {
			return err
		}
	}

	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL COLLATE NOCASE UNIQUE,
			username TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','blocked')),
			role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
			vip_plan TEXT NOT NULL DEFAULT 'none',
			vip_expires_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			verified_at INTEGER NOT NULL DEFAULT 0,
			last_login_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS user_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL UNIQUE,
			csrf_token TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			last_seen_at INTEGER NOT NULL,
			ip_hash TEXT NOT NULL DEFAULT '',
			user_agent_hash TEXT NOT NULL DEFAULT '',
			revoked_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS verification_codes (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			purpose TEXT NOT NULL CHECK(purpose IN ('verify','reset')),
			code_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			consumed_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS guest_sessions (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			last_seen_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS resource_accounts (
			user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			storage_used_bytes INTEGER NOT NULL DEFAULT 0,
			free_traffic_remaining INTEGER NOT NULL DEFAULT 0,
			free_traffic_period TEXT NOT NULL DEFAULT '',
			traffic_reserved_bytes INTEGER NOT NULL DEFAULT 0,
			points_balance INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS resource_entitlements (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			resource_type TEXT NOT NULL CHECK(resource_type IN ('storage','traffic')),
			amount_bytes INTEGER NOT NULL,
			remaining_bytes INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			source_type TEXT NOT NULL,
			source_id TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS daily_checkins (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			checkin_date TEXT NOT NULL CHECK(
				checkin_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
			reward_bytes INTEGER NOT NULL CHECK(reward_bytes BETWEEN 10485760 AND 209715200),
			created_at INTEGER NOT NULL,
			UNIQUE(user_id,checkin_date)
		)`,
		`CREATE TABLE IF NOT EXISTS vip_daily_login_grants (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			grant_date TEXT NOT NULL CHECK(
				grant_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
			vip_plan TEXT NOT NULL CHECK(vip_plan IN ('monthly','yearly','lifetime')),
			reward_bytes INTEGER NOT NULL CHECK(reward_bytes IN (209715200,524288000,1073741824)),
			created_at INTEGER NOT NULL,
			UNIQUE(user_id,grant_date)
		)`,
		`CREATE TABLE IF NOT EXISTS points_ledger (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			delta INTEGER NOT NULL,
			balance_after INTEGER NOT NULL,
			reason TEXT NOT NULL,
			event_key TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS products (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT NOT NULL,
			kind TEXT NOT NULL CHECK(kind IN ('storage','traffic','bundle')),
			storage_bytes INTEGER NOT NULL DEFAULT 0,
			traffic_bytes INTEGER NOT NULL DEFAULT 0,
			valid_days INTEGER NOT NULL,
			vip_plan TEXT NOT NULL DEFAULT '',
			vip_days INTEGER NOT NULL DEFAULT 0,
			price_cents INTEGER NOT NULL,
			points_price INTEGER NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			sort_order INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS orders (
			id TEXT PRIMARY KEY,
			idempotency_key TEXT NOT NULL DEFAULT '',
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
			product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
			product_name TEXT NOT NULL,
			price_cents INTEGER NOT NULL,
			points_price INTEGER NOT NULL,
			payment_method TEXT NOT NULL CHECK(payment_method IN ('sandbox','points','wechat','alipay')),
			status TEXT NOT NULL CHECK(status IN ('pending','paid','closed','refunded')),
			provider_transaction_id TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			paid_at INTEGER NOT NULL DEFAULT 0,
			refunded_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_provider_transaction ON orders(provider_transaction_id) WHERE provider_transaction_id!=''`,
		`CREATE TABLE IF NOT EXISTS payment_events (
			event_id TEXT PRIMARY KEY,
			provider TEXT NOT NULL,
			order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
			payload_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS download_reservations (
			id TEXT PRIMARY KEY,
			upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
			transfer_id TEXT NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
			user_id TEXT NOT NULL DEFAULT '',
			reserved_bytes INTEGER NOT NULL DEFAULT 0,
			actual_bytes INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL CHECK(status IN ('reserved','consuming','settled','released')),
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			settled_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS retrieval_sessions (
			id TEXT PRIMARY KEY,
			transfer_id TEXT NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
			recipient_key TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL CHECK(status IN ('provisional','active','closed','released')),
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			hard_expires_at INTEGER NOT NULL,
			last_used_at INTEGER NOT NULL,
			completed_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS upload_traffic_charges (
			upload_id TEXT PRIMARY KEY REFERENCES uploads(id) ON DELETE CASCADE,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
			amount_bytes INTEGER NOT NULL CHECK(amount_bytes>=0),
			status TEXT NOT NULL CHECK(status IN ('reserved','settled','refunded','grandfathered')),
			created_at INTEGER NOT NULL,
			settled_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS upload_traffic_allocations (
			upload_id TEXT NOT NULL REFERENCES upload_traffic_charges(upload_id) ON DELETE CASCADE,
			ordinal INTEGER NOT NULL CHECK(ordinal>=0),
			source_kind TEXT NOT NULL CHECK(source_kind IN ('free','entitlement')),
			source_id TEXT NOT NULL DEFAULT '',
			amount_bytes INTEGER NOT NULL CHECK(amount_bytes>0),
			PRIMARY KEY(upload_id,ordinal)
		)`,
		`CREATE TABLE IF NOT EXISTS redemption_batches (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL CHECK(kind IN ('traffic','vip')),
			quantity INTEGER NOT NULL CHECK(quantity>0),
			traffic_bytes INTEGER NOT NULL DEFAULT 0 CHECK(traffic_bytes>=0),
			vip_plan TEXT NOT NULL DEFAULT '' CHECK(vip_plan IN ('','monthly','yearly','lifetime')),
			vip_days INTEGER NOT NULL DEFAULT 0 CHECK(vip_days>=0),
			status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
			expires_at INTEGER NOT NULL DEFAULT 0,
			note TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
			created_at INTEGER NOT NULL,
			disabled_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS redemption_codes (
			id TEXT PRIMARY KEY,
			batch_id TEXT NOT NULL REFERENCES redemption_batches(id) ON DELETE RESTRICT,
			code_hash TEXT NOT NULL UNIQUE,
			masked_code TEXT NOT NULL,
			protected_code TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','redeemed','disabled')),
			redeemed_by TEXT REFERENCES users(id) ON DELETE RESTRICT,
			redeemed_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS rate_limits (
			bucket_key TEXT NOT NULL,
			window_start INTEGER NOT NULL,
			request_count INTEGER NOT NULL DEFAULT 0,
			amount INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(bucket_key,window_start)
		)`,
		`CREATE TABLE IF NOT EXISTS verification_delivery_limits (
			subject_key TEXT PRIMARY KEY,
			last_sent_at INTEGER NOT NULL,
			hour_window_start INTEGER NOT NULL,
			hour_count INTEGER NOT NULL,
			day_window_start INTEGER NOT NULL,
			day_count INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL,
			target_type TEXT NOT NULL DEFAULT '',
			target_id TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '',
			ip TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS abuse_reports (
			id TEXT PRIMARY KEY,
			share_token TEXT NOT NULL,
			reason TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			ip TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved','rejected')),
			created_at INTEGER NOT NULL,
			resolved_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS service_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			value_json TEXT NOT NULL,
			revision INTEGER NOT NULL,
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS service_secrets (
			name TEXT PRIMARY KEY,
			ciphertext TEXT NOT NULL,
			protector TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS settings_revisions (
			id TEXT PRIMARY KEY,
			revision INTEGER NOT NULL UNIQUE,
			value_hash TEXT NOT NULL,
			updated_by TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS user_consents (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			document_type TEXT NOT NULL,
			document_version TEXT NOT NULL,
			document_hash TEXT NOT NULL,
			accepted_at INTEGER NOT NULL,
			ip_hash TEXT NOT NULL,
			user_agent_hash TEXT NOT NULL,
			UNIQUE(user_id,document_type,document_version)
		)`,
		`CREATE TABLE IF NOT EXISTS legal_documents (
			version TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			document_hash TEXT NOT NULL UNIQUE,
			effective_at INTEGER NOT NULL,
			published_at INTEGER NOT NULL,
			created_by TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS human_verification_receipts (
			id TEXT PRIMARY KEY,
			provider TEXT NOT NULL,
			action TEXT NOT NULL,
			proof_hash TEXT NOT NULL UNIQUE,
			result TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			ip_hash TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS risk_events (
			id TEXT PRIMARY KEY,
			action TEXT NOT NULL,
			decision TEXT NOT NULL,
			rule_code TEXT NOT NULL,
			subject_hash TEXT NOT NULL DEFAULT '',
			ip_hash TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at INTEGER NOT NULL
		)`,
		"CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_hash,expires_at,revoked_at)",
		"CREATE INDEX IF NOT EXISTS idx_entitlements_user ON resource_entitlements(user_id,resource_type,expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_daily_checkins_user_created ON daily_checkins(user_id,created_at)",
		"CREATE INDEX IF NOT EXISTS idx_vip_daily_login_grants_user_created ON vip_daily_login_grants(user_id,created_at)",
		"CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id,created_at)",
		"CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_users_created ON users(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_reports_status_created ON abuse_reports(status,created_at)",
		"CREATE INDEX IF NOT EXISTS idx_download_reservation_expiry ON download_reservations(status,expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_retrieval_sessions_expiry ON retrieval_sessions(status,expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_retrieval_sessions_transfer ON retrieval_sessions(transfer_id,status,expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_upload_traffic_charges_user_status ON upload_traffic_charges(user_id,status,created_at)",
		"CREATE INDEX IF NOT EXISTS idx_upload_traffic_charges_status ON upload_traffic_charges(status,created_at)",
		"CREATE INDEX IF NOT EXISTS idx_upload_traffic_allocations_source ON upload_traffic_allocations(source_kind,source_id)",
		"CREATE INDEX IF NOT EXISTS idx_redemption_batches_status_expiry ON redemption_batches(status,expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_redemption_batches_created_by ON redemption_batches(created_by,created_at)",
		"CREATE INDEX IF NOT EXISTS idx_redemption_codes_batch_status ON redemption_codes(batch_id,status)",
		"CREATE INDEX IF NOT EXISTS idx_redemption_codes_redeemed_by ON redemption_codes(redeemed_by,redeemed_at) WHERE redeemed_by IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_verification_delivery_day ON verification_delivery_limits(day_window_start)",
		"CREATE INDEX IF NOT EXISTS idx_consents_user ON user_consents(user_id,accepted_at)",
		"CREATE INDEX IF NOT EXISTS idx_human_receipts_expiry ON human_verification_receipts(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_risk_events_action_created ON risk_events(action,created_at)",
		"CREATE INDEX IF NOT EXISTS idx_uploads_storage_placement ON uploads(storage_kind,storage_node_id,storage_key)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_documents_version_hash ON legal_documents(version,document_hash)",
		`CREATE TRIGGER IF NOT EXISTS legal_documents_no_update BEFORE UPDATE ON legal_documents
		BEGIN SELECT RAISE(ABORT,'legal documents are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS legal_documents_no_delete BEFORE DELETE ON legal_documents
		BEGIN SELECT RAISE(ABORT,'legal documents are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS user_consents_no_update BEFORE UPDATE ON user_consents
		BEGIN SELECT RAISE(ABORT,'consent evidence is immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS user_consents_require_document BEFORE INSERT ON user_consents
		WHEN NOT EXISTS (SELECT 1 FROM legal_documents
			WHERE version=NEW.document_version AND document_hash=NEW.document_hash)
		BEGIN SELECT RAISE(ABORT,'consent document is not archived'); END`,
		`CREATE TRIGGER IF NOT EXISTS uploads_import_legacy_node_insert AFTER INSERT ON uploads
		WHEN NEW.storage_kind='local' AND (
			(NEW.temp_path LIKE 'remote:%:' || NEW.id AND length(NEW.temp_path)>length(NEW.id)+8) OR
			(NEW.object_path LIKE 'remote:%:' || NEW.id AND length(NEW.object_path)>length(NEW.id)+8)
		)
		BEGIN
			UPDATE uploads SET storage_kind='node',
				storage_node_id=CASE
					WHEN NEW.temp_path LIKE 'remote:%:' || NEW.id
						THEN substr(NEW.temp_path,8,length(NEW.temp_path)-length(NEW.id)-8)
					ELSE substr(NEW.object_path,8,length(NEW.object_path)-length(NEW.id)-8)
				END,
				storage_key=NEW.id,storage_version=1 WHERE id=NEW.id;
		END`,
		`CREATE TRIGGER IF NOT EXISTS uploads_import_legacy_node_update AFTER UPDATE OF temp_path,object_path ON uploads
		WHEN OLD.storage_kind='local' AND NEW.storage_kind='local' AND (
			(NEW.temp_path LIKE 'remote:%:' || NEW.id AND length(NEW.temp_path)>length(NEW.id)+8) OR
			(NEW.object_path LIKE 'remote:%:' || NEW.id AND length(NEW.object_path)>length(NEW.id)+8)
		)
		BEGIN
			UPDATE uploads SET storage_kind='node',
				storage_node_id=CASE
					WHEN NEW.temp_path LIKE 'remote:%:' || NEW.id
						THEN substr(NEW.temp_path,8,length(NEW.temp_path)-length(NEW.id)-8)
					ELSE substr(NEW.object_path,8,length(NEW.object_path)-length(NEW.id)-8)
				END,
				storage_key=NEW.id,storage_version=OLD.storage_version+1 WHERE id=NEW.id;
		END`,
	}
	// v4 is additive. Ordinary legacy rows become explicit local placements.
	// Builds that briefly used remote:<node>:<upload> pseudo paths are imported
	// into the node placement model once, while retaining the old strings as a
	// downgrade aid. New node uploads never write those pseudo paths.
	for _, statement := range []string{
		`UPDATE uploads SET storage_kind='local',storage_node_id='',storage_key='',storage_version=1
			WHERE storage_kind IS NULL OR storage_kind='' OR storage_kind NOT IN ('local','node')`,
		`UPDATE uploads SET storage_kind='node',
			storage_node_id=CASE
				WHEN temp_path LIKE 'remote:%:' || id AND length(temp_path)>length(id)+8
					THEN substr(temp_path,8,length(temp_path)-length(id)-8)
				ELSE substr(object_path,8,length(object_path)-length(id)-8)
			END,
			storage_key=id,storage_version=CASE
				WHEN status IN ('ready','blocked','quarantined') THEN 2 ELSE 1 END
			WHERE storage_kind='local' AND (
				(temp_path LIKE 'remote:%:' || id AND length(temp_path)>length(id)+8) OR
				(object_path LIKE 'remote:%:' || id AND length(object_path)>length(id)+8)
			)`,
		`UPDATE uploads SET storage_node_id='',storage_key='' WHERE storage_kind='local'`,
		`UPDATE uploads SET storage_version=1 WHERE storage_version IS NULL OR storage_version<1`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("backfill upload storage placement: %w", err)
		}
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("extended database migration: %w", err)
		}
	}
	if err := ensureSQLiteColumn(tx, "redemption_codes", "protected_code", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(tx, "download_reservations", "retrieval_session_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_download_reservation_retrieval
		ON download_reservations(retrieval_session_id,upload_id,status)`); err != nil {
		return fmt.Errorf("create retrieval reservation index: %w", err)
	}
	if _, err := tx.Exec(`WITH ranked AS (
		SELECT id,ROW_NUMBER() OVER (
			PARTITION BY retrieval_session_id,upload_id
			ORDER BY CASE status WHEN 'consuming' THEN 0 ELSE 1 END,created_at,id
		) AS ordinal
		FROM download_reservations
		WHERE retrieval_session_id!='' AND status IN ('reserved','consuming')
	)
	UPDATE download_reservations SET status='released',settled_at=strftime('%s','now')
	WHERE id IN (SELECT id FROM ranked WHERE ordinal>1)`); err != nil {
		return fmt.Errorf("deduplicate live retrieval reservations: %w", err)
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_download_reservation_retrieval_live
		ON download_reservations(retrieval_session_id,upload_id)
		WHERE retrieval_session_id!='' AND status IN ('reserved','consuming')`); err != nil {
		return fmt.Errorf("create live retrieval reservation index: %w", err)
	}
	if _, err := tx.Exec(`UPDATE transfers SET download_limit_mode='retrieval_session_v1',
		delete_on_exhaustion=1 WHERE kind='send' AND (
		status='exhausted' OR EXISTS(SELECT 1 FROM retrieval_sessions s WHERE s.transfer_id=transfers.id)
	)`); err != nil {
		return fmt.Errorf("retain v9 retrieval transfer mode: %w", err)
	}
	if err := ensureSQLiteColumn(tx, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(tx, "users", "username", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(tx, "users", "vip_plan", "TEXT NOT NULL DEFAULT 'none'"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(tx, "users", "vip_expires_at", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(tx, "products", "vip_plan", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(tx, "products", "vip_days", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(tx, "orders", "idempotency_key", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE users SET username=substr(email,1,1) WHERE username=''`); err != nil {
		return fmt.Errorf("backfill user names: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_users_vip_plan_expiry
		ON users(vip_plan,vip_expires_at)`); err != nil {
		return fmt.Errorf("create user vip index: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_products_active_kind_vip
		ON products(active,kind,vip_plan,sort_order)`); err != nil {
		return fmt.Errorf("create product vip index: %w", err)
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_user_idempotency
		ON orders(user_id,idempotency_key) WHERE idempotency_key!=''`); err != nil {
		return fmt.Errorf("create order idempotency index: %w", err)
	}

	products := []struct {
		id, name, description, kind, vipPlan string
		storage, traffic                     int64
		days, vipDays, price, points, order  int
	}{
		{"storage-5", "临时空间 5 GB", "增加 5 GB 临时存储空间，30 天有效", "storage", "", 5 * 1024 * 1024 * 1024, 0, 30, 0, 500, 500, 10},
		{"traffic-2", "上传流量 2 GiB", "增加 2 GiB 永久上传流量", "traffic", "", 0, 2 * 1024 * 1024 * 1024, 0, 0, 100, 100, 15},
		{"traffic-10", "上传流量 10 GB", "增加 10 GB 永久上传流量", "traffic", "", 0, 10 * 1024 * 1024 * 1024, 0, 0, 300, 300, 20},
		{"bundle-20", "轻享组合包", "20 GB 临时空间与 50 GB 下载流量，30 天有效", "bundle", "", 20 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024, 30, 0, 1800, 1800, 30},
		{"traffic-50", "上传流量 50 GB", "增加 50 GB 永久上传流量", "traffic", "", 0, 50 * 1024 * 1024 * 1024, 0, 0, 1200, 1200, 30},
		{"traffic-200", "上传流量 200 GB", "增加 200 GB 永久上传流量", "traffic", "", 0, 200 * 1024 * 1024 * 1024, 0, 0, 3600, 3600, 40},
		{"vip-monthly", "VIP 月卡", "会员期内每天首次登录赠送 200 MiB 永久上传流量", "bundle", VIPPlanMonthly, 0, 0, 30, 30, 590, 590, 110},
		{"vip-yearly", "VIP 年卡", "会员期内每天首次登录赠送 500 MiB 永久上传流量", "bundle", VIPPlanYearly, 0, 0, 365, 365, 5900, 5900, 120},
		{"vip-lifetime", "VIP 终身卡", "每天首次登录赠送 1 GiB 永久上传流量", "bundle", VIPPlanLifetime, 0, 0, 0, 0, 9900, 9900, 130},
	}
	for _, product := range products {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO products
			(id,name,description,kind,storage_bytes,traffic_bytes,valid_days,vip_plan,vip_days,
			price_cents,points_price,active,sort_order)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?)`, product.id, product.name, product.description, product.kind,
			product.storage, product.traffic, product.days, product.vipPlan, product.vipDays, product.price,
			product.points, product.order); err != nil {
			return fmt.Errorf("seed products: %w", err)
		}
	}
	for _, statement := range []string{
		`UPDATE products SET active=0 WHERE id IN ('storage-5','bundle-20')`,
		`UPDATE products SET name='上传流量 2 GiB',description='增加 2 GiB 永久上传流量',
			kind='traffic',storage_bytes=0,traffic_bytes=2147483648,valid_days=0,vip_plan='',vip_days=0,
			price_cents=100,points_price=100,active=1,sort_order=15 WHERE id='traffic-2'`,
		`UPDATE products SET name='上传流量 10 GB',description='增加 10 GB 永久上传流量',
			kind='traffic',storage_bytes=0,traffic_bytes=10737418240,valid_days=0,vip_plan='',vip_days=0
			WHERE id='traffic-10'`,
		`UPDATE products SET description='增加 50 GB 永久上传流量',valid_days=0 WHERE id='traffic-50'`,
		`UPDATE products SET description='增加 200 GB 永久上传流量',valid_days=0 WHERE id='traffic-200'`,
		`UPDATE products SET description='会员期内每天首次登录赠送 200 MiB 永久上传流量'
			WHERE id='vip-monthly'`,
		`UPDATE products SET description='会员期内每天首次登录赠送 500 MiB 永久上传流量'
			WHERE id='vip-yearly'`,
		`UPDATE products SET description='每天首次登录赠送 1 GiB 永久上传流量'
			WHERE id='vip-lifetime'`,
		`UPDATE resource_entitlements SET expires_at=253402300799
			WHERE resource_type='traffic' AND expires_at!=253402300799`,
		`UPDATE upload_traffic_allocations SET source_id='permanent' WHERE source_kind='free'`,
		`UPDATE resource_accounts SET free_traffic_period='permanent'
			WHERE free_traffic_period!='' AND free_traffic_period!='permanent'`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("activate v7 permanent traffic balances: %w", err)
		}
	}
	for _, statement := range []string{
		`DELETE FROM service_secrets WHERE name IN ('wechat_api_v3_key','alipay_private_key')`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(2,'admin-settings-legal-human-risk',strftime('%s','now'))`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(3,'immutable-legal-documents',strftime('%s','now'))`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(4,'explicit-upload-storage-placement',strftime('%s','now'))`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(5,'upload-traffic-vip-redemption',strftime('%s','now'))`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(6,'permanent-upload-traffic',strftime('%s','now'))`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(7,'permanent-base-upload-traffic',strftime('%s','now'))`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(8,'daily-welfare-checkin',strftime('%s','now'))`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(9,'retrieval-session-download-limits',strftime('%s','now'))`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(10,'safe-retrieval-lifecycle',strftime('%s','now'))`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(11,'vip-daily-login-traffic',strftime('%s','now'))`,
		`INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(12,'admin-redemption-user-operations',strftime('%s','now'))`,
		"PRAGMA user_version=12",
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("record database migration: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database migration: %w", err)
	}
	if _, err := db.Exec("PRAGMA optimize"); err != nil {
		return fmt.Errorf("optimize database: %w", err)
	}
	return nil
}

type sqliteSchemaConnection interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
}

func ensureSQLiteColumn(connection sqliteSchemaConnection, table, column, definition string) error {
	rows, err := connection.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("inspect %s columns: %w", table, err)
	}
	found := false
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		if name == column {
			found = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	if found {
		return nil
	}
	if _, err := connection.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}
