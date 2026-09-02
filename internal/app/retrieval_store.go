package app

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	RetrievalSessionStatusProvisional = "provisional"
	RetrievalSessionStatusActive      = "active"
	RetrievalSessionStatusClosed      = "closed"
	RetrievalSessionStatusReleased    = "released"

	retrievalSessionProvisionalLifetime = 5 * time.Minute
	retrievalSessionLifetime            = 30 * time.Minute
)

func scanRetrievalSession(scanner interface{ Scan(...any) error }) (RetrievalSession, error) {
	var session RetrievalSession
	err := scanner.Scan(&session.ID, &session.TransferID, &session.RecipientKey, &session.Status,
		&session.CreatedAt, &session.ExpiresAt, &session.HardExpiresAt, &session.LastUsedAt,
		&session.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RetrievalSession{}, ErrNotFound
	}
	return session, err
}

func (store *Store) RetrievalSessionByID(ctx context.Context, id string) (RetrievalSession, error) {
	return scanRetrievalSession(store.db.QueryRowContext(ctx, `SELECT id,transfer_id,recipient_key,status,
		created_at,expires_at,hard_expires_at,last_used_at,completed_at
		FROM retrieval_sessions WHERE id=?`, id))
}

func (store *Store) ValidRetrievalSession(ctx context.Context, id, transferID string, now int64) (RetrievalSession, error) {
	return scanRetrievalSession(store.db.QueryRowContext(ctx, `SELECT id,transfer_id,recipient_key,status,
		created_at,expires_at,hard_expires_at,last_used_at,completed_at
		FROM retrieval_sessions WHERE id=? AND transfer_id=?
		AND status IN ('provisional','active') AND expires_at>? AND hard_expires_at>?`,
		id, transferID, now, now))
}

func (store *Store) CreateRetrievalDownloadReservation(ctx context.Context, transfer Transfer, upload Upload,
	recipientKey, retrievalSessionID string, reservationLifetime time.Duration) (DownloadReservation,
	RetrievalSession, bool, error) {
	if len(recipientKey) > 256 || reservationLifetime <= 0 {
		return DownloadReservation{}, RetrievalSession{}, false, ErrConflict
	}
	if err := store.ensureDownloadReservationStateSchema(ctx); err != nil {
		return DownloadReservation{}, RetrievalSession{}, false, err
	}
	reservationID, err := randomToken(18)
	if err != nil {
		return DownloadReservation{}, RetrievalSession{}, false, err
	}
	newSessionID := retrievalSessionID
	if newSessionID == "" {
		newSessionID, err = randomToken(18)
		if err != nil {
			return DownloadReservation{}, RetrievalSession{}, false, err
		}
	}
	now := time.Now()
	nowUnix := now.Unix()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return DownloadReservation{}, RetrievalSession{}, false, err
	}
	defer tx.Rollback()
	// Obtain SQLite's write lock before reading transfer/session state. This keeps
	// the final available retrieval slot atomic across concurrent ticket requests.
	if _, err := tx.ExecContext(ctx, `UPDATE transfers SET downloads=downloads WHERE id=?`, transfer.ID); err != nil {
		return DownloadReservation{}, RetrievalSession{}, false, err
	}
	var currentStatus, currentMode string
	var currentExpires int64
	var deleteOnExhaustion bool
	if err := tx.QueryRowContext(ctx, `SELECT status,expires_at,download_limit_mode,delete_on_exhaustion
		FROM transfers WHERE id=?`, transfer.ID).
		Scan(&currentStatus, &currentExpires, &currentMode, &deleteOnExhaustion); errors.Is(err, sql.ErrNoRows) {
		return DownloadReservation{}, RetrievalSession{}, false, ErrNotFound
	} else if err != nil {
		return DownloadReservation{}, RetrievalSession{}, false, err
	}
	if currentExpires <= nowUnix || (currentStatus != TransferStatusActive && currentStatus != TransferStatusExhausted) {
		return DownloadReservation{}, RetrievalSession{}, false, ErrNotFound
	}
	if currentMode != DownloadLimitModeRetrievalSessionV1 || !deleteOnExhaustion {
		return DownloadReservation{}, RetrievalSession{}, false, ErrConflict
	}
	var session RetrievalSession
	createdSession := false
	if retrievalSessionID == "" && recipientKey != "" {
		session, err = scanRetrievalSession(tx.QueryRowContext(ctx, `SELECT id,transfer_id,recipient_key,status,
			created_at,expires_at,hard_expires_at,last_used_at,completed_at
			FROM retrieval_sessions WHERE transfer_id=? AND recipient_key=? AND status='provisional'
			AND expires_at>? AND hard_expires_at>? ORDER BY created_at DESC LIMIT 1`,
			transfer.ID, recipientKey, nowUnix, nowUnix))
		if err == nil {
			retrievalSessionID = session.ID
		} else if !errors.Is(err, ErrNotFound) {
			return DownloadReservation{}, RetrievalSession{}, false, err
		}
	}
	createdSession = retrievalSessionID == ""
	if createdSession {
		result, err := tx.ExecContext(ctx, `UPDATE transfers SET
			downloads=downloads+1,
			status=CASE WHEN downloads+1>=max_downloads THEN 'exhausted' ELSE status END
			WHERE id=? AND status='active' AND expires_at>? AND downloads<max_downloads`,
			transfer.ID, nowUnix)
		if err != nil {
			return DownloadReservation{}, RetrievalSession{}, false, err
		}
		rows, _ := result.RowsAffected()
		if rows != 1 {
			return DownloadReservation{}, RetrievalSession{}, false, ErrDownloadLimit
		}
		session = RetrievalSession{
			ID: newSessionID, TransferID: transfer.ID, RecipientKey: recipientKey,
			Status: RetrievalSessionStatusProvisional, CreatedAt: nowUnix,
			ExpiresAt:     now.Add(retrievalSessionProvisionalLifetime).Unix(),
			HardExpiresAt: now.Add(retrievalSessionLifetime).Unix(), LastUsedAt: nowUnix,
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO retrieval_sessions
			(id,transfer_id,recipient_key,status,created_at,expires_at,hard_expires_at,last_used_at)
			VALUES(?,?,?,?,?,?,?,?)`, session.ID, session.TransferID, session.RecipientKey, session.Status,
			session.CreatedAt, session.ExpiresAt, session.HardExpiresAt, session.LastUsedAt); err != nil {
			return DownloadReservation{}, RetrievalSession{}, false, err
		}
	} else {
		if session.ID == "" {
			session, err = scanRetrievalSession(tx.QueryRowContext(ctx, `SELECT id,transfer_id,recipient_key,status,
				created_at,expires_at,hard_expires_at,last_used_at,completed_at
				FROM retrieval_sessions WHERE id=? AND transfer_id=?
				AND status IN ('provisional','active') AND expires_at>? AND hard_expires_at>?`,
				retrievalSessionID, transfer.ID, nowUnix, nowUnix))
			if err != nil {
				return DownloadReservation{}, RetrievalSession{}, false, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE retrieval_sessions SET last_used_at=? WHERE id=?`,
			nowUnix, session.ID); err != nil {
			return DownloadReservation{}, RetrievalSession{}, false, err
		}
		session.LastUsedAt = nowUnix
	}
	var ready int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM uploads
		WHERE id=? AND transfer_id=? AND status='ready'`, upload.ID, transfer.ID).Scan(&ready); err != nil {
		return DownloadReservation{}, RetrievalSession{}, false, err
	}
	if ready != 1 {
		return DownloadReservation{}, RetrievalSession{}, false, ErrNotFound
	}
	reservationExpiresAt := min(now.Add(reservationLifetime).Unix(), session.ExpiresAt)
	var existing DownloadReservation
	err = tx.QueryRowContext(ctx, `SELECT id,upload_id,transfer_id,retrieval_session_id,user_id,
		reserved_bytes,status,expires_at FROM download_reservations
		WHERE retrieval_session_id=? AND upload_id=?
		AND ((status='reserved' AND expires_at>?) OR status='consuming')
		ORDER BY CASE status WHEN 'consuming' THEN 0 ELSE 1 END LIMIT 1`,
		session.ID, upload.ID, nowUnix).Scan(&existing.ID, &existing.UploadID, &existing.TransferID,
		&existing.RetrievalSessionID, &existing.UserID, &existing.ReservedBytes, &existing.Status,
		&existing.ExpiresAt)
	if err == nil {
		if existing.Status == "consuming" {
			return DownloadReservation{}, RetrievalSession{}, false, ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE download_reservations SET expires_at=? WHERE id=?`,
			reservationExpiresAt, existing.ID); err != nil {
			return DownloadReservation{}, RetrievalSession{}, false, err
		}
		existing.ExpiresAt = reservationExpiresAt
		if err := tx.Commit(); err != nil {
			return DownloadReservation{}, RetrievalSession{}, false, err
		}
		return existing, session, createdSession, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DownloadReservation{}, RetrievalSession{}, false, err
	}
	reservation := DownloadReservation{
		ID: reservationID, UploadID: upload.ID, TransferID: transfer.ID,
		RetrievalSessionID: session.ID, Status: "reserved", ExpiresAt: reservationExpiresAt,
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO download_reservations
		(id,upload_id,transfer_id,retrieval_session_id,user_id,reserved_bytes,status,created_at,
		 expires_at,recipient_key,monthly_traffic_bytes)
		VALUES(?,?,?,?,'',0,'reserved',?,?,'',0)`, reservation.ID, reservation.UploadID,
		reservation.TransferID, reservation.RetrievalSessionID, nowUnix, reservation.ExpiresAt); err != nil {
		return DownloadReservation{}, RetrievalSession{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return DownloadReservation{}, RetrievalSession{}, false, err
	}
	return reservation, session, createdSession, nil
}

func activateRetrievalSessionTx(ctx context.Context, tx *sql.Tx, sessionID string, now int64) error {
	if sessionID == "" {
		return nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE retrieval_sessions SET
		status='active',expires_at=hard_expires_at,last_used_at=?
		WHERE id=? AND status IN ('provisional','active') AND hard_expires_at>?`, now, sessionID, now)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func touchRetrievalSessionTx(ctx context.Context, tx *sql.Tx, sessionID string, now int64) error {
	if sessionID == "" {
		return nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE retrieval_sessions SET last_used_at=?
		WHERE id=? AND status='active'`, now, sessionID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func (store *Store) AbortRetrievalDownloadReservation(ctx context.Context, reservationID string,
	releaseSession bool, now int64) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sessionID, transferID, status string
	if err := tx.QueryRowContext(ctx, `SELECT retrieval_session_id,transfer_id,status
		FROM download_reservations WHERE id=?`, reservationID).Scan(&sessionID, &transferID, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if status == "reserved" {
		if _, err := tx.ExecContext(ctx, `UPDATE download_reservations SET status='released',settled_at=?
			WHERE id=? AND status='reserved'`, now, reservationID); err != nil {
			return err
		}
	}
	if releaseSession && sessionID != "" {
		result, err := tx.ExecContext(ctx, `UPDATE retrieval_sessions SET status='released',expires_at=?,
			last_used_at=?,completed_at=? WHERE id=? AND status='provisional'
			AND NOT EXISTS(SELECT 1 FROM download_reservations r
				WHERE r.retrieval_session_id=retrieval_sessions.id AND r.status='consuming')`,
			now, now, now, sessionID)
		if err != nil {
			return err
		}
		affected, _ := result.RowsAffected()
		if affected == 1 {
			if _, err := tx.ExecContext(ctx, `UPDATE transfers SET downloads=MAX(downloads-1,0),
				status=CASE WHEN status='exhausted' AND expires_at>? THEN 'active' ELSE status END
				WHERE id=?`, now, transferID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func closeCompletedRetrievalSessionTx(ctx context.Context, tx *sql.Tx, sessionID, transferID string, now int64) error {
	if sessionID == "" {
		return nil
	}
	var readyFiles, completedFiles int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM uploads WHERE transfer_id=? AND status='ready'`,
		transferID).Scan(&readyFiles); err != nil {
		return err
	}
	if readyFiles == 0 {
		return nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT r.upload_id)
		FROM download_reservations r JOIN uploads u ON u.id=r.upload_id
		WHERE r.retrieval_session_id=? AND r.status='settled' AND r.actual_bytes>=u.length`,
		sessionID).Scan(&completedFiles); err != nil {
		return err
	}
	if completedFiles < readyFiles {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE retrieval_sessions SET status='closed',expires_at=?,
		last_used_at=?,completed_at=? WHERE id=? AND status='active'
		AND NOT EXISTS(SELECT 1 FROM download_reservations r
			WHERE r.retrieval_session_id=retrieval_sessions.id AND r.status='consuming')`,
		now, now, now, sessionID)
	return err
}

func (store *Store) ReleaseExpiredRetrievalSessions(ctx context.Context, now int64) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE retrieval_sessions SET last_used_at=last_used_at
		WHERE status IN ('provisional','active') AND expires_at<=?`, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE download_reservations SET status='released',settled_at=?
		WHERE status='reserved' AND retrieval_session_id IN (
			SELECT id FROM retrieval_sessions WHERE status='provisional' AND expires_at<=?
		)`, now, now); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,transfer_id FROM retrieval_sessions s
		WHERE s.status='provisional' AND s.expires_at<=?
		AND NOT EXISTS(SELECT 1 FROM download_reservations r
			WHERE r.retrieval_session_id=s.id AND r.status='consuming')`, now)
	if err != nil {
		return err
	}
	type expiredSession struct{ id, transferID string }
	expired := []expiredSession{}
	for rows.Next() {
		var item expiredSession
		if err := rows.Scan(&item.id, &item.transferID); err != nil {
			_ = rows.Close()
			return err
		}
		expired = append(expired, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range expired {
		result, err := tx.ExecContext(ctx, `UPDATE retrieval_sessions SET status='released',
			expires_at=?,last_used_at=?,completed_at=? WHERE id=? AND status='provisional'`,
			now, now, now, item.id)
		if err != nil {
			return err
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE transfers SET downloads=MAX(downloads-1,0),
			status=CASE WHEN status='exhausted' AND expires_at>? THEN 'active' ELSE status END
			WHERE id=?`, now, item.transferID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE retrieval_sessions SET status='closed',completed_at=?,
		last_used_at=? WHERE status='active' AND expires_at<=?
		AND NOT EXISTS(SELECT 1 FROM download_reservations r
			WHERE r.retrieval_session_id=retrieval_sessions.id AND r.status='consuming')`, now, now, now); err != nil {
		return err
	}
	return tx.Commit()
}
