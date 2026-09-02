package app

import (
	"context"
	"net/http"
	"time"
)

func (store *Store) ChangeUserPassword(ctx context.Context, userID, passwordHash, sessionTokenHash, csrfToken,
	ipHash, userAgentHash, auditIP string, now, expiresAt int64,
) error {
	sessionID, err := sessionIDGenerator(16)
	if err != nil {
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
	result, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=?,must_change_password=0 WHERE id=? AND status='active'`,
		passwordHash, userID)
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
	if _, err := tx.ExecContext(ctx, `UPDATE user_sessions SET revoked_at=? WHERE user_id=? AND revoked_at=0`,
		now, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_sessions
		(id,user_id,token_hash,csrf_token,created_at,expires_at,last_seen_at,ip_hash,user_agent_hash)
		VALUES(?,?,?,?,?,?,?,?,?)`, sessionID, userID, sessionTokenHash, csrfToken, now, expiresAt, now,
		ipHash, userAgentHash); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE verification_codes SET consumed_at=? WHERE user_id=? AND consumed_at=0`,
		now, userID); err != nil {
		return err
	}
	if err := insertAuditTx(ctx, tx, auditID, userID, "user.password_change", "user", userID, "", auditIP, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (server *Server) changePassword(writer http.ResponseWriter, request *http.Request) {
	user, _, _, ok := server.requireUser(writer, request, true)
	if !ok {
		return
	}
	if !server.allowPersistent(request, "password-change:"+user.ID, 5, time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "密码修改过于频繁")
		return
	}
	var payload struct {
		CurrentPassword string     `json:"currentPassword"`
		NewPassword     string     `json:"newPassword"`
		HumanProof      HumanProof `json:"humanProof"`
	}
	if decodeJSON(request, &payload, 16*1024) != nil || len(payload.NewPassword) < 12 || len(payload.NewPassword) > 128 ||
		payload.NewPassword == payload.CurrentPassword {
		writeAPIError(writer, http.StatusBadRequest, "password_invalid", "新密码至少 12 位，且不能与当前密码相同")
		return
	}
	valid, err := server.verifyCredential(request, user.PasswordHash, payload.CurrentPassword)
	if err != nil || !valid {
		writeAPIError(writer, http.StatusForbidden, "current_password_invalid", "当前密码不正确")
		return
	}
	passwordHash, err := server.hashCredential(request, payload.NewPassword)
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "authentication_busy", "密码服务繁忙，请稍后再试")
		return
	}
	session, err := newSessionCredentials()
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "password_change_failed", "暂时无法修改密码")
		return
	}
	now := time.Now()
	if err := server.store.ChangeUserPassword(request.Context(), user.ID, passwordHash, tokenHash(session.token), session.csrf,
		tokenHash(server.clientIP(request)), tokenHash(request.UserAgent()),
		privateRateKey(server.cfg.Secret, server.clientIP(request)), now.Unix(),
		now.Add(server.cfg.SessionLifetime).Unix()); err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "password_change_failed", "暂时无法修改密码")
		return
	}
	server.setSessionCookie(writer, session.token)
	writeJSON(writer, http.StatusOK, map[string]any{
		"changed": true, "otherSessionsRevoked": true, "csrfToken": session.csrf,
	})
}
