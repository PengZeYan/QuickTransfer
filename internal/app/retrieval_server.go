package app

import (
	"context"
	"net/http"
	"time"
)

const retrievalTokenHeader = "X-Retrieval-Token"

func writeDownloadLimitError(writer http.ResponseWriter) {
	writeAPIError(writer, http.StatusGone, "download_limit", "下载次数已用完，文件将自动删除")
}

func (server *Server) validRetrievalSession(ctx context.Context, token, transferID string) (RetrievalSession, bool) {
	if token == "" {
		return RetrievalSession{}, false
	}
	id, err := verifyTicket(server.cfg.Secret, token, "retrieval")
	if err != nil {
		return RetrievalSession{}, false
	}
	session, err := server.store.ValidRetrievalSession(ctx, id, transferID, time.Now().Unix())
	return session, err == nil
}

func (server *Server) signRetrievalSession(session RetrievalSession) (string, error) {
	remaining := time.Until(time.Unix(session.HardExpiresAt, 0))
	if remaining <= 0 {
		return "", ErrConflict
	}
	return signTicket(server.cfg.Secret, "retrieval", session.ID, remaining)
}

func activeOrExhaustedTransfer(transfer Transfer, sessionValid bool, now int64) error {
	if transfer.ExpiresAt <= now || (transfer.Status != TransferStatusActive && transfer.Status != TransferStatusExhausted) {
		return ErrNotFound
	}
	if transfer.Status == TransferStatusExhausted && !sessionValid {
		return ErrDownloadLimit
	}
	return nil
}
