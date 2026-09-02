package app

import (
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const controlStorageBodyLimit = 32 * 1024

func (server *Server) completeStorageUpload(writer http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if !validStorageObjectID(id) {
		http.NotFound(writer, request)
		return
	}
	var payload StorageUploadCompleteRequest
	if !server.decodeStorageInternalJSON(writer, request, &payload) {
		return
	}
	if payload.NodeID != server.cfg.StorageNodeID ||
		(payload.Status != "ready" && payload.Status != "blocked" && payload.Status != "quarantined") {
		writeAPIError(writer, http.StatusBadRequest, "invalid_storage_result", "存储节点结果无效")
		return
	}
	payload.SHA256 = strings.ToLower(strings.TrimSpace(payload.SHA256))
	if (payload.Status != "quarantined" || payload.SHA256 != "") && !validSHA256(payload.SHA256) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_storage_result", "存储节点摘要无效")
		return
	}
	payload.ScanDetail = cleanText(payload.ScanDetail, 512)
	if err := server.store.CompleteRemoteUpload(request.Context(), id, payload.NodeID, payload.Status,
		payload.SHA256, payload.ScanDetail); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.NotFound(writer, request)
			return
		}
		if errors.Is(err, ErrConflict) {
			writeAPIError(writer, http.StatusConflict, "storage_state_conflict", "上传状态已经变化")
			return
		}
		server.logger.Error("complete remote upload", "upload", id, "error", err)
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法更新上传状态")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) beginStorageDownload(writer http.ResponseWriter, request *http.Request) {
	reservationID := request.PathValue("id")
	if !validStorageObjectID(reservationID) {
		http.NotFound(writer, request)
		return
	}
	var payload StorageDownloadBeginRequest
	if !server.decodeStorageInternalJSON(writer, request, &payload) {
		return
	}
	if payload.NodeID != server.cfg.StorageNodeID || !validStorageObjectID(payload.UploadID) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_storage_request", "下载开始参数无效")
		return
	}
	if _, err := server.store.BeginDownloadReservationForUpload(request.Context(), reservationID,
		payload.UploadID, time.Now().Unix()); err != nil {
		if errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrDownloadLimit) {
			writeDownloadLimitError(writer)
		} else {
			writeAPIError(writer, http.StatusConflict, "download_reservation_unavailable", "下载凭据已使用或失效")
		}
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) settleStorageDownload(writer http.ResponseWriter, request *http.Request) {
	reservationID := request.PathValue("id")
	if !validStorageObjectID(reservationID) {
		http.NotFound(writer, request)
		return
	}
	var payload StorageDownloadSettleRequest
	if !server.decodeStorageInternalJSON(writer, request, &payload) {
		return
	}
	if payload.ActualBytes < 0 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_storage_request", "下载结算参数无效")
		return
	}
	belongs, err := server.store.ReservationUsesRemoteNode(request.Context(), reservationID, server.cfg.StorageNodeID)
	if err != nil || !belongs {
		writeAPIError(writer, http.StatusConflict, "download_reservation_unavailable", "下载凭据不属于此存储节点")
		return
	}
	// v5 keeps this callback for rolling-upgrade compatibility and progress
	// finalization only. Download bytes never consume account traffic.
	if err := server.store.SettleDownloadReservation(request.Context(), reservationID, payload.ActualBytes,
		0, time.Now().Unix()); err != nil {
		server.logger.Error("settle remote download", "reservation", reservationID, "error", err)
		writeAPIError(writer, http.StatusConflict, "download_settlement_failed", "下载结算暂时失败")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) decodeStorageInternalJSON(writer http.ResponseWriter, request *http.Request, target any) bool {
	if request.Header.Get("Content-Type") != "application/json" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "invalid_content_type", "内部请求类型无效")
		return false
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, controlStorageBodyLimit+1))
	if err != nil || len(body) == 0 || len(body) > controlStorageBodyLimit {
		writeAPIError(writer, http.StatusBadRequest, "invalid_storage_request", "内部请求体无效")
		return false
	}
	if err := VerifyInternalRequest(request, body, server.cfg.StorageSharedSecret, server.cfg.StorageNodeID,
		server.storageReplay, time.Now()); err != nil {
		status := http.StatusUnauthorized
		code := "storage_auth_failed"
		if errors.Is(err, ErrStorageInternalReplay) {
			status = http.StatusConflict
			code = "storage_replay"
		}
		writeAPIError(writer, status, code, "存储节点认证失败")
		return false
	}
	if err := decodeStorageProtocolJSON(body, target); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_storage_request", "内部请求参数无效")
		return false
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
