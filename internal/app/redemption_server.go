package app

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (server *Server) redeemCode(writer http.ResponseWriter, request *http.Request) {
	user, _, _, ok := server.requireUser(writer, request, true)
	if !ok {
		return
	}
	if !server.allowRedemptionAttempt(request, user.ID) {
		writer.Header().Set("Retry-After", "600")
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "兑换尝试过于频繁，请稍后重试")
		return
	}
	var payload struct {
		Code       string     `json:"code"`
		HumanProof HumanProof `json:"humanProof"`
	}
	if decodeJSON(request, &payload, 8192) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "兑换参数无效")
		return
	}

	// A completed redemption is checked before consuming another one-time
	// human-verification receipt. This makes a transport retry by the same user
	// idempotent without weakening the verification required for a new claim.
	_, normalizeErr := normalizeRedemptionCode(payload.Code)
	if normalizeErr == nil {
		result, redeemed, err := server.store.RedeemedRedemptionForUser(request.Context(), user.ID, payload.Code)
		if err != nil {
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "兑换状态暂时无法确认")
			return
		}
		if redeemed {
			writeJSON(writer, http.StatusOK, map[string]any{"redemption": result, "idempotent": true})
			return
		}
	}
	if !server.requireHumanVerification(writer, request, "redeem", payload.HumanProof) {
		return
	}
	if normalizeErr != nil {
		_ = server.store.AddRiskEvent(request.Context(), "redeem", "rejected", "invalid_code_format", "",
			privateRateKey(server.cfg.Secret, server.clientIP(request)), "")
		writeAPIError(writer, http.StatusBadRequest, "redemption_unavailable", "兑换码无效、已使用或已失效")
		return
	}
	result, err := server.store.RedeemRedemptionCode(request.Context(), user.ID, payload.Code,
		server.clientIP(request), time.Now().Unix())
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidRedemption), errors.Is(err, ErrRedemptionUnavailable),
			errors.Is(err, ErrConflict), errors.Is(err, ErrNotFound):
			_ = server.store.AddRiskEvent(request.Context(), "redeem", "rejected", "code_unavailable", "",
				privateRateKey(server.cfg.Secret, server.clientIP(request)), "")
			writeAPIError(writer, http.StatusConflict, "redemption_unavailable", "兑换码无效、已使用或已失效")
		default:
			server.logger.Error("redeem code", "user", user.ID, "error", err)
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "兑换暂时无法完成")
		}
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"redemption": result, "idempotent": false})
}

func (server *Server) allowRedemptionAttempt(request *http.Request, userID string) bool {
	userKey := privateRateKey(server.cfg.Secret, userID)
	ipKey := privateRateKey(server.cfg.Secret, server.clientIP(request))
	limits := []struct {
		key    string
		limit  int
		window time.Duration
	}{
		{"redeem:user:short:" + userKey, 20, 15 * time.Minute},
		{"redeem:user:day:" + userKey, 100, 24 * time.Hour},
		{"redeem:ip:short:" + ipKey, 60, 15 * time.Minute},
		{"redeem:ip:day:" + ipKey, 300, 24 * time.Hour},
	}
	for _, limit := range limits {
		if !server.allowPersistent(request, limit.key, limit.limit, limit.window) {
			return false
		}
	}
	return true
}

func (server *Server) adminListRedemptionBatches(writer http.ResponseWriter, request *http.Request) {
	admin, ok := server.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	adminKey := privateRateKey(server.cfg.Secret, admin.ID)
	if !server.allowPersistent(request, "admin:redemption-list:"+adminKey, 120, time.Minute) {
		writer.Header().Set("Retry-After", "60")
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "查询过于频繁")
		return
	}
	limit := 100
	if value := strings.TrimSpace(request.URL.Query().Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 200 {
			writeAPIError(writer, http.StatusBadRequest, "invalid_request", "查询数量无效")
			return
		}
		limit = parsed
	}
	batches, err := server.store.ListRedemptionBatches(request.Context(), limit)
	if err != nil {
		server.logger.Error("list redemption batches", "user", admin.ID, "error", err)
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取兑换码批次")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"batches": batches})
}

func (server *Server) adminCreateRedemptionBatch(writer http.ResponseWriter, request *http.Request) {
	admin, ok := server.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	var payload struct {
		Kind         string `json:"kind"`
		Type         string `json:"type"`
		Count        int    `json:"count"`
		Quantity     int    `json:"quantity"`
		TrafficBytes int64  `json:"trafficBytes"`
		VIPPlan      string `json:"vipPlan"`
		Days         int    `json:"days"`
		VIPDays      int    `json:"vipDays"`
		ExpiresAt    int64  `json:"expiresAt"`
		Note         string `json:"note"`
	}
	if decodeJSON(request, &payload, 8192) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "批次参数无效")
		return
	}
	kind := strings.TrimSpace(payload.Kind)
	if kind == "" {
		kind = strings.TrimSpace(payload.Type)
	} else if payload.Type != "" && !strings.EqualFold(kind, strings.TrimSpace(payload.Type)) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "兑换码类型冲突")
		return
	}
	count := payload.Count
	if count == 0 {
		count = payload.Quantity
	} else if payload.Quantity != 0 && payload.Quantity != count {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "兑换码数量冲突")
		return
	}
	days := payload.Days
	if days == 0 {
		days = payload.VIPDays
	} else if payload.VIPDays != 0 && payload.VIPDays != days {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "权益天数冲突")
		return
	}
	now := time.Now().Unix()
	spec, err := normalizeRedemptionBatchSpec(RedemptionBatchSpec{
		Kind: kind, Count: count, TrafficBytes: payload.TrafficBytes,
		VIPPlan: payload.VIPPlan, VIPDays: days, ExpiresAt: payload.ExpiresAt, Note: payload.Note,
	}, now)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "批次参数无效")
		return
	}
	adminKey := privateRateKey(server.cfg.Secret, admin.ID)
	if !server.allowPersistent(request, "admin:redemption-create:"+adminKey, 30, time.Hour) {
		writer.Header().Set("Retry-After", "3600")
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "创建批次过于频繁")
		return
	}
	allowed, err := server.store.AllowPersistent(request.Context(), "admin:redemption-volume:"+adminKey,
		0, 24*time.Hour, int64(spec.Count), 5000)
	if err != nil {
		server.logger.Error("redemption volume limit", "user", admin.ID, "error", err)
		writeAPIError(writer, http.StatusServiceUnavailable, "temporarily_unavailable", "暂时无法创建兑换码")
		return
	}
	if !allowed {
		writer.Header().Set("Retry-After", "86400")
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "今日生成数量已达上限")
		return
	}
	batch, rawCodes, err := server.store.CreateRedemptionBatch(request.Context(), admin.ID, spec,
		server.clientIP(request), now)
	if err != nil {
		server.logger.Error("create redemption batch", "user", admin.ID, "error", err)
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法创建兑换码批次")
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{
		"batch": batch,
		"codes": rawCodes,
	})
}

func (server *Server) adminDisableRedemptionBatch(writer http.ResponseWriter, request *http.Request) {
	admin, ok := server.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	batchID := strings.TrimSpace(request.PathValue("id"))
	if batchID == "" || len(batchID) > 128 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "批次标识无效")
		return
	}
	var payload struct{}
	if decodeJSON(request, &payload, 2048) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "请求参数无效")
		return
	}
	adminKey := privateRateKey(server.cfg.Secret, admin.ID)
	if !server.allowPersistent(request, "admin:redemption-disable:"+adminKey, 120, time.Hour) {
		writer.Header().Set("Retry-After", "3600")
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "停用操作过于频繁")
		return
	}
	batch, err := server.store.DisableRedemptionBatch(request.Context(), batchID, admin.ID,
		server.clientIP(request), time.Now().Unix())
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			writeAPIError(writer, http.StatusNotFound, "batch_not_found", "兑换码批次不存在")
		case errors.Is(err, ErrInvalidRedemption), errors.Is(err, ErrConflict):
			writeAPIError(writer, http.StatusConflict, "batch_unavailable", "兑换码批次无法停用")
		default:
			server.logger.Error("disable redemption batch", "user", admin.ID, "error", err)
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法停用兑换码批次")
		}
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"batch": batch})
}
