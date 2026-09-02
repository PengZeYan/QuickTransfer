package app

import (
	"context"
	"net/http"
	"time"
)

func (server *Server) getWelfareStatus(writer http.ResponseWriter, request *http.Request) {
	user, _, _, ok := server.requireUser(writer, request, false)
	if !ok {
		return
	}
	status, err := server.store.WelfareStatus(request.Context(), user.ID, time.Now())
	if err != nil {
		server.logger.Error("read welfare status", "userId", user.ID, "error", err)
		writeAPIError(writer, http.StatusInternalServerError, "welfare_unavailable", "暂时无法读取签到记录")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"welfare": status})
}

func (server *Server) claimDailyCheckIn(writer http.ResponseWriter, request *http.Request) {
	user, _, _, ok := server.requireUser(writer, request, true)
	if !ok {
		return
	}
	if !server.allowPersistent(request, "welfare-checkin:"+user.ID, 12, time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "签到操作过于频繁，请稍后再试")
		return
	}
	now := time.Now()
	result, err := server.store.ClaimDailyCheckIn(request.Context(), user.ID, server.clientIP(request), now)
	if err != nil {
		server.logger.Error("claim daily welfare", "userId", user.ID, "error", err)
		writeAPIError(writer, http.StatusServiceUnavailable, "welfare_unavailable", "签到暂时不可用，请稍后再试")
		return
	}
	status, statusErr := server.store.WelfareStatus(request.Context(), user.ID, now)
	settings, _ := server.settings.snapshot()
	account, accountErr := server.store.AccountSummary(request.Context(), user.ID, settings.Defaults.UserStorageBytes,
		settings.Defaults.UserMonthlyTraffic, now)
	response := map[string]any{"result": result}
	if statusErr == nil {
		response["welfare"] = status
	} else {
		server.logger.Error("read welfare after claim", "userId", user.ID, "error", statusErr)
	}
	if accountErr == nil {
		response["account"] = account
	} else {
		server.logger.Error("read account after welfare claim", "userId", user.ID, "error", accountErr)
	}
	statusCode := http.StatusCreated
	if result.Idempotent {
		statusCode = http.StatusOK
	}
	writeJSON(writer, statusCode, response)
}

func (server *Server) shouldPromptDailyCheckIn(ctx context.Context, user User, now time.Time) bool {
	if sameWelfareDate(user.LastLoginAt, now) {
		return false
	}
	claimed, err := server.store.HasDailyCheckIn(ctx, user.ID, now)
	if err != nil {
		server.logger.Warn("check daily welfare reminder", "userId", user.ID, "error", err)
		return false
	}
	return !claimed
}
