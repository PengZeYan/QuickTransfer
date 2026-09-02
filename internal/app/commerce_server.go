package app

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,80}$`)

func (server *Server) listProducts(writer http.ResponseWriter, request *http.Request) {
	products, err := server.store.ListProducts(request.Context())
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取套餐")
		return
	}
	settings, _ := server.settings.snapshot()
	writeJSON(writer, http.StatusOK, map[string]any{
		"products": products,
		"payments": map[string]bool{
			"points": settings.Payment.PointsEnabled,
			"wechat": false,
			"alipay": false,
		},
	})
}

func (server *Server) createOrder(writer http.ResponseWriter, request *http.Request) {
	user, _, _, ok := server.requireUser(writer, request, true)
	if !ok {
		return
	}
	if !server.allowPersistent(request, "order:"+user.ID, 20, time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "创建订单过于频繁")
		return
	}
	var payload struct {
		ProductID     string     `json:"productId"`
		PaymentMethod string     `json:"paymentMethod"`
		HumanProof    HumanProof `json:"humanProof"`
	}
	if decodeJSON(request, &payload, 4096) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "订单参数无效")
		return
	}
	settings, _ := server.settings.snapshot()
	switch payload.PaymentMethod {
	case "points":
		if !settings.Payment.PointsEnabled {
			writeAPIError(writer, http.StatusServiceUnavailable, "payment_unavailable", "支付方式暂未开放")
			return
		}
	case "wechat", "alipay":
		writeAPIError(writer, http.StatusServiceUnavailable, "payment_unavailable", "支付方式暂未开放")
		return
	case "sandbox":
		if user.Role != "admin" || !server.cfg.LoopbackOnly || server.cfg.PublicMode || !server.cfg.SandboxCommerce {
			writeAPIError(writer, http.StatusServiceUnavailable, "payment_unavailable", "支付方式暂未开放")
			return
		}
	default:
		writeAPIError(writer, http.StatusServiceUnavailable, "payment_unavailable", "支付方式暂未开放")
		return
	}
	idempotencyKey := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if !idempotencyKeyPattern.MatchString(idempotencyKey) {
		writeAPIError(writer, http.StatusBadRequest, "idempotency_key_required", "订单请求缺少有效的幂等标识")
		return
	}
	order, err := server.store.CreateOrder(request.Context(), user.ID, payload.ProductID, payload.PaymentMethod,
		idempotencyKey, time.Now().Unix())
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "order_failed", "无法创建订单")
		return
	}
	if payload.PaymentMethod == "points" {
		order, err = server.store.PayOrderWithPoints(request.Context(), order.ID, user.ID, time.Now().Unix())
		if errors.Is(err, ErrQuotaExceeded) {
			writeAPIError(writer, http.StatusPaymentRequired, "points_insufficient", "积分不足")
			return
		}
		if err != nil {
			writeAPIError(writer, http.StatusConflict, "order_failed", "积分兑换失败")
			return
		}
	}
	_ = server.store.AddAudit(request.Context(), user.ID, "order.create", "order", order.ID, order.PaymentMethod, server.clientIP(request))
	response := map[string]any{"order": order}
	if user.Role == "admin" && order.PaymentMethod == "sandbox" {
		response["checkout"] = map[string]any{"mode": "local-sandbox", "completeURL": "/api/v1/orders/" + order.ID + "/sandbox-complete"}
	}
	writeJSON(writer, http.StatusCreated, response)
}

func (server *Server) listOrders(writer http.ResponseWriter, request *http.Request) {
	user, _, _, ok := server.requireUser(writer, request, false)
	if !ok {
		return
	}
	orders, err := server.store.OrdersForUser(request.Context(), user.ID)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取订单")
		return
	}
	if user.Role != "admin" {
		visibleOrders := orders[:0]
		for _, order := range orders {
			if order.PaymentMethod != "sandbox" {
				visibleOrders = append(visibleOrders, order)
			}
		}
		orders = visibleOrders
	}
	writeJSON(writer, http.StatusOK, map[string]any{"orders": orders})
}

func (server *Server) completeSandboxOrder(writer http.ResponseWriter, request *http.Request) {
	user, ok := server.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	if !server.cfg.LoopbackOnly || server.cfg.PublicMode || !server.cfg.SandboxCommerce {
		http.NotFound(writer, request)
		return
	}
	eventID, err := commerceIDGenerator(18)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "payment_failed", "沙箱支付无法完成")
		return
	}
	transactionID, err := commerceIDGenerator(18)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "payment_failed", "沙箱支付无法完成")
		return
	}
	order, err := server.store.CompleteSandboxOrder(request.Context(), request.PathValue("id"), user.ID,
		"sandbox-event-"+eventID, "sandbox-transaction-"+transactionID, time.Now().Unix())
	if err != nil {
		writeAPIError(writer, http.StatusConflict, "payment_failed", "沙箱支付无法完成")
		return
	}
	_ = server.store.AddAudit(request.Context(), user.ID, "order.paid", "order", order.ID, "sandbox", server.clientIP(request))
	writeJSON(writer, http.StatusOK, map[string]any{"order": order})
}

func (server *Server) createReport(writer http.ResponseWriter, request *http.Request) {
	ip := server.clientIP(request)
	if !server.allowPersistent(request, "report:"+ip, 5, 24*time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "举报提交过于频繁")
		return
	}
	var payload struct {
		ShareToken string `json:"shareToken"`
		Reason     string `json:"reason"`
		Detail     string `json:"detail"`
	}
	if decodeJSON(request, &payload, 16*1024) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "举报信息无效")
		return
	}
	payload.ShareToken = cleanText(payload.ShareToken, 128)
	payload.Reason = cleanText(payload.Reason, 48)
	payload.Detail = cleanText(payload.Detail, 500)
	if payload.ShareToken == "" || payload.Reason == "" {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "请填写举报原因")
		return
	}
	if _, err := server.store.TransferByShare(request.Context(), payload.ShareToken); err == nil {
		_ = server.store.CreateAbuseReport(request.Context(), payload.ShareToken, payload.Reason, payload.Detail, ip)
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"accepted": true})
}

func (server *Server) adminOverview(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireAdmin(writer, request, false); !ok {
		return
	}
	overview, err := server.store.AdminOverview(request.Context())
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取管理数据")
		return
	}
	free, _ := availableDiskBytes(server.cfg.DataDir)
	overview.Stats["freeBytes"] = free
	overview.Stats["scanner"] = server.scanner.Name()
	overview.Stats["productionScanner"] = server.scanner.ProductionReady()
	writeJSON(writer, http.StatusOK, overview)
}

func (server *Server) adminUsers(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireAdmin(writer, request, false); !ok {
		return
	}
	users, err := server.store.AdminUsers(request.Context())
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取用户")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"users": users})
}

func (server *Server) adminUserDetail(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireAdmin(writer, request, false); !ok {
		return
	}
	userID := strings.TrimSpace(request.PathValue("id"))
	if userID == "" || len(userID) > 128 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "用户标识无效")
		return
	}
	detail, err := server.store.AdminUserDetail(request.Context(), userID)
	if errors.Is(err, ErrNotFound) {
		writeAPIError(writer, http.StatusNotFound, "user_not_found", "用户不存在")
		return
	}
	if err != nil {
		server.logger.Error("read admin user detail", "userId", userID, "error", err)
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取用户详情")
		return
	}
	writeJSON(writer, http.StatusOK, detail)
}

func (server *Server) adminReports(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireAdmin(writer, request, false); !ok {
		return
	}
	reports, err := server.store.AdminReports(request.Context())
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取举报")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"reports": reports})
}

func (server *Server) adminOrders(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireAdmin(writer, request, false); !ok {
		return
	}
	orders, err := server.store.AdminOrders(request.Context())
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取订单")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"orders": orders})
}

func (server *Server) adminSetUserStatus(writer http.ResponseWriter, request *http.Request) {
	user, ok := server.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	var payload struct {
		Status string `json:"status"`
	}
	if decodeJSON(request, &payload, 4096) != nil {
		writeAPIError(writer, http.StatusBadRequest, "update_failed", "无法更新用户状态")
		return
	}
	targetID := request.PathValue("id")
	if targetID == user.ID && payload.Status == "blocked" {
		writeAPIError(writer, http.StatusBadRequest, "update_failed", "不能停用当前管理员账户")
		return
	}
	if err := server.store.ValidateUserStatusChange(request.Context(), user.ID, targetID, payload.Status); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "update_failed", "无法更新用户状态；系统必须保留至少一个启用的管理员账户")
		return
	}
	if server.store.SetUserStatus(request.Context(), user.ID, targetID, payload.Status,
		server.clientIP(request), time.Now().Unix()) != nil {
		writeAPIError(writer, http.StatusBadRequest, "update_failed", "无法更新用户状态")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) adminSetReportStatus(writer http.ResponseWriter, request *http.Request) {
	user, ok := server.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	var payload struct {
		Status string `json:"status"`
	}
	if decodeJSON(request, &payload, 4096) != nil {
		writeAPIError(writer, http.StatusBadRequest, "update_failed", "无法更新举报状态")
		return
	}
	if _, err := server.store.SetReportStatus(request.Context(), request.PathValue("id"), payload.Status, time.Now().Unix()); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "update_failed", "无法更新举报状态")
		return
	}
	_ = server.store.AddAudit(request.Context(), user.ID, "admin.report-status", "report", request.PathValue("id"), payload.Status, server.clientIP(request))
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) adminRefundOrder(writer http.ResponseWriter, request *http.Request) {
	user, ok := server.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	var payload struct{}
	if decodeJSON(request, &payload, 8192) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "退款确认参数无效")
		return
	}
	settings, _ := server.settings.snapshot()
	order, err := server.store.RefundOrder(request.Context(), request.PathValue("id"), settings.Defaults.UserStorageBytes,
		settings.Defaults.UserMonthlyTraffic, time.Now().Unix())
	if errors.Is(err, ErrQuotaExceeded) {
		writeAPIError(writer, http.StatusConflict, "refund_not_available", "套餐资源或奖励积分已经使用，不能自动退款")
		return
	}
	if err != nil {
		writeAPIError(writer, http.StatusConflict, "refund_failed", "订单无法退款")
		return
	}
	_ = server.store.AddAudit(request.Context(), user.ID, "admin.order-refund", "order", order.ID, order.PaymentMethod, server.clientIP(request))
	writeJSON(writer, http.StatusOK, map[string]any{"order": order})
}

func (server *Server) requireAdmin(writer http.ResponseWriter, request *http.Request, requireCSRF bool) (User, bool) {
	user, _, _, ok := server.requireUser(writer, request, requireCSRF)
	if !ok {
		return User{}, false
	}
	if user.Role != "admin" {
		writeAPIError(writer, http.StatusForbidden, "admin_required", "需要管理员权限")
		return User{}, false
	}
	if user.MustChangePassword {
		writeAPIError(writer, http.StatusForbidden, "password_change_required", "请先修改初始管理员密码")
		return User{}, false
	}
	return user, true
}
