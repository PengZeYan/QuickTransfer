const JSON_HEADERS = { "Content-Type": "application/json" };
const RELATIVE_URL_VALIDATION_BASE = new URL("https://relative-url.invalid");
const LOCAL_HTTP_STORAGE_HOSTS = new Set(["localhost", "127.0.0.1"]);
let csrfToken = "";

const ERROR_MESSAGES = {
  account_blocked: "当前账户已被停用，请联系管理员。",
  authentication_busy: "登录请求较多，请稍后再试。",
  authentication_required: "请先登录后继续。",
  captcha_failed: "人机验证未通过，请重新验证。",
  captcha_replayed: "本次验证已失效，请重新验证。",
  challenge_unavailable: "人机验证暂不可用，请稍后再试。",
  csrf_failed: "页面状态已过期，请刷新后重试。",
  current_password_invalid: "当前密码不正确。",
  download_limit: "下载次数已用完，文件将自动删除。",
  download_in_progress: "该文件正在当前领取会话中下载。",
  email_delivery_failed: "验证码邮件暂时无法发送，请稍后再试。",
  email_domain_not_allowed: "该邮箱域名暂不支持注册。",
  file_not_found: "文件不存在或已到期。",
  file_unavailable: "文件暂不可用。",
  forbidden: "当前账户无权执行此操作。",
  guest_daily_limit: "今日游客传输额度已用完，请明日再试或登录账户。",
  guest_file_type_blocked: "该文件类型不支持游客上传。",
  human_verification_failed: "人机验证未通过，请重新验证。",
  human_verification_replayed: "本次验证已失效，请重新验证。",
  human_verification_required: "请先完成人机验证。",
  human_verification_unavailable: "人机验证尚未配置，请稍后再试。",
  invalid_access_code: "访问密码不正确。",
  invalid_body: "提交内容有误，请检查后重试。",
  invalid_code: "验证码或兑换码不正确。",
  invalid_credentials: "邮箱或密码不正确。",
  invalid_email: "请输入有效邮箱地址。",
  invalid_expiry: "所选有效期不可用。",
  invalid_download_limit: "下载次数超出当前账号允许范围。",
  invalid_file: "文件信息无效，请重新选择。",
  invalid_request: "请求内容有误，请检查后重试。",
  method_not_allowed: "当前操作不可用。",
  not_ready: "服务尚未就绪，请稍后再试。",
  order_failed: "订单暂时无法创建，请稍后再试。",
  password_invalid: "密码不符合安全要求。",
  payment_failed: "支付未完成，请稍后重试。",
  payment_unavailable: "支付暂未开放或尚未配置。",
  pickup_not_found: "取件码不存在或文件已到期。",
  rate_limited: "操作过于频繁，请稍后再试。",
  redemption_already_used: "该兑换码已被使用。",
  redemption_disabled: "该兑换码已停用。",
  redemption_expired: "该兑换码已过期。",
  redemption_not_found: "兑换码不存在或已失效。",
  redemption_unavailable: "兑换码无效、已使用或已失效。",
  registration_risk_limit: "当前网络的注册次数已达上限，请稍后再试。",
  settings_revision_conflict: "设置已被其他管理员更新，请刷新后重试。",
  storage_not_ready: "文件存储正在维护，请稍后再试。",
  storage_unavailable: "文件存储暂不可用，请稍后再试。",
  traffic_insufficient: "剩余上传流量不足，请先购买流量。",
  transfer_limit: "当前账户的文件数量已达上限。",
  transfer_unavailable: "文件传输暂不可用，请稍后再试。",
  unauthorized: "登录状态已失效，请重新登录。",
  username_invalid: "用户名格式不正确。",
  username_too_long: "用户名过长，请缩短后重试。",
  invalid_username: "用户名需为 1 至 20 个字符。",
  batch_not_found: "兑换码批次不存在。",
  batch_unavailable: "该兑换码批次当前无法停用。",
  temporarily_unavailable: "服务暂时不可用，请稍后再试。",
  verification_rate_limited: "验证码发送过于频繁，请稍后再试。",
  verification_required: "请先完成邮箱验证。",
  verification_unavailable: "邮箱验证尚未配置，请稍后再试。",
  welfare_unavailable: "签到暂时不可用，请稍后再试。",
};

function apiErrorMessage(details, status) {
  const code = details?.error?.code || "request_failed";
  if (ERROR_MESSAGES[code]) return ERROR_MESSAGES[code];

  const serverMessage = String(details?.error?.message || "").trim();
  const safeChineseMessage =
    serverMessage.length > 0 &&
    serverMessage.length <= 120 &&
    /[\u3400-\u9fff]/u.test(serverMessage) &&
    !/[A-Za-z_]{3,}|https?:|\/api\//u.test(serverMessage);
  if (safeChineseMessage) return serverMessage;
  if (status === 401) return "登录状态已失效，请重新登录。";
  if (status === 403) return "当前账户无权执行此操作。";
  if (status === 404) return "请求的内容不存在或已失效。";
  if (status === 409) return "当前状态已发生变化，请刷新后重试。";
  if (status === 413) return "文件大小超过当前账户上限。";
  if (status === 429) return "操作过于频繁，请稍后再试。";
  if (status >= 500) return "服务暂时不可用，请稍后再试。";
  return "操作未完成，请检查后重试。";
}

function csrfHeaders(headers, csrf = "") {
  return csrf
    ? { ...headers, "X-CSRF-Token": csrf }
    : headers;
}

export class ApiError extends Error {
  constructor(message, code, status, retryAfterSeconds = 0) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

function parseRetryAfter(value) {
  if (!value) return 0;
  const seconds = Number.parseInt(value, 10);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds;
  const deadline = Date.parse(value);
  return Number.isFinite(deadline)
    ? Math.max(0, Math.ceil((deadline - Date.now()) / 1000))
    : 0;
}

function invalidURL(message, code) {
  return new ApiError(message, code, 0);
}

function isLocalStorageDevelopment() {
  const runtimeHostname =
    globalThis.location?.hostname || globalThis.window?.location?.hostname || "";
  return (
    import.meta.env?.DEV === true || LOCAL_HTTP_STORAGE_HOSTS.has(runtimeHostname)
  );
}

function validateTransportURL(value, { allowAbsoluteStorage = false } = {}) {
  const code = allowAbsoluteStorage ? "invalid_storage_url" : "invalid_api_url";
  const label = allowAbsoluteStorage ? "文件存储地址" : "接口地址";

  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value !== value.trim() ||
    value.includes("#")
  ) {
    throw invalidURL(`${label}无效`, code);
  }

  if (value.startsWith("/api/")) {
    const parsed = new URL(value, RELATIVE_URL_VALIDATION_BASE);
    if (
      parsed.origin !== RELATIVE_URL_VALIDATION_BASE.origin ||
      !parsed.pathname.startsWith("/api/") ||
      parsed.username ||
      parsed.password
    ) {
      throw invalidURL(`${label}格式无效`, code);
    }
    return value;
  }

  if (!allowAbsoluteStorage) {
    throw invalidURL("接口地址无效", code);
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw invalidURL("文件存储地址格式无效", code);
  }

  if (parsed.username || parsed.password) {
    throw invalidURL("文件存储地址不能包含用户名或密码", code);
  }

  const localHTTP =
    parsed.protocol === "http:" &&
    LOCAL_HTTP_STORAGE_HOSTS.has(parsed.hostname) &&
    isLocalStorageDevelopment();
  if (parsed.protocol !== "https:" && !localHTTP) {
    throw invalidURL("文件存储地址必须使用安全连接", code);
  }

  return value;
}

function parseUploadOffset(value, previousOffset, fileSize, status = 0) {
  const text = typeof value === "number" ? String(value) : value;
  if (typeof text !== "string" || !/^\d+$/.test(text)) {
    throw new ApiError(
      value === null || value === undefined || value === ""
        ? "存储服务响应缺少上传进度"
        : "存储服务返回了无效的上传进度",
      "invalid_upload_offset",
      status,
    );
  }

  const offset = Number(text);
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new ApiError(
      "存储服务返回了无效的上传进度",
      "invalid_upload_offset",
      status,
    );
  }
  if (offset < previousOffset) {
    throw new ApiError(
      "存储服务返回的上传进度出现倒退",
      "invalid_upload_offset",
      status,
    );
  }
  if (offset > fileSize) {
    throw new ApiError(
      "存储服务返回的上传进度超过文件长度",
      "invalid_upload_offset",
      status,
    );
  }
  return offset;
}

async function storageFetch(url, options, networkMessage) {
  try {
    return await fetch(url, {
      ...options,
      credentials: "omit",
    });
  } catch {
    throw new ApiError(networkMessage, "storage_network_error", 0);
  }
}

async function request(path, options = {}) {
  const apiPath = validateTransportURL(path);
  const { requireCsrf = false, ...fetchOptions } = options;
  const method = String(fetchOptions.method || "GET").toUpperCase();
  const headers = new Headers(fetchOptions.headers || {});
  if (
    (requireCsrf || !["GET", "HEAD", "OPTIONS"].includes(method)) &&
    csrfToken &&
    !headers.has("X-CSRF-Token")
  ) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  let response;
  try {
    response = await fetch(apiPath, {
      ...fetchOptions,
      cache: "no-store",
      credentials: "same-origin",
      headers,
    });
  } catch {
    throw new ApiError("无法连接服务，请检查网络后重试", "network_error", 0);
  }
  if (!response.ok) {
    let details;
    try {
      details = await response.json();
    } catch {
      details = null;
    }
    throw new ApiError(
      apiErrorMessage(details, response.status),
      details?.error?.code || "request_failed",
      response.status,
      parseRetryAfter(response.headers.get("Retry-After")),
    );
  }
  if (response.status === 204) return null;
  return response.json();
}

export function getConfig() {
  return request("/api/v1/config");
}

export function getTerms() {
  return request("/api/v1/legal/terms");
}

export async function getMe() {
  const result = await request("/api/v1/me");
  csrfToken = result.csrfToken || "";
  return result;
}

export function register(payload) {
  return request("/api/v1/auth/register", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
}

export function verifyRegistration(payload) {
  return request("/api/v1/auth/verify", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
}

export function login(payload) {
  return request("/api/v1/auth/login", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
}

export async function logout() {
  const result = await request("/api/v1/auth/logout", { method: "POST" });
  csrfToken = "";
  return result;
}

export function requestPasswordReset(payload) {
  return request("/api/v1/auth/password/request", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(
      typeof payload === "string" ? { email: payload } : payload,
    ),
  });
}

export function confirmPasswordReset(payload) {
  return request("/api/v1/auth/password/confirm", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
}

export function changePassword(payload) {
  return request("/api/v1/me/password", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
}

export function getMyTransfers() {
  return request("/api/v1/me/transfers");
}

export function getMyResources() {
  return request("/api/v1/me/resources");
}

export function getWelfareStatus() {
  return request("/api/v1/me/welfare");
}

export function claimDailyCheckIn() {
  return request("/api/v1/me/welfare/check-in", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({}),
  });
}

export function updateProfile(username, csrf = "") {
  return request("/api/v1/me/profile", {
    method: "PUT",
    headers: csrfHeaders(JSON_HEADERS, csrf),
    body: JSON.stringify({ username: String(username || "").trim() }),
  });
}

export function redeemCode(code, humanProof = null, csrf = "") {
  return request("/api/v1/me/redemptions", {
    method: "POST",
    headers: csrfHeaders(JSON_HEADERS, csrf),
    body: JSON.stringify({
      code: String(code || "").trim().toUpperCase(),
      humanProof,
    }),
  });
}

export function claimTransfer(shareToken, manageToken) {
  return request("/api/v1/me/transfers/claim", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ shareToken, manageToken }),
  });
}

export function getProducts() {
  return request("/api/v1/products");
}

export function createOrder(
  productId,
  paymentMethod,
  humanProof,
  idempotencyKey,
) {
  return request("/api/v1/orders", {
    method: "POST",
    headers: { ...JSON_HEADERS, "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({ productId, paymentMethod, humanProof }),
  });
}

export function getOrders() {
  return request("/api/v1/orders");
}

export function reportShare(shareToken, reason, detail = "") {
  return request("/api/v1/reports", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ shareToken, reason, detail }),
  });
}

export function getAdminOverview() {
  return request("/api/v1/admin/overview", { requireCsrf: true });
}

export function getAdminSettings() {
  return request("/api/v1/admin/settings");
}

export function updateAdminSettings(payload) {
  return request("/api/v1/admin/settings", {
    method: "PUT",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
}

export function testAdminSMTP(payload) {
  return request("/api/v1/admin/settings/smtp/test", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
}

export function getAdminUsers() {
  return request("/api/v1/admin/users");
}

export function getAdminUserDetail(id) {
  return request(`/api/v1/admin/users/${encodeURIComponent(id)}`);
}

export function setAdminUserStatus(id, status) {
  return request(`/api/v1/admin/users/${encodeURIComponent(id)}/status`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ status }),
  });
}

export function getAdminReports() {
  return request("/api/v1/admin/reports");
}

export function getAdminOrders() {
  return request("/api/v1/admin/orders");
}

export function setAdminReportStatus(id, status) {
  return request(`/api/v1/admin/reports/${encodeURIComponent(id)}/status`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ status }),
  });
}

export function refundAdminOrder(id) {
  return request(`/api/v1/admin/orders/${encodeURIComponent(id)}/refund`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({}),
  });
}

export function getAdminRedemptions() {
  return request("/api/v1/admin/redemption-batches", { requireCsrf: true });
}

export const getAdminRedemptionBatches = getAdminRedemptions;

export function createAdminRedemptionBatch(payload) {
  return request("/api/v1/admin/redemption-batches", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
}

export function disableAdminRedemptionBatch(id) {
  return request(
    `/api/v1/admin/redemption-batches/${encodeURIComponent(id)}/disable`,
    {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({}),
    },
  );
}

export function createTransfer(payload) {
  return request("/api/v1/transfers", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
}

export function getShare(shareToken, unlockToken = "", retrievalToken = "") {
  return request(`/api/v1/shares/${encodeURIComponent(shareToken)}`, {
    headers: {
      ...(unlockToken ? { "X-Unlock-Token": unlockToken } : {}),
      ...(retrievalToken ? { "X-Retrieval-Token": retrievalToken } : {}),
    },
  });
}

export function unlockShare(shareToken, code) {
  return request(`/api/v1/shares/${encodeURIComponent(shareToken)}/unlock`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ code }),
  });
}

export function resolvePickup(code) {
  return request(
    `/api/v1/pickup/${encodeURIComponent(code.trim().toUpperCase())}`,
  );
}

export function getManagedTransfer(shareToken, manageToken) {
  return request(`/api/v1/manage/${encodeURIComponent(shareToken)}`, {
    headers: { "X-Manage-Token": manageToken },
  });
}

export function publishTransfer(shareToken, manageToken) {
  return request(
    `/api/v1/manage/${encodeURIComponent(shareToken)}/publish`,
    {
      method: "POST",
      headers: { "X-Manage-Token": manageToken },
    },
  );
}

export function revokeTransfer(shareToken, manageToken) {
  return request(`/api/v1/manage/${encodeURIComponent(shareToken)}`, {
    method: "DELETE",
    headers: { "X-Manage-Token": manageToken },
  });
}

export async function createDownload(
  shareToken,
  fileId,
  unlockToken = "",
  manageToken = "",
  retrievalToken = "",
) {
  const result = await request(
    `/api/v1/shares/${encodeURIComponent(shareToken)}/tickets`,
    {
      method: "POST",
      headers: {
        ...JSON_HEADERS,
        ...(unlockToken ? { "X-Unlock-Token": unlockToken } : {}),
        ...(manageToken ? { "X-Manage-Token": manageToken } : {}),
        ...(retrievalToken ? { "X-Retrieval-Token": retrievalToken } : {}),
      },
      body: JSON.stringify({ fileId }),
    },
  );
  return {
    downloadURL: validateTransportURL(result?.downloadURL, {
      allowAbsoluteStorage: true,
    }),
    retrievalToken: String(result?.retrievalToken || ""),
    retrievalExpiresAt: Number(result?.retrievalExpiresAt || 0),
  };
}

async function createUploadSession(
  shareToken,
  file,
  credentials,
  submitterName,
  humanProof,
) {
  return request(
    `/api/v1/transfers/${encodeURIComponent(shareToken)}/uploads`,
    {
      method: "POST",
      headers: {
        ...JSON_HEADERS,
        ...(credentials.manageToken
          ? { "X-Manage-Token": credentials.manageToken }
          : {}),
        ...(credentials.unlockToken
          ? { "X-Unlock-Token": credentials.unlockToken }
          : {}),
      },
      body: JSON.stringify({
        name: file.webkitRelativePath || file.name,
        size: file.size,
        contentType: file.type || "application/octet-stream",
        submitterName,
        humanProof,
      }),
    },
  );
}

async function readOffset(session, uploadURL, previousOffset, fileSize) {
  const response = await storageFetch(
    uploadURL,
    {
      method: "HEAD",
      cache: "no-store",
      headers: { Authorization: `Bearer ${session.uploadToken}` },
    },
    "无法连接文件存储服务，无法恢复上传进度",
  );
  if (!response.ok)
    throw new ApiError("无法恢复上传进度", "resume_failed", response.status);
  return parseUploadOffset(
    response.headers.get("Upload-Offset"),
    previousOffset,
    fileSize,
    response.status,
  );
}

export async function uploadFile({
  shareToken,
  file,
  manageToken = "",
  unlockToken = "",
  submitterName = "",
  humanProof = null,
  onProgress = () => {},
}) {
  const session = await createUploadSession(
    shareToken,
    file,
    { manageToken, unlockToken },
    submitterName,
    humanProof,
  );
  const uploadURL = validateTransportURL(session?.uploadURL, {
    allowAbsoluteStorage: true,
  });
  let offset = parseUploadOffset(session?.offset, 0, file.size);
  const chunkBytes = Number(session.chunkBytes || 4 * 1024 * 1024);
  let retries = 0;

  while (offset < file.size) {
    const end = Math.min(offset + chunkBytes, file.size);
    const chunk = file.slice(offset, end);
    let response;
    try {
      response = await storageFetch(
        uploadURL,
        {
          method: "PATCH",
          cache: "no-store",
          headers: {
            Authorization: `Bearer ${session.uploadToken}`,
            "Content-Type": "application/offset+octet-stream",
            "Upload-Offset": String(offset),
          },
          body: chunk,
        },
        "无法连接文件存储服务，请检查网络后重试",
      );
    } catch (error) {
      if (retries >= 3) throw error;
      retries += 1;
      await wait(350 * retries);
      offset = await readOffset(session, uploadURL, offset, file.size);
      continue;
    }

    if (response.status === 409 && retries < 3) {
      retries += 1;
      offset = await readOffset(session, uploadURL, offset, file.size);
      continue;
    }
    if (!response.ok) {
      let details;
      try {
        details = await response.json();
      } catch {
        details = null;
      }
      throw new ApiError(
        apiErrorMessage(details, response.status),
        details?.error?.code || "upload_failed",
        response.status,
      );
    }

    offset = parseUploadOffset(
      response.headers.get("Upload-Offset"),
      offset,
      file.size,
      response.status,
    );
    retries = 0;
    onProgress(offset, file.size);
  }

  return session.id;
}

export async function waitForManagedTransfer(
  shareToken,
  manageToken,
  timeoutMs = 45_000,
) {
  const started = Date.now();
  let latest = await getManagedTransfer(shareToken, manageToken);
  while (latest.scanning && Date.now() - started < timeoutMs) {
    await wait(700);
    latest = await getManagedTransfer(shareToken, manageToken);
  }
  if (latest.scanning) {
    throw new ApiError("文件检查尚未完成，请稍后重试", "scan_timeout", 0);
  }
  return latest;
}

export function formatBytes(value) {
  const parsed = Number(value || 0);
  const bytes = Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = bytes / 1024;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  const precision = size >= 100 ? 0 : size >= 10 ? 1 : 2;
  return `${Number(size.toFixed(precision))} ${units[index]}`;
}

export function wait(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}
