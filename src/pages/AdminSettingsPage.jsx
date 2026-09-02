import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  CheckCircle,
  CloudArrowUp,
  Crown,
  CreditCard,
  Database,
  DownloadSimple,
  Flag,
  Gauge,
  Eye,
  LockKey,
  MagnifyingGlass,
  PaperPlaneTilt,
  Receipt,
  ShieldCheck,
  Ticket,
  User,
  UsersThree,
  WarningCircle,
  X,
} from "@phosphor-icons/react";
import { showToast } from "../components/ToastCenter.jsx";
import "../styles/admin-settings.css";

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

const SMTP_PRESETS = {
  qq: {
    host: "smtp.qq.com",
    port: 465,
    tlsMode: "implicit",
    authMode: "login",
  },
  163: {
    host: "smtp.163.com",
    port: 465,
    tlsMode: "implicit",
    authMode: "login",
  },
  gmail: {
    host: "smtp.gmail.com",
    port: 465,
    tlsMode: "implicit",
    authMode: "login",
  },
};

const CAPTCHA_ACTIONS = [
  { key: "login", label: "账户登录", detail: "拦截撞库和自动化登录尝试" },
  {
    key: "register",
    label: "注册与发送验证码",
    detail: "拦截批量注册和邮件轰炸",
  },
  {
    key: "password_reset",
    label: "找回密码",
    detail: "拦截自动化找回和重置请求",
  },
  {
    key: "guest_transfer",
    label: "游客创建传输",
    detail: "拦截游客批量占用上传流量",
  },
  {
    key: "redeem",
    label: "兑换权益",
    detail: "拦截批量猜码和自动化兑换尝试",
  },
];

const TABS = [
  { id: "registration", label: "注册与条款", icon: User },
  { id: "smtp", label: "邮箱 / SMTP", icon: PaperPlaneTilt },
  { id: "levels", label: "流量与等级", icon: Crown },
  { id: "captcha", label: "验证码与风控", icon: ShieldCheck },
  { id: "payment", label: "支付设置", icon: CreditCard },
  { id: "redemption", label: "兑换码", icon: Ticket },
  { id: "operations", label: "运营管理", icon: UsersThree },
  { id: "runtime", label: "运行状态", icon: Gauge },
];

const SETTINGS_TABS = new Set([
  "registration",
  "smtp",
  "levels",
  "captcha",
  "payment",
  "runtime",
]);

const LEVEL_RULES = [
  {
    id: "guest",
    name: "游客",
    fileLimit: "单次总量 100 MiB",
    fileCount: "最多 100 个文件",
    retention: "保留 24 小时",
  },
  {
    id: "normal",
    name: "普通用户",
    fileLimit: "单次总量 2 GiB",
    fileCount: "最多 100 个文件",
    retention: "最长保留 3 天",
  },
  {
    id: "vip",
    name: "VIP 用户",
    fileLimit: "单次总量 10 GiB",
    fileCount: "最多 1,000 个文件",
    retention: "按 VIP 权益执行",
  },
  {
    id: "lifetime",
    name: "终身 VIP",
    fileLimit: "单次总量 50 GiB",
    fileCount: "最多 10,000 个文件",
    retention: "终身权益持续有效",
  },
];

const EMPTY_REDEMPTION_FORM = {
  type: "traffic",
  count: 1,
  trafficGiB: 10,
  vipPlan: "monthly",
  expiresAt: "",
  note: "",
};

const EMPTY_SETTINGS = {
  revision: 0,
  registration: {
    open: false,
    requireTerms: true,
    allowedDomains: "qq.com\n163.com\ngmail.com",
    emailCooldownSeconds: 120,
    emailHourly: 3,
    emailDaily: 5,
    ipHourly: 10,
    ipDaily: 20,
    domainHourly: 100,
    domainDaily: 500,
    successfulPerIPDaily: 3,
    successfulPerSubnetDaily: 20,
  },
  defaults: {
    guestMaxFileBytes: 100 * MIB,
    guestMaxTransferBytes: 100 * MIB,
    guestMaxFiles: 100,
    guestMaxDownloads: 20,
    guestDailyBytes: 300 * MIB,
    guestDailyTasks: 3,
    userStorageBytes: 10 * GIB,
    userMonthlyTrafficBytes: 50 * GIB,
    defaultExpiryHours: 24,
    maximumExpiryHours: 72,
  },
  smtp: {
    enabled: false,
    provider: "qq",
    host: SMTP_PRESETS.qq.host,
    port: SMTP_PRESETS.qq.port,
    username: "",
    from: "",
    fromName: "快传",
    tlsMode: SMTP_PRESETS.qq.tlsMode,
    authMode: SMTP_PRESETS.qq.authMode,
    passwordConfigured: false,
    lastTestedAt: "",
    lastTestSucceeded: false,
  },
  captcha: {
    enabled: false,
    provider: "disabled",
    siteKey: "",
    allowedHostnames: "",
    tencentCaptchaAppId: "",
    actions: Object.fromEntries(CAPTCHA_ACTIONS.map(({ key }) => [key, false])),
    secretConfigured: false,
    tencentCredentialsConfigured: false,
  },
  payment: {
    pointsEnabled: true,
    wechatEnabled: false,
    wechatMerchantId: "",
    wechatAppId: "",
    wechatSecretConfigured: false,
    alipayEnabled: false,
    alipayAppId: "",
    alipaySecretConfigured: false,
  },
  terms: {
    version: "",
    title: "快传用户协议、隐私政策与可接受使用规则",
    content: "",
    effectiveAt: "",
  },
};

const EMPTY_SECRETS = {
  smtpPassword: "",
  turnstileSecret: "",
  tencentAppSecretKey: "",
  tencentSecretId: "",
  tencentSecretKey: "",
};

function finiteNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function listText(value) {
  if (Array.isArray(value)) return value.filter(Boolean).join("\n");
  return String(value || "")
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter(Boolean)
    .join("\n");
}

function parseList(value) {
  return [
    ...new Set(
      String(value || "")
        .split(/[\s,;]+/)
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean),
    ),
  ];
}

function normalizeActions(value) {
  const enabled = Array.isArray(value)
    ? Object.fromEntries(value.map((key) => [key, true]))
    : value && typeof value === "object"
      ? value
      : {};
  return Object.fromEntries(
    CAPTCHA_ACTIONS.map(({ key }) => [key, Boolean(enabled[key])]),
  );
}

function serverDate(value) {
  if (!value) return "";
  const numeric = Number(value);
  const date =
    Number.isFinite(numeric) && numeric > 0
      ? new Date(numeric * 1000)
      : new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date;
}

function toLocalDateTime(value) {
  const date = serverDate(value);
  if (!date) return "";
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function toUnixSeconds(value) {
  if (!value) return 0;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 0 : Math.floor(date.getTime() / 1000);
}

function normalizeSettings(value = {}) {
  const registration = value.registration || {};
  const defaults = value.defaults || {};
  const smtp = value.smtp || {};
  const captcha = value.captcha || {};
  const payment = value.payment || {};
  const terms = value.terms || {};
  const smtpProvider = SMTP_PRESETS[smtp.provider] ? smtp.provider : "qq";
  const smtpPreset = SMTP_PRESETS[smtpProvider];
  const captchaProvider = ["turnstile", "tencent"].includes(captcha.provider)
    ? captcha.provider
    : "disabled";

  return {
    revision: finiteNumber(value.revision, 0),
    registration: {
      ...EMPTY_SETTINGS.registration,
      ...registration,
      open: Boolean(registration.open),
      requireTerms: true,
      allowedDomains: listText(
        registration.allowedDomains ||
          EMPTY_SETTINGS.registration.allowedDomains,
      ),
    },
    defaults: {
      ...EMPTY_SETTINGS.defaults,
      ...Object.fromEntries(
        Object.keys(EMPTY_SETTINGS.defaults).map((key) => [
          key,
          finiteNumber(defaults[key], EMPTY_SETTINGS.defaults[key]),
        ]),
      ),
    },
    smtp: {
      ...EMPTY_SETTINGS.smtp,
      ...smtp,
      enabled: Boolean(smtp.enabled),
      provider: smtpProvider,
      host: String(smtp.host || smtpPreset.host),
      port: finiteNumber(smtp.port, smtpPreset.port),
      tlsMode: ["implicit", "starttls"].includes(smtp.tlsMode)
        ? smtp.tlsMode
        : smtpPreset.tlsMode,
      authMode: ["login", "plain"].includes(smtp.authMode)
        ? smtp.authMode
        : smtpPreset.authMode,
      passwordConfigured: Boolean(smtp.passwordConfigured),
      lastTestSucceeded: Boolean(smtp.lastTestSucceeded),
    },
    captcha: {
      ...EMPTY_SETTINGS.captcha,
      ...captcha,
      enabled: Boolean(captcha.enabled) && captchaProvider !== "disabled",
      provider: captchaProvider,
      allowedHostnames: listText(captcha.allowedHostnames),
      actions: normalizeActions(captcha.actions),
      secretConfigured: Boolean(captcha.secretConfigured),
      tencentCredentialsConfigured: Boolean(
        captcha.tencentCredentialsConfigured,
      ),
    },
    payment: {
      ...EMPTY_SETTINGS.payment,
      ...payment,
      pointsEnabled: payment.pointsEnabled !== false,
      wechatEnabled: false,
      alipayEnabled: false,
      wechatSecretConfigured: Boolean(payment.wechatSecretConfigured),
      alipaySecretConfigured: Boolean(payment.alipaySecretConfigured),
    },
    terms: {
      ...EMPTY_SETTINGS.terms,
      ...terms,
      effectiveAt: toLocalDateTime(terms.effectiveAt),
    },
  };
}

function normalizeRuntime(value = {}) {
  return {
    emailActive: Boolean(value.emailActive),
    restartRequired: Boolean(value.restartRequired),
    scanner: String(value.scanner || "未报告"),
    productionScanner: Boolean(value.productionScanner),
  };
}

function payloadSettings(form) {
  return {
    ...form,
    registration: {
      ...form.registration,
      allowedDomains: parseList(form.registration.allowedDomains),
    },
    defaults: Object.fromEntries(
      Object.entries(form.defaults).map(([key, value]) => [
        key,
        Math.max(0, Math.round(finiteNumber(value, 0))),
      ]),
    ),
    smtp: {
      ...form.smtp,
      passwordConfigured: Boolean(form.smtp.passwordConfigured),
    },
    captcha: {
      ...form.captcha,
      allowedHostnames: parseList(form.captcha.allowedHostnames),
      tencentCaptchaAppId: Math.max(
        0,
        Math.trunc(finiteNumber(form.captcha.tencentCaptchaAppId, 0)),
      ),
    },
    payment: {
      ...form.payment,
      wechatEnabled: false,
      alipayEnabled: false,
    },
    terms: {
      ...form.terms,
      effectiveAt: toUnixSeconds(form.terms.effectiveAt),
    },
  };
}

function formatDate(value) {
  if (!value) return "尚未执行";
  const date = serverDate(value);
  if (!date) return String(value);
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function formatBytes(value) {
  const bytes = Math.max(0, finiteNumber(value, 0));
  if (!bytes) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const index = Math.min(
    units.length - 1,
    Math.floor(Math.log(bytes) / Math.log(1024)),
  );
  const size = bytes / 1024 ** index;
  return `${size >= 100 || index === 0 ? Math.round(size) : size.toFixed(1)} ${units[index]}`;
}

function userStatusLabel(status) {
  return (
    {
      active: "正常",
      blocked: "已停用",
      pending: "待验证",
    }[status] || "未知"
  );
}

function reportStatusLabel(status) {
  return (
    {
      open: "待处理",
      resolved: "已处理",
      rejected: "已驳回",
    }[status] || "未知"
  );
}

function orderStatusLabel(status) {
  return (
    {
      pending: "待支付",
      paid: "已生效",
      closed: "已关闭",
      refunded: "已退款",
    }[status] || "未知"
  );
}

function paymentMethodLabel(method) {
  return (
    {
      points: "账户积分",
      wechat: "微信支付",
      alipay: "支付宝",
    }[method] || "未配置渠道"
  );
}

function tierLabel(value) {
  return (
    {
      guest: "游客",
      user: "普通用户",
      normal: "普通用户",
      vip: "VIP 用户",
      monthly: "月度 VIP",
      yearly: "年度 VIP",
      lifetime: "终身 VIP",
    }[value] || "普通用户"
  );
}

function auditActionLabel(action) {
  const labels = {
    "admin.settings.update": "更新系统设置",
    "admin.smtp.test": "验证邮件投递",
    "admin.user.status": "变更用户状态",
    "admin.report.resolve": "处理举报",
    "admin.order.refund": "处理订单退款",
    "admin.redemption.create": "生成兑换码",
    "admin.redemption.disable": "停用兑换码批次",
  };
  return labels[action] || "管理员操作";
}

function redemptionTypeLabel(type) {
  return type === "vip" || type === "entitlement" ? "VIP 权益" : "上传流量";
}

function vipPlanLabel(plan) {
  return (
    { monthly: "月度 VIP", yearly: "年度 VIP", lifetime: "终身 VIP" }[
      plan
    ] || "VIP 权益"
  );
}

function redemptionCodeStatusLabel(status) {
  return (
    { active: "未使用", redeemed: "已使用", disabled: "已停用" }[status] ||
    "未知"
  );
}

function entitlementSourceLabel(source) {
  return (
    {
      order: "套餐购买",
      redemption: "兑换码",
      daily_checkin: "每日签到",
      vip_daily_login: "会员登录权益",
      registration: "注册赠送",
    }[source] || "系统权益"
  );
}

function roleLabel(role) {
  return role === "admin" ? "管理员" : "注册用户";
}

function batchID(batch) {
  return String(batch?.id || batch?.batchId || "");
}

function batchStatus(batch) {
  if (batch?.disabled || batch?.status === "disabled") return "已停用";
  const expiresAt = finiteNumber(batch?.expiresAt, 0);
  if (expiresAt && expiresAt * 1000 <= Date.now()) return "已失效";
  return "可使用";
}

function plainCode(entry) {
  if (typeof entry === "string") return entry;
  return String(
    entry?.code || entry?.plaintext || entry?.plainCode || entry?.token || "",
  );
}

function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function downloadRedemptionCSV(created) {
  const codes = Array.isArray(created?.codes) ? created.codes : [];
  if (!codes.length) return;
  const rows = [
    ["序号", "兑换码", "类型", "权益", "状态", "兑换用户", "兑换时间", "失效时间", "备注"],
    ...codes.map((entry, index) => [
      index + 1,
      plainCode(entry),
      redemptionTypeLabel(created.type),
      created.type === "traffic"
        ? formatBytes(
            created.trafficBytes ||
              finiteNumber(created.trafficGiB, 0) * GIB,
          ) + " 上传流量"
        : vipPlanLabel(created.vipPlan),
      redemptionCodeStatusLabel(entry?.status || "active"),
      entry?.redeemedUsername || entry?.redeemedEmail || "",
      entry?.redeemedAt ? formatDate(entry.redeemedAt) : "",
      created.expiresAt ? formatDate(created.expiresAt) : "长期有效",
      created.note || "",
    ]),
  ];
  const csv = `\uFEFF${rows.map((row) => row.map(csvCell).join(",")).join("\r\n")}`;
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `兑换码-${created.batchId || "新批次"}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function redemptionBatchCSVData(batch) {
  return {
    batchId: batchID(batch),
    type: batch?.type || batch?.kind || "traffic",
    trafficBytes: finiteNumber(batch?.trafficBytes, 0),
    vipPlan: batch?.vipPlan || "",
    expiresAt: finiteNumber(batch?.expiresAt, 0),
    note: batch?.note || "",
    codes: Array.isArray(batch?.codes)
      ? batch.codes.filter((item) => item?.codeAvailable && plainCode(item))
      : [],
  };
}

function cleanSecrets(secrets) {
  return Object.fromEntries(
    Object.entries(secrets).filter(([, value]) => String(value).length > 0),
  );
}

function validate(form, runtime, secrets) {
  if (form.registration.open && !runtime.emailActive) {
    return "真实邮件投递尚未生效，当前不能开放注册。";
  }
  if (!parseList(form.registration.allowedDomains).length) {
    return "请至少保留一个允许注册的邮箱域名。";
  }
  if (form.registration.requireTerms) {
    if (
      !String(form.terms.version).trim() ||
      !String(form.terms.title).trim()
    ) {
      return "启用条款确认时，必须填写条款版本和标题。";
    }
    if (String(form.terms.content).trim().length < 200) {
      return "条款正文过短，请补充完整的用户协议、隐私与可接受使用规则。";
    }
    if (!form.terms.effectiveAt) return "请设置条款生效时间。";
  }
  if (
    form.defaults.guestMaxFileBytes > 100 * MIB ||
    form.defaults.guestMaxTransferBytes > 100 * MIB
  ) {
    return "游客单次上传总量不得超过 100 MiB。";
  }
  if (form.smtp.enabled) {
    if (!SMTP_PRESETS[form.smtp.provider])
      return "请选择受支持的 SMTP 服务商。";
    if (!String(form.smtp.username).trim() || !String(form.smtp.from).trim()) {
      return "启用 SMTP 前必须填写登录账号和发件地址。";
    }
    if (!form.smtp.passwordConfigured && !secrets.smtpPassword) {
      return "启用 SMTP 前必须填写授权码或应用专用密码。";
    }
  }
  if (form.captcha.enabled) {
    if (form.captcha.provider === "turnstile") {
      if (!String(form.captcha.siteKey).trim())
        return "请填写 Turnstile Site Key。";
      if (!form.captcha.secretConfigured && !secrets.turnstileSecret) {
        return "请填写 Turnstile Secret Key。";
      }
    }
    if (form.captcha.provider === "tencent") {
      const appId = Number(form.captcha.tencentCaptchaAppId);
      if (!Number.isSafeInteger(appId) || appId <= 0)
        return "请填写有效的腾讯云 CaptchaAppId。";
      if (
        !form.captcha.tencentCredentialsConfigured &&
        (!secrets.tencentAppSecretKey ||
          !secrets.tencentSecretId ||
          !secrets.tencentSecretKey)
      ) {
        return "请完整填写腾讯云 AppSecretKey、SecretId 和 SecretKey。";
      }
    }
    if (!Object.values(form.captcha.actions).some(Boolean)) {
      return "启用人机验证时，请至少选择一个关键操作。";
    }
  }
  return "";
}

function Toggle({ checked, onChange, label, detail, disabled = false }) {
  return (
    <label className={`admin-settings-toggle${disabled ? " is-disabled" : ""}`}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        disabled={disabled}
      />
      <span>
        <strong>{label}</strong>
        {detail && <small>{detail}</small>}
      </span>
    </label>
  );
}

function Field({ label, hint, wide = false, children }) {
  return (
    <label className={`admin-settings-field${wide ? " is-wide" : ""}`}>
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}

function NumberField({
  label,
  value,
  onChange,
  min = 0,
  max,
  step = 1,
  hint,
  disabled = false,
}) {
  return (
    <Field label={label} hint={hint}>
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        step={step}
        disabled={disabled}
        onChange={(event) =>
          onChange(Math.max(min, finiteNumber(event.target.value, min)))
        }
      />
    </Field>
  );
}

function ByteField({ label, value, unit = "MiB", onChange, max, hint }) {
  const multiplier = unit === "GiB" ? GIB : MIB;
  const displayValue =
    Math.round((finiteNumber(value, 0) / multiplier) * 100) / 100;
  return (
    <Field label={`${label}（${unit}）`} hint={hint}>
      <input
        type="number"
        value={displayValue}
        min="0"
        max={max}
        step="1"
        onChange={(event) =>
          onChange(
            Math.max(
              0,
              Math.round(finiteNumber(event.target.value, 0) * multiplier),
            ),
          )
        }
      />
    </Field>
  );
}

function SectionHeading({ eyebrow, title, detail, icon: Icon }) {
  return (
    <div className="admin-settings-section-heading">
      <span className="admin-settings-section-icon">
        <Icon />
      </span>
      <div>
        <span>{eyebrow}</span>
        <h2>{title}</h2>
        <p>{detail}</p>
      </div>
    </div>
  );
}

function StatusBadge({
  ready,
  readyText = "已就绪",
  pendingText = "尚未就绪",
}) {
  return (
    <span
      className={`admin-settings-badge${ready ? " is-ready" : " is-pending"}`}
    >
      {ready ? <CheckCircle weight="fill" /> : <WarningCircle weight="fill" />}
      {ready ? readyText : pendingText}
    </span>
  );
}

function AccessState({ navigate, signedIn, unauthorized = false }) {
  return (
    <div className="page-frame inner-page admin-settings-page">
      <main className="admin-settings-access">
        <span>
          <LockKey />
        </span>
        <p>管理员专属入口</p>
        <h1>{unauthorized ? "没有管理员权限" : "需要管理员登录"}</h1>
        <small>
          {unauthorized
            ? "系统设置只对管理员开放。"
            : "登录管理员账户后才能读取或修改系统配置。"}
        </small>
        <button
          type="button"
          onClick={() => navigate(signedIn ? "/" : "/login")}
        >
          <ArrowLeft /> {signedIn ? "返回首页" : "前往登录"}
        </button>
      </main>
		</div>
	);
}

function AdminUserDetailModal({ detail: selectedUserDetail, onClose }) {
	if (!selectedUserDetail) return null;
	return (
			<div className="admin-user-modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
				<section className="admin-user-modal" role="dialog" aria-modal="true" aria-labelledby="admin-user-detail-title">
					<header>
						<div>
							<span>用户运营档案</span>
							<h2 id="admin-user-detail-title">{selectedUserDetail.user?.username || "未设置用户名"}</h2>
							<p>{selectedUserDetail.user?.email} · {selectedUserDetail.user?.id}</p>
						</div>
						<button className="admin-icon-button" type="button" aria-label="关闭用户详情" onClick={onClose}><X /></button>
					</header>

					<div className="admin-user-modal-body">
						<div className="admin-user-detail-stats">
							<article><small>剩余上传流量</small><strong>{formatBytes(selectedUserDetail.user?.remainingUploadTrafficBytes)}</strong><span>基础 {formatBytes(selectedUserDetail.user?.baseTrafficRemainingBytes)} · 权益 {formatBytes(selectedUserDetail.user?.entitlementTrafficRemainingBytes)}</span></article>
							<article><small>已生效充值</small><strong>{finiteNumber(selectedUserDetail.user?.paidOrderCount, 0)} 笔</strong><span>退款 {finiteNumber(selectedUserDetail.user?.refundedOrderCount, 0)} 笔</span></article>
							<article><small>现金支付累计</small><strong>¥{(finiteNumber(selectedUserDetail.user?.cashPaidCents, 0) / 100).toFixed(2)}</strong><span>积分消费 {finiteNumber(selectedUserDetail.user?.pointsSpent, 0)}</span></article>
							<article><small>累计上传扣费</small><strong>{formatBytes(selectedUserDetail.user?.trafficConsumedBytes)}</strong><span>当前预留 {formatBytes(selectedUserDetail.user?.trafficReservedBytes)}</span></article>
						</div>

						<section className="admin-user-detail-section">
							<div className="admin-settings-subheading"><div><strong>账户信息</strong><span>身份、验证、等级与最近活动。</span></div></div>
							<div className="admin-user-facts">
								<span><small>账户角色</small><strong>{roleLabel(selectedUserDetail.user?.role)}</strong></span>
								<span><small>账户等级</small><strong>{tierLabel(selectedUserDetail.user?.vipPlan || selectedUserDetail.user?.level)}</strong></span>
								<span><small>VIP 有效期</small><strong>{selectedUserDetail.user?.vipPlan === "lifetime" ? "永久" : selectedUserDetail.user?.vipExpiresAt ? formatDate(selectedUserDetail.user.vipExpiresAt) : "无 VIP"}</strong></span>
								<span><small>账户状态</small><strong>{userStatusLabel(selectedUserDetail.user?.status)}</strong></span>
								<span><small>邮箱验证</small><strong>{selectedUserDetail.user?.verifiedAt ? formatDate(selectedUserDetail.user.verifiedAt) : "尚未验证"}</strong></span>
								<span><small>最近登录</small><strong>{selectedUserDetail.user?.lastLoginAt ? formatDate(selectedUserDetail.user.lastLoginAt) : "从未登录"}</strong></span>
								<span><small>注册时间</small><strong>{formatDate(selectedUserDetail.user?.createdAt)}</strong></span>
								<span><small>积分余额</small><strong>{finiteNumber(selectedUserDetail.user?.points, 0)}</strong></span>
							</div>
						</section>

						<section className="admin-user-detail-section">
							<div className="admin-settings-subheading"><div><strong>流量与福利</strong><span>累计权益、签到、会员日赠与兑换记录。</span></div></div>
							<div className="admin-user-facts is-compact">
								<span><small>权益累计发放</small><strong>{formatBytes(selectedUserDetail.user?.trafficGrantedBytes)}</strong></span>
								<span><small>签到累计</small><strong>{finiteNumber(selectedUserDetail.user?.checkInDays, 0)} 天 · {formatBytes(selectedUserDetail.user?.checkInTrafficBytes)}</strong></span>
								<span><small>会员登录赠送</small><strong>{finiteNumber(selectedUserDetail.user?.vipDailyGrantDays, 0)} 天 · {formatBytes(selectedUserDetail.user?.vipDailyTrafficBytes)}</strong></span>
								<span><small>兑换次数</small><strong>{finiteNumber(selectedUserDetail.user?.redemptionCount, 0)} 次</strong></span>
							</div>
							<div className="admin-settings-table-scroll">
								<table className="admin-settings-table"><thead><tr><th>权益来源</th><th>发放流量</th><th>剩余流量</th><th>发放时间</th></tr></thead><tbody>
									{(selectedUserDetail.entitlements || []).map((item) => <tr key={item.id}><td>{entitlementSourceLabel(item.sourceType)}</td><td>{formatBytes(item.amountBytes)}</td><td>{formatBytes(item.remainingBytes)}</td><td>{formatDate(item.createdAt)}</td></tr>)}
									{!(selectedUserDetail.entitlements || []).length && <tr><td colSpan="4" className="admin-empty-cell">暂无流量权益记录。</td></tr>}
								</tbody></table>
							</div>
						</section>

						<section className="admin-user-detail-section">
							<div className="admin-settings-subheading"><div><strong>充值与订单</strong><span>最多展示最近 200 笔订单。</span></div></div>
							<div className="admin-settings-table-scroll"><table className="admin-settings-table"><thead><tr><th>商品</th><th>支付方式</th><th>金额</th><th>状态</th><th>创建时间</th></tr></thead><tbody>
								{(selectedUserDetail.orders || []).map((order) => <tr key={order.id}><td><strong>{order.productName}</strong><small>{order.id}</small></td><td>{paymentMethodLabel(order.paymentMethod)}</td><td>{order.paymentMethod === "points" ? `${finiteNumber(order.pointsPrice, 0)} 积分` : `¥${(finiteNumber(order.priceCents, 0) / 100).toFixed(2)}`}</td><td>{orderStatusLabel(order.status)}</td><td>{formatDate(order.createdAt)}</td></tr>)}
								{!(selectedUserDetail.orders || []).length && <tr><td colSpan="5" className="admin-empty-cell">暂无充值或订单记录。</td></tr>}
							</tbody></table></div>
						</section>

						<section className="admin-user-detail-section admin-user-detail-split">
							<div>
								<div className="admin-settings-subheading"><div><strong>兑换记录</strong><span>完整兑换码与使用时间。</span></div></div>
								<div className="admin-settings-table-scroll"><table className="admin-settings-table"><thead><tr><th>兑换码</th><th>状态</th><th>时间</th></tr></thead><tbody>
									{(selectedUserDetail.redemptions || []).map((item) => <tr key={item.id}><td><code>{item.codeAvailable ? item.code : "旧批次未保存明文"}</code></td><td>{redemptionCodeStatusLabel(item.status)}</td><td>{formatDate(item.redeemedAt)}</td></tr>)}
									{!(selectedUserDetail.redemptions || []).length && <tr><td colSpan="3" className="admin-empty-cell">暂无兑换记录。</td></tr>}
								</tbody></table></div>
							</div>
							<div>
								<div className="admin-settings-subheading"><div><strong>积分明细</strong><span>最多展示最近 200 条。</span></div></div>
								<div className="admin-settings-table-scroll"><table className="admin-settings-table"><thead><tr><th>原因</th><th>变化</th><th>余额</th><th>时间</th></tr></thead><tbody>
									{(selectedUserDetail.pointsLedger || []).map((item) => <tr key={item.id}><td>{item.reason}</td><td>{item.delta > 0 ? `+${item.delta}` : item.delta}</td><td>{item.balanceAfter}</td><td>{formatDate(item.createdAt)}</td></tr>)}
									{!(selectedUserDetail.pointsLedger || []).length && <tr><td colSpan="4" className="admin-empty-cell">暂无积分记录。</td></tr>}
								</tbody></table></div>
							</div>
						</section>

						<section className="admin-user-detail-section">
							<div className="admin-settings-subheading"><div><strong>文件传输</strong><span>累计 {finiteNumber(selectedUserDetail.user?.transferCount, 0)} 个任务，当前活跃 {finiteNumber(selectedUserDetail.user?.activeTransferCount, 0)} 个。</span></div></div>
							<div className="admin-settings-table-scroll"><table className="admin-settings-table"><thead><tr><th>任务</th><th>文件与总量</th><th>领取次数</th><th>状态</th><th>创建时间</th></tr></thead><tbody>
								{(selectedUserDetail.recentTransfers || []).map((item) => <tr key={item.id}><td><strong>{item.title || "未命名任务"}</strong><small>{item.kind === "collection" ? "收集文件" : "发送文件"}</small></td><td>{finiteNumber(item.fileCount, 0)} 个 · {formatBytes(item.totalBytes)}</td><td>{finiteNumber(item.downloads, 0)} / {finiteNumber(item.maxDownloads, 0)}</td><td>{item.status}</td><td>{formatDate(item.createdAt)}</td></tr>)}
								{!(selectedUserDetail.recentTransfers || []).length && <tr><td colSpan="5" className="admin-empty-cell">暂无传输记录。</td></tr>}
							</tbody></table></div>
						</section>
					</div>
				</section>
			</div>
	);
}

export function AdminSettingsPage({ navigate, me, config, api }) {
  const role = me?.user?.role || me?.role;
  const adminEmail = me?.user?.email || me?.email || "当前管理员邮箱";
  const adminName = me?.user?.username || me?.username || "管理员";
  const getAdminSettings = api?.getAdminSettings;
	const refreshPublicConfig = api?.refreshPublicConfig;
  const updateAdminSettings = api?.updateAdminSettings;
  const testAdminSMTP = api?.testAdminSMTP;
  const getAdminOverview = api?.getAdminOverview;
  const getAdminUsers = api?.getAdminUsers;
  const getAdminUserDetail = api?.getAdminUserDetail;
  const setAdminUserStatus = api?.setAdminUserStatus;
  const getAdminReports = api?.getAdminReports;
  const setAdminReportStatus = api?.setAdminReportStatus;
  const getAdminOrders = api?.getAdminOrders;
  const refundAdminOrder = api?.refundAdminOrder;
  const getAdminRedemptionBatches =
    api?.getAdminRedemptionBatches || api?.getAdminRedemptions;
  const createAdminRedemptionBatch = api?.createAdminRedemptionBatch;
  const disableAdminRedemptionBatch = api?.disableAdminRedemptionBatch;
  const [activeTab, setActiveTab] = useState("registration");
  const [form, setForm] = useState(() => normalizeSettings(EMPTY_SETTINGS));
  const [runtime, setRuntime] = useState(() => normalizeRuntime());
  const [secrets, setSecrets] = useState(EMPTY_SECRETS);
  const [busy, setBusy] = useState("idle");
  const [loaded, setLoaded] = useState(false);
  const setNotice = useCallback((next) => {
    if (next?.message) showToast(next.message, next.tone || "info");
  }, []);
  const [loadError, setLoadError] = useState("");
  const [operations, setOperations] = useState({
    overview: null,
    users: [],
    reports: [],
    orders: [],
  });
  const [operationsLoaded, setOperationsLoaded] = useState(false);
  const [operationsBusy, setOperationsBusy] = useState("");
  const [operationsError, setOperationsError] = useState("");
	const [userQuery, setUserQuery] = useState("");
	const [selectedUserDetail, setSelectedUserDetail] = useState(null);
	const [userDetailBusy, setUserDetailBusy] = useState("");
  const [redemptionForm, setRedemptionForm] = useState(
    EMPTY_REDEMPTION_FORM,
  );
  const [redemptionBatches, setRedemptionBatches] = useState([]);
  const [redemptionsLoaded, setRedemptionsLoaded] = useState(false);
  const [redemptionBusy, setRedemptionBusy] = useState("");
  const [redemptionsError, setRedemptionsError] = useState("");
  const [createdRedemption, setCreatedRedemption] = useState(null);
  const baselineRef = useRef("");
	const filteredUsers = useMemo(() => {
		const query = userQuery.trim().toLowerCase();
		if (!query) return operations.users;
		return operations.users.filter((user) =>
			[user.username, user.email, user.id, tierLabel(user.vipPlan || user.level)]
				.filter(Boolean)
				.some((value) => String(value).toLowerCase().includes(query)),
		);
	}, [operations.users, userQuery]);

  const setSection = useCallback((section, key, value) => {
    setForm((current) => ({
      ...current,
      [section]: { ...current[section], [key]: value },
    }));
  }, []);

  const applyEnvelope = useCallback(
    (result, fallbackSettings) => {
      const sourceSettings =
        result?.settings || fallbackSettings || EMPTY_SETTINGS;
      const normalized = normalizeSettings(sourceSettings);
      const nextRuntime = normalizeRuntime(
        result?.runtime || {
          ...runtime,
          restartRequired: result?.restartRequired ?? runtime.restartRequired,
        },
      );
      setForm(normalized);
      setRuntime(nextRuntime);
      setSecrets(EMPTY_SECRETS);
      baselineRef.current = JSON.stringify(normalized);
      setLoaded(true);
      return normalized;
    },
    [runtime],
  );

  const load = useCallback(
    async ({ announce = true } = {}) => {
      if (typeof getAdminSettings !== "function") {
        setLoadError("管理设置接口尚未接入。");
        return;
      }
      setBusy("loading");
      setLoadError("");
      try {
        const result = await getAdminSettings();
        const sourceSettings = result?.settings || result;
        const normalized = normalizeSettings(sourceSettings);
        setForm(normalized);
        setRuntime(normalizeRuntime(result?.runtime));
        setSecrets(EMPTY_SECRETS);
        baselineRef.current = JSON.stringify(normalized);
        setLoaded(true);
        setLoadError("");
        setNotice(
          announce
            ? {
                tone: "success",
                message: `已读取配置版本 r${normalized.revision}。`,
              }
            : { tone: "", message: "" },
        );
      } catch (error) {
        setLoadError(error?.message || "无法读取管理员设置。");
      } finally {
        setBusy("idle");
      }
    },
    [getAdminSettings],
  );

  useEffect(() => {
    if (role === "admin") void load({ announce: false });
  }, [load, role]);

  const hasSecretChanges = useMemo(
    () => Object.values(secrets).some((value) => String(value).length > 0),
    [secrets],
  );
  const dirty = useMemo(
    () =>
      loaded &&
      (JSON.stringify(form) !== baselineRef.current || hasSecretChanges),
    [form, hasSecretChanges, loaded],
  );

  const changeProvider = (provider) => {
    const preset = SMTP_PRESETS[provider];
    setForm((current) => ({
      ...current,
      smtp: { ...current.smtp, provider, ...preset, passwordConfigured: false },
    }));
    setSecrets((current) => ({ ...current, smtpPassword: "" }));
  };

  const changeCaptchaProvider = (provider) => {
    setForm((current) => ({
      ...current,
      captcha: {
        ...current.captcha,
        enabled: provider !== "disabled",
        provider,
      },
    }));
  };

  const save = async (event) => {
    event.preventDefault();
    if (typeof updateAdminSettings !== "function") {
      setNotice({ tone: "error", message: "管理设置保存接口尚未接入。" });
      return;
    }
    const validationError = validate(form, runtime, secrets);
    if (validationError) {
      setNotice({ tone: "error", message: validationError });
      return;
    }

    const submittedSettings = payloadSettings(form);
    setBusy("saving");
    try {
      const result = await updateAdminSettings({
        settings: submittedSettings,
        secrets: cleanSecrets(secrets),
      });
      const fallback = { ...submittedSettings, revision: form.revision + 1 };
      const normalized = applyEnvelope(result, fallback);
			if (typeof refreshPublicConfig === "function") {
				await refreshPublicConfig();
			}
      setNotice({
        tone: "success",
        message: `配置已安全保存为 r${normalized.revision}${result?.restartRequired || result?.runtime?.restartRequired ? "，部分设置需重启服务后生效" : ""}。`,
      });
    } catch (error) {
      const conflict =
        error?.status === 409 || error?.code === "settings_revision_conflict";
      setNotice({
        tone: "error",
        message: conflict
          ? "配置已被其他管理员更新。请重新读取后核对并再次保存。"
          : error?.message || "保存设置失败。",
      });
    } finally {
      setBusy("idle");
    }
  };

  const testSMTP = async () => {
    if (typeof testAdminSMTP !== "function") {
      setNotice({ tone: "error", message: "SMTP 测试接口尚未接入。" });
      return;
    }
    if (dirty) {
      setNotice({
        tone: "error",
        message: "请先保存当前 SMTP 配置，再发送测试邮件。",
      });
      return;
    }
    if (!form.smtp.enabled) {
      setNotice({ tone: "error", message: "请先启用并保存 SMTP 配置。" });
      return;
    }
    const recipient = String(
      form.smtp.username || form.smtp.from || adminEmail,
    ).trim();
    setBusy("smtp-test");
    try {
      await testAdminSMTP({ recipient });
      const refreshed = await getAdminSettings();
      const normalized = applyEnvelope(refreshed, form);
			if (typeof refreshPublicConfig === "function") {
				await refreshPublicConfig();
			}
      setNotice({
        tone: "success",
        message: `测试邮件已发送至 ${recipient}，设置已刷新为 r${normalized.revision}。`,
      });
    } catch (error) {
      setNotice({
        tone: "error",
        message: error?.message || "SMTP 测试失败。",
      });
    } finally {
      setBusy("idle");
    }
  };

  const loadOperations = useCallback(
    async ({ announce = true } = {}) => {
      const readers = [
        getAdminOverview,
        getAdminUsers,
        getAdminReports,
        getAdminOrders,
      ];
      if (readers.some((reader) => typeof reader !== "function")) {
        setOperationsError("运营管理接口尚未完整接入。");
        return;
      }
      setOperationsBusy("loading");
      setOperationsError("");
      try {
        const [overview, users, reports, orders] = await Promise.all(
          readers.map((reader) => reader()),
        );
        setOperations({
          overview: overview || {},
          users: Array.isArray(users?.users) ? users.users : [],
          reports: Array.isArray(reports?.reports) ? reports.reports : [],
          orders: Array.isArray(orders?.orders) ? orders.orders : [],
        });
        setOperationsLoaded(true);
        setOperationsError("");
        if (announce)
          setNotice({ tone: "success", message: "运营数据已刷新。" });
      } catch (error) {
        setOperationsError(error?.message || "运营数据读取失败。");
      } finally {
        setOperationsBusy("");
      }
    },
    [getAdminOrders, getAdminOverview, getAdminReports, getAdminUsers],
  );

  const loadRedemptions = useCallback(
    async ({ announce = true } = {}) => {
      if (typeof getAdminRedemptionBatches !== "function") {
        setRedemptionsError("兑换码管理接口尚未接入。");
        return;
      }
      setRedemptionBusy("loading");
      setRedemptionsError("");
      try {
        const result = await getAdminRedemptionBatches();
        setRedemptionBatches(
          Array.isArray(result?.batches)
            ? result.batches
            : Array.isArray(result)
              ? result
              : [],
        );
        setRedemptionsLoaded(true);
        setRedemptionsError("");
        if (announce)
          setNotice({ tone: "success", message: "兑换码批次已刷新。" });
      } catch (error) {
        setRedemptionsError(error?.message || "兑换码批次读取失败。");
      } finally {
        setRedemptionBusy("");
      }
    },
    [getAdminRedemptionBatches],
  );

  const updateUser = async (user) => {
    if (typeof setAdminUserStatus !== "function") {
      setNotice({ tone: "error", message: "用户状态接口尚未接入。" });
      return;
    }
    const status = user.status === "blocked" ? "active" : "blocked";
    const username = user.username || "该用户";
    if (
      status === "blocked" &&
      !window.confirm(`确认停用用户“${username}”并撤销其登录会话？`)
    )
      return;
    setOperationsBusy(`user:${user.id}`);
    try {
      await setAdminUserStatus(user.id, status);
      await loadOperations({ announce: false });
      setNotice({
        tone: "success",
        message: status === "blocked" ? "用户已停用。" : "用户已恢复。",
      });
    } catch (error) {
      setNotice({ tone: "error", message: error?.message || "用户状态修改失败。" });
    } finally {
      setOperationsBusy("");
    }
  };

	const viewUserDetail = async (user) => {
		if (typeof getAdminUserDetail !== "function") {
			setNotice({ tone: "error", message: "用户详情接口尚未接入。" });
			return;
		}
		setUserDetailBusy(user.id);
		try {
			const detail = await getAdminUserDetail(user.id);
			setSelectedUserDetail(detail);
		} catch (error) {
			setNotice({ tone: "error", message: error?.message || "用户详情读取失败。" });
		} finally {
			setUserDetailBusy("");
		}
	};

	useEffect(() => {
		if (!selectedUserDetail) return undefined;
		const closeOnEscape = (event) => {
			if (event.key === "Escape") setSelectedUserDetail(null);
		};
		window.addEventListener("keydown", closeOnEscape);
		return () => window.removeEventListener("keydown", closeOnEscape);
	}, [selectedUserDetail]);

  const updateReport = async (report, status) => {
    if (typeof setAdminReportStatus !== "function") {
      setNotice({ tone: "error", message: "举报处置接口尚未接入。" });
      return;
    }
    setOperationsBusy(`report:${report.id}`);
    try {
      await setAdminReportStatus(report.id, status);
      await loadOperations({ announce: false });
      setNotice({ tone: "success", message: "举报状态已更新。" });
    } catch (error) {
      setNotice({ tone: "error", message: error?.message || "举报处置失败。" });
    } finally {
      setOperationsBusy("");
    }
  };

  const refundOrder = async (order) => {
    if (typeof refundAdminOrder !== "function") {
      setNotice({ tone: "error", message: "退款接口尚未接入。" });
      return;
    }
    if (!window.confirm(`确认处理“${order.productName || "该订单"}”退款？`))
      return;
    setOperationsBusy(`order:${order.id}`);
    try {
      await refundAdminOrder(order.id);
      await loadOperations({ announce: false });
      setNotice({ tone: "success", message: "退款处理已提交。" });
    } catch (error) {
      setNotice({ tone: "error", message: error?.message || "退款处理失败。" });
    } finally {
      setOperationsBusy("");
    }
  };

  const createRedemptionBatch = async () => {
    if (typeof createAdminRedemptionBatch !== "function") {
      setNotice({ tone: "error", message: "兑换码生成接口尚未接入。" });
      return;
    }
    const count = Math.trunc(finiteNumber(redemptionForm.count, 0));
    if (count < 1 || count > 500) {
      setNotice({ tone: "error", message: "单个批次只能生成 1 至 500 个兑换码。" });
      return;
    }
    if (
      redemptionForm.type === "traffic" &&
      finiteNumber(redemptionForm.trafficGiB, 0) <= 0
    ) {
      setNotice({ tone: "error", message: "请输入大于 0 的上传流量值。" });
      return;
    }
    const expiresAt = toUnixSeconds(redemptionForm.expiresAt);
    if (redemptionForm.expiresAt && expiresAt * 1000 <= Date.now()) {
      setNotice({ tone: "error", message: "失效时间必须晚于当前时间。" });
      return;
    }

    setRedemptionBusy("creating");
    setCreatedRedemption(null);
    try {
      const payload = {
        type: redemptionForm.type,
        count,
        trafficBytes:
          redemptionForm.type === "traffic"
            ? Math.round(finiteNumber(redemptionForm.trafficGiB, 0) * GIB)
            : 0,
        vipPlan:
          redemptionForm.type === "vip" ? redemptionForm.vipPlan : "",
        expiresAt,
        note: String(redemptionForm.note || "").trim(),
      };
      const result = await createAdminRedemptionBatch(payload);
      const codes = Array.isArray(result?.codes)
        ? result.codes
        : Array.isArray(result?.plainCodes)
          ? result.plainCodes
          : Array.isArray(result?.redemptionCodes)
            ? result.redemptionCodes
            : [];
      const batch = result?.batch || result || {};
      const created = {
        ...payload,
        batchId: batchID(batch),
        trafficGiB: redemptionForm.trafficGiB,
        codes,
      };
      setCreatedRedemption(created);
      setRedemptionForm((current) => ({
        ...EMPTY_REDEMPTION_FORM,
        type: current.type,
        vipPlan: current.vipPlan,
      }));
      await loadRedemptions({ announce: false });
      setNotice({
        tone: codes.length ? "success" : "error",
        message: codes.length
          ? `已生成 ${codes.length} 个一次性兑换码，可随时在批次详情查看。`
          : "批次已创建，但服务端没有返回兑换码内容。",
      });
    } catch (error) {
      setNotice({ tone: "error", message: error?.message || "兑换码生成失败。" });
    } finally {
      setRedemptionBusy("");
    }
  };

  const disableRedemptionBatch = async (batch) => {
    if (typeof disableAdminRedemptionBatch !== "function") {
      setNotice({ tone: "error", message: "兑换码停用接口尚未接入。" });
      return;
    }
    const id = batchID(batch);
    if (!id || !window.confirm("确认停用这个批次中尚未兑换的兑换码？"))
      return;
    setRedemptionBusy(`disable:${id}`);
    try {
      await disableAdminRedemptionBatch(id);
      await loadRedemptions({ announce: false });
      setNotice({ tone: "success", message: "兑换码批次已停用。" });
    } catch (error) {
      setNotice({ tone: "error", message: error?.message || "批次停用失败。" });
    } finally {
      setRedemptionBusy("");
    }
  };

  const reload = () => {
    if (activeTab === "operations") {
      void loadOperations();
      return;
    }
    if (activeTab === "redemption") {
      void loadRedemptions();
      return;
    }
    if (dirty && !window.confirm("重新读取会丢弃尚未保存的修改，是否继续？"))
      return;
    void load();
  };

  useEffect(() => {
    if (role !== "admin") return;
    if (activeTab === "operations" && !operationsLoaded)
      void loadOperations({ announce: false });
    if (activeTab === "redemption" && !redemptionsLoaded)
      void loadRedemptions({ announce: false });
  }, [
    activeTab,
    loadOperations,
    loadRedemptions,
    operationsLoaded,
    redemptionsLoaded,
    role,
  ]);

  if (!me) return <AccessState navigate={navigate} signedIn={false} />;
  if (role !== "admin")
    return <AccessState navigate={navigate} signedIn unauthorized />;

  const currentTab = TABS.find((tab) => tab.id === activeTab) || TABS[0];
  const saving = busy === "saving";
  const loading = busy === "loading";
  const isSettingsTab = SETTINGS_TABS.has(activeTab);
  const captchaConfigured =
    !form.captcha.enabled ||
    (form.captcha.provider === "turnstile"
      ? Boolean(
          String(form.captcha.siteKey).trim() &&
            (form.captcha.secretConfigured || secrets.turnstileSecret),
        )
      : form.captcha.provider === "tencent"
        ? Boolean(
            Number(form.captcha.tencentCaptchaAppId) > 0 &&
              (form.captcha.tencentCredentialsConfigured ||
                (secrets.tencentAppSecretKey &&
                  secrets.tencentSecretId &&
                  secrets.tencentSecretKey)),
          )
        : false);

  return (
    <div className="page-frame inner-page admin-settings-page">
      <header className="admin-settings-header">
        <button
          className="admin-settings-back"
          type="button"
          onClick={() => navigate("/")}
        >
          <ArrowLeft /> 返回首页
        </button>
        <div className="admin-settings-title">
          <span>
            <ShieldCheck weight="fill" />
          </span>
          <div>
            <small>管理员设置</small>
            <strong>系统设置</strong>
          </div>
        </div>
        <div className="admin-settings-header-actions">
          <span>配置版本 r{form.revision}</span>
          <button type="button" onClick={reload} disabled={loading || saving}>
            <Database /> 重新读取
          </button>
        </div>
      </header>

      <main className="admin-settings-layout">
        <section className="admin-settings-intro">
          <div>
            <span>系统设置与运营管理</span>
            <h1>一处完成配置与日常处置。</h1>
            <p>
              注册、邮件、人机验证、流量等级、兑换码与运营操作统一管理；密钥只写入服务器。
            </p>
          </div>
          <div className="admin-settings-intro-status">
            <StatusBadge
              ready={runtime.emailActive}
              readyText="真实邮件已启用"
              pendingText="邮件尚未生效"
            />
            <StatusBadge
              ready={runtime.productionScanner}
              readyText="生产扫描器已就绪"
              pendingText="扫描能力未达生产要求"
            />
          </div>
        </section>

        {loadError && (
          <div className="admin-settings-callout is-warning" role="alert">
            <WarningCircle weight="fill" />
            <div>
              <strong>系统设置读取失败</strong>
              <span>{loadError}</span>
            </div>
            <button
              className="admin-inline-button"
              type="button"
              onClick={() => void load({ announce: false })}
            >
              重新读取
            </button>
          </div>
        )}

        <div className="admin-settings-workspace">
          <nav
            className="admin-settings-tabs"
            role="tablist"
            aria-label="系统设置分区"
          >
            {TABS.map(({ id, label, icon: Icon }) => (
              <button
                id={`settings-tab-${id}`}
                key={id}
                type="button"
                role="tab"
                aria-selected={activeTab === id}
                aria-controls={`settings-panel-${id}`}
                className={activeTab === id ? "is-active" : ""}
                onClick={() => setActiveTab(id)}
              >
                <Icon />
                <span>{label}</span>
              </button>
            ))}
          </nav>

          <form className="admin-settings-panel" onSubmit={save}>
            <section
              id={`settings-panel-${activeTab}`}
              role="tabpanel"
              aria-labelledby={`settings-tab-${activeTab}`}
              tabIndex="0"
            >
              {activeTab === "registration" && (
                <>
                  <SectionHeading
                    eyebrow="注册管理"
                    title="注册与条款"
                    detail="只有真实邮件投递和有效条款均就绪后，系统才允许开放注册。"
                    icon={currentTab.icon}
                  />
                  {!runtime.emailActive && (
                    <div className="admin-settings-callout is-warning">
                      <WarningCircle weight="fill" />
                      <div>
                        <strong>注册开关受到保护</strong>
                        <span>
                          SMTP
                          尚未处于可投递状态，当前不能把注册从关闭切换为开放。
                        </span>
                      </div>
                    </div>
                  )}
                  <div className="admin-settings-toggle-stack">
                    <Toggle
                      checked={form.registration.open}
                      onChange={(checked) =>
                        setSection("registration", "open", checked)
                      }
                      disabled={!runtime.emailActive && !form.registration.open}
                      label="开放用户注册"
                      detail="关闭后不再发送注册验证码，已有用户仍可正常登录。"
                    />
                    <Toggle
                      checked
                      onChange={() => {}}
                      disabled
                      label="注册时强制同意当前条款"
                      detail="安全基线强制启用：前端复选框和服务端版本校验必须同时通过。"
                    />
                  </div>
                  <div className="admin-settings-form-grid">
                    <Field
                      label="允许注册的邮箱域名"
                      hint="每行一个域名。建议仅保留 QQ、163 和 Gmail 等需要真实邮箱访问的服务。"
                      wide
                    >
                      <textarea
                        rows="5"
                        value={form.registration.allowedDomains}
                        onChange={(event) =>
                          setSection(
                            "registration",
                            "allowedDomains",
                            event.target.value,
                          )
                        }
                        spellCheck="false"
                        placeholder={"qq.com\n163.com\ngmail.com"}
                      />
                    </Field>
                  </div>

                  <div className="admin-settings-subsection">
                    <div className="admin-settings-subheading">
                      <div>
                        <strong>生效条款</strong>
                        <span>
                          历史版本应由后端留存，更新版本不会覆盖既有同意证据。
                        </span>
                      </div>
                      <StatusBadge
                        ready={Boolean(
                          form.terms.version && form.terms.content,
                        )}
                        readyText="正文已填写"
                        pendingText="正文不完整"
                      />
                    </div>
                    <div className="admin-settings-form-grid">
                      <Field label="版本号" hint="例如 2026-08-29.1">
                        <input
                          value={form.terms.version}
                          onChange={(event) =>
                            setSection("terms", "version", event.target.value)
                          }
                          maxLength="40"
                          placeholder="2026-08-29.1"
                        />
                      </Field>
                      <Field label="生效时间">
                        <input
                          type="datetime-local"
                          value={form.terms.effectiveAt}
                          onChange={(event) =>
                            setSection(
                              "terms",
                              "effectiveAt",
                              event.target.value,
                            )
                          }
                        />
                      </Field>
                      <Field label="条款标题" wide>
                        <input
                          value={form.terms.title}
                          onChange={(event) =>
                            setSection("terms", "title", event.target.value)
                          }
                          maxLength="120"
                        />
                      </Field>
                      <Field
                        label="完整条款正文"
                        hint="应覆盖用户协议、隐私政策、违禁内容、知识产权、文件保存与删除、举报处置、未成年人、付费退款及责任边界；上线前仍需由适用法域的专业人士复核。"
                        wide
                      >
                        <textarea
                          className="admin-settings-terms-editor"
                          rows="18"
                          value={form.terms.content}
                          onChange={(event) =>
                            setSection("terms", "content", event.target.value)
                          }
                          placeholder="在此维护正式生效的条款正文…"
                        />
                      </Field>
                    </div>
                  </div>
                </>
              )}

              {activeTab === "smtp" && (
                <>
                  <SectionHeading
                    eyebrow="邮件投递"
                    title="邮箱与 SMTP"
                    detail="仅允许预设的 QQ、163 和 Gmail SMTP；授权码只写入服务器，不会返回浏览器。"
                    icon={currentTab.icon}
                  />
                  <div className="admin-settings-subheading">
                    <div>
                      <strong>邮件投递状态</strong>
                      <span>
                        最近测试：{formatDate(form.smtp.lastTestedAt)}
                      </span>
                    </div>
                    <StatusBadge
                      ready={runtime.emailActive && form.smtp.lastTestSucceeded}
                      readyText="投递已验证"
                      pendingText={
                        form.smtp.lastTestSucceeded ? "等待生效" : "尚未验证"
                      }
                    />
                  </div>
                  <div className="admin-settings-toggle-stack">
                    <Toggle
                      checked={form.smtp.enabled}
                      onChange={(checked) =>
                        setSection("smtp", "enabled", checked)
                      }
                      label="启用真实邮件投递"
                      detail="启用前必须保存完整配置并向当前管理员邮箱完成测试。"
                    />
                  </div>
                  <div className="admin-settings-form-grid">
                    <Field label="SMTP 服务商">
                      <select
                        value={form.smtp.provider}
                        onChange={(event) => changeProvider(event.target.value)}
                      >
                        <option value="qq">QQ 邮箱</option>
                        <option value="163">163 邮箱</option>
                        <option value="gmail">Gmail</option>
                      </select>
                    </Field>
                    <Field
                      label="服务器地址"
                      hint="由服务商预设锁定，避免任意主机探测。"
                    >
                      <input
                        value={form.smtp.host}
                        readOnly
                        aria-readonly="true"
                      />
                    </Field>
                    <NumberField
                      label="端口"
                      value={form.smtp.port}
                      min={1}
                      max={65535}
                      disabled
                      hint="随服务商预设锁定。"
                      onChange={(value) => setSection("smtp", "port", value)}
                    />
                    <Field label="TLS 模式">
                      <select
                        value={form.smtp.tlsMode}
                        disabled
                        onChange={(event) =>
                          setSection("smtp", "tlsMode", event.target.value)
                        }
                      >
                        <option value="implicit">隐式 TLS</option>
                        <option value="starttls">STARTTLS</option>
                      </select>
                    </Field>
                    <Field label="认证方式">
                      <select
                        value={form.smtp.authMode}
                        disabled
                        onChange={(event) =>
                          setSection("smtp", "authMode", event.target.value)
                        }
                      >
                        <option value="login">LOGIN</option>
                        <option value="plain">PLAIN（仅在 TLS 内）</option>
                      </select>
                    </Field>
                    <Field label="登录账号">
                      <input
                        type="email"
                        value={form.smtp.username}
                        onChange={(event) =>
                          setSection("smtp", "username", event.target.value)
                        }
                        autoComplete="off"
                        placeholder="name@example.com"
                      />
                    </Field>
                    <Field label="发件地址">
                      <input
                        type="email"
                        value={form.smtp.from}
                        onChange={(event) =>
                          setSection("smtp", "from", event.target.value)
                        }
                        autoComplete="off"
                        placeholder="name@example.com"
                      />
                    </Field>
                    <Field label="发件人名称">
                      <input
                        value={form.smtp.fromName}
                        onChange={(event) =>
                          setSection("smtp", "fromName", event.target.value)
                        }
                        maxLength="80"
                      />
                    </Field>
                    <Field
                      label="授权码 / 应用专用密码"
                      hint={
                        form.smtp.passwordConfigured
                          ? "已配置。留空会保留现有密钥。"
                          : "尚未配置；启用 SMTP 前必须填写。"
                      }
                      wide
                    >
                      <input
                        type="password"
                        value={secrets.smtpPassword}
                        onChange={(event) =>
                          setSecrets((current) => ({
                            ...current,
                            smtpPassword: event.target.value,
                          }))
                        }
                        autoComplete="new-password"
                        placeholder={
                          form.smtp.passwordConfigured
                            ? "留空保留现有密钥"
                            : "输入服务商授权码"
                        }
                      />
                    </Field>
                  </div>
                  <div className="admin-settings-test-row">
                    <div>
                      <strong>安全投递测试</strong>
                      <span>
                        测试邮件固定发送至当前管理员邮箱 {adminEmail}
                        ，不能指定任意收件人。
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={testSMTP}
                      disabled={busy !== "idle" || dirty || !form.smtp.enabled}
                    >
                      <PaperPlaneTilt />{" "}
                      {busy === "smtp-test" ? "正在发送…" : "发送测试邮件"}
                    </button>
                  </div>
                </>
              )}

              {activeTab === "levels" && (
                <>
                  <SectionHeading
                    eyebrow="流量与账户等级"
                    title="流量与等级"
                    detail="账户不设置存储空间上限，只记录剩余上传流量；上传成功后扣流量，下载和重复下载均不扣流量。"
                    icon={currentTab.icon}
                  />
                  <div className="admin-settings-callout">
                    <ShieldCheck weight="fill" />
                    <div>
                      <strong>等级规则由服务端固定执行</strong>
                      <span>
                        以下单次上传总量、文件数量和保留规则不可在此调高；物理磁盘仍保留安全检查。
                      </span>
                    </div>
                  </div>
                  <div className="admin-level-grid">
                    {LEVEL_RULES.map((level) => (
                      <article className={`admin-level-card is-${level.id}`} key={level.id}>
                        <span className="admin-level-card-icon">
                          {level.id === "vip" || level.id === "lifetime" ? (
                            <Crown weight="fill" />
                          ) : (
                            <User weight="fill" />
                          )}
                        </span>
                        <div>
                          <strong>{level.name}</strong>
                          <span>{level.fileLimit}</span>
                          <span>{level.fileCount}</span>
                          <span>{level.retention}</span>
                        </div>
                      </article>
                    ))}
                  </div>
                  <div className="admin-settings-subsection">
                    <div className="admin-settings-subheading">
                      <div>
                        <strong>可配置的流量与滥用阈值</strong>
                        <span>设置注册用户首次获得的永久上传流量，以及游客每日防滥用上限。</span>
                      </div>
                    </div>
                    <div className="admin-settings-form-grid is-three-columns">
                      <ByteField
                        label="注册用户初始上传流量"
                        unit="GiB"
                        value={form.defaults.userMonthlyTrafficBytes}
                        onChange={(value) =>
                          setSection(
                            "defaults",
                            "userMonthlyTrafficBytes",
                            value,
                          )
                        }
                      />
                      <ByteField
                        label="游客每日上传流量"
                        unit="MiB"
                        value={form.defaults.guestDailyBytes}
                        onChange={(value) =>
                          setSection("defaults", "guestDailyBytes", value)
                        }
                      />
                      <NumberField
                        label="游客每日任务数"
                        value={form.defaults.guestDailyTasks}
                        min={1}
                        onChange={(value) =>
                          setSection("defaults", "guestDailyTasks", value)
                        }
                      />
                    </div>
                  </div>
                </>
              )}

              {activeTab === "captcha" && (
                <>
                  <SectionHeading
                    eyebrow="防机器滥用"
                    title="验证码与风控"
                    detail="用于注册、登录、找回、游客上传和兑换等容易被机器滥用的行为；管理员修改设置不需要人机验证。"
                    icon={currentTab.icon}
                  />
                  <div className="admin-settings-callout">
                    <ShieldCheck weight="fill" />
                    <div>
                      <strong>完整配置后才会保护所选操作</strong>
                      <span>
                        开启供应商时必须同时提供公开参数与服务器密钥；配置不完整将无法保存为启用状态。
                      </span>
                    </div>
                  </div>
                  <div className="admin-settings-form-grid">
                    <Field label="人机验证服务商">
                      <select
                        value={form.captcha.provider}
                        onChange={(event) =>
                          changeCaptchaProvider(event.target.value)
                        }
                      >
                        <option value="disabled">关闭</option>
                        <option value="turnstile">Cloudflare Turnstile</option>
                        <option value="tencent">腾讯云验证码</option>
                      </select>
                    </Field>
                    <div className="admin-settings-provider-state">
                      <span>服务状态</span>
                      <StatusBadge
                        ready={captchaConfigured}
                        readyText={
                          form.captcha.enabled ? "配置完整" : "当前关闭"
                        }
                        pendingText="配置尚未完成"
                      />
                    </div>
                  </div>

                  {form.captcha.provider === "turnstile" && (
                    <div className="admin-settings-form-grid">
                      <Field label="Turnstile Site Key">
                        <input
                          value={form.captcha.siteKey}
                          onChange={(event) =>
                            setSection("captcha", "siteKey", event.target.value)
                          }
                          autoComplete="off"
                        />
                      </Field>
                      <Field
                        label="Turnstile Secret Key"
                        hint={
                          form.captcha.secretConfigured
                            ? "已配置。留空会保留现有密钥。"
                            : "只写字段，保存后不会回显。"
                        }
                      >
                        <input
                          type="password"
                          value={secrets.turnstileSecret}
                          onChange={(event) =>
                            setSecrets((current) => ({
                              ...current,
                              turnstileSecret: event.target.value,
                            }))
                          }
                          autoComplete="new-password"
                          placeholder={
                            form.captcha.secretConfigured
                              ? "留空保留现有密钥"
                              : "输入 Secret Key"
                          }
                        />
                      </Field>
                      <Field
                        label="允许的主机名"
                        hint="每行一个正式域名；本地验收主机名应由后端环境策略单独控制。"
                        wide
                      >
                        <textarea
                          rows="4"
                          value={form.captcha.allowedHostnames}
                          onChange={(event) =>
                            setSection(
                              "captcha",
                              "allowedHostnames",
                              event.target.value,
                            )
                          }
                          spellCheck="false"
                          placeholder={"files.example.com\nshare.example.com"}
                        />
                      </Field>
                    </div>
                  )}

                  {form.captcha.provider === "tencent" && (
                    <div className="admin-settings-form-grid">
                      <Field label="腾讯云 CaptchaAppId">
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={form.captcha.tencentCaptchaAppId}
                          onChange={(event) =>
                            setSection(
                              "captcha",
                              "tencentCaptchaAppId",
                              event.target.value,
                            )
                          }
                          inputMode="numeric"
                          autoComplete="off"
                        />
                      </Field>
                      <Field
                        label="腾讯云 AppSecretKey"
                        hint={
                          form.captcha.tencentCredentialsConfigured
                            ? "凭据已配置。留空会保留现有值。"
                            : "验证码应用的只写密钥。"
                        }
                      >
                        <input
                          type="password"
                          value={secrets.tencentAppSecretKey}
                          onChange={(event) =>
                            setSecrets((current) => ({
                              ...current,
                              tencentAppSecretKey: event.target.value,
                            }))
                          }
                          autoComplete="new-password"
                          placeholder={
                            form.captcha.tencentCredentialsConfigured
                              ? "留空保留现有凭据"
                              : "输入 AppSecretKey"
                          }
                        />
                      </Field>
                      <Field
                        label="腾讯云 SecretId"
                        hint={
                          form.captcha.tencentCredentialsConfigured
                            ? "凭据已配置。留空会保留现有值。"
                            : "只写字段。"
                        }
                      >
                        <input
                          type="password"
                          value={secrets.tencentSecretId}
                          onChange={(event) =>
                            setSecrets((current) => ({
                              ...current,
                              tencentSecretId: event.target.value,
                            }))
                          }
                          autoComplete="new-password"
                          placeholder={
                            form.captcha.tencentCredentialsConfigured
                              ? "留空保留现有凭据"
                              : "输入 SecretId"
                          }
                        />
                      </Field>
                      <Field
                        label="腾讯云 SecretKey"
                        hint="保存后不会返回浏览器。"
                      >
                        <input
                          type="password"
                          value={secrets.tencentSecretKey}
                          onChange={(event) =>
                            setSecrets((current) => ({
                              ...current,
                              tencentSecretKey: event.target.value,
                            }))
                          }
                          autoComplete="new-password"
                          placeholder={
                            form.captcha.tencentCredentialsConfigured
                              ? "留空保留现有凭据"
                              : "输入 SecretKey"
                          }
                        />
                      </Field>
                    </div>
                  )}

                  <fieldset
                    className="admin-settings-actions"
                    disabled={!form.captcha.enabled}
                  >
                    <legend>要求人机验证的关键操作</legend>
                    <div>
                      {CAPTCHA_ACTIONS.map((action) => (
                        <Toggle
                          key={action.key}
                          checked={Boolean(form.captcha.actions[action.key])}
                          onChange={(checked) =>
                            setForm((current) => ({
                              ...current,
                              captcha: {
                                ...current.captcha,
                                actions: {
                                  ...current.captcha.actions,
                                  [action.key]: checked,
                                },
                              },
                            }))
                          }
                          disabled={!form.captcha.enabled}
                          label={action.label}
                          detail={action.detail}
                        />
                      ))}
                    </div>
                  </fieldset>

                  <div className="admin-settings-subsection">
                    <div className="admin-settings-subheading">
                      <div>
                        <strong>注册风控阈值</strong>
                        <span>
                          邮箱、IP、域名与成功注册数量均由服务端持久化计数。
                        </span>
                      </div>
                    </div>
                    <div className="admin-settings-form-grid is-three-columns">
                      <NumberField
                        label="邮箱冷却（秒）"
                        value={form.registration.emailCooldownSeconds}
                        min={30}
                        onChange={(value) =>
                          setSection(
                            "registration",
                            "emailCooldownSeconds",
                            value,
                          )
                        }
                      />
                      <NumberField
                        label="单邮箱每小时"
                        value={form.registration.emailHourly}
                        min={1}
                        onChange={(value) =>
                          setSection("registration", "emailHourly", value)
                        }
                      />
                      <NumberField
                        label="单邮箱每日"
                        value={form.registration.emailDaily}
                        min={1}
                        onChange={(value) =>
                          setSection("registration", "emailDaily", value)
                        }
                      />
                      <NumberField
                        label="单 IP 每小时"
                        value={form.registration.ipHourly}
                        min={1}
                        onChange={(value) =>
                          setSection("registration", "ipHourly", value)
                        }
                      />
                      <NumberField
                        label="单 IP 每日"
                        value={form.registration.ipDaily}
                        min={1}
                        onChange={(value) =>
                          setSection("registration", "ipDaily", value)
                        }
                      />
                      <NumberField
                        label="单域名每小时"
                        value={form.registration.domainHourly}
                        min={1}
                        onChange={(value) =>
                          setSection("registration", "domainHourly", value)
                        }
                      />
                      <NumberField
                        label="单域名每日"
                        value={form.registration.domainDaily}
                        min={1}
                        onChange={(value) =>
                          setSection("registration", "domainDaily", value)
                        }
                      />
                      <NumberField
                        label="单 IP 每日成功注册"
                        value={form.registration.successfulPerIPDaily}
                        min={1}
                        onChange={(value) =>
                          setSection(
                            "registration",
                            "successfulPerIPDaily",
                            value,
                          )
                        }
                      />
                      <NumberField
                        label="单网段每日成功注册"
                        value={form.registration.successfulPerSubnetDaily}
                        min={1}
                        onChange={(value) =>
                          setSection(
                            "registration",
                            "successfulPerSubnetDaily",
                            value,
                          )
                        }
                      />
                    </div>
                  </div>
                </>
              )}

              {activeTab === "payment" && (
                <>
                  <SectionHeading
                    eyebrow="支付渠道"
                    title="支付设置"
                    detail="真实支付渠道尚未配置，当前页面不会发起现金扣款。"
                    icon={currentTab.icon}
                  />
                  <div className="admin-settings-toggle-stack">
                    <Toggle
                      checked={form.payment.pointsEnabled}
                      onChange={(checked) =>
                        setSection("payment", "pointsEnabled", checked)
                      }
                      label="允许使用账户积分兑换"
                      detail="积分仅用于站内流量或权益兑换，不会产生现金扣款。"
                    />
                  </div>
                  <div className="admin-settings-payment-grid">
                    <article>
                      <div>
                        <CreditCard />
                        <span>
                          <strong>微信支付</strong>
                          <small>尚未配置</small>
                        </span>
                      </div>
                      <p>完成商户配置并确认支付、退款流程可用后，才会开放此渠道。</p>
                      <StatusBadge ready={false} pendingText="尚未配置" />
                    </article>
                    <article>
                      <div>
                        <CreditCard />
                        <span>
                          <strong>支付宝</strong>
                          <small>尚未配置</small>
                        </span>
                      </div>
                      <p>完成应用配置并确认支付、退款流程可用后，才会开放此渠道。</p>
                      <StatusBadge ready={false} pendingText="尚未配置" />
                    </article>
                  </div>
                </>
              )}

              {activeTab === "redemption" && (
                <>
                  <SectionHeading
                    eyebrow="权益发放"
                    title="兑换码"
                    detail="生成并管理一次性流量或 VIP 权益兑换码，查看每个代码的完整内容与使用情况。"
                    icon={currentTab.icon}
                  />
                  {redemptionsError && (
                    <div className="admin-settings-callout is-warning" role="alert">
                      <WarningCircle weight="fill" />
                      <div>
                        <strong>兑换码批次读取失败</strong>
                        <span>{redemptionsError}</span>
                      </div>
                    </div>
                  )}
                  <div className="admin-settings-callout">
                    <ShieldCheck weight="fill" />
                    <div>
                      <strong>每个兑换码只能成功使用一次</strong>
                      <span>
                        服务端以事务原子占用兑换码；代码在数据库中加密保存，只向已登录管理员返回完整内容。
                      </span>
                    </div>
                  </div>

                  <div className="admin-settings-subsection admin-redemption-create">
                    <div className="admin-settings-subheading">
                      <div>
                        <strong>生成新批次</strong>
                        <span>每批可生成 1 至 500 个兑换码。</span>
                      </div>
                    </div>
                    <div className="admin-settings-form-grid is-three-columns">
                      <Field label="兑换类型">
                        <select
                          value={redemptionForm.type}
                          onChange={(event) =>
                            setRedemptionForm((current) => ({
                              ...current,
                              type: event.target.value,
                            }))
                          }
                        >
                          <option value="traffic">上传流量</option>
                          <option value="vip">VIP 权益</option>
                        </select>
                      </Field>
                      <NumberField
                        label="生成数量"
                        value={redemptionForm.count}
                        min={1}
                        max={500}
                        onChange={(value) =>
                          setRedemptionForm((current) => ({
                            ...current,
                            count: Math.min(500, Math.trunc(value)),
                          }))
                        }
                        hint="单个批次最多 500 个。"
                      />
                      {redemptionForm.type === "traffic" ? (
                        <NumberField
                          label="每个兑换码的上传流量（GiB）"
                          value={redemptionForm.trafficGiB}
                          min={1}
                          step={1}
                          onChange={(value) =>
                            setRedemptionForm((current) => ({
                              ...current,
                              trafficGiB: value,
                            }))
                          }
                        />
                      ) : (
                        <Field label="VIP 权益">
                          <select
                            value={redemptionForm.vipPlan}
                            onChange={(event) =>
                              setRedemptionForm((current) => ({
                                ...current,
                                vipPlan: event.target.value,
                              }))
                            }
                          >
                            <option value="monthly">月度 VIP</option>
                            <option value="yearly">年度 VIP</option>
                            <option value="lifetime">终身 VIP</option>
                          </select>
                        </Field>
                      )}
                      <Field label="失效时间" hint="留空表示长期有效。">
                        <input
                          type="datetime-local"
                          value={redemptionForm.expiresAt}
                          onChange={(event) =>
                            setRedemptionForm((current) => ({
                              ...current,
                              expiresAt: event.target.value,
                            }))
                          }
                        />
                      </Field>
                      <Field label="备注" wide>
                        <input
                          value={redemptionForm.note}
                          maxLength="120"
                          placeholder="仅管理员可见，例如活动名称或发放原因"
                          onChange={(event) =>
                            setRedemptionForm((current) => ({
                              ...current,
                              note: event.target.value,
                            }))
                          }
                        />
                      </Field>
                    </div>
                    <div className="admin-redemption-create-actions">
                      <button
                        className="admin-action-primary"
                        type="button"
                        onClick={createRedemptionBatch}
                        disabled={Boolean(redemptionBusy)}
                      >
                        <Ticket weight="fill" />
                        {redemptionBusy === "creating"
                          ? "正在生成…"
                          : "生成兑换码"}
                      </button>
                    </div>
                  </div>

                  {createdRedemption && (
                    <div className="admin-redemption-reveal" role="status">
                      <div className="admin-settings-subheading">
                        <div>
                          <strong>本次生成的明文兑换码</strong>
                          <span>
                            共 {createdRedemption.codes.length} 个，后续仍可在批次详情查看与导出。
                          </span>
                        </div>
                        <button
                          className="admin-icon-button"
                          type="button"
                          aria-label="关闭本次生成结果"
                          title="关闭"
                          onClick={() => setCreatedRedemption(null)}
                        >
                          <X />
                        </button>
                      </div>
                      <textarea
                        readOnly
                        rows={Math.min(12, Math.max(4, createdRedemption.codes.length))}
                        value={createdRedemption.codes.map(plainCode).join("\n")}
                        aria-label="新生成的兑换码"
                      />
                      <button
                        className="admin-action-primary"
                        type="button"
                        disabled={!createdRedemption.codes.length}
                        onClick={() => {
                          try {
                            downloadRedemptionCSV(createdRedemption);
                            showToast("CSV 已开始下载", "success");
                          } catch {
                            showToast("CSV 导出失败，请稍后重试", "error");
                          }
                        }}
                      >
                        <DownloadSimple weight="bold" /> 下载本次 CSV
                      </button>
                    </div>
                  )}

                  <div className="admin-settings-subsection">
                    <div className="admin-settings-subheading">
                      <div>
                        <strong>兑换码批次</strong>
                        <span>展开批次可查看完整代码、使用账号和兑换时间。</span>
                      </div>
                      <button
                        className="admin-inline-button"
                        type="button"
                        onClick={() => loadRedemptions()}
                        disabled={Boolean(redemptionBusy)}
                      >
                        <Database /> 刷新批次
                      </button>
                    </div>
                    <div className="admin-settings-table-scroll">
                      <table className="admin-settings-table">
                        <thead>
                          <tr>
                            <th>批次</th>
                            <th>类型与权益</th>
                            <th>兑换进度</th>
                            <th>失效时间</th>
                            <th>状态</th>
                            <th>操作</th>
                          </tr>
                        </thead>
                        <tbody>
                          {redemptionBatches.map((batch) => {
                            const id = batchID(batch);
                            const type = batch.type || batch.kind || "traffic";
                            const total = finiteNumber(
                              batch.count ?? batch.totalCount ?? batch.quantity,
                              0,
                            );
                            const used = finiteNumber(
                              batch.redeemedCodes ?? batch.redeemedCount ?? batch.usedCount,
                              0,
                            );
                            const status = batchStatus(batch);
                            return (
                              <tr key={id || `${type}-${batch.createdAt}`}>
                                <td>
                                  <strong>{id ? id.slice(0, 12) : "未提供编号"}</strong>
                                  <small>{batch.note || "无备注"}</small>
                                </td>
                                <td>
                                  <strong>{redemptionTypeLabel(type)}</strong>
                                  <small>
                                    {type === "traffic"
                                      ? formatBytes(
                                          batch.trafficBytes ||
                                            batch.benefitBytes ||
                                            0,
                                        )
                                      : vipPlanLabel(
                                          batch.vipPlan || batch.entitlement,
                                        )}
                                  </small>
                                </td>
                                <td>{used} / {total}</td>
                                <td>
                                  {batch.expiresAt
                                    ? formatDate(batch.expiresAt)
                                    : "长期有效"}
                                </td>
                                <td>
                                  <span
                                    className={`admin-row-status${status === "可使用" ? " is-ready" : ""}`}
                                  >
                                    {status}
                                  </span>
                                </td>
                                <td>
                                  {status === "可使用" ? (
                                    <button
                                      className="admin-inline-button is-danger"
                                      type="button"
                                      disabled={redemptionBusy === `disable:${id}`}
                                      onClick={() => disableRedemptionBatch(batch)}
                                    >
                                      停用
                                    </button>
                                  ) : (
                                    <span className="admin-muted-copy">不可操作</span>
                                  )}
                                </td>
                              </tr>
                            );
                          })}
                          {redemptionsLoaded && !redemptionBatches.length && (
                            <tr>
                              <td colSpan="6" className="admin-empty-cell">
                                暂无兑换码批次。
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>

					{redemptionBatches.map((batch) => {
						const id = batchID(batch);
						const codes = Array.isArray(batch.codes) ? batch.codes : [];
						const exportData = redemptionBatchCSVData(batch);
						return (
							<details className="admin-redemption-batch-detail" key={`codes-${id}`}>
								<summary>
									<span><strong>{batch.note || "兑换码批次"}</strong><small>{id}</small></span>
									<span>{finiteNumber(batch.redeemedCodes, 0)} 已使用 · {finiteNumber(batch.activeCodes, 0)} 未使用</span>
								</summary>
								<div className="admin-redemption-batch-toolbar">
									<span>共 {codes.length} 个代码</span>
									<button className="admin-inline-button" type="button" disabled={!exportData.codes.length} onClick={() => downloadRedemptionCSV(exportData)}>
										<DownloadSimple /> 导出完整代码
									</button>
								</div>
								<div className="admin-settings-table-scroll">
									<table className="admin-settings-table admin-redemption-code-table">
										<thead><tr><th>完整兑换码</th><th>状态</th><th>兑换用户</th><th>兑换时间</th></tr></thead>
										<tbody>
											{codes.map((entry) => (
												<tr key={entry.id}>
													<td><code>{entry.codeAvailable ? entry.code : "旧批次未保存明文"}</code></td>
													<td><span className={`admin-row-status${entry.status === "active" ? " is-ready" : ""}`}>{redemptionCodeStatusLabel(entry.status)}</span></td>
													<td>{entry.redeemedUsername || entry.redeemedEmail || "—"}{entry.redeemedUsername && entry.redeemedEmail ? <small>{entry.redeemedEmail}</small> : null}</td>
													<td>{entry.redeemedAt ? formatDate(entry.redeemedAt) : "—"}</td>
												</tr>
											))}
											{!codes.length && <tr><td colSpan="4" className="admin-empty-cell">该批次没有代码记录。</td></tr>}
										</tbody>
									</table>
								</div>
							</details>
						);
					})}
                  </div>
                </>
              )}

              {activeTab === "operations" && (
                <>
                  <SectionHeading
                    eyebrow="日常运营"
                    title="运营管理"
                    detail="在系统设置中完成用户状态、举报、订单退款和审计查看，不再保留独立管理后台。"
                    icon={currentTab.icon}
                  />
                  {operationsError && (
                    <div className="admin-settings-callout is-warning" role="alert">
                      <WarningCircle weight="fill" />
                      <div>
                        <strong>运营数据读取失败</strong>
                        <span>{operationsError}</span>
                      </div>
                    </div>
                  )}
                  <div className="admin-operations-stats">
                    <article>
                      <UsersThree />
                      <span><small>用户</small><strong>{operations.overview?.users ?? operations.users.length}</strong></span>
                    </article>
                    <article>
                      <PaperPlaneTilt />
                      <span><small>活跃传输</small><strong>{operations.overview?.stats?.activeTransfers ?? 0}</strong></span>
                    </article>
                    <article>
                      <Flag />
                      <span><small>待处理举报</small><strong>{operations.overview?.openReports ?? operations.reports.filter((item) => item.status === "open").length}</strong></span>
                    </article>
                    <article>
                      <Receipt />
                      <span><small>已生效订单</small><strong>{operations.overview?.paidOrders ?? operations.orders.filter((item) => item.status === "paid").length}</strong></span>
                    </article>
                  </div>

                  {!operationsLoaded && operationsBusy === "loading" ? (
                    <div className="admin-settings-empty">正在读取运营数据…</div>
                  ) : (
                    <div className="admin-operations-grid">
                      <article className="admin-operations-card">
                        <div className="admin-settings-subheading">
                          <div><strong>用户列表</strong><span>账号、充值、流量、会员、福利与使用信息统一查看。</span></div>
									<label className="admin-user-search">
										<MagnifyingGlass />
										<input value={userQuery} onChange={(event) => setUserQuery(event.target.value)} placeholder="搜索用户名、邮箱或用户编号" aria-label="搜索用户" />
									</label>
                        </div>
                        <div className="admin-settings-table-scroll">
                          <table className="admin-settings-table admin-user-table">
                            <thead><tr><th>用户</th><th>账号与会员</th><th>剩余流量</th><th>充值信息</th><th>福利与兑换</th><th>最近登录</th><th>状态</th><th>操作</th></tr></thead>
                            <tbody>
                              {filteredUsers.map((user) => (
                                <tr key={user.id}>
										<td><strong>{user.username || "未设置用户名"}</strong><small>{user.email}</small></td>
										<td><strong>{user.role === "admin" ? "管理员" : tierLabel(user.vipPlan || user.level)}</strong><small>{user.vipPlan && user.vipPlan !== "none" ? `${vipPlanLabel(user.vipPlan)} · ${user.vipPlan === "lifetime" ? "永久" : formatDate(user.vipExpiresAt)}` : roleLabel(user.role)}</small></td>
										<td><strong>{formatBytes(user.remainingUploadTrafficBytes)}</strong><small>已上传扣费 {formatBytes(user.trafficConsumedBytes)} · 预留 {formatBytes(user.trafficReservedBytes)}</small></td>
										<td><strong>{finiteNumber(user.paidOrderCount, 0)} 笔已生效</strong><small>现金 ¥{(finiteNumber(user.cashPaidCents, 0) / 100).toFixed(2)} · 积分 {finiteNumber(user.pointsSpent, 0)}</small></td>
										<td><strong>{finiteNumber(user.redemptionCount, 0)} 次兑换 · {finiteNumber(user.checkInDays, 0)} 天签到</strong><small>会员日赠 {formatBytes(user.vipDailyTrafficBytes)} · 积分余额 {finiteNumber(user.points, 0)}</small></td>
										<td>{user.lastLoginAt ? formatDate(user.lastLoginAt) : "从未登录"}<small>注册于 {formatDate(user.createdAt)}</small></td>
                                  <td><span className={`admin-row-status${user.status === "active" ? " is-ready" : ""}`}>{userStatusLabel(user.status)}</span></td>
                                  <td>
										<span className="admin-table-actions">
											<button className="admin-inline-button" type="button" disabled={Boolean(userDetailBusy)} onClick={() => viewUserDetail(user)}><Eye /> {userDetailBusy === user.id ? "读取中…" : "详情"}</button>
											{user.id === (me?.user?.id || me?.id) ? (
												<span className="admin-muted-copy">当前账户</span>
											) : (
                                      <button
                                        className={`admin-inline-button${user.status === "blocked" ? "" : " is-danger"}`}
                                        type="button"
                                        disabled={Boolean(operationsBusy) || user.status === "pending"}
                                        onClick={() => updateUser(user)}
                                      >
                                        {user.status === "blocked" ? "恢复" : "停用"}
                                      </button>
											)}
										</span>
                                  </td>
                                </tr>
                              ))}
									{!filteredUsers.length && <tr><td colSpan="8" className="admin-empty-cell">没有符合条件的用户。</td></tr>}
                            </tbody>
                          </table>
                        </div>
                      </article>

                      <article className="admin-operations-card">
                        <div className="admin-settings-subheading">
                          <div><strong>举报处置</strong><span>仅展示处置所需信息。</span></div>
                        </div>
                        <div className="admin-settings-table-scroll">
                          <table className="admin-settings-table">
                            <thead><tr><th>原因</th><th>提交时间</th><th>状态</th><th>操作</th></tr></thead>
                            <tbody>
                              {operations.reports.map((report) => (
                                <tr key={report.id}>
                                  <td><strong>{report.reason || "未说明"}</strong><small>{report.detail || "无补充说明"}</small></td>
                                  <td>{formatDate(report.createdAt)}</td>
                                  <td><span className={`admin-row-status${report.status !== "open" ? " is-ready" : ""}`}>{reportStatusLabel(report.status)}</span></td>
                                  <td>
                                    {report.status === "open" ? (
                                      <span className="admin-table-actions">
                                        <button className="admin-inline-button" type="button" disabled={Boolean(operationsBusy)} onClick={() => updateReport(report, "resolved")}>已处理</button>
                                        <button className="admin-inline-button is-danger" type="button" disabled={Boolean(operationsBusy)} onClick={() => updateReport(report, "rejected")}>驳回</button>
                                      </span>
                                    ) : <span className="admin-muted-copy">已完成</span>}
                                  </td>
                                </tr>
                              ))}
                              {!operations.reports.length && <tr><td colSpan="4" className="admin-empty-cell">当前没有举报。</td></tr>}
                            </tbody>
                          </table>
                        </div>
                      </article>

                      <article className="admin-operations-card">
                        <div className="admin-settings-subheading">
                          <div><strong>订单与退款</strong><span>仅对服务端允许退款的已生效订单提供操作。</span></div>
                        </div>
                        <div className="admin-settings-table-scroll">
                          <table className="admin-settings-table">
                            <thead><tr><th>商品</th><th>支付方式</th><th>金额</th><th>状态</th><th>操作</th></tr></thead>
                            <tbody>
                              {operations.orders.map((order) => (
                                <tr key={order.id}>
                                  <td><strong>{order.productName || "权益订单"}</strong><small>{formatDate(order.createdAt)}</small></td>
                                  <td>{paymentMethodLabel(order.paymentMethod)}</td>
                                  <td>{order.paymentMethod === "points" ? `${finiteNumber(order.pointsPrice, 0)} 积分` : `¥${(finiteNumber(order.priceCents, 0) / 100).toFixed(2)}`}</td>
                                  <td><span className={`admin-row-status${order.status === "paid" ? " is-ready" : ""}`}>{orderStatusLabel(order.status)}</span></td>
                                  <td>{order.status === "paid" ? <button className="admin-inline-button is-danger" type="button" disabled={Boolean(operationsBusy)} onClick={() => refundOrder(order)}>退款</button> : <span className="admin-muted-copy">不可退款</span>}</td>
                                </tr>
                              ))}
                              {!operations.orders.length && <tr><td colSpan="5" className="admin-empty-cell">暂无订单。</td></tr>}
                            </tbody>
                          </table>
                        </div>
                      </article>

                      <article className="admin-operations-card">
                        <div className="admin-settings-subheading">
                          <div><strong>最近操作</strong><span>查看系统记录的管理员操作。</span></div>
                        </div>
                        <div className="admin-audit-list">
                          {(operations.overview?.recentAudits || []).map((entry) => (
                            <div key={entry.id}>
                              <span><strong>{auditActionLabel(entry.action)}</strong><small>{formatDate(entry.createdAt)}</small></span>
                              <small>{entry.targetId ? String(entry.targetId).slice(0, 12) : "系统设置"}</small>
                            </div>
                          ))}
                          {!(operations.overview?.recentAudits || []).length && <div className="admin-settings-empty">暂无审计记录。</div>}
                        </div>
                      </article>
                    </div>
                  )}
                </>
              )}

              {activeTab === "runtime" && (
                <>
                  <SectionHeading
                    eyebrow="服务状态"
                    title="运行状态"
                    detail="这里展示服务端返回的实际状态，不用界面文案替代生产验收。"
                    icon={currentTab.icon}
                  />
                  <div className="admin-settings-runtime-grid">
                    <article>
                      <PaperPlaneTilt />
                      <div>
                        <span>真实邮件投递</span>
                        <strong>
                          {runtime.emailActive ? "已启用" : "尚未生效"}
                        </strong>
                        <small>
                          {runtime.emailActive
                            ? "注册邮件可由真实 SMTP 发送。"
                            : "应保持注册关闭，先完成 SMTP 配置与测试。"}
                        </small>
                      </div>
                      <StatusBadge ready={runtime.emailActive} />
                    </article>
                    <article>
                      <ShieldCheck />
                      <div>
                        <span>恶意文件扫描</span>
                        <strong>{runtime.scanner}</strong>
                        <small>
                          {runtime.productionScanner
                            ? "服务端报告为生产扫描能力。"
                            : "当前能力不得描述为生产级防病毒。"}
                        </small>
                      </div>
                      <StatusBadge ready={runtime.productionScanner} />
                    </article>
                    <article>
                      <Database />
                      <div>
                        <span>配置生效</span>
                        <strong>
                          {runtime.restartRequired
                            ? "等待服务重启"
                            : "当前版本已加载"}
                        </strong>
                        <small>
                          {runtime.restartRequired
                            ? "请通过受控发布流程重启，并重新执行就绪与端到端验收。"
                            : "服务端未报告待重启配置。"}
                        </small>
                      </div>
                      <StatusBadge
                        ready={!runtime.restartRequired}
                        readyText="无需重启"
                        pendingText="需要重启"
                      />
                    </article>
                    <article>
                      <Gauge />
                      <div>
                        <span>构建标识</span>
                        <strong>
                          {config?.buildVersion || config?.version || "未报告"}
                        </strong>
                        <small>
                          配置修订 r{form.revision} · 管理员 {adminName}
                        </small>
                      </div>
                      <StatusBadge
                        ready={Boolean(config?.buildVersion || config?.version)}
                        readyText="已报告"
                        pendingText="未报告"
                      />
                    </article>
                  </div>
                  {!runtime.productionScanner && (
                    <div className="admin-settings-callout is-warning">
                      <WarningCircle weight="fill" />
                      <div>
                        <strong>当前不能宣称生产就绪</strong>
                        <span>
                          在生产扫描器、HTTPS、备份恢复和完整端到端验收完成前，不应直接开放公网服务。
                        </span>
                      </div>
                    </div>
                  )}
                </>
              )}
            </section>

            {isSettingsTab && <footer className="admin-settings-savebar">
              <div className="admin-settings-save-state">
                <span className={dirty ? "is-dirty" : "is-clean"} />
                <div>
                  <strong>
                    {dirty ? "有尚未保存的修改" : "配置已与服务器同步"}
                  </strong>
                  <small>
                    保存使用配置版本 r{form.revision} 进行并发保护。
                  </small>
                </div>
              </div>
              <button
                className="admin-settings-save"
                type="submit"
                disabled={
                  !loaded ||
                  !dirty ||
                  busy !== "idle"
                }
              >
                <CloudArrowUp weight="bold" />{" "}
                {saving ? "正在保存…" : "保存全部设置"}
              </button>
            </footer>}
          </form>
        </div>
      </main>
		<AdminUserDetailModal
			detail={selectedUserDetail}
			onClose={() => setSelectedUserDetail(null)}
		/>
    </div>
  );
}
