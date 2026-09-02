import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  ArrowLeft,
  ArrowRight,
  CalendarBlank,
  CaretDown,
  Check,
  CheckCircle,
  Clock,
  CloudArrowUp,
  Coins,
  Copy,
  Crown,
  DownloadSimple,
  File,
  FileArrowUp,
  FolderOpen,
  Gauge,
  Gift,
  LinkSimple,
  LockKey,
  PaperPlaneTilt,
  Password,
  Plus,
  QrCode,
  Scan,
  ShieldCheck,
  ShieldStar,
  ShoppingCart,
  SignIn,
  SignOut,
  Sparkle,
  Trash,
  UploadSimple,
  User,
  UserCircle,
  Flag,
  WarningCircle,
  X,
} from "@phosphor-icons/react";
import { QRCodeSVG } from "qrcode.react";
import {
  confirmPasswordReset,
  createOrder,
  createDownload,
  createTransfer,
  formatBytes,
  getAdminOrders,
  getAdminOverview,
  getAdminReports,
  getAdminUserDetail,
  getAdminUsers,
  getConfig,
  getAdminSettings,
  getManagedTransfer,
  getMe,
  getMyResources,
  getWelfareStatus,
  getProducts,
  getShare,
  login,
  logout,
  claimDailyCheckIn,
  publishTransfer,
  redeemCode,
  refundAdminOrder,
  register,
  reportShare,
  requestPasswordReset,
  resolvePickup,
  revokeTransfer,
  setAdminReportStatus,
  setAdminUserStatus,
  unlockShare,
  uploadFile,
  updateAdminSettings,
  testAdminSMTP,
  updateProfile,
  verifyRegistration,
  waitForManagedTransfer,
  getAdminRedemptions,
  createAdminRedemptionBatch,
  disableAdminRedemptionBatch,
} from "./api.js";
import { HumanVerification } from "./components/security/HumanVerification.jsx";
import {
  showToast,
  ToastCenter,
  useToastMessage,
} from "./components/ToastCenter.jsx";
import { AdminSettingsPage } from "./pages/AdminSettingsPage.jsx";
import { TermsPage } from "./pages/TermsPage.jsx";
import "./styles/welfare.css";

const STORAGE_KEY = "quicktransfer-records-v1";
const RETRIEVAL_STORAGE_PREFIX = "quicktransfer:retrieval-session-v1";
const EXPIRY_OPTIONS = [
  [1, "1 小时"],
  [12, "12 小时"],
  [24, "24 小时"],
  [72, "3 天"],
];
const SessionContext = createContext({
  me: null,
  config: null,
  configStatus: "loading",
  refreshSession: async () => {},
  requestDailyCheckInReminder: () => {},
});

const WELFARE_UPDATED_EVENT = "quicktransfer:welfare-updated";
const WELFARE_REMINDER_STORAGE_PREFIX =
  "quicktransfer:welfare-reminder-shown-v1";

function welfareReminderStorageKey(userID, date) {
  return `${WELFARE_REMINDER_STORAGE_PREFIX}:${userID}:${date}`;
}

function hasStoredWelfareReminder(key) {
  try {
    return window.localStorage.getItem(key) === "1";
  } catch {
    return false;
  }
}

function storeWelfareReminder(key) {
  try {
    window.localStorage.setItem(key, "1");
  } catch {
    // In-memory suppression below still prevents duplicate reminders this load.
  }
}

const ROUTE_TITLES = {
  "/": "发文件 · 快传",
  "/login": "登录与注册 · 快传",
  "/account": "账户与资源 · 快传",
  "/plans": "流量与 VIP · 快传",
  "/welfare": "每日福利 · 快传",
  "/admin": "系统设置 · 快传",
  "/admin/settings": "系统设置 · 快传",
  "/terms": "服务条款 · 快传",
};

function getDocumentTitle(pathname, search = "") {
  if (pathname.startsWith("/s/")) return "领取文件 · 快传";
  if (pathname.startsWith("/c/")) return "提交文件 · 快传";
  if (pathname.startsWith("/manage/")) return "传输管理 · 快传";
  if (pathname === "/") {
    const mode = new URLSearchParams(search).get("mode");
    if (mode === "pickup") return "取文件 · 快传";
    if (mode === "collect") return "收集文件 · 快传";
  }
  return ROUTE_TITLES[pathname] || ROUTE_TITLES["/"];
}

function getTransferAvailability(configStatus, config) {
  if (configStatus === "loading") {
    return {
      available: false,
      label: "状态检查中",
      reason: "正在读取服务状态，请稍候。",
      tone: "loading",
    };
  }
  if (configStatus !== "ready" || !config) {
    return {
      available: false,
      label: "服务不可用",
      reason: "暂时无法确认服务配置，请刷新页面后重试。",
      tone: "unavailable",
    };
  }
  if (config.storageReady !== true) {
    const remote = config.storageMode === "remote";
    return {
      available: false,
      label: remote ? "存储维护中" : "服务不可用",
      reason: remote
        ? "存储节点正在维护，已暂停新的文件传输。"
        : "文件存储尚未就绪，已暂停新的文件传输。",
      tone: remote ? "maintenance" : "unavailable",
    };
  }
  if (
    config.humanVerificationRequired === true &&
    config.humanVerificationReady !== true
  ) {
    return {
      available: false,
      label: "安全验证维护中",
      reason: "关键操作的人机验证尚未完成配置，已暂停新的文件传输。",
      tone: "unavailable",
    };
  }
  return {
    available: true,
    label: "",
    reason: "可以开始传输文件",
    tone: "online",
  };
}

function prepareMainForNavigation({ focus = false } = {}) {
  const main = document.querySelector("main");
  if (!main) return;
  main.id = "main-content";
  main.tabIndex = -1;
  if (focus) main.focus({ preventScroll: true });
}

function readRecords() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

function rememberRecord(record) {
  const records = readRecords().filter(
    (item) => item.shareToken !== record.shareToken,
  );
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify([record, ...records].slice(0, 20)),
  );
}

function retrievalStorageKey(shareToken) {
  return `${RETRIEVAL_STORAGE_PREFIX}:${shareToken}`;
}

function readRetrievalSession(shareToken) {
  try {
    const key = retrievalStorageKey(shareToken);
    const value = JSON.parse(window.sessionStorage.getItem(key) || "null");
    if (
      !value?.token ||
      !Number.isFinite(value.expiresAt) ||
      value.expiresAt <= Math.floor(Date.now() / 1000)
    ) {
      window.sessionStorage.removeItem(key);
      return null;
    }
    return value;
  } catch {
    return null;
  }
}

function storeRetrievalSession(shareToken, token, expiresAt) {
  if (!token || !Number.isFinite(expiresAt)) return null;
  const value = { token, expiresAt };
  try {
    window.sessionStorage.setItem(
      retrievalStorageKey(shareToken),
      JSON.stringify(value),
    );
  } catch {
    // The in-memory value still keeps the current page's retrieval session.
  }
  return value;
}

function clearRetrievalSession(shareToken) {
  try {
    window.sessionStorage.removeItem(retrievalStorageKey(shareToken));
  } catch {
    // Nothing else is required when storage is unavailable.
  }
}

function usePolicyExpiry(policy) {
  const maxExpiryHours = Math.max(1, Number(policy?.maxExpiryHours) || 24);
  const options = useMemo(
    () => EXPIRY_OPTIONS.filter(([hours]) => hours <= maxExpiryHours),
    [maxExpiryHours],
  );
  const [expiresHours, setExpiresHours] = useState(24);

  useEffect(() => {
    if (options.some(([hours]) => hours === expiresHours)) return;
    setExpiresHours(options.at(-1)?.[0] || 1);
  }, [expiresHours, options]);

  const effectiveExpiresHours = options.some(
    ([hours]) => hours === expiresHours,
  )
    ? expiresHours
    : options.at(-1)?.[0] || 1;
  return { expiresHours: effectiveExpiresHours, options, setExpiresHours };
}

function getRecord(shareToken) {
  return readRecords().find((item) => item.shareToken === shareToken);
}

function usePath() {
  const [path, setPath] = useState(window.location.pathname);
  const [navigationKey, setNavigationKey] = useState(0);
  useEffect(() => {
    const onPopState = () => {
      setPath(window.location.pathname);
      setNavigationKey((value) => value + 1);
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  const navigate = (next) => {
    window.history.pushState({}, "", next);
    setPath(window.location.pathname);
    setNavigationKey((value) => value + 1);
    window.scrollTo({ top: 0, behavior: "auto" });
  };
  return [path, navigate, navigationKey];
}

export function App() {
  const [path, navigate, navigationKey] = usePath();
  const [config, setConfig] = useState(null);
  const [configStatus, setConfigStatus] = useState("loading");
  const [me, setMe] = useState(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [dailyCheckInReminderOpen, setDailyCheckInReminderOpen] =
    useState(false);
  const shownWelfareReminderKeys = useRef(new Set());
  const inspectDailyCheckInReminder = useCallback(
    async (session, { force = false } = {}) => {
      const userID = session?.user?.id;
      if (!userID || window.location.pathname !== "/") return false;
      try {
        const response = await getWelfareStatus();
        const welfare = response?.welfare;
        if (
          window.location.pathname !== "/" ||
          !welfare?.today ||
          welfare.claimedToday
        ) {
          return false;
        }
        const key = welfareReminderStorageKey(userID, welfare.today);
        if (
          !force &&
          (shownWelfareReminderKeys.current.has(key) ||
            hasStoredWelfareReminder(key))
        ) {
          return false;
        }
        shownWelfareReminderKeys.current.add(key);
        storeWelfareReminder(key);
        setDailyCheckInReminderOpen(true);
        return true;
      } catch {
        return false;
      }
    },
    [],
  );
  const requestDailyCheckInReminder = useCallback(
    (session) => void inspectDailyCheckInReminder(session, { force: true }),
    [inspectDailyCheckInReminder],
  );
  const closeDailyCheckInReminder = useCallback(
    () => setDailyCheckInReminderOpen(false),
    [],
  );

  const refreshSession = async ({ checkDailyReminder = false } = {}) => {
    setConfigStatus("loading");
    let nextMe = null;
    try {
      nextMe = await getMe();
    } catch {
      nextMe = null;
    }
    setMe(nextMe);
    try {
      const nextConfig = await getConfig();
      setConfig(nextConfig);
      setConfigStatus("ready");
    } catch {
      setConfig(null);
      setConfigStatus("failed");
    }
    setSessionLoading(false);
    if (checkDailyReminder && nextMe) {
      await inspectDailyCheckInReminder(nextMe);
    }
    return nextMe;
  };

  useEffect(() => {
    refreshSession({ checkDailyReminder: true });
  }, []);

  useEffect(() => {
    document.title = getDocumentTitle(path, window.location.search);
    const frame = window.requestAnimationFrame(() =>
      prepareMainForNavigation({ focus: navigationKey > 0 }),
    );
    return () => window.cancelAnimationFrame(frame);
  }, [path, navigationKey]);

  const shareMatch = path.match(/^\/s\/([^/]+)$/);
  const collectMatch = path.match(/^\/c\/([^/]+)$/);
  const manageMatch = path.match(/^\/manage\/([^/]+)$/);

  let content;
  if (shareMatch) {
    content = (
      <ReceivePage
        token={decodeURIComponent(shareMatch[1])}
        navigate={navigate}
      />
    );
  } else if (collectMatch) {
    content = (
      <CollectionUploadPage
        token={decodeURIComponent(collectMatch[1])}
        navigate={navigate}
      />
    );
  } else if (manageMatch) {
    content = (
      <ManagePage
        token={decodeURIComponent(manageMatch[1])}
        navigate={navigate}
      />
    );
  } else if (path === "/login") {
    content = <AuthPage navigate={navigate} />;
  } else if (path === "/account") {
    content = (
      <>
        <AccountPage navigate={navigate} sessionLoading={sessionLoading} />
        <div className="account-route-underlay" aria-hidden="true" inert={true}>
          <HomePage config={config} navigate={navigate} />
        </div>
      </>
    );
  } else if (path === "/plans") {
    content = <PlansPage navigate={navigate} />;
  } else if (path === "/welfare") {
    content = (
      <WelfarePage navigate={navigate} sessionLoading={sessionLoading} />
    );
  } else if (path === "/admin") {
    content = <RouteRedirect to="/admin/settings" navigate={navigate} />;
  } else if (path === "/admin/settings") {
    content = (
      <AdminSettingsPage
        navigate={navigate}
        me={me}
        config={config}
        api={{
          getAdminSettings,
          refreshPublicConfig: refreshSession,
          updateAdminSettings,
          testAdminSMTP,
          getAdminOverview,
          getAdminUsers,
          getAdminUserDetail,
          getAdminReports,
          getAdminOrders,
          setAdminUserStatus,
          setAdminReportStatus,
          refundAdminOrder,
          getAdminRedemptions,
          createAdminRedemptionBatch,
          disableAdminRedemptionBatch,
        }}
      />
    );
  } else if (path === "/terms") {
    content = <TermsPage navigate={navigate} />;
  } else {
    content = <HomePage config={config} navigate={navigate} />;
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        跳到主要内容
      </a>
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <ToastCenter />
      <SessionContext.Provider
        value={{
          me,
          config,
          configStatus,
          refreshSession,
          requestDailyCheckInReminder,
        }}
      >
        <div className="route-stage" key={path}>
          {content}
        </div>
        <DailyCheckInReminder
          open={dailyCheckInReminderOpen}
          onClose={closeDailyCheckInReminder}
          refreshSession={refreshSession}
          me={me}
        />
      </SessionContext.Provider>
    </div>
  );
}

function RouteRedirect({ to, navigate }) {
  useEffect(() => {
    navigate(to);
  }, [navigate, to]);
  return (
    <main className="centered-inner redirect-state">
      <LoadingState label="正在打开系统设置…" />
    </main>
  );
}

function Header({ active = null, onMode, navigate }) {
  const { me, config, configStatus, refreshSession } =
    useContext(SessionContext);
  const availability = getTransferAvailability(configStatus, config);
  const currentPath = window.location.pathname;
  const headerTraffic = me ? remainingUploadTraffic(me.account) : 0;
  const [menuOpen, setMenuOpen] = useState(false);
  const [logoutBusy, setLogoutBusy] = useState(false);
  const [, setMenuError] = useToastMessage("error");
  const accountButtonRef = useRef(null);
  const menuRef = useRef(null);
  const tabs = [
    ["send", "发文件"],
    ["pickup", "取文件"],
    ["collect", "收集文件"],
  ];
  const choose = (mode) => {
    setMenuOpen(false);
    if (onMode) onMode(mode);
    else navigate(`/?mode=${mode}`);
  };
  const openRoute = (route) => {
    setMenuOpen(false);
    navigate(route);
  };
  const signOut = async () => {
    if (logoutBusy) return;
    setLogoutBusy(true);
    setMenuError("");
    try {
      await logout();
      await refreshSession();
      setMenuOpen(false);
      navigate("/");
    } catch (reason) {
      setMenuError(reason.message || "暂时无法退出，请稍后再试");
    } finally {
      setLogoutBusy(false);
    }
  };
  const handleMenuKeyDown = (event) => {
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key))
      return;
    const items = Array.from(
      menuRef.current?.querySelectorAll('[role="menuitem"]:not(:disabled)') ||
        [],
    );
    if (!items.length) return;
    event.preventDefault();
    const current = items.indexOf(document.activeElement);
    const next =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? items.length - 1
          : event.key === "ArrowDown"
            ? (current + 1 + items.length) % items.length
            : (current - 1 + items.length) % items.length;
    items[next].focus();
  };
  useEffect(() => {
    if (!menuOpen) return undefined;
    const onPointerDown = (event) => {
      if (!menuRef.current?.contains(event.target)) setMenuOpen(false);
    };
    const onKeyDown = (event) => {
      if (event.key !== "Escape") return;
      setMenuOpen(false);
      accountButtonRef.current?.focus();
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    window.requestAnimationFrame(() =>
      menuRef.current?.querySelector('[role="menuitem"]')?.focus(),
    );
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [menuOpen]);
  return (
    <header className="site-header">
      <button
        className="brand"
        type="button"
        onClick={() => navigate("/")}
        aria-label="返回快传首页"
      >
        <span className="brand-mark" aria-hidden="true">
          <img src="/icon-192.png" alt="" width="38" height="38" />
        </span>
        <span>快传</span>
      </button>
      <nav className="main-nav" aria-label="主要功能">
        {tabs.map(([key, label]) => (
          <button
            className={active === key ? "nav-item is-active" : "nav-item"}
            key={key}
            type="button"
            aria-current={active === key ? "page" : undefined}
            onClick={() => choose(key)}
          >
            {label}
          </button>
        ))}
      </nav>
      <div className="header-actions">
        {!availability.available && (
          <div
            className={`header-alert header-alert--${availability.tone}`}
            title={availability.reason}
            role="status"
            aria-live="polite"
          >
            <WarningCircle weight="fill" />
            <span>上传暂停</span>
          </div>
        )}
        {me && (
          <button
            className="header-traffic"
            type="button"
            aria-label={`查看账户与资源，剩余上传流量 ${formatBytes(headerTraffic)}`}
            title={`剩余上传流量 ${formatBytes(headerTraffic)}`}
            onClick={() => navigate("/account")}
          >
            <Gauge weight="duotone" />
            <span className="header-traffic__label">剩余流量</span>
            <strong>{formatBytes(headerTraffic)}</strong>
          </button>
        )}
        <button
          className={`header-plan ${currentPath === "/plans" ? "is-active" : ""}`}
          type="button"
          aria-label="流量与 VIP 套餐"
          aria-current={currentPath === "/plans" ? "page" : undefined}
          onClick={() => navigate("/plans")}
        >
          <ShoppingCart /> <span>套餐</span>
        </button>
        <div className="account-menu" ref={menuRef}>
          <button
            ref={accountButtonRef}
            className={`account-button ${["/account", "/login", "/welfare"].includes(currentPath) ? "is-active" : ""}`}
            type="button"
            aria-label={me ? "打开账户菜单" : "登录账户"}
            aria-haspopup={me ? "menu" : undefined}
            aria-expanded={me ? menuOpen : undefined}
            aria-current={
              ["/account", "/login", "/welfare"].includes(currentPath)
                ? "page"
                : undefined
            }
            onClick={() =>
              me ? setMenuOpen((value) => !value) : navigate("/login")
            }
          >
            {me ? <UserCircle weight="fill" /> : <SignIn />}
            <span>{me ? me.user.username || "用户" : "登录"}</span>
            {me && <CaretDown className="account-caret" />}
          </button>
          {me && menuOpen && (
            <div
              className="account-dropdown"
              role="menu"
              aria-label="账户菜单"
              onKeyDown={handleMenuKeyDown}
            >
              <div className="account-dropdown__identity">
                <strong>{me.user.username || "用户"}</strong>
                <span>{accountLevelLabel(me)}</span>
              </div>
              <button
                type="button"
                role="menuitem"
                onClick={() => openRoute("/account")}
              >
                <UserCircle />
                <span>账户与资源</span>
              </button>
              <button
                type="button"
                role="menuitem"
                onClick={() => openRoute("/plans")}
              >
                <ShoppingCart />
                <span>流量与 VIP</span>
              </button>
              <button
                type="button"
                role="menuitem"
                onClick={() => openRoute("/welfare")}
              >
                <Gift />
                <span>每日福利</span>
              </button>
              {me.user.role === "admin" && (
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => openRoute("/admin/settings")}
                >
                  <ShieldStar />
                  <span>系统设置</span>
                </button>
              )}
              <button
                className="account-dropdown__logout"
                type="button"
                role="menuitem"
                disabled={logoutBusy}
                onClick={signOut}
              >
                <SignOut />
                <span>{logoutBusy ? "正在退出…" : "退出登录"}</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

function HomePage({ config, navigate }) {
  const { me } = useContext(SessionContext);
  const params = new URLSearchParams(window.location.search);
  const requested = params.get("mode");
  const [mode, setMode] = useState(
    ["send", "pickup", "collect"].includes(requested) ? requested : "send",
  );
  const changeMode = (next) => {
    setMode(next);
    window.history.replaceState(
      {},
      "",
      next === "send" ? "/" : `/?mode=${next}`,
    );
    document.title = getDocumentTitle("/", window.location.search);
    window.requestAnimationFrame(() =>
      prepareMainForNavigation({ focus: true }),
    );
  };
  return (
    <div className="page-frame home-page">
      <Header active={mode} onMode={changeMode} navigate={navigate} />
      <main className="hero-layout" key={mode}>
        <HeroCopy mode={mode} navigate={navigate} config={config} />
        {mode === "send" && <SendPanel config={config} navigate={navigate} />}
        {mode === "pickup" && <PickupPanel navigate={navigate} />}
        {mode === "collect" && (
          <CreateCollectionPanel config={config} navigate={navigate} />
        )}
      </main>
      <footer className="home-footer">
        <span>断点续传 · 到期自动销毁 · 下载不计流量</span>
        <span>
          {me ? "上传按实际流量计费" : "游客单次总量 100 MiB"}
        </span>
      </footer>
    </div>
  );
}

function HeroCopy({ mode, navigate, config }) {
  const content = {
    send: [
      "文件传送，",
      "就该这么简单",
      "拖入文件，生成链接，对方打开即可领取。",
    ],
    pickup: [
      "一串取件码，",
      "文件即刻抵达",
      "输入发送方给你的取件码，安全领取文件。",
    ],
    collect: ["收文件，", "不再逐个催", "生成专属收集入口，让所有人直接提交。"],
  }[mode];
  return (
    <section className="hero-copy" aria-labelledby="hero-title">
      <div className="eyebrow">
        <Sparkle weight="fill" /> 快速传送
      </div>
      <h1 id="hero-title">
        {content[0]}
        <br />
        {content[1]}
      </h1>
      <span className="title-streak" />
      <p>{content[2]}</p>
      {mode === "send" && <InlinePickup navigate={navigate} />}
      <div className="trust-row" aria-label="安全能力">
        <span>
          <LockKey />{" "}
          {window.location.protocol === "https:"
            ? "传输连接已加密"
            : "受控安全连接"}
        </span>
        <i />
        <span>
          <ShieldCheck /> 到期销毁
        </span>
        <i />
        <span>
          <Scan /> {config?.productionScanner ? "完整安全扫描" : "基础风险检查"}
        </span>
      </div>
    </section>
  );
}

function InlinePickup({ navigate }) {
  const inputRef = useRef(null);
  const [code, setCode] = useState("");
  const [, setError] = useToastMessage("error");
  const submit = async (event) => {
    event.preventDefault();
    if (!code.trim()) return;
    setError("");
    try {
      const result = await resolvePickup(code);
      navigate(
        `/${result.kind === "collection" ? "c" : "s"}/${result.shareToken}`,
      );
    } catch (reason) {
      setError(reason.message);
      window.requestAnimationFrame(() => inputRef.current?.focus());
    }
  };
  return (
    <form className="inline-pickup" onSubmit={submit}>
      <label htmlFor="quick-pickup">已有取件码？</label>
      <div className="pickup-input-wrap">
        <input
          ref={inputRef}
          id="quick-pickup"
          value={code}
          onChange={(event) => setCode(event.target.value.toUpperCase())}
          placeholder="输入取件码"
          maxLength={12}
          autoComplete="off"
        />
        <button type="submit" aria-label="领取文件">
          <ArrowRight />
        </button>
      </div>
    </form>
  );
}

function SendPanel({ config, navigate }) {
  const { me, configStatus } = useContext(SessionContext);
  const policy = config?.policy || {};
  const fileInput = useRef(null);
  const folderInput = useRef(null);
  const [files, setFiles] = useState([]);
  const [stage, setStage] = useState("idle");
  const [progress, setProgress] = useState(0);
  const [currentName, setCurrentName] = useState("");
  const [title, setTitle] = useState("");
  const {
    expiresHours,
    options: expiryOptions,
    setExpiresHours,
  } = usePolicyExpiry(policy);
  const policyMaxDownloads = Math.max(
    1,
    Number(policy.maxDownloads) || 1,
  );
  const downloadOptions = useMemo(
    () => Array.from({ length: policyMaxDownloads }, (_, index) => index + 1),
    [policyMaxDownloads],
  );
  const hasDownloadPolicy = Number(policy.maxDownloads) > 0;
  const defaultMaxDownloads = Math.min(20, policyMaxDownloads);
  const [maxDownloads, setMaxDownloads] = useState(null);
  const [downloadLimitTouched, setDownloadLimitTouched] = useState(false);
  const [result, setResult] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [, setError] = useToastMessage("error");
  const [dragging, setDragging] = useState(false);
  const [humanProof, setHumanProof] = useState(null);
  const [proofEpoch, setProofEpoch] = useState(0);
  const totalBytes = useMemo(
    () => files.reduce((sum, file) => sum + file.size, 0),
    [files],
  );
  const availability = getTransferAvailability(configStatus, config);
  const transferDisabled = !availability.available;

  useEffect(() => {
    if (!hasDownloadPolicy) return;
    setMaxDownloads((value) =>
      downloadLimitTouched
        ? Math.min(
            Math.max(1, Number(value) || defaultMaxDownloads),
            policyMaxDownloads,
          )
        : defaultMaxDownloads,
    );
  }, [
    defaultMaxDownloads,
    downloadLimitTouched,
    hasDownloadPolicy,
    policyMaxDownloads,
  ]);

  const addFiles = (incoming) => {
    if (transferDisabled) {
      setError(availability.reason);
      return;
    }
    const source = Array.from(incoming || []);
    const next = source.filter((file) => file.size > 0);
    if (!next.length) return;
    const tooLarge = next.find(
      (file) =>
        file.size >
        (policy.maxFileBytes ||
          config?.maxFileBytes ||
          Number.MAX_SAFE_INTEGER),
    );
    if (tooLarge) {
      setError(
        `${tooLarge.name} 超过本次上传总量上限 ${formatBytes(policy.maxFileBytes || config?.maxFileBytes)}`,
      );
      return;
    }
    const combined = [...files, ...next].slice(
      0,
      policy.maxFiles || config?.maxFiles || 100,
    );
    setFiles(combined);
    setStage("selected");
    setError("");
    if (next.length !== source.length) showToast("已忽略空文件", "warning");
  };
  const onDrop = (event) => {
    event.preventDefault();
    setDragging(false);
    if (transferDisabled) {
      setError(availability.reason);
      return;
    }
    addFiles(event.dataTransfer.files);
  };
  const removeFile = (index) => {
    const next = files.filter((_, itemIndex) => itemIndex !== index);
    setFiles(next);
    if (!next.length) setStage("idle");
  };
  const reset = () => {
    setFiles([]);
    setResult(null);
    setScanResult(null);
    setError("");
    setProgress(0);
    setStage("idle");
  };
  const submit = async () => {
    if (!files.length) return;
    if (transferDisabled) {
      setError(availability.reason);
      return;
    }
    if (
      totalBytes >
      (policy.maxTransferBytes ||
        config?.maxTransferBytes ||
        Number.MAX_SAFE_INTEGER)
    ) {
      setError(
        `文件总大小超过本次传输上限 ${formatBytes(policy.maxTransferBytes || config?.maxTransferBytes)}`,
      );
      return;
    }
    setError("");
    setStage("uploading");
    setProgress(0);
    let transfer;
    try {
      transfer = await createTransfer({
        kind: "send",
        title:
          title.trim() ||
          (files.length === 1 ? files[0].name : `${files.length} 个文件`),
        expiresHours: Number(expiresHours),
        maxDownloads: Number(maxDownloads ?? defaultMaxDownloads),
        humanProof,
      });
      let finishedBytes = 0;
      for (const file of files) {
        setCurrentName(file.webkitRelativePath || file.name);
        await uploadFile({
          shareToken: transfer.shareToken,
          manageToken: transfer.manageToken,
          file,
          onProgress: (loaded) =>
            setProgress(
              Math.round(((finishedBytes + loaded) / totalBytes) * 100),
            ),
        });
        finishedBytes += file.size;
        setProgress(Math.round((finishedBytes / totalBytes) * 100));
      }
      setStage("scanning");
      const finalState = await waitForManagedTransfer(
        transfer.shareToken,
        transfer.manageToken,
      );
      const published = await publishTransfer(
        transfer.shareToken,
        transfer.manageToken,
      );
      const completedTransfer = { ...transfer, ...published };
      setScanResult(finalState);
      rememberRecord({ ...completedTransfer, createdAt: Date.now() });
      setResult(completedTransfer);
      setStage(finalState.blockedFiles ? "partial" : "complete");
      showToast("上传完成，访问链接与取件码已生成", "success");
    } catch (reason) {
      setError(reason.message || "上传失败，请稍后重试");
      setResult(null);
      setScanResult(null);
      setStage("selected");
    } finally {
      setHumanProof(null);
      setProofEpoch((value) => value + 1);
    }
  };
  const acceptFiles = (event) => {
    addFiles(event.target.files);
    event.target.value = "";
  };

  return (
    <section
      className={`transfer-card ${dragging ? "is-dragging" : ""} ${transferDisabled ? "is-unavailable" : ""}`}
      onDragOver={(event) => {
        event.preventDefault();
        if (!transferDisabled) setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      aria-label="发送文件"
      aria-disabled={transferDisabled}
    >
      <div className="card-shine" />
      {transferDisabled && (
        <div className="transfer-availability" role="status">
          <WarningCircle weight="fill" />
          <span>{availability.reason}</span>
        </div>
      )}
      {stage === "idle" && (
        <div className="drop-state">
          <div className="upload-glyph">
            <FileArrowUp />
          </div>
          <h2>添加文件或文件夹</h2>
          <p>拖入此处，或从设备中选择</p>
          <button
            className="primary-button upload-button"
            type="button"
            disabled={transferDisabled}
            onClick={() => fileInput.current?.click()}
          >
            <FolderOpen weight="bold" /> 选择文件
          </button>
          <button
            className="text-button"
            type="button"
            disabled={transferDisabled}
            onClick={() => folderInput.current?.click()}
          >
            或选择整个文件夹
          </button>
          <Limits config={config} availability={availability} />
        </div>
      )}
      {stage === "selected" && (
        <div className="composer-state">
          <PanelHeading
            icon={<CloudArrowUp />}
            title="准备发送"
            subtitle={`${files.length} 个文件 · ${formatBytes(totalBytes)}`}
            onClose={reset}
          />
          <FileQueue files={files} onRemove={removeFile} />
          <div className="form-grid">
            <label className="field field-wide">
              <span>分享名称</span>
              <input
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                placeholder="例如：项目资料"
                maxLength={80}
              />
            </label>
            <label className="field">
              <span>有效期</span>
              <select
                value={expiresHours}
                onChange={(event) =>
                  setExpiresHours(Number(event.target.value))
                }
              >
                {expiryOptions.map(([hours, label]) => (
                  <option value={hours} key={hours}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>领取次数</span>
              <select
                value={maxDownloads ?? defaultMaxDownloads}
                onChange={(event) => {
                  setDownloadLimitTouched(true);
                  setMaxDownloads(Number(event.target.value));
                }}
              >
                {downloadOptions.map((count) => (
                  <option value={count} key={count}>
                    {count} 次
                  </option>
                ))}
              </select>
            </label>
          </div>
          {!me && (
            <HumanVerification
              key={`guest-transfer-${proofEpoch}`}
              action="guest_transfer"
              config={config?.captcha}
              onProof={setHumanProof}
              disabled={transferDisabled || stage !== "selected"}
            />
          )}
          <div className="composer-actions">
            <button
              className="secondary-button"
              type="button"
              disabled={transferDisabled}
              onClick={() => fileInput.current?.click()}
            >
              <Plus /> 添加文件
            </button>
            <button
              className="primary-button"
              type="button"
              onClick={submit}
              disabled={
                transferDisabled ||
                (!me &&
                  config?.captcha?.enabled &&
                  config?.captcha?.actions?.guest_transfer &&
                  !humanProof)
              }
            >
              <UploadSimple weight="bold" /> 生成链接并上传
            </button>
          </div>
        </div>
      )}
      {(stage === "uploading" || stage === "scanning") && (
        <ProgressState
          progress={progress}
          scanning={stage === "scanning"}
          name={currentName}
        />
      )}
      {(stage === "complete" || stage === "partial") &&
        result && (
          <ResultState
            result={result}
            partial={stage === "partial"}
            scanResult={scanResult}
            onReset={reset}
            navigate={navigate}
          />
        )}
      <input
        ref={fileInput}
        className="visually-hidden"
        type="file"
        tabIndex={-1}
        aria-hidden="true"
        multiple
        disabled={transferDisabled}
        onChange={acceptFiles}
      />
      <input
        ref={folderInput}
        className="visually-hidden"
        type="file"
        tabIndex={-1}
        aria-hidden="true"
        multiple
        webkitdirectory=""
        directory=""
        disabled={transferDisabled}
        onChange={acceptFiles}
      />
    </section>
  );
}

function Limits({ config, availability }) {
  const policy = config?.policy || {};
  return (
    <div className="limit-stack">
      <div className="limit-row">
        <span>
          本次总大小 ≤{" "}
          {formatBytes(
            policy.maxTransferBytes ||
              config?.maxTransferBytes ||
              100 * 1024 ** 2,
          )}
        </span>
        <i />
        <span>文件数量 ≤ {policy.maxFiles || config?.maxFiles || 100}</span>
      </div>
      {!availability.available && (
        <div className="limit-row limit-row--unavailable" role="status">
          <span>{availability.label}</span>
          <i />
          <span>新传输已暂停</span>
        </div>
      )}
      <span className="tier-note">
        每次领取会话计 1 次，会话内可下载全部文件；次数用完后自动删除
      </span>
    </div>
  );
}

function FileQueue({ files, onRemove }) {
  return (
    <div className="file-queue">
      {files.slice(0, 4).map((file, index) => (
        <div className="file-row" key={`${file.name}-${file.size}-${index}`}>
          <span className="file-icon">
            <File weight="duotone" />
          </span>
          <span className="file-meta">
            <strong title={file.webkitRelativePath || file.name}>
              {file.webkitRelativePath || file.name}
            </strong>
            <small>{formatBytes(file.size)}</small>
          </span>
          <button
            type="button"
            onClick={() => onRemove(index)}
            aria-label={`移除 ${file.name}`}
          >
            <X />
          </button>
        </div>
      ))}
      {files.length > 4 && (
        <div className="queue-more">另有 {files.length - 4} 个文件已加入</div>
      )}
    </div>
  );
}

function PanelHeading({ icon, title, subtitle, onClose }) {
  return (
    <div className="panel-heading">
      <span className="panel-heading-icon">{icon}</span>
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
      {onClose && (
        <button type="button" onClick={onClose} aria-label="关闭">
          <X />
        </button>
      )}
    </div>
  );
}

function ProgressState({ progress, scanning, name }) {
  return (
    <div className="progress-state">
      <div className={`progress-orbit ${scanning ? "is-scanning" : ""}`}>
        {scanning ? (
          <Scan />
        ) : (
          <span>
            {progress}
            <small>%</small>
          </span>
        )}
      </div>
      <span className="progress-kicker">
        {scanning ? "文件检查中" : "正在分片上传"}
      </span>
      <h2>{scanning ? "最后一步，正在检查文件" : "保持页面开启，很快就好"}</h2>
      <p>{scanning ? "通过检查后才会开放下载" : name}</p>
      <progress
        className="progress-track"
        max="100"
        value={scanning ? 100 : progress}
      />
    </div>
  );
}

function ResultState({
  result,
  partial,
  scanResult,
  onReset,
  navigate,
}) {
  const [copied, setCopied] = useState("");
  const copy = async (value, key) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(key);
      showToast(key === "link" ? "访问链接已复制" : "取件码已复制", "success");
      window.setTimeout(() => setCopied(""), 1600);
    } catch {
      showToast("复制失败，请手动复制", "error");
    }
  };
  return (
    <div className="result-state">
      <div className={`result-icon ${partial ? "is-warning" : ""}`}>
        {partial ? (
          <WarningCircle weight="fill" />
        ) : (
          <CheckCircle weight="fill" />
        )}
      </div>
      <span className="progress-kicker">
        {partial ? "已完成，部分文件被拦截" : "文件已完成检查"}
      </span>
      <h2>把链接或取件码发给对方</h2>
      {partial && (
        <InlineNotice tone="warning">
          {`文件检查拦截了 ${scanResult?.blockedFiles || 1} 个风险文件`}
        </InlineNotice>
      )}
      <div className="share-box">
        <div>
          <span>分享链接</span>
          <strong>{result.shareURL}</strong>
        </div>
        <button
          type="button"
          onClick={() => copy(result.shareURL, "link")}
          aria-label="复制分享链接"
        >
          {copied === "link" ? <Check /> : <Copy />}
        </button>
      </div>
      <div className="result-grid">
        <div className="pickup-code-card">
          <span>取件码</span>
          <strong>{result.pickupCode}</strong>
          <button type="button" onClick={() => copy(result.pickupCode, "code")}>
            {copied === "code" ? "已复制" : "复制"}
          </button>
        </div>
        <div className="qr-card">
          <QRCodeSVG
            value={result.shareURL}
            size={108}
            bgColor="transparent"
            fgColor="#ffffff"
            level="M"
          />
          <span>
            <QrCode /> 扫码领取
          </span>
        </div>
      </div>
      <div className="composer-actions result-actions">
        <button
          className="secondary-button"
          type="button"
          onClick={() => navigate(`/manage/${result.shareToken}`)}
        >
          管理传输
        </button>
        <button className="primary-button" type="button" onClick={onReset}>
          继续发送
        </button>
      </div>
    </div>
  );
}

function PickupPanel({ navigate }) {
  const inputRef = useRef(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useToastMessage("error");
  const submit = async (event) => {
    event.preventDefault();
    if (code.trim().length < 4) return;
    setBusy(true);
    setError("");
    try {
      const result = await resolvePickup(code);
      navigate(
        `/${result.kind === "collection" ? "c" : "s"}/${result.shareToken}`,
      );
    } catch (reason) {
      setError(reason.message);
      window.requestAnimationFrame(() => inputRef.current?.focus());
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="transfer-card compact-card">
      <div className="card-shine" />
      <form className="pickup-panel" onSubmit={submit}>
        <div className="upload-glyph">
          <Password />
        </div>
        <span className="progress-kicker">取件</span>
        <h2>输入取件码</h2>
        <p>取件码不区分大小写</p>
        <input
          ref={inputRef}
          className="code-input"
          aria-label="取件码"
          aria-invalid={Boolean(error)}
          value={code}
          onChange={(event) =>
            setCode(event.target.value.toUpperCase().replace(/\s/g, ""))
          }
          placeholder="•••• ••••••"
          maxLength={10}
          autoFocus
        />
        <button
          className="primary-button wide-button"
          type="submit"
          disabled={busy || code.length < 4}
        >
          {busy ? "正在查找…" : "领取文件"}
          <ArrowRight />
        </button>
        <p className="subtle-copy">
          <ShieldCheck /> 连续输错会自动限流，防止取件码被猜测
        </p>
      </form>
    </section>
  );
}

function CreateCollectionPanel({ config, navigate }) {
  const { me, configStatus } = useContext(SessionContext);
  const policy = config?.policy || {};
  const [title, setTitle] = useState("资料收集");
  const {
    expiresHours,
    options: expiryOptions,
    setExpiresHours,
  } = usePolicyExpiry(policy);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useToastMessage("error");
  const [copied, setCopied] = useState(false);
  const [humanProof, setHumanProof] = useState(null);
  const [proofEpoch, setProofEpoch] = useState(0);
  const availability = getTransferAvailability(configStatus, config);
  const creationDisabled = !availability.available;
  const submit = async (event) => {
    event.preventDefault();
    if (creationDisabled) {
      setError(availability.reason);
      return;
    }
    setBusy(true);
    setError("");
    try {
      const created = await createTransfer({
        kind: "collection",
        title,
        expiresHours: Number(expiresHours),
        maxDownloads: Math.min(100, policy.maxDownloads || 20),
        humanProof,
      });
      rememberRecord({ ...created, createdAt: Date.now() });
      setResult(created);
      showToast("收集入口与取件码已生成", "success");
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy(false);
      setHumanProof(null);
      setProofEpoch((value) => value + 1);
    }
  };
  if (result)
    return (
      <section className="transfer-card compact-card">
        <div className="card-shine" />
        <div className="collection-result">
          <div className="result-icon">
            <CheckCircle weight="fill" />
          </div>
          <span className="progress-kicker">收集入口已创建</span>
          <h2>把入口发给提交者</h2>
          <p>提交者只能上传，看不到其他人交来的文件。</p>
          <div className="share-box">
            <div>
              <span>收集链接</span>
              <strong>{result.shareURL}</strong>
            </div>
            <button
              type="button"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(result.shareURL);
                  setCopied(true);
                  showToast("收集链接已复制", "success");
                } catch {
                  showToast("复制失败，请手动复制", "error");
                }
              }}
              aria-label="复制收集链接"
            >
              {copied ? <Check /> : <Copy />}
            </button>
          </div>
          <div className="collection-code">
            <span>入口码</span>
            <strong>{result.pickupCode}</strong>
          </div>
          <div className="composer-actions result-actions">
            <button
              className="secondary-button"
              type="button"
              onClick={() => navigate(`/manage/${result.shareToken}`)}
            >
              查看收件箱
            </button>
            <button
              className="primary-button"
              type="button"
              onClick={() => setResult(null)}
            >
              再建一个
            </button>
          </div>
        </div>
      </section>
    );
  return (
    <section
      className={`transfer-card compact-card ${creationDisabled ? "is-unavailable" : ""}`}
      aria-disabled={creationDisabled}
    >
      <div className="card-shine" />
      {creationDisabled && (
        <div className="transfer-availability" role="status">
          <WarningCircle weight="fill" />
          <span>{availability.reason}</span>
        </div>
      )}
      <form className="collection-form" onSubmit={submit}>
        <PanelHeading
          icon={<FolderOpen />}
          title="创建收集入口"
          subtitle="只需一个链接，集中接收文件"
        />
        <label className="field field-wide">
          <span>收集主题</span>
          <input
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            maxLength={80}
            disabled={creationDisabled}
            required
          />
        </label>
        <div className="form-grid">
          <label className="field">
            <span>有效期</span>
            <select
              value={expiresHours}
              onChange={(event) => setExpiresHours(Number(event.target.value))}
              disabled={creationDisabled}
            >
              {expiryOptions.map(([hours, label]) => (
                <option value={hours} key={hours}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="privacy-note">
          <ShieldCheck />
          <div>
            <strong>提交内容彼此隔离</strong>
            <span>上传者无法查看、下载或覆盖其他人的文件</span>
          </div>
        </div>
        {!me && (
          <HumanVerification
            key={`guest-collection-${proofEpoch}`}
            action="guest_transfer"
            config={config?.captcha}
            onProof={setHumanProof}
            disabled={creationDisabled || busy}
          />
        )}
        <button
          className="primary-button wide-button"
          disabled={
            busy ||
            creationDisabled ||
            (!me &&
              config?.captcha?.enabled &&
              config?.captcha?.actions?.guest_transfer &&
              !humanProof)
          }
          type="submit"
        >
          {busy ? "正在创建…" : "生成收集入口"}
          <ArrowRight />
        </button>
      </form>
    </section>
  );
}

function ReceivePage({ token, navigate }) {
  const [transfer, setTransfer] = useState(null);
  const [unlockToken, setUnlockToken] = useState("");
  const [retrievalSession, setRetrievalSession] = useState(() =>
    readRetrievalSession(token),
  );
  const [code, setCode] = useState("");
  const [error, setError] = useToastMessage("error");
  const [pageError, setPageError] = useState("");
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState("");
  const [reported, setReported] = useState(false);
  const load = async (
    ticket = unlockToken,
    { persistent = false, session = retrievalSession } = {},
  ) => {
    setLoading(true);
    if (persistent) setPageError("");
    try {
      setTransfer(await getShare(token, ticket, session?.token || ""));
    } catch (reason) {
      if (reason.code === "download_limit") {
        clearRetrievalSession(token);
        setRetrievalSession(null);
      }
      if (persistent) setPageError(reason.message);
      else setError(reason.message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    const storedSession = readRetrievalSession(token);
    setRetrievalSession(storedSession);
    setTransfer(null);
    load("", { persistent: true, session: storedSession });
  }, [token]);
  const unlock = async (event) => {
    event.preventDefault();
    setError("");
    try {
      const result = await unlockShare(token, code);
      setUnlockToken(result.unlockToken);
      await load(result.unlockToken);
    } catch (reason) {
      setError(reason.message);
    }
  };
  const download = async (file) => {
    setDownloading(file.id);
    setError("");
    try {
      const result = await createDownload(
        token,
        file.id,
        unlockToken,
        "",
        retrievalSession?.token || "",
      );
      const nextSession = storeRetrievalSession(
        token,
        result.retrievalToken,
        result.retrievalExpiresAt,
      );
      if (nextSession) setRetrievalSession(nextSession);
      window.location.assign(result.downloadURL);
    } catch (reason) {
      if (reason.code === "download_limit") {
        clearRetrievalSession(token);
        setRetrievalSession(null);
        setTransfer((current) =>
          current ? { ...current, status: "exhausted" } : current,
        );
      }
      setError(reason.message);
    } finally {
      setDownloading("");
    }
  };
  const report = async () => {
    const detail = window.prompt(
      "请简要描述问题（不要填写隐私信息）",
      "疑似风险文件",
    );
    if (detail === null) return;
    try {
      await reportShare(token, "suspicious-file", detail);
      setReported(true);
      showToast("举报已提交", "success");
    } catch (reason) {
      setError(reason.message);
    }
  };
  return (
    <div className="page-frame inner-page">
      <Header active="pickup" navigate={navigate} />
      <main className="inner-layout">
        <section className="inner-intro">
          <button
            className="back-link"
            type="button"
            onClick={() => navigate("/")}
          >
            <ArrowLeft /> 返回首页
          </button>
          <span className="eyebrow">
            <LinkSimple /> 文件领取
          </span>
          <h1>
            你的文件，
            <br />
            已经抵达。
          </h1>
          <p>文件完成隔离检查后才会出现在这里。</p>
          <div className="trust-column">
            <span>
              <ShieldCheck /> 一次领取可下载任务内全部文件
            </span>
            <span>
              <Clock /> 领取会话最长保留 30 分钟
            </span>
            <span>
              <LockKey />{" "}
              {window.location.protocol === "https:"
                ? "传输连接已加密"
                : "当前为受控安全连接"}
            </span>
          </div>
        </section>
        <section className="content-glass receive-card">
          {loading && <LoadingState label="正在读取文件…" />}
          {!loading && pageError && !transfer && (
            <EmptyState
              icon={<WarningCircle />}
              title="无法领取文件"
              detail={pageError}
              action={() => load("", { persistent: true })}
              actionLabel="重新尝试"
            />
          )}
          {!loading && transfer?.locked && (
            <form className="unlock-form" onSubmit={unlock}>
              <div className="upload-glyph">
                <LockKey />
              </div>
              <span className="progress-kicker">受密码保护</span>
              <h2>{transfer.title}</h2>
              <p>输入发送方设置的访问密码</p>
              <input
                className="code-input password-input"
                type="password"
                aria-label="文件访问密码"
                aria-invalid={Boolean(error)}
                value={code}
                onChange={(event) => setCode(event.target.value)}
                placeholder="访问密码"
                autoFocus
              />
              <button className="primary-button wide-button" type="submit">
                验证并查看
              </button>
            </form>
          )}
          {!loading && transfer && !transfer.locked && (
            <div className="download-view">
              <PanelHeading
                icon={<FolderOpen />}
                title={transfer.title}
                subtitle={`${transfer.fileCount} 个文件 · ${formatBytes(transfer.totalBytes)}`}
              />
              <div className="transfer-meta">
                <span>
                  <Clock /> {formatExpiry(transfer.expiresAt)}
                </span>
                <span>
                  <DownloadSimple />
                  {retrievalSession?.token
                    ? " 当前领取会话内不重复计次"
                    : ` 剩余 ${Math.max(
                        Number(transfer.maxDownloads || 0) -
                          Number(transfer.downloads || 0),
                        0,
                      )} 次`}
                </span>
                <span>
                  <ShieldCheck /> 已完成基础风险检查
                </span>
              </div>
              {transfer.status === "exhausted" && !retrievalSession?.token && (
                <InlineNotice tone="warning">
                  领取次数已用完，文件将在有效领取会话结束后自动删除。
                </InlineNotice>
              )}
              {transfer.scanning && (
                <InlineNotice tone="info">
                  仍有文件正在隔离检查，通过后会自动出现。
                </InlineNotice>
              )}
              <div className="download-list">
                {(transfer.files || []).map((file) => (
                  <div className="download-row" key={file.id}>
                    <span className="file-icon">
                      <File weight="duotone" />
                    </span>
                    <span className="file-meta">
                      <strong>{file.name}</strong>
                      <small>{formatBytes(file.size)} · 已完成检查</small>
                    </span>
                    <button
                      type="button"
                      aria-label={`下载 ${file.name}`}
                      title={`下载 ${file.name}`}
                      onClick={() => download(file)}
                      disabled={
                        Boolean(downloading) ||
                        (transfer.status === "exhausted" &&
                          !retrievalSession?.token)
                      }
                    >
                      {downloading === file.id ? (
                        <span className="mini-spinner" />
                      ) : (
                        <DownloadSimple />
                      )}
                    </button>
                  </div>
                ))}
              </div>
              {!transfer.files?.length && !transfer.scanning && (
                <EmptyState
                  icon={<File />}
                  title="暂时没有可领取文件"
                  detail="文件可能已被撤销或未通过检查"
                />
              )}
              <p className="legal-note">
                <span>请仅下载你信任的文件。本站不会要求你运行未知程序。</span>
                <button type="button" onClick={report} disabled={reported}>
                  <Flag /> {reported ? "已提交举报" : "举报"}
                </button>
              </p>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

function CollectionUploadPage({ token, navigate }) {
  const { me, config, configStatus } = useContext(SessionContext);
  const fileInput = useRef(null);
  const [transfer, setTransfer] = useState(null);
  const [unlockToken, setUnlockToken] = useState("");
  const [code, setCode] = useState("");
  const [submitterName, setSubmitterName] = useState("");
  const [files, setFiles] = useState([]);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState("loading");
  const [error, setError] = useToastMessage("error");
  const [pageError, setPageError] = useState("");
  const [humanProof, setHumanProof] = useState(null);
  const [proofEpoch, setProofEpoch] = useState(0);
  const availability = getTransferAvailability(configStatus, config);
  const uploadDisabled = !availability.available;
  const proofRequired = Boolean(
    !me &&
      config?.captcha?.enabled &&
      config?.captcha?.actions?.guest_transfer,
  );
  useEffect(() => {
    setPageError("");
    getShare(token)
      .then((data) => {
        setTransfer(data);
        setStage(data.locked ? "locked" : "ready");
      })
      .catch((reason) => {
        setPageError(reason.message);
        setStage("error");
      });
  }, [token]);
  const unlock = async (event) => {
    event.preventDefault();
    setError("");
    try {
      const result = await unlockShare(token, code);
      setUnlockToken(result.unlockToken);
      setStage("ready");
    } catch (reason) {
      setError(reason.message);
    }
  };
  const send = async () => {
    if (!files.length) return;
    if (uploadDisabled) {
      setError(availability.reason);
      return;
    }
    if (proofRequired && !humanProof) {
      setError("请先完成人机验证");
      return;
    }
    const total = files.reduce((sum, file) => sum + file.size, 0);
    let done = 0;
    setStage("uploading");
    setError("");
    try {
      for (const file of files) {
        await uploadFile({
          shareToken: token,
          unlockToken,
          submitterName,
          humanProof,
          file,
          onProgress: (loaded) =>
            setProgress(Math.round(((done + loaded) / total) * 100)),
        });
        done += file.size;
      }
      setProgress(100);
      setStage("complete");
    } catch (reason) {
      setError(reason.message);
      setStage("ready");
    } finally {
      setHumanProof(null);
      setProofEpoch((value) => value + 1);
    }
  };
  return (
    <div className="page-frame inner-page">
      <Header active="collect" navigate={navigate} />
      <main className="centered-inner">
        <section className="collection-title">
          <span className="eyebrow">
            <CloudArrowUp /> 文件收集
          </span>
          <h1>{transfer?.title || "文件收集"}</h1>
          <p>你只能提交自己的文件，无法查看其他人的内容。</p>
        </section>
        <section className="content-glass collection-upload-card">
          {stage === "loading" && <LoadingState label="正在打开收集入口…" />}
          {stage === "error" && (
            <EmptyState
              icon={<WarningCircle />}
              title="入口不可用"
              detail={pageError}
              action={() => navigate("/")}
              actionLabel="返回首页"
            />
          )}
          {stage === "locked" && (
            <form className="unlock-form" onSubmit={unlock}>
              <div className="upload-glyph">
                <LockKey />
              </div>
              <span className="progress-kicker">需要提交密码</span>
              <h2>验证后即可上传</h2>
              <input
                className="code-input password-input"
                type="password"
                aria-label="收集入口提交密码"
                aria-invalid={Boolean(error)}
                value={code}
                onChange={(event) => setCode(event.target.value)}
                placeholder="提交密码"
                autoFocus
              />
              <button className="primary-button wide-button" type="submit">
                验证入口
              </button>
            </form>
          )}
          {stage === "ready" && (
            <div className="collection-ready">
              <PanelHeading
                icon={<UploadSimple />}
                title="提交文件"
                subtitle={
                  files.length
                    ? `${files.length} 个文件 · ${formatBytes(files.reduce((sum, file) => sum + file.size, 0))}`
                    : "选择需要提交的文件"
                }
              />
              {uploadDisabled && (
                <InlineNotice tone="warning">
                  {availability.reason}
                </InlineNotice>
              )}
              <label className="field field-wide">
                <span>你的称呼（可选）</span>
                <div className="input-with-icon">
                  <User />
                  <input
                    value={submitterName}
                    onChange={(event) => setSubmitterName(event.target.value)}
                    maxLength={48}
                    disabled={uploadDisabled}
                    placeholder="方便收件人识别"
                  />
                </div>
              </label>
              <button
                className="collection-drop"
                type="button"
                disabled={uploadDisabled}
                onClick={() => fileInput.current?.click()}
              >
                <span className="upload-glyph small">
                  <FileArrowUp />
                </span>
                <strong>{files.length ? "继续添加文件" : "选择文件"}</strong>
                <small>文件会先上传至隔离区并接受文件检查</small>
              </button>
              {files.length > 0 && (
                <FileQueue
                  files={files}
                  onRemove={(index) =>
                    setFiles(
                      files.filter((_, itemIndex) => itemIndex !== index),
                    )
                  }
                />
              )}
              {!me && (
                <HumanVerification
                  key={`collection-upload-${proofEpoch}`}
                  action="guest_transfer"
                  config={config?.captcha}
                  onProof={(proof) => {
                    setHumanProof(proof);
                    if (proof) setError("");
                  }}
                  disabled={uploadDisabled || stage !== "ready"}
                />
              )}
              <button
                className="primary-button wide-button"
                type="button"
                disabled={
                  uploadDisabled ||
                  !files.length ||
                  (proofRequired && !humanProof)
                }
                onClick={send}
              >
                开始提交 <ArrowRight />
              </button>
              <input
                ref={fileInput}
                className="visually-hidden"
                type="file"
                tabIndex={-1}
                aria-hidden="true"
                multiple={!proofRequired}
                disabled={uploadDisabled}
                onChange={(event) => {
                  const selected = Array.from(event.target.files).filter(
                    (file) => file.size > 0,
                  );
                  if (proofRequired) {
                    setFiles(selected.slice(0, 1));
                    if (selected.length > 1) {
                      setError("启用人机验证时每次提交一个文件，完成后可继续提交");
                    }
                  } else {
                    setFiles([...files, ...selected]);
                  }
                  event.target.value = "";
                }}
              />
            </div>
          )}
          {stage === "uploading" && (
            <ProgressState
              progress={progress}
              scanning={false}
              name="正在提交，请保持页面开启"
            />
          )}
          {stage === "complete" && (
            <div className="submission-complete">
              <div className="result-icon">
                <CheckCircle weight="fill" />
              </div>
              <span className="progress-kicker">提交成功</span>
              <h2>文件已进入隔离检查</h2>
              <p>收件人会在检查通过后看到文件。</p>
              <button
                className="primary-button"
                type="button"
                onClick={() => {
                  setFiles([]);
                  setProgress(0);
                  setStage("ready");
                }}
              >
                继续提交
              </button>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

function ManagePage({ token, navigate }) {
  const { me } = useContext(SessionContext);
  const record = getRecord(token);
  const [transfer, setTransfer] = useState(null);
  const [retrievalSession, setRetrievalSession] = useState(() =>
    readRetrievalSession(token),
  );
  const [, setError] = useToastMessage("error");
  const [pageError, setPageError] = useState("");
  const [loading, setLoading] = useState(true);
  const [revoked, setRevoked] = useState(false);
  const [downloading, setDownloading] = useState("");
  const load = async ({ silent = false } = {}) => {
    if (!record && !me) {
      setLoading(false);
      return;
    }
    if (!silent) setPageError("");
    try {
      setTransfer(await getManagedTransfer(token, record?.manageToken || ""));
    } catch (reason) {
      if (!silent && !transfer) setPageError(reason.message);
      else if (!silent) setError(reason.message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    setRetrievalSession(readRetrievalSession(token));
    load({ silent: false });
  }, [token, me?.user?.id]);
  useEffect(() => {
    if (!transfer?.scanning) return undefined;
    const timer = window.setInterval(() => load({ silent: true }), 1000);
    return () => window.clearInterval(timer);
  }, [transfer?.scanning]);
  const download = async (file) => {
    setDownloading(file.id);
    try {
      const result = await createDownload(
        token,
        file.id,
        "",
        record?.manageToken || "",
        retrievalSession?.token || "",
      );
      const nextSession = storeRetrievalSession(
        token,
        result.retrievalToken,
        result.retrievalExpiresAt,
      );
      if (nextSession) setRetrievalSession(nextSession);
      await load({ silent: true });
      window.location.assign(result.downloadURL);
    } catch (reason) {
      if (reason.code === "download_limit") {
        clearRetrievalSession(token);
        setRetrievalSession(null);
        await load({ silent: true });
      }
      setError(reason.message);
    } finally {
      setDownloading("");
    }
  };
  const revoke = async () => {
    if (!window.confirm("撤销后，分享链接和全部文件将不再可用。确定继续？"))
      return;
    try {
      await revokeTransfer(token, record?.manageToken || "");
      setRevoked(true);
    } catch (reason) {
      setError(reason.message);
    }
  };
  return (
    <div className="page-frame inner-page">
      <Header
        active={
          (record?.kind || transfer?.kind) === "collection" ? "collect" : "send"
        }
        navigate={navigate}
        compact
      />
      <main className="manage-layout">
        <div className="manage-top">
          <div>
            <button
              className="back-link"
              type="button"
              onClick={() => navigate("/")}
            >
              <ArrowLeft /> 返回首页
            </button>
            <span className="eyebrow">
              <ShieldCheck /> 传输管理
            </span>
            <h1>传输管理</h1>
          </div>
          {(record || transfer) && !revoked && (
            <button className="danger-button" type="button" onClick={revoke}>
              <Trash /> 撤销并销毁
            </button>
          )}
        </div>
        <section className="content-glass manage-card">
          {!loading && !record && !me && (
            <EmptyState
              icon={<LockKey />}
              title="缺少管理权限"
              detail="请在创建任务的浏览器中打开，或登录已认领该任务的账户。"
              action={() => navigate("/login")}
              actionLabel="登录账户"
            />
          )}
          {loading && <LoadingState label="正在读取传输状态…" />}
          {!loading && pageError && !transfer && (record || me) && (
            <EmptyState
              icon={<WarningCircle />}
              title="无法管理此传输"
              detail={pageError}
              action={() => navigate("/account")}
              actionLabel="返回账户"
            />
          )}
          {revoked && (
            <EmptyState
              icon={<CheckCircle />}
              title="传输已撤销"
              detail="链接已经失效，文件将在后台安全清理。"
              action={() => navigate("/")}
              actionLabel="完成"
            />
          )}
          {!loading && !revoked && transfer && (
            <div className="manage-content">
              <PanelHeading
                icon={
                  transfer.kind === "collection" ? (
                    <FolderOpen />
                  ) : (
                    <PaperPlaneTilt />
                  )
                }
                title={transfer.title}
                subtitle={`${transfer.fileCount} 个文件 · ${formatBytes(transfer.totalBytes)}`}
              />
              <div className="stats-row">
                <Stat label="取件码" value={transfer.pickupCode} />
                <Stat
                  label="领取次数"
                  value={`${transfer.downloads} / ${transfer.maxDownloads}`}
                />
                <Stat
                  label="剩余时间"
                  value={formatExpiry(transfer.expiresAt, true)}
                />
                <Stat
                  label="安全状态"
                  value={
                    transfer.status === "exhausted"
                      ? "领取已耗尽"
                      : transfer.scanning
                      ? "扫描中"
                      : transfer.blockedFiles
                        ? `拦截 ${transfer.blockedFiles}`
                        : "正常"
                  }
                />
              </div>
              {transfer.scanning && (
                <InlineNotice tone="info">
                  文件仍在隔离区扫描，通过后才能下载。
                </InlineNotice>
              )}
              {transfer.blockedFiles > 0 && (
                <InlineNotice tone="warning">
                  有 {transfer.blockedFiles} 个文件未通过检查，已阻止下载。
                </InlineNotice>
              )}
              {transfer.status === "exhausted" && (
                <InlineNotice tone="warning">
                  领取次数已用完；现有领取会话结束后文件将自动删除。
                </InlineNotice>
              )}
              <div className="manage-files">
                {(transfer.files || []).map((file) => (
                  <div className="manage-file" key={file.id}>
                    <span className={`status-icon status-${file.status}`}>
                      {file.status === "ready" ? (
                        <Check />
                      ) : file.status === "blocked" ? (
                        <X />
                      ) : (
                        <Scan />
                      )}
                    </span>
                    <span className="file-meta">
                      <strong>{file.name}</strong>
                      <small>
                        {formatBytes(file.size)} · {statusLabel(file.status)}
                        {file.submitterName
                          ? ` · 来自 ${file.submitterName}`
                          : ""}
                      </small>
                    </span>
                    {file.status === "ready" && (
                      <button
                        type="button"
                        onClick={() => download(file)}
                        disabled={Boolean(downloading)}
                      >
                        {downloading === file.id ? (
                          <span className="mini-spinner" />
                        ) : (
                          <DownloadSimple />
                        )}
                        下载
                      </button>
                    )}
                  </div>
                ))}
              </div>
              {!transfer.files?.length && (
                <EmptyState
                  icon={<File />}
                  title="还没有文件"
                  detail={
                    transfer.kind === "collection"
                      ? "把收集链接发给提交者，文件会显示在这里。"
                      : "等待文件上传完成。"
                  }
                />
              )}
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

function AuthPage({ navigate }) {
  const {
    me,
    config,
    refreshSession,
    requestDailyCheckInReminder,
  } = useContext(SessionContext);
  const [mode, setMode] = useState("login");
  const [phase, setPhase] = useState("form");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [humanProof, setHumanProof] = useState(null);
  const [proofEpoch, setProofEpoch] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useToastMessage("error");
  const [, setNotice] = useToastMessage("success");
  const [retryAt, setRetryAt] = useState(0);
  const [clock, setClock] = useState(Date.now());
  const codeInputRef = useRef(null);
  const allowedDomains = config?.emailAllowedDomains || [];
  const allowedDomainText = allowedDomains.length
    ? allowedDomains.map((domain) => `@${domain}`).join("、")
    : "正在读取邮箱策略";
  const resendIn = Math.max(0, Math.ceil((retryAt - clock) / 1000));

  useEffect(() => {
    if (!retryAt) return undefined;
    const update = () => {
      const now = Date.now();
      setClock(now);
      if (now >= retryAt) setRetryAt(0);
    };
    update();
    const timer = window.setInterval(update, 1000);
    return () => window.clearInterval(timer);
  }, [retryAt]);

  useEffect(() => {
    if (phase === "verify") codeInputRef.current?.focus();
  }, [phase]);

  const startRetryCountdown = (seconds) => {
    const duration = Math.max(
      1,
      Number(seconds) || Number(config?.verificationCooldownSeconds) || 120,
    );
    const now = Date.now();
    setClock(now);
    setRetryAt(now + duration * 1000);
  };

  const switchMode = (next) => {
    if (busy) return;
    if (next === "register" && !config?.registrationOpen) return;
    setMode(next);
    setPhase("form");
    setPassword("");
    setCode("");
    setTermsAccepted(false);
    setHumanProof(null);
    setProofEpoch((value) => value + 1);
    setError("");
    setNotice("");
    setRetryAt(0);
  };
  const finish = async (
    showDailyCheckInReminder = false,
    membershipDailyTrafficGrant = null,
  ) => {
    const nextMe = await refreshSession();
    if (Number(membershipDailyTrafficGrant?.rewardBytes) > 0) {
      const planName =
        {
          monthly: "月度会员",
          yearly: "年度会员",
          lifetime: "终身会员",
        }[membershipDailyTrafficGrant.vipPlan] || "会员";
      showToast(
        `${planName}权益到账：${formatBytes(membershipDailyTrafficGrant.rewardBytes)} 永久上传流量`,
        "success",
      );
    }
    if (showDailyCheckInReminder) {
      navigate("/");
      requestDailyCheckInReminder(nextMe);
      return;
    }
    navigate("/account");
  };
  const maskedEmail = () => {
    const [local = "", domain = ""] = email.split("@");
    if (!domain) return email;
    return `${local.slice(0, 2)}${"*".repeat(Math.max(2, Math.min(6, local.length - 2)))}@${domain}`;
  };
  const requestCode = async () => {
    if (!allowedDomains.length)
      throw new Error("邮箱验证策略尚未加载，请稍后重试");
    const normalizedInput = email.trim().toLowerCase();
    const domain = normalizedInput.split("@").pop();
    if (normalizedInput.includes("+") || !allowedDomains.includes(domain)) {
      throw new Error(`仅支持 ${allowedDomainText}，且不接受 + 别名`);
    }
    if (mode === "register" && !config?.registrationOpen)
      throw new Error("当前暂未开放新用户注册");
    const result =
      mode === "register"
        ? await register({
            email,
            termsAccepted,
            termsVersion: config?.terms?.version,
            humanProof,
          })
        : await requestPasswordReset({ email, humanProof });
    setCode("");
    setHumanProof(null);
    setProofEpoch((value) => value + 1);
    setPhase("verify");
    startRetryCountdown(result.retryAfterSeconds);
    const minutes = Math.max(
      1,
      Math.ceil(
        Number(
          result.expiresIn || config?.verificationCodeExpiresSeconds || 600,
        ) / 60,
      ),
    );
    if (mode === "reset") {
      showToast(
        `如账户存在，验证码将发送至 ${maskedEmail()}，${minutes} 分钟内有效`,
        "info",
      );
    } else {
      showToast(
        `验证码已发送至 ${maskedEmail()}，${minutes} 分钟内有效`,
        "info",
      );
    }
  };
  const resend = async () => {
    if (busy || resendIn > 0) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestCode();
    } catch (reason) {
      setError(reason.message);
      setHumanProof(null);
      setProofEpoch((value) => value + 1);
      if (reason.retryAfterSeconds > 0)
        startRetryCountdown(reason.retryAfterSeconds);
    } finally {
      setBusy(false);
    }
  };
  const submit = async (event) => {
    event.preventDefault();
    if (mode !== "login" && phase === "form" && resendIn > 0) {
      showToast(`${resendIn} 秒后可再次发送验证码`, "warning");
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (mode === "login") {
        const result = await login({ email, password, humanProof });
        await finish(
          Boolean(result?.dailyCheckInReminder),
          result?.membershipDailyTrafficGrant,
        );
      } else if (mode === "register" && phase === "form") {
        await requestCode();
      } else if (mode === "register") {
        const result = await verifyRegistration({ email, code, password });
        await finish(Boolean(result?.dailyCheckInReminder));
      } else if (mode === "reset" && phase === "form") {
        await requestCode();
      } else {
        await confirmPasswordReset({ email, code, password });
        setMode("login");
        setPhase("form");
        setPassword("");
        setCode("");
        setRetryAt(0);
        setNotice("密码已重置，请重新登录");
      }
    } catch (reason) {
      setError(reason.message);
      if (phase === "form") {
        setHumanProof(null);
        setProofEpoch((value) => value + 1);
      }
      if (reason.retryAfterSeconds > 0)
        startRetryCountdown(reason.retryAfterSeconds);
    } finally {
      setBusy(false);
    }
  };

  const authModes = config?.registrationOpen
    ? ["login", "register", "reset"]
    : ["login", "reset"];
  const handleTabKeyDown = (event) => {
    if (!["ArrowLeft", "ArrowRight"].includes(event.key) || busy) return;
    event.preventDefault();
    const direction = event.key === "ArrowRight" ? 1 : -1;
    const index =
      (authModes.indexOf(mode) + direction + authModes.length) %
      authModes.length;
    switchMode(authModes[index]);
    window.requestAnimationFrame(() =>
      document.getElementById(`auth-tab-${authModes[index]}`)?.focus(),
    );
  };
  const editVerificationDetails = () => {
    if (busy) return;
    setPassword("");
    setPhase("form");
    setCode("");
    setHumanProof(null);
    setProofEpoch((value) => value + 1);
    setNotice("");
    setError("");
  };
  const showPassword =
    mode === "login" ||
    ((mode === "register" || mode === "reset") && phase === "verify");
  const captchaAction =
    mode === "login"
      ? "login"
      : mode === "register"
        ? "register"
        : "password_reset";
  const captchaRequired = Boolean(
    captchaAction &&
    phase === "form" &&
    config?.captcha?.enabled &&
    config?.captcha?.actions?.[captchaAction],
  );
  const emailDescribedBy =
    [
      mode !== "login" && phase === "form" ? "auth-email-policy" : "",
    ]
      .filter(Boolean)
      .join(" ") || undefined;
  return (
    <div className="page-frame inner-page">
      <Header navigate={navigate} />
      <main className="auth-layout">
        <section className="auth-copy">
          <span className="eyebrow">
            <ShieldStar /> 账户服务
          </span>
          <h1>
            更大文件，
            <br />
            仍然足够简单。
          </h1>
          <p>
            登录后可使用更高单次上传总量、上传流量与会员权益。游客仍可直接发送 100
            MiB 文件。
          </p>
          <div className="trust-column">
            <span>
              <LockKey /> 登录状态受到保护
            </span>
            <span>
              <Gauge /> 下载不消耗流量
            </span>
            <span>
              <ShieldCheck /> 异常操作会被拦截
            </span>
          </div>
        </section>
        <section className="content-glass auth-card">
          {me ? (
            <EmptyState
              icon={<UserCircle />}
              title="你已经登录"
              detail={me.user.username || "用户"}
              action={() => navigate("/account")}
              actionLabel="进入账户"
            />
          ) : (
            <>
              <div
                className="auth-tabs"
                role="tablist"
                aria-label="账户操作"
                onKeyDown={handleTabKeyDown}
              >
                <button
                  id="auth-tab-login"
                  role="tab"
                  aria-selected={mode === "login"}
                  aria-controls="auth-panel"
                  tabIndex={mode === "login" ? 0 : -1}
                  type="button"
                  disabled={busy}
                  className={mode === "login" ? "is-active" : ""}
                  onClick={() => switchMode("login")}
                >
                  登录
                </button>
                <button
                  id="auth-tab-register"
                  role="tab"
                  aria-selected={mode === "register"}
                  aria-controls="auth-panel"
                  tabIndex={mode === "register" ? 0 : -1}
                  type="button"
                  disabled={busy || !config?.registrationOpen}
                  title={
                    config?.registrationOpen ? "创建账户" : "当前暂未开放注册"
                  }
                  className={mode === "register" ? "is-active" : ""}
                  onClick={() => switchMode("register")}
                >
                  注册
                </button>
                <button
                  id="auth-tab-reset"
                  role="tab"
                  aria-selected={mode === "reset"}
                  aria-controls="auth-panel"
                  tabIndex={mode === "reset" ? 0 : -1}
                  type="button"
                  disabled={busy}
                  className={mode === "reset" ? "is-active" : ""}
                  onClick={() => switchMode("reset")}
                >
                  找回密码
                </button>
              </div>
              <form
                id="auth-panel"
                className="auth-form"
                role="tabpanel"
                aria-labelledby={`auth-tab-${mode}`}
                aria-busy={busy}
                onSubmit={submit}
              >
                <span className="progress-kicker">
                  {mode === "login"
                    ? "欢迎回来"
                    : mode === "register"
                      ? "创建账户"
                      : "找回密码"}
                </span>
                <h2>
                  {mode === "login"
                    ? "登录快传账户"
                    : mode === "register"
                      ? phase === "verify"
                        ? "验证邮箱"
                        : "创建账户"
                      : phase === "verify"
                        ? "设置新密码"
                        : "找回密码"}
                </h2>
                <label className="field field-wide">
                  <span>邮箱</span>
                  <input
                    type="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    autoComplete="email"
                    required
                    disabled={phase === "verify"}
                    placeholder="name@qq.com"
                    aria-invalid={Boolean(error)}
                    aria-describedby={emailDescribedBy}
                  />
                </label>
                {mode !== "login" && phase === "form" && (
                  <div id="auth-email-policy" className="email-policy">
                    <ShieldCheck />
                    <span>
                      仅支持 {allowedDomainText}，不接受临时邮箱或{" "}
                      <code>+</code> 别名。
                    </span>
                  </div>
                )}
                {showPassword && (
                  <label className="field field-wide">
                    <span>
                      {mode === "login"
                        ? "密码"
                        : mode === "register"
                          ? "设置密码"
                          : "新密码"}
                    </span>
                    <input
                      type="password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      autoComplete={
                        mode === "login" ? "current-password" : "new-password"
                      }
                      minLength={10}
                      maxLength={128}
                      required
                      placeholder="至少 10 个字符"
                      aria-invalid={Boolean(error)}
                    />
                  </label>
                )}
                {phase === "verify" && (
                  <label className="field field-wide">
                    <span>6 位邮箱验证码</span>
                    <input
                      ref={codeInputRef}
                      className="verification-input"
                      value={code}
                      onChange={(event) =>
                        setCode(
                          event.target.value.replace(/\D/g, "").slice(0, 6),
                        )
                      }
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      minLength={6}
                      maxLength={6}
                      required
                      aria-invalid={Boolean(error)}
                    />
                  </label>
                )}
                {mode === "register" && phase === "form" && (
                  <label className="terms-consent">
                    <input
                      type="checkbox"
                      checked={termsAccepted}
                      onChange={(event) =>
                        setTermsAccepted(event.target.checked)
                      }
                      required
                    />
                    <span>
                      我已阅读并同意{" "}
                      <button type="button" onClick={() => navigate("/terms")}>
                        服务条款、隐私政策与可接受使用规则
                      </button>
                      {config?.terms?.version
                        ? `（版本 ${config.terms.version}）`
                        : ""}
                    </span>
                  </label>
                )}
                {captchaAction && phase === "form" && (
                  <HumanVerification
                    key={`${captchaAction}-${proofEpoch}`}
                    action={captchaAction}
                    config={config?.captcha}
                    onProof={setHumanProof}
                    disabled={busy}
                  />
                )}
                {phase === "form" && resendIn > 0 && (
                  <p className="countdown-note">
                    {resendIn} 秒后可再次发送验证码
                  </p>
                )}
                <button
                  className="primary-button wide-button"
                  type="submit"
                  disabled={
                    busy ||
                    (phase === "form" && captchaRequired && !humanProof) ||
                    (mode !== "login" &&
                      phase === "form" &&
                      (!allowedDomains.length ||
                        resendIn > 0 ||
                        (mode === "register" && !termsAccepted)))
                  }
                >
                  {busy
                    ? "请稍候…"
                    : phase === "verify"
                      ? mode === "reset"
                        ? "确认重置"
                        : "完成验证并创建账户"
                      : mode === "login"
                        ? "安全登录"
                        : resendIn > 0
                          ? `${resendIn} 秒后可重试`
                          : "发送邮箱验证码"}
                  <ArrowRight />
                </button>
                {phase === "verify" && (
                  <div className="verification-actions">
                    <button
                      className="verification-resend"
                      type="button"
                      onClick={resend}
                      disabled={busy || resendIn > 0}
                    >
                      {resendIn > 0
                        ? `${resendIn} 秒后可重新发送`
                        : "重新发送邮箱验证码"}
                    </button>
                    <button
                      className="verification-resend"
                      type="button"
                      onClick={editVerificationDetails}
                      disabled={busy}
                    >
                      修改邮箱
                    </button>
                    {resendIn === 0 && (
                      <span className="visually-hidden" role="status">
                        现在可以重新发送验证码
                      </span>
                    )}
                  </div>
                )}
                {mode === "register" && !config?.registrationOpen && (
                  <p className="sandbox-note">
                    <ShieldCheck /> 当前暂未开放新用户注册，请稍后再试。
                  </p>
                )}
              </form>
            </>
          )}
        </section>
      </main>
    </div>
  );
}

function AccountPage({ navigate, sessionLoading }) {
  const { me, config, refreshSession } = useContext(SessionContext);
  const [resources, setResources] = useState(null);
  const [username, setUsername] = useState(me?.user?.username || "");
  const [redeemValue, setRedeemValue] = useState("");
  const [humanProof, setHumanProof] = useState(null);
  const [proofEpoch, setProofEpoch] = useState(0);
  const [busy, setBusy] = useState("");
  const [, setNotice] = useToastMessage("success");
  const [error, setError] = useToastMessage("error");
  const dialogRef = useRef(null);
  const closeButtonRef = useRef(null);
  const close = () => navigate("/");
  const proofRequired = Boolean(
    config?.captcha?.enabled && config?.captcha?.actions?.redeem,
  );

  const loadResources = async () => {
    if (!me) return;
    try {
      setResources(await getMyResources());
    } catch (reason) {
      setError(reason.message);
    }
  };

  useEffect(() => {
    setUsername(me?.user?.username || "");
    loadResources();
  }, [me?.user?.id, me?.user?.username]);

  useEffect(() => {
    const previousFocus = document.activeElement;
    document.body.classList.add("account-modal-open");
    const focusDialog = () => closeButtonRef.current?.focus();
    const frame = window.requestAnimationFrame(focusDialog);
    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = Array.from(
        dialogRef.current?.querySelectorAll(
          'button:not(:disabled), input:not(:disabled), select:not(:disabled), [href], [tabindex]:not([tabindex="-1"])',
        ) || [],
      );
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      window.cancelAnimationFrame(frame);
      document.removeEventListener("keydown", onKeyDown);
      document.body.classList.remove("account-modal-open");
      if (previousFocus instanceof HTMLElement) previousFocus.focus();
    };
  }, []);

  const saveUsername = async (event) => {
    event.preventDefault();
    const nextUsername = username.trim();
    if (!nextUsername) {
      setError("用户名不能为空");
      return;
    }
    setBusy("profile");
    setError("");
    setNotice("");
    try {
      await updateProfile(nextUsername);
      await refreshSession();
      setNotice("用户名已更新");
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy("");
    }
  };

  const redeem = async (event) => {
    event.preventDefault();
    const code = redeemValue.trim();
    if (!code) return;
    setBusy("redeem");
    setError("");
    setNotice("");
    try {
      await redeemCode(code, humanProof);
      setRedeemValue("");
      setHumanProof(null);
      setProofEpoch((value) => value + 1);
      await Promise.all([refreshSession(), loadResources()]);
      setNotice("兑换成功，权益已加入当前账户");
    } catch (reason) {
      setError(reason.message);
      setHumanProof(null);
      setProofEpoch((value) => value + 1);
    } finally {
      setBusy("");
    }
  };

  const account = resources?.account || me?.account || {};
  const traffic = remainingUploadTraffic(account);
  const points = Number(account.points ?? me?.account?.points ?? 0);

  return (
    <main
      className="account-modal-layer"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <section
        ref={dialogRef}
        className="account-modal content-glass"
        role="dialog"
        aria-modal="true"
        aria-labelledby="account-modal-title"
      >
        <header className="account-modal__header">
          <div>
            <span>当前账户</span>
            <h1 id="account-modal-title">账户与资源</h1>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            aria-label="关闭账户与资源"
            onClick={close}
          >
            <X />
          </button>
        </header>

        {sessionLoading ? (
          <LoadingState label="正在读取账户…" />
        ) : !me ? (
          <EmptyState
            icon={<LockKey />}
            title="登录后查看账户"
            detail="登录后可查看上传流量、积分和会员权益。"
            action={() => navigate("/login")}
            actionLabel="前往登录"
          />
        ) : (
          <div className="account-modal__body">
            <section className="account-summary-grid" aria-label="账户资源">
              <ResourceCard
                icon={<UserCircle />}
                label="账号等级"
                value={accountLevelLabel(me, account)}
                detail={accountLevelDetail(me, account)}
              />
              <ResourceCard
                icon={<Gauge />}
                label="剩余上传流量"
                value={formatBytes(traffic)}
                detail="上传成功后扣除，下载不计流量"
                action={() => navigate("/plans")}
                actionLabel="购买流量"
              />
              <ResourceCard
                icon={<Coins />}
                label="积分"
                value={`${points} 积分`}
                detail="可用于已开放的积分权益"
              />
            </section>


            <div className="account-modal__forms">
              <form className="account-profile-form" onSubmit={saveUsername}>
                <div className="section-heading">
                  <div>
                    <span>用户信息</span>
                    <h2>用户名</h2>
                  </div>
                </div>
                <label className="field field-wide">
                  <span>对外显示名称</span>
                  <input
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    minLength={1}
                    maxLength={20}
                    autoComplete="nickname"
                    required
                  />
                </label>
                <button
                  className="secondary-button"
                  type="submit"
                  disabled={
                    busy === "profile" ||
                    username.trim() === (me.user.username || "")
                  }
                >
                  {busy === "profile" ? "正在保存…" : "保存用户名"}
                </button>
              </form>

              <form className="account-redeem-form" onSubmit={redeem}>
                <div className="section-heading">
                  <div>
                    <span>兑换权益</span>
                    <h2>使用兑换码</h2>
                  </div>
                </div>
                <label className="field field-wide">
                  <span>流量或 VIP 兑换码</span>
                  <input
                    value={redeemValue}
                    onChange={(event) =>
                      setRedeemValue(
                        event.target.value
                          .toUpperCase()
                          .replace(/[^A-Z0-9-]/g, "")
                          .slice(0, 64),
                      )
                    }
                    placeholder="输入兑换码"
                    autoComplete="off"
                    required
                  />
                </label>
                {proofRequired && (
                  <HumanVerification
                    key={`redeem-${proofEpoch}`}
                    action="redeem"
                    config={config?.captcha}
                    onProof={setHumanProof}
                    disabled={busy === "redeem"}
                  />
                )}
                <button
                  className="primary-button"
                  type="submit"
                  disabled={
                    busy === "redeem" ||
                    !redeemValue.trim() ||
                    (proofRequired && !humanProof)
                  }
                >
                  {busy === "redeem" ? "正在兑换…" : "立即兑换"}
                </button>
              </form>
            </div>

            <p className="account-modal__footnote">
              账户存储容量不设上限；单次上传总量、文件数量和保留时间按账号等级执行。
            </p>
          </div>
        )}
      </section>
    </main>
  );
}

function ResourceCard({
  icon,
  label,
  value,
  current,
  max,
  detail,
  action,
  actionLabel,
}) {
  const percentage = max ? Math.min(100, Math.round((current / max) * 100)) : 0;
  return (
    <article className="resource-card">
      <span className="resource-icon">{icon}</span>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
      {typeof current === "number" && <progress max="100" value={percentage} />}
      {action && (
        <button type="button" onClick={action}>
          {actionLabel}
          <ArrowRight />
        </button>
      )}
    </article>
  );
}

function formatWelfareReward(bytes) {
  const value = Number(bytes || 0);
  const mib = value / (1024 * 1024);
  return Number.isInteger(mib) ? `${mib} MiB` : formatBytes(value);
}

function welfareMonthTitle(month) {
  const match = String(month || "").match(/^(\d{4})-(\d{2})$/);
  return match ? `${Number(match[1])} 年 ${Number(match[2])} 月` : "本月";
}

function buildWelfareCalendar(month) {
  const match = String(month || "").match(/^(\d{4})-(\d{2})$/);
  if (!match) return [];
  const year = Number(match[1]);
  const monthNumber = Number(match[2]);
  const firstWeekday = new Date(
    Date.UTC(year, monthNumber - 1, 1),
  ).getUTCDay();
  const daysInMonth = new Date(Date.UTC(year, monthNumber, 0)).getUTCDate();
  const cells = Array.from({ length: firstWeekday }, () => null);
  for (let day = 1; day <= daysInMonth; day += 1) {
    cells.push({
      day,
      date: `${month}-${String(day).padStart(2, "0")}`,
    });
  }
  while (cells.length % 7) cells.push(null);
  return cells;
}

function WelfarePage({ navigate, sessionLoading }) {
  const { me, refreshSession } = useContext(SessionContext);
  const [state, setState] = useState({ status: "loading", welfare: null });
  const [busy, setBusy] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [, setError] = useToastMessage("error");

  useEffect(() => {
    if (!me) {
      setState({ status: sessionLoading ? "loading" : "signed-out", welfare: null });
      return undefined;
    }
    let cancelled = false;
    setState((current) => ({ ...current, status: "loading" }));
    getWelfareStatus()
      .then((response) => {
        if (!cancelled)
          setState({ status: "ready", welfare: response.welfare || null });
      })
      .catch((reason) => {
        if (!cancelled) {
          setState({ status: "error", welfare: null });
          setError(reason.message);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [me?.user?.id, reloadKey, sessionLoading]);

  useEffect(() => {
    const reload = () => setReloadKey((value) => value + 1);
    window.addEventListener(WELFARE_UPDATED_EVENT, reload);
    return () => window.removeEventListener(WELFARE_UPDATED_EVENT, reload);
  }, []);

  const claim = async () => {
    if (busy || state.welfare?.claimedToday) return;
    setBusy(true);
    setError("");
    try {
      const response = await claimDailyCheckIn();
      const reward = response.result?.checkIn?.rewardBytes || 0;
      if (response.welfare) {
        setState({ status: "ready", welfare: response.welfare });
      } else {
        setReloadKey((value) => value + 1);
      }
      await refreshSession();
      showToast(
        response.result?.idempotent
          ? `今日已签到，获得 ${formatWelfareReward(reward)}`
          : `签到成功，${formatWelfareReward(reward)} 永久流量已到账`,
        "success",
      );
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy(false);
    }
  };

  const welfare = state.welfare;
  const checkIns = new Map(
    (welfare?.checkIns || []).map((item) => [item.date, item]),
  );
  const calendar = buildWelfareCalendar(welfare?.month);
  const weekdays = ["日", "一", "二", "三", "四", "五", "六"];

  return (
    <div className="page-frame inner-page welfare-page">
      <Header navigate={navigate} />
      <main className="welfare-layout">
        {!me ? (
          <section className="content-glass welfare-empty-card">
            {state.status === "loading" ? (
              <LoadingState label="正在读取账户…" />
            ) : (
              <EmptyState
                icon={<Gift />}
                title="登录后领取每日福利"
                detail="登录用户每天可签到一次，随机获得 10–200 MiB 永久上传流量。"
                action={() => navigate("/login")}
                actionLabel="前往登录"
              />
            )}
          </section>
        ) : state.status === "loading" ? (
          <section className="content-glass welfare-empty-card">
            <LoadingState label="正在读取签到记录…" />
          </section>
        ) : !welfare ? (
          <section className="content-glass welfare-empty-card">
            <EmptyState
              icon={<WarningCircle />}
              title="暂时无法读取福利"
              detail="请稍后刷新页面重试。"
              action={() => setReloadKey((value) => value + 1)}
              actionLabel="重新加载"
            />
          </section>
        ) : (
          <>
            <section className="welfare-claim-card">
              <span className="eyebrow">
                <Sparkle weight="fill" /> 每日福利
              </span>
              <div className="welfare-gift-mark" aria-hidden="true">
                <Gift weight="duotone" />
              </div>
              <div className="welfare-claim-copy">
                <p>{me.user.username || "用户"}，今天也有一份流量福利。</p>
                <h1>
                  每日签到，
                  <br />
                  流量直接到账。
                </h1>
                <p>
                  每天可领取一次 10–200 MiB 随机永久上传流量，奖励由服务器安全生成。
                </p>
              </div>
              <button
                className="primary-button welfare-claim-button"
                type="button"
                disabled={busy || welfare.claimedToday}
                onClick={claim}
              >
                {busy ? (
                  "正在签到…"
                ) : welfare.claimedToday ? (
                  <>
                    <CheckCircle weight="fill" /> 今日已领取 {formatWelfareReward(welfare.todayRewardBytes)}
                  </>
                ) : (
                  <>
                    <Gift weight="fill" /> 立即签到
                  </>
                )}
              </button>
              <small>每日 00:00（北京时间）开启新一轮签到</small>
            </section>

            <section className="welfare-calendar-card">
              <header className="welfare-calendar-header">
                <div>
                  <span>签到日历</span>
                  <h2>{welfareMonthTitle(welfare.month)}</h2>
                </div>
                <CalendarBlank weight="duotone" />
              </header>
              <div className="welfare-stats" aria-label="本月签到统计">
                <div>
                  <span>本月签到</span>
                  <strong>{welfare.checkInDays} 天</strong>
                </div>
                <div>
                  <span>本月获得</span>
                  <strong>{formatWelfareReward(welfare.monthRewardBytes)}</strong>
                </div>
                <div>
                  <span>今日状态</span>
                  <strong>{welfare.claimedToday ? "已领取" : "待领取"}</strong>
                </div>
              </div>
              <div className="welfare-calendar" role="grid" aria-label={`${welfareMonthTitle(welfare.month)}签到记录`}>
                {weekdays.map((weekday) => (
                  <span className="welfare-weekday" role="columnheader" key={weekday}>
                    {weekday}
                  </span>
                ))}
                {calendar.map((cell, index) => {
                  if (!cell)
                    return <span className="welfare-day is-empty" aria-hidden="true" key={`empty-${index}`} />;
                  const record = checkIns.get(cell.date);
                  const isToday = cell.date === welfare.today;
                  const isFuture = cell.date > welfare.today;
                  const stateLabel = record
                    ? `获得 ${formatWelfareReward(record.rewardBytes)}`
                    : isFuture
                      ? "待开启"
                      : isToday
                        ? "待领取"
                        : "未签到";
                  return (
                    <div
                      className={`welfare-day${record ? " is-claimed" : ""}${isToday ? " is-today" : ""}${isFuture ? " is-future" : ""}`}
                      role="gridcell"
                      aria-label={`${cell.day} 日，${stateLabel}`}
                      key={cell.date}
                    >
                      <span>{cell.day}</span>
                      <strong>{record ? `+${formatWelfareReward(record.rewardBytes)}` : stateLabel}</strong>
                    </div>
                  );
                })}
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  );
}

function DailyCheckInReminder({ open, onClose, refreshSession, me }) {
  const [busy, setBusy] = useState(false);
  const [, setError] = useToastMessage("error");
  const dialogRef = useRef(null);
  const claimButtonRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const previousFocus = document.activeElement;
    document.body.classList.add("welfare-reminder-open");
    const frame = window.requestAnimationFrame(() => claimButtonRef.current?.focus());
    const onKeyDown = (event) => {
      if (event.key === "Escape" && !busy) {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = Array.from(
        dialogRef.current?.querySelectorAll("button:not(:disabled)") || [],
      );
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      window.cancelAnimationFrame(frame);
      document.removeEventListener("keydown", onKeyDown);
      document.body.classList.remove("welfare-reminder-open");
      if (previousFocus instanceof HTMLElement) previousFocus.focus();
    };
  }, [open, busy, onClose]);

  if (!open || !me) return null;

  const claim = async () => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await claimDailyCheckIn();
      const reward = response.result?.checkIn?.rewardBytes || 0;
      await refreshSession();
      window.dispatchEvent(new CustomEvent(WELFARE_UPDATED_EVENT));
      showToast(
        response.result?.idempotent
          ? `今日已签到，获得 ${formatWelfareReward(reward)}`
          : `签到成功，${formatWelfareReward(reward)} 永久流量已到账`,
        "success",
      );
      onClose();
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="welfare-reminder-layer"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onClose();
      }}
    >
      <section
        ref={dialogRef}
        className="content-glass welfare-reminder"
        role="dialog"
        aria-modal="true"
        aria-labelledby="welfare-reminder-title"
      >
        <button
          className="welfare-reminder-close"
          type="button"
          aria-label="稍后领取"
          disabled={busy}
          onClick={onClose}
        >
          <X />
        </button>
        <div className="welfare-reminder-icon" aria-hidden="true">
          <Gift weight="duotone" />
        </div>
        <span>今日签到待领取</span>
        <h2 id="welfare-reminder-title">今天的流量福利已准备好</h2>
        <p>签到可随机获得 10–200 MiB 永久上传流量，领取后直接加入当前账户。</p>
        <button
          ref={claimButtonRef}
          className="primary-button welfare-reminder-primary"
          type="button"
          disabled={busy}
          onClick={claim}
        >
          <Gift weight="fill" /> {busy ? "正在签到…" : "立即签到"}
        </button>
        <button
          className="welfare-reminder-later"
          type="button"
          disabled={busy}
          onClick={onClose}
        >
          稍后领取
        </button>
      </section>
    </div>
  );
}

const VIP_PLAN_BLUEPRINTS = [
  {
    key: "monthly",
    name: "月度 VIP",
    priceCents: 590,
    period: "30 天",
    summary: "适合短期大文件传输与集中收集。",
    benefits: ["每天首次登录赠送 200 MiB", "单次总量最高 10 GiB", "最多上传 1,000 个文件"],
  },
  {
    key: "yearly",
    name: "年度 VIP",
    priceCents: 5900,
    period: "1 年",
    summary: "适合长期稳定使用，减少逐月续订。",
    benefits: ["每天首次登录赠送 500 MiB", "单次总量最高 10 GiB", "最多上传 1,000 个文件"],
  },
  {
    key: "lifetime",
    name: "终身 VIP",
    priceCents: 9900,
    period: "长期有效",
    summary: "解锁最高等级的大文件与文件数量上限。",
    benefits: ["每天首次登录赠送 1 GiB", "单次总量最高 50 GiB", "最多上传 10,000 个文件"],
  },
];

function PlansPage({ navigate }) {
  const { me, config, refreshSession } = useContext(SessionContext);
  const [activeTab, setActiveTab] = useState("traffic");
  const [products, setProducts] = useState([]);
  const [busy, setBusy] = useState("");
  const [, setNotice] = useToastMessage("success");
  const [error, setError] = useToastMessage("error");
  const [productsError, setProductsError] = useState("");
  const [humanProof, setHumanProof] = useState(null);
  const [proofEpoch, setProofEpoch] = useState(0);
  const orderKeys = useRef(new Map());
  const proofRequired = Boolean(
    config?.captcha?.enabled && config?.captcha?.actions?.order,
  );

  useEffect(() => {
    setProductsError("");
    getProducts()
      .then((data) => setProducts(data.products || []))
      .catch((reason) => setProductsError(reason.message));
  }, []);

  const trafficProducts = useMemo(
    () =>
      products.filter(
        (product) =>
          product.active !== false &&
          (product.kind === "traffic" || product.benefitType === "traffic"),
      ),
    [products],
  );
  const vipPlans = useMemo(
    () =>
      VIP_PLAN_BLUEPRINTS.map((blueprint) => {
        const product = products.find((candidate) => {
          const source = [
            candidate.id,
            candidate.kind,
            candidate.name,
            candidate.vipLevel,
            candidate.membershipLevel,
            candidate.durationType,
          ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();
          if (!/(vip|membership|subscription|会员)/.test(source)) return false;
          if (blueprint.key === "monthly")
            return /(month|monthly|月)/.test(source);
          if (blueprint.key === "yearly")
            return /(year|yearly|annual|年)/.test(source);
          return /(lifetime|permanent|forever|终身|永久)/.test(source);
        });
        return { ...blueprint, product };
      }),
    [products],
  );

  const purchaseWithPoints = async (product) => {
    if (!me) {
      navigate("/login");
      return;
    }
    setBusy(product.id);
    setError("");
    setNotice("");
    try {
      let idempotencyKey = orderKeys.current.get(product.id);
      if (!idempotencyKey) {
        idempotencyKey = crypto.randomUUID().replaceAll("-", "_");
        orderKeys.current.set(product.id, idempotencyKey);
      }
      const created = await createOrder(
        product.id,
        "points",
        humanProof,
        idempotencyKey,
      );
      orderKeys.current.delete(product.id);
      await refreshSession();
      setNotice(`${created.order.productName} 已加入当前账户`);
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy("");
      setHumanProof(null);
      setProofEpoch((value) => value + 1);
    }
  };

  const showPaymentUnavailable = (configured = true) => {
    setError("");
    showToast(
      configured
        ? "在线支付暂未开放，请稍后再试。"
        : "该套餐尚未配置，暂时无法购买。",
      "warning",
    );
  };

  return (
    <div className="page-frame inner-page plans-page">
      <Header navigate={navigate} />
      <main className="plans-layout">
        <section className="plans-hero">
          <span className="eyebrow">
            <Crown /> 流量与会员
          </span>
          <h1>按需要选择，规则清楚。</h1>
          <p>账户存储不设容量上限。上传成功后扣除流量，下载和重复下载均免费。</p>
        </section>
        {productsError && (
          <InlineNotice tone="error">{productsError}</InlineNotice>
        )}

        <div className="plans-tabs" role="tablist" aria-label="套餐类型">
          <button
            id="plans-tab-traffic"
            type="button"
            role="tab"
            aria-selected={activeTab === "traffic"}
            aria-controls="plans-panel-traffic"
            className={activeTab === "traffic" ? "is-active" : ""}
            onClick={() => setActiveTab("traffic")}
          >
            <Gauge /> 上传流量
          </button>
          <button
            id="plans-tab-vip"
            type="button"
            role="tab"
            aria-selected={activeTab === "vip"}
            aria-controls="plans-panel-vip"
            className={activeTab === "vip" ? "is-active" : ""}
            onClick={() => setActiveTab("vip")}
          >
            <Crown /> VIP 订阅
          </button>
        </div>


        {activeTab === "traffic" && (
          <section
            id="plans-panel-traffic"
            role="tabpanel"
            aria-labelledby="plans-tab-traffic"
          >
            {me && proofRequired && (
              <HumanVerification
                key={`order-${proofEpoch}`}
                action="order"
                config={config?.captcha}
                onProof={setHumanProof}
                disabled={Boolean(busy)}
              />
            )}
            <div className="product-grid traffic-product-grid">
              {trafficProducts.map((product) => (
                <article className="product-card" key={product.id}>
                  <span className="product-icon">
                    <Gauge />
                  </span>
                  <span className="progress-kicker">上传流量</span>
                  <h2>{formatBytes(product.trafficBytes)} 上传流量</h2>
                  <p>用于上传文件，接收方下载和重复下载均不扣流量。</p>
                  <div className="product-value">
                    <span>
                      <Gauge /> {formatBytes(product.trafficBytes)} 上传流量
                    </span>
                    <span>
                      <CheckCircle /> 永久有效
                    </span>
                  </div>
                  <div className="product-price">
                    <strong>¥{(product.priceCents / 100).toFixed(2)}</strong>
                    {product.pointsPrice > 0 && (
                      <span>或 {product.pointsPrice} 积分</span>
                    )}
                  </div>
                  <div className="product-actions">
                    <button
                      className="primary-button"
                      type="button"
                      disabled={Boolean(busy)}
                      onClick={() => showPaymentUnavailable(true)}
                    >
                      在线支付暂未开放
                    </button>
                    {product.pointsPrice > 0 && (
                      <button
                        className="secondary-button"
                        type="button"
                        disabled={
                          Boolean(busy) ||
                          !config?.payments?.points ||
                          (proofRequired && !humanProof)
                        }
                        onClick={() => purchaseWithPoints(product)}
                      >
                        {busy === product.id
                          ? "正在兑换…"
                          : config?.payments?.points
                            ? "使用积分"
                            : "积分功能尚未配置"}
                      </button>
                    )}
                  </div>
                </article>
              ))}
              {!trafficProducts.length && (
                <section className="content-glass plans-empty-state">
                  <Gauge />
                  <h2>流量套餐尚未配置</h2>
                  <p>管理员完成套餐与支付设置后即可购买。</p>
                </section>
              )}
            </div>
          </section>
        )}

        {activeTab === "vip" && (
          <section
            id="plans-panel-vip"
            role="tabpanel"
            aria-labelledby="plans-tab-vip"
          >
            <div className="product-grid vip-product-grid">
              {vipPlans.map((plan, index) => (
                <article
                  className={`product-card vip-card vip-level-${index + 1}`}
                  key={plan.key}
                >
                  <span className="product-icon">
                    <Crown weight={index === 2 ? "fill" : "regular"} />
                  </span>
                  <span className="progress-kicker">{plan.period}</span>
                  <h2>{plan.name}</h2>
                  <p>{plan.summary}</p>
                  <div className="product-value vip-benefits">
                    {plan.benefits.map((benefit) => (
                      <span key={benefit}>
                        <CheckCircle /> {benefit}
                      </span>
                    ))}
                  </div>
                  <div className="product-price">
                    <strong>
                      ¥{((plan.product?.priceCents ?? plan.priceCents) / 100).toFixed(2)}
                    </strong>
                    <span>{plan.period}</span>
                  </div>
                  <div className="product-actions">
                    <button
                      className="primary-button"
                      type="button"
                      onClick={() => showPaymentUnavailable(Boolean(plan.product))}
                    >
                      {plan.product ? "在线支付暂未开放" : "套餐尚未配置"}
                    </button>
                  </div>
                </article>
              ))}
            </div>
          </section>
        )}

        <section className="content-glass commerce-note">
          <ShieldStar />
          <div>
            <h2>购买说明</h2>
            <p>页面只展示真实可用状态；支付渠道未配置前，购买入口保持不可用。</p>
          </div>
        </section>
      </main>
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function LoadingState({ label }) {
  return (
    <div className="loading-state">
      <span className="loading-ring" />
      <p>{label}</p>
    </div>
  );
}

function EmptyState({ icon, title, detail, action, actionLabel }) {
  return (
    <div className="empty-state">
      <span className="empty-icon">{icon}</span>
      <h2>{title}</h2>
      <p>{detail}</p>
      {action && (
        <button className="secondary-button" type="button" onClick={action}>
          {actionLabel}
        </button>
      )}
    </div>
  );
}

function InlineNotice({ tone = "info", children, id }) {
  return (
    <div
      id={id}
      className={`notice notice-${tone}`}
      role={tone === "error" ? "alert" : "status"}
      aria-live={tone === "error" ? "assertive" : "polite"}
    >
      <WarningCircle weight="fill" />
      <span>{children}</span>
    </div>
  );
}

function normalizedAccountLevel(me, account = {}) {
  if (!me) return "guest";
  const source = [
    account.accountLevel,
    account.membershipLevel,
    account.vipLevel,
    account.vipPlan,
    account.tier,
    me.user?.accountLevel,
    me.user?.membershipLevel,
    me.user?.vipLevel,
    me.user?.vipPlan,
    me.user?.tier,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (/(lifetime|permanent|forever|终身|永久)/.test(source)) return "lifetime";
  if (/(vip|member|会员)/.test(source)) return "vip";
  return "normal";
}

function accountLevelLabel(me, account = me?.account || {}) {
  const level = normalizedAccountLevel(me, account);
  if (level === "lifetime") return "终身 VIP";
  if (level === "vip") return "VIP 用户";
  if (level === "normal") return "普通用户";
  return "游客";
}

function accountLevelDetail(me, account = me?.account || {}) {
  const level = normalizedAccountLevel(me, account);
  if (level === "lifetime") return "单次总量 50 GiB · 最多 10,000 个文件";
  if (level === "vip") return "单次总量 10 GiB · 最多 1,000 个文件";
  if (level === "normal") return "单次总量 2 GiB · 最多 100 个文件";
  return "单次总量 100 MiB · 最多 100 个文件";
}

function remainingUploadTraffic(account = {}) {
  const direct = [
    account.remainingUploadTrafficBytes,
    account.remainingTrafficBytes,
    account.availableTrafficBytes,
    account.uploadTrafficBytes,
  ].find((value) => Number.isFinite(Number(value)));
  if (direct !== undefined) return Math.max(0, Number(direct));
  return Math.max(
    0,
    Number(account.freeTrafficBytes || 0) +
      Number(account.paidTrafficBytes || 0),
  );
}

function formatExpiry(timestamp, compact = false) {
  const distance = Number(timestamp) * 1000 - Date.now();
  if (distance <= 0) return "已到期";
  const hours = Math.floor(distance / 3_600_000);
  const minutes = Math.max(1, Math.floor((distance % 3_600_000) / 60_000));
  if (compact) return hours ? `${hours}小时${minutes}分` : `${minutes} 分钟`;
  return hours ? `${hours} 小时后到期` : `${minutes} 分钟后到期`;
}

function statusLabel(status) {
  return (
    {
      uploading: "上传中",
      uploaded: "待扫描",
      scanning: "扫描中",
      ready: "可下载",
      blocked: "已拦截",
      quarantined: "隔离中",
      deleted: "已删除",
    }[status] || "状态更新中"
  );
}
