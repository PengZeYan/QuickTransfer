const TURNSTILE_SCRIPT_URL =
  "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
const TENCENT_CAPTCHA_SCRIPT_URL = "https://turing.captcha.qcloud.com/TJCaptcha.js";

const loaderPromises = new Map();

function readWindowValue(reader) {
  if (typeof window === "undefined") return null;
  return reader(window) || null;
}

function loadExternalScript({ key, source, readApi, label }) {
  const currentApi = readWindowValue(readApi);
  if (currentApi) return Promise.resolve(currentApi);

  if (typeof window === "undefined" || typeof document === "undefined") {
    return Promise.reject(new Error(`${label} 只能在浏览器中加载`));
  }

  const existingPromise = loaderPromises.get(key);
  if (existingPromise) return existingPromise;

  let scriptNode = null;
  let createdByLoader = false;

  const pending = new Promise((resolve, reject) => {
    const absoluteSource = new URL(source, document.baseURI).href;
    scriptNode = Array.from(document.scripts).find((script) => script.src === absoluteSource) || null;

    const finish = () => {
      const api = readWindowValue(readApi);
      if (api) {
        resolve(api);
        return;
      }
      reject(new Error(`${label} 脚本已加载，但接口不可用`));
    };

    const fail = () => reject(new Error(`${label} 加载失败，请检查网络或内容安全策略`));
    const timeoutId = window.setTimeout(
      () => reject(new Error(`${label} 加载超时，请稍后重试`)),
      15_000,
    );
    const clearTimerAndFinish = () => {
      window.clearTimeout(timeoutId);
      finish();
    };
    const clearTimerAndFail = () => {
      window.clearTimeout(timeoutId);
      fail();
    };

    if (!scriptNode) {
      scriptNode = document.createElement("script");
      scriptNode.src = source;
      scriptNode.async = true;
      scriptNode.defer = true;
      scriptNode.referrerPolicy = "strict-origin-when-cross-origin";
      scriptNode.dataset.quicktransferCaptcha = key;
      createdByLoader = true;
    }

    scriptNode.addEventListener("load", clearTimerAndFinish, { once: true });
    scriptNode.addEventListener("error", clearTimerAndFail, { once: true });

    if (scriptNode.dataset.quicktransferCaptchaLoaded === "true") {
      window.queueMicrotask(clearTimerAndFinish);
    } else {
      scriptNode.addEventListener(
        "load",
        () => {
          scriptNode.dataset.quicktransferCaptchaLoaded = "true";
        },
        { once: true },
      );
    }

    if (createdByLoader) document.head.appendChild(scriptNode);
  });

  const tracked = pending.catch((error) => {
    if (loaderPromises.get(key) === tracked) loaderPromises.delete(key);
    if (
      scriptNode?.parentNode &&
      (createdByLoader || scriptNode.dataset.quicktransferCaptcha === key)
    ) {
      scriptNode.parentNode.removeChild(scriptNode);
    }
    throw error;
  });

  loaderPromises.set(key, tracked);
  return tracked;
}

export function normalizeCaptchaProvider(provider) {
  const value = String(provider || "").trim().toLowerCase();
  if (["turnstile", "cloudflare", "cloudflare-turnstile"].includes(value)) {
    return "turnstile";
  }
  if (["tencent", "tencent-cloud", "tencent-captcha", "tianyu"].includes(value)) {
    return "tencent";
  }
  return "";
}

export function isCaptchaActionEnabled(config, action) {
  if (!config?.enabled || !action) return false;

  const actions = config.actions;
  if (Array.isArray(actions)) return actions.includes(action);
  if (typeof actions === "string") {
    return actions
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
      .includes(action);
  }
  if (actions && typeof actions === "object") {
    const setting = actions[action];
    if (setting && typeof setting === "object") return setting.enabled === true;
    return setting === true;
  }
  return false;
}

export function loadTurnstile() {
  return loadExternalScript({
    key: "turnstile",
    source: TURNSTILE_SCRIPT_URL,
    readApi: (browserWindow) => browserWindow.turnstile,
    label: "Cloudflare Turnstile",
  });
}

export function loadTencentCaptcha() {
  return loadExternalScript({
    key: "tencent",
    source: TENCENT_CAPTCHA_SCRIPT_URL,
    readApi: (browserWindow) => browserWindow.TencentCaptcha,
    label: "腾讯云验证码",
  });
}

export const captchaScriptUrls = Object.freeze({
  turnstile: TURNSTILE_SCRIPT_URL,
  tencent: TENCENT_CAPTCHA_SCRIPT_URL,
});
