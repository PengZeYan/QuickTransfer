import { useCallback, useEffect, useRef, useState } from "react";
import {
  isCaptchaActionEnabled,
  loadTencentCaptcha,
  loadTurnstile,
  normalizeCaptchaProvider,
} from "../../security/captcha.js";
import "../../styles/security.css";

const EMPTY_PROOF = null;

function initialMessage(provider) {
  return provider === "tencent" ? "点击按钮完成人机验证" : "正在准备安全验证…";
}

export function HumanVerification({
  action,
  config,
  onProof,
  disabled = false,
}) {
  const provider = normalizeCaptchaProvider(config?.provider);
  const actionEnabled = isCaptchaActionEnabled(config, action);
  const siteKey = String(config?.siteKey || "").trim();
  const appId = String(config?.appId || "").trim();
  const onProofRef = useRef(onProof);
  const mountedRef = useRef(true);
  const turnstileContainerRef = useRef(null);
  const turnstileApiRef = useRef(null);
  const turnstileWidgetIdRef = useRef(null);
  const tencentInstanceRef = useRef(null);
  const [status, setStatus] = useState("idle");
  const [message, setMessage] = useState(initialMessage(provider));
  const [retryVersion, setRetryVersion] = useState(0);

  useEffect(() => {
    onProofRef.current = onProof;
  }, [onProof]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const emitProof = useCallback((proof) => {
    if (typeof onProofRef.current === "function") onProofRef.current(proof);
  }, []);

  const resetTurnstile = useCallback(() => {
    const api = turnstileApiRef.current;
    const widgetId = turnstileWidgetIdRef.current;
    if (!api || widgetId === null || widgetId === undefined) return false;
    try {
      api.reset(widgetId);
      return true;
    } catch {
      return false;
    }
  }, []);

  useEffect(() => {
    if (!actionEnabled) emitProof(EMPTY_PROOF);
  }, [actionEnabled, emitProof]);

  useEffect(() => {
    if (!actionEnabled || provider !== "turnstile") return undefined;

    let cancelled = false;
    emitProof(EMPTY_PROOF);
    setStatus("loading");
    setMessage("正在加载 Cloudflare Turnstile…");

    if (!siteKey) {
      setStatus("error");
      setMessage("Cloudflare Turnstile 尚未配置站点密钥");
      return undefined;
    }

    loadTurnstile()
      .then((turnstile) => {
        if (cancelled || !turnstileContainerRef.current) return;

        turnstileApiRef.current = turnstile;
        const widgetId = turnstile.render(turnstileContainerRef.current, {
          sitekey: siteKey,
          action,
          theme: "dark",
          size: "compact",
          callback: (token) => {
            if (cancelled) return;
            const normalizedToken = String(token || "").trim();
            if (!normalizedToken) {
              emitProof(EMPTY_PROOF);
              setStatus("error");
              setMessage("验证结果无效，请重新验证");
              window.setTimeout(resetTurnstile, 0);
              return;
            }
            emitProof({ token: normalizedToken, randStr: "" });
            setStatus("verified");
            setMessage("人机验证已通过");
          },
          "error-callback": () => {
            if (cancelled) return;
            emitProof(EMPTY_PROOF);
            setStatus("error");
            setMessage("验证服务暂时不可用，请重新验证");
            window.setTimeout(resetTurnstile, 0);
          },
          "expired-callback": () => {
            if (cancelled) return;
            emitProof(EMPTY_PROOF);
            setStatus("expired");
            setMessage("验证结果已过期，请重新验证");
            window.setTimeout(resetTurnstile, 0);
          },
          "timeout-callback": () => {
            if (cancelled) return;
            emitProof(EMPTY_PROOF);
            setStatus("expired");
            setMessage("验证等待超时，请重新验证");
            window.setTimeout(resetTurnstile, 0);
          },
        });

        turnstileWidgetIdRef.current = widgetId;
        setStatus("ready");
        setMessage("请完成 Cloudflare 人机验证");
      })
      .catch((error) => {
        if (cancelled) return;
        emitProof(EMPTY_PROOF);
        setStatus("error");
        setMessage(
          error instanceof Error ? error.message : "验证服务加载失败，请重试",
        );
      });

    return () => {
      cancelled = true;
      const api = turnstileApiRef.current;
      const widgetId = turnstileWidgetIdRef.current;
      if (api && widgetId !== null && widgetId !== undefined) {
        try {
          api.remove(widgetId);
        } catch {
          // The provider may already have removed an expired widget.
        }
      }
      turnstileApiRef.current = null;
      turnstileWidgetIdRef.current = null;
    };
  }, [
    action,
    actionEnabled,
    emitProof,
    provider,
    resetTurnstile,
    retryVersion,
    siteKey,
  ]);

  useEffect(() => {
    if (!actionEnabled || provider !== "tencent") return undefined;
    emitProof(EMPTY_PROOF);
    setStatus(appId ? "idle" : "error");
    setMessage(appId ? "点击按钮完成人机验证" : "腾讯云验证码尚未配置应用 ID");

    return () => {
      const instance = tencentInstanceRef.current;
      if (instance && typeof instance.destroy === "function") {
        try {
          instance.destroy();
        } catch {
          // Tencent's widget may already be closed after completing a challenge.
        }
      }
      tencentInstanceRef.current = null;
    };
  }, [action, actionEnabled, appId, emitProof, provider]);

  useEffect(() => {
    if (!actionEnabled || provider) return;
    emitProof(EMPTY_PROOF);
    setStatus("error");
    setMessage("验证码服务配置无效");
  }, [actionEnabled, emitProof, provider]);

  const startTencentVerification = useCallback(async () => {
    if (disabled || !appId || status === "loading") return;

    emitProof(EMPTY_PROOF);
    setStatus("loading");
    setMessage("正在加载腾讯云验证码…");

    try {
      const challengeResponse = await fetch(
        `/api/v1/human-verification/challenge?action=${encodeURIComponent(action)}`,
        { cache: "no-store", credentials: "same-origin" },
      );
      if (!challengeResponse.ok)
        throw new Error("无法创建验证码挑战，请稍后重试");
      const challengePayload = await challengeResponse.json();
      const challenge = String(challengePayload?.challenge || "");
      if (!challenge) throw new Error("验证码挑战无效，请稍后重试");
      const TencentCaptcha = await loadTencentCaptcha();
      if (!mountedRef.current) return;
      const instance = new TencentCaptcha(
        appId,
        (result) => {
          if (!mountedRef.current) return;
          const token = String(result?.ticket || "").trim();
          const randStr = String(result?.randstr || "").trim();
          if (
            result?.ret !== 0 ||
            !token ||
            !randStr ||
            token.startsWith("trerror_") ||
            Number(result?.errorCode || 0) !== 0
          ) {
            emitProof(EMPTY_PROOF);
            setStatus("error");
            setMessage(
              result?.ret === 2 ? "验证已取消，请重试" : "验证未通过，请重试",
            );
            return;
          }

          emitProof({ token, randStr, challenge });
          setStatus("verified");
          setMessage("人机验证已通过");
        },
        { enableDarkMode: "force", userLanguage: "zh-cn" },
      );
      tencentInstanceRef.current = instance;
      setStatus("ready");
      setMessage("请在弹出的窗口中完成验证");
      instance.show();
    } catch (error) {
      if (!mountedRef.current) return;
      emitProof(EMPTY_PROOF);
      setStatus("error");
      setMessage(
        error instanceof Error ? error.message : "验证服务加载失败，请重试",
      );
    }
  }, [action, appId, disabled, emitProof, status]);

  const retry = useCallback(() => {
    if (disabled) return;
    emitProof(EMPTY_PROOF);
    if (provider === "turnstile" && resetTurnstile()) {
      setStatus("ready");
      setMessage("请重新完成 Cloudflare 人机验证");
      return;
    }
    if (provider === "turnstile") {
      setRetryVersion((version) => version + 1);
      return;
    }
    void startTencentVerification();
  }, [disabled, emitProof, provider, resetTurnstile, startTencentVerification]);

  if (!actionEnabled) return null;

  const providerConfigured =
    (provider === "turnstile" && Boolean(siteKey)) ||
    (provider === "tencent" && Boolean(appId));
  const canRetry = providerConfigured && ["error", "expired"].includes(status);

  return (
    <section
      className={`human-verification human-verification--${provider || "unknown"} human-verification--${status}${disabled ? " is-disabled" : ""}`}
      aria-label="人机验证"
      aria-disabled={disabled || undefined}
      inert={disabled || undefined}
    >
      <div className="human-verification__heading">
        <span>安全验证</span>
        <strong>{status === "verified" ? "已通过" : "必需"}</strong>
      </div>

      {provider === "turnstile" && (
        <div
          className="human-verification__turnstile"
          ref={turnstileContainerRef}
        />
      )}

      {provider === "tencent" && status !== "verified" && (
        <button
          className="human-verification__launch"
          type="button"
          onClick={startTencentVerification}
          disabled={disabled || !appId || status === "loading"}
        >
          {status === "loading"
            ? "正在加载…"
            : status === "error"
              ? "重新进行验证"
              : "开始人机验证"}
        </button>
      )}

      {!provider && (
        <p className="human-verification__configuration-error">
          验证码服务配置无效
        </p>
      )}

      <p
        className="human-verification__status"
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        {message}
      </p>

      {canRetry && provider === "turnstile" && (
        <button
          className="human-verification__retry"
          type="button"
          onClick={retry}
          disabled={disabled}
        >
          重新验证
        </button>
      )}
    </section>
  );
}
