import { useCallback, useEffect, useRef, useState } from "react";
import {
  CheckCircle,
  Info,
  WarningCircle,
  X,
  XCircle,
} from "@phosphor-icons/react";

const TOAST_EVENT = "quicktransfer:toast";
const TOAST_DURATION_MS = 2000;
const TOAST_EXIT_MS = 220;
const VALID_TONES = new Set(["success", "error", "warning", "info"]);

let toastSequence = 0;

function normalizeTone(tone) {
  return VALID_TONES.has(tone) ? tone : "info";
}

export function showToast(message, tone = "info") {
  const text = String(message || "").trim();
  if (!text || typeof window === "undefined") return;
  window.dispatchEvent(
    new CustomEvent(TOAST_EVENT, {
      detail: { message: text, tone: normalizeTone(tone) },
    }),
  );
}

export function useToastMessage(tone = "info") {
  const [message, setStoredMessage] = useState("");
  const setMessage = useCallback(
    (value) => {
      if (typeof value === "function") {
        setStoredMessage((current) => {
          const next = String(value(current) || "").trim();
          if (next) window.queueMicrotask(() => showToast(next, tone));
          return next;
        });
        return;
      }
      const next = String(value || "").trim();
      setStoredMessage(next);
      if (next) showToast(next, tone);
    },
    [tone],
  );
  return [message, setMessage];
}

function ToastIcon({ tone }) {
  if (tone === "success") return <CheckCircle weight="fill" />;
  if (tone === "error") return <XCircle weight="fill" />;
  if (tone === "warning") return <WarningCircle weight="fill" />;
  return <Info weight="fill" />;
}

export function ToastCenter() {
  const [toasts, setToasts] = useState([]);
  const timersRef = useRef(new Map());

  const removeToast = useCallback((id) => {
    const timers = timersRef.current.get(id);
    if (timers) {
      window.clearTimeout(timers.dismiss);
      window.clearTimeout(timers.remove);
      timersRef.current.delete(id);
    }
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const dismissToast = useCallback(
    (id) => {
      setToasts((current) =>
        current.map((toast) =>
          toast.id === id ? { ...toast, closing: true } : toast,
        ),
      );
      const timers = timersRef.current.get(id) || {};
      window.clearTimeout(timers.dismiss);
      timers.remove = window.setTimeout(() => removeToast(id), TOAST_EXIT_MS);
      timersRef.current.set(id, timers);
    },
    [removeToast],
  );

  useEffect(() => {
    const onToast = (event) => {
      const message = String(event.detail?.message || "").trim();
      if (!message) return;
      const tone = normalizeTone(event.detail?.tone);
      const id = `${Date.now()}-${(toastSequence += 1)}`;
      setToasts((current) => [
        ...current.slice(-3),
        { id, message, tone, closing: false },
      ]);
      const dismiss = window.setTimeout(
        () => dismissToast(id),
        TOAST_DURATION_MS,
      );
      timersRef.current.set(id, { dismiss, remove: 0 });
    };
    window.addEventListener(TOAST_EVENT, onToast);
    const timers = timersRef.current;
    return () => {
      window.removeEventListener(TOAST_EVENT, onToast);
      for (const timer of timers.values()) {
        window.clearTimeout(timer.dismiss);
        window.clearTimeout(timer.remove);
      }
      timers.clear();
    };
  }, [dismissToast]);

  if (!toasts.length) return null;

  return (
    <aside className="toast-viewport" aria-label="操作提示">
      {toasts.map((toast) => (
        <div
          className={`toast-message toast-message--${toast.tone}${toast.closing ? " is-closing" : ""}`}
          role={toast.tone === "error" ? "alert" : "status"}
          key={toast.id}
        >
          <span className="toast-message__icon" aria-hidden="true">
            <ToastIcon tone={toast.tone} />
          </span>
          <span className="toast-message__text">{toast.message}</span>
          <button
            type="button"
            onClick={() => dismissToast(toast.id)}
            aria-label="关闭提示"
          >
            <X />
          </button>
          <span className="toast-message__timer" aria-hidden="true" />
        </div>
      ))}
    </aside>
  );
}
