import { Fragment, useEffect, useState } from "react";
import { getTerms } from "../api.js";
import "../styles/legal.css";

function asPlainText(value) {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return "";
}

function normalizeTerms(response) {
  const terms = response?.terms && typeof response.terms === "object" ? response.terms : {};
  return {
    title: asPlainText(terms.title).trim(),
    content: asPlainText(terms.content).replace(/\r\n?/g, "\n").trim(),
    version: asPlainText(terms.version).trim(),
    effectiveAt: terms.effectiveAt,
  };
}

function displayDate(value) {
  if (value === null || value === undefined || value === "") return "—";

  let date;
  if (typeof value === "number" && Number.isFinite(value)) {
    date = new Date(Math.abs(value) < 1_000_000_000_000 ? value * 1000 : value);
  } else {
    const source = String(value).trim();
    if (/^-?\d+(?:\.\d+)?$/.test(source)) {
      const numeric = Number(source);
      date = new Date(Math.abs(numeric) < 1_000_000_000_000 ? numeric * 1000 : numeric);
    } else {
      date = new Date(/^\d{4}-\d{2}-\d{2}$/.test(source) ? `${source}T00:00:00` : source);
    }
  }

  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

function PlainTextBlock({ text }) {
  const lines = text.split("\n");
  return (
    <p>
      {lines.map((line, index) => (
        <Fragment key={`${index}-${line}`}>
          {line}
          {index < lines.length - 1 ? <br /> : null}
        </Fragment>
      ))}
    </p>
  );
}

function PlainTextDocument({ content }) {
  if (!content) {
    return (
      <section className="legal-clause">
        <p role="status">当前版本未提供正文内容。</p>
      </section>
    );
  }

  return content
    .split(/\n[\t ]*\n+/)
    .map((paragraph) => paragraph.trim())
    .filter(Boolean)
    .map((paragraph, index) => (
      <section className="legal-clause" key={`${index}-${paragraph.slice(0, 24)}`}>
        <PlainTextBlock text={paragraph} />
      </section>
    ));
}

export function TermsPage({ navigate }) {
  const [reloadKey, setReloadKey] = useState(0);
  const [state, setState] = useState({ status: "loading", terms: null });

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading", terms: null });

    getTerms()
      .then((response) => {
        if (!cancelled) setState({ status: "ready", terms: normalizeTerms(response) });
      })
      .catch(() => {
        if (!cancelled) setState({ status: "error", terms: null });
      });

    return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  const goHome = () => {
    if (typeof navigate === "function") {
      navigate("/");
      return;
    }
    if (typeof window !== "undefined") window.location.assign("/");
  };

  const terms = state.terms;
  const title = terms?.title || "条款与隐私";
  const version = terms?.version || "—";
  const effectiveAt = displayDate(terms?.effectiveAt);

  return (
    <div className="legal-page">
      <a className="legal-skip-link" href="#legal-main">跳到正文</a>

      <header className="legal-header">
        <div className="legal-header__inner">
          <button className="legal-brand" type="button" onClick={goHome} aria-label="返回快传首页">
            <span>快传</span>
            <small>条款与隐私</small>
          </button>
          <nav className="legal-header__nav" aria-label="法律文件导航">
            <a href="#terms-content">条款正文</a>
          </nav>
          <button className="legal-home-button" type="button" onClick={goHome}>返回首页</button>
        </div>
      </header>

      <main id="legal-main" className="legal-main">
        <section className="legal-hero" aria-labelledby="legal-title">
          <div className="legal-hero__copy">
            <span className="legal-eyebrow">使用前请仔细阅读</span>
            <h1 id="legal-title">
              {state.status === "loading" ? "正在载入条款" : state.status === "error" ? "条款载入失败" : title}
            </h1>
            <p>
              {state.status === "ready"
                ? "请在注册或继续使用服务前阅读当前生效版本。"
                : state.status === "error"
                  ? "暂时无法读取条款，请稍后重试。"
                  : "正在获取当前生效版本。"}
            </p>
          </div>
          <dl className="legal-meta" aria-label="文件版本信息">
            <div>
              <dt>当前版本</dt>
              <dd>{version}</dd>
            </div>
            <div>
              <dt>生效日期</dt>
              <dd>{effectiveAt}</dd>
            </div>
            <div>
              <dt>载入状态</dt>
              <dd>{state.status === "ready" ? "当前生效" : state.status === "error" ? "读取失败" : "载入中"}</dd>
            </div>
          </dl>
        </section>

        <div className="legal-layout">
          <aside className="legal-toc" aria-label="本页目录">
            <p>本页目录</p>
            <nav>
              <a href="#terms-content"><span>01</span>条款正文</a>
            </nav>
          </aside>

          <div className="legal-document">
            {state.status === "error" ? (
              <article id="terms-content" className="legal-article" aria-labelledby="terms-content-title">
                <header className="legal-article__header">
                  <span>条款读取失败</span>
                  <h2 id="terms-content-title">无法读取当前条款</h2>
                  <p>请确认服务可用后重新载入。</p>
                </header>
                <section className="legal-clause">
                  <button className="legal-home-button" type="button" onClick={() => setReloadKey((value) => value + 1)}>
                    重新载入
                  </button>
                </section>
              </article>
            ) : state.status === "loading" ? (
              <article id="terms-content" className="legal-article" aria-labelledby="terms-content-title" aria-busy="true">
                <header className="legal-article__header">
                  <span>当前生效条款</span>
                  <h2 id="terms-content-title">正在载入</h2>
                  <p role="status">正在读取当前生效条款。</p>
                </header>
              </article>
            ) : (
              <article id="terms-content" className="legal-article" aria-labelledby="terms-content-title">
                <header className="legal-article__header">
                  <span>当前生效条款</span>
                  <h2 id="terms-content-title">{title}</h2>
                  <p>版本 {version} · 生效于 {effectiveAt}</p>
                </header>
                <PlainTextDocument content={terms.content} />
              </article>
            )}

            <footer className="legal-footer">
              <p>版本 {version} · 生效于 {effectiveAt}</p>
              <button type="button" onClick={goHome}>返回快传</button>
            </footer>
          </div>
        </div>
      </main>
    </div>
  );
}

export default TermsPage;
