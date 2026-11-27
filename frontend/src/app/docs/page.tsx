"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, BookOpen, ChevronDown, ExternalLink, Search } from "lucide-react";
import {
  DOC_CATEGORIES,
  DOC_FEATURES,
  DOCS_VERSION,
  REPO_DOCS_URL,
  REPO_FILE_BASE,
  type DocFeature,
} from "@/lib/docs-features";

// Shared control styles, mirroring VulnsView / SettingsView.
const FOCUS = "focus-visible:outline-2 focus-visible:outline-rh-primary";
const INPUT =
  "px-3 py-1.5 rounded-[6px] bg-rh-bg border border-rh-line text-xs text-rh-text placeholder:text-rh-muted focus:outline-none focus-visible:border-rh-primary focus-visible:ring-1 focus-visible:ring-rh-primary";
const CHIP = "px-2 py-0.5 rounded-[6px] text-xs font-semibold whitespace-nowrap";
const CODE_BLOCK =
  "mt-1.5 overflow-x-auto rounded-[6px] border border-rh-line bg-rh-bg px-3 py-2 font-mono text-xs leading-relaxed text-rh-text";
const PANEL = "rounded-[10px] border border-rh-line bg-rh-surface";

/** slug for a category anchor (#category id used by the sidebar). */
function categoryAnchor(category: string): string {
  return `cat-${category.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
}

function featureMatches(feature: DocFeature, query: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  return (
    feature.title.toLowerCase().includes(q) ||
    feature.tagline.toLowerCase().includes(q) ||
    feature.category.toLowerCase().includes(q)
  );
}

function CodeBlock({ code }: { code: string }) {
  return (
    <pre className={CODE_BLOCK}>
      <code>{code}</code>
    </pre>
  );
}

function FeatureCard({ feature }: { feature: DocFeature }) {
  const [open, setOpen] = useState(true);
  return (
    <article id={feature.id} className={`${PANEL} scroll-mt-24`}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className={`flex w-full cursor-pointer items-center gap-3 px-4 py-3 text-left ${FOCUS}`}
      >
        <ChevronDown
          className={`h-4 w-4 shrink-0 text-rh-muted transition-transform ${open ? "" : "-rotate-90"}`}
          aria-hidden="true"
        />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold text-rh-text">{feature.title}</span>
          <span className="block truncate text-xs text-rh-muted">{feature.tagline}</span>
        </span>
      </button>

      {open && (
        <div className="border-t border-rh-line px-4 py-4">
          <section aria-label={`${feature.title} what it does`}>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-rh-muted">What it does</h3>
            <ul className="mt-1.5 list-disc space-y-1 pl-4 text-sm text-rh-text marker:text-rh-muted">
              {feature.whatItDoes.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </section>

          <section aria-label={`${feature.title} why it matters`} className="mt-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-rh-muted">Why it matters</h3>
            <p className="mt-1.5 text-sm text-rh-muted">{feature.whyItMatters}</p>
          </section>

          <section aria-label={`${feature.title} how to use`} className="mt-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-rh-muted">How to use</h3>
            <ol className="mt-1.5 space-y-2.5">
              {feature.howToUse.map((step, i) => (
                <li key={i} className="text-sm text-rh-text">
                  <span className="text-rh-muted">
                    {i + 1}. {step.description}
                  </span>
                  {step.code ? <CodeBlock code={step.code} /> : null}
                </li>
              ))}
            </ol>
          </section>

          {(feature.config || feature.docs) && (
            <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-rh-line pt-3">
              {(feature.config ?? []).map((c) => (
                <span key={c} className={`${CHIP} border border-rh-line bg-rh-raised font-mono font-medium text-rh-muted`}>
                  {c}
                </span>
              ))}
              {feature.docs && (
                <a
                  href={`${REPO_FILE_BASE}/${feature.docs}`}
                  target="_blank"
                  rel="noreferrer"
                  className={`inline-flex items-center gap-1.5 text-xs font-medium text-rh-primary hover:text-rh-primary-hover ${FOCUS}`}
                >
                  <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                  Full documentation
                </a>
              )}
            </div>
          )}
        </div>
      )}
    </article>
  );
}

export default function DocsPage() {
  const [query, setQuery] = useState("");

  const visible = useMemo(() => DOC_FEATURES.filter((f) => featureMatches(f, query)), [query]);
  const visibleByCategory = useMemo(
    () =>
      DOC_CATEGORIES.map((category) => ({
        category,
        features: visible.filter((f) => f.category === category),
      })).filter((group) => group.features.length > 0),
    [visible]
  );

  return (
    <main className="h-full overflow-y-auto bg-rh-bg" aria-label="ReadyHai documentation">
      <div className="mx-auto w-full max-w-5xl px-4 pb-16 pt-8">
        {/* Page header */}
        <div className="flex flex-wrap items-center gap-3">
          <BookOpen className="h-6 w-6 shrink-0 text-rh-primary" aria-hidden="true" />
          <h1 className="text-2xl font-semibold text-rh-text">ReadyHai documentation</h1>
          <span className={`${CHIP} bg-rh-primary/15 font-mono text-rh-primary`}>v{DOCS_VERSION}</span>
        </div>
        <p className="mt-2 max-w-2xl text-sm text-rh-muted">
          Every ReadyHai feature, what it does and how to use it — generated from the v{DOCS_VERSION}{" "}
          feature registry. Verdicts come from code, never from an LLM.
        </p>

        {/* Actions: back, external docs, search */}
        <div className="mt-5 flex flex-wrap items-center gap-3">
          <Link
            href="/"
            className={`inline-flex items-center gap-1.5 rounded-[6px] border border-rh-line bg-rh-raised px-2.5 py-1.5 text-xs font-medium text-rh-text transition-colors hover:bg-rh-line ${FOCUS}`}
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            Back to Agent Studio
          </Link>
          <a
            href={REPO_DOCS_URL}
            target="_blank"
            rel="noreferrer"
            className={`inline-flex items-center gap-1.5 text-xs font-medium text-rh-primary hover:text-rh-primary-hover ${FOCUS}`}
          >
            <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
            Repository docs index
          </a>
          <label className="relative ml-auto block">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-rh-muted" aria-hidden="true" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search features…"
              aria-label="Search features"
              className={`${INPUT} w-56 pl-8`}
            />
          </label>
        </div>

        <div className="mt-8 flex gap-8">
          {/* Sticky category sidebar (desktop) */}
          <nav aria-label="Documentation categories" className="sticky top-8 hidden h-fit w-52 shrink-0 lg:block">
            <ul className="space-y-1">
              {visibleByCategory.map(({ category, features }) => (
                <li key={category}>
                  <a
                    href={`#${categoryAnchor(category)}`}
                    className={`flex items-center justify-between rounded-[6px] px-2 py-1.5 text-xs font-medium text-rh-muted transition-colors hover:bg-rh-raised hover:text-rh-text ${FOCUS}`}
                  >
                    {category}
                    <span className="tabular-nums text-rh-muted/70">{features.length}</span>
                  </a>
                </li>
              ))}
            </ul>
          </nav>

          {/* Feature sections */}
          <div className="min-w-0 flex-1">
            {visibleByCategory.length === 0 ? (
              <p className="text-sm text-rh-muted">
                No features match &ldquo;{query}&rdquo;. Clear the search to see all{" "}
                {DOC_FEATURES.length} features.
              </p>
            ) : (
              visibleByCategory.map(({ category, features }) => (
                <section key={category} id={categoryAnchor(category)} className="mb-10 scroll-mt-24">
                  <h2 className="text-xl font-semibold text-rh-text">{category}</h2>
                  <div className="mt-3 space-y-3">
                    {features.map((feature) => (
                      <FeatureCard key={feature.id} feature={feature} />
                    ))}
                  </div>
                </section>
              ))
            )}
          </div>
        </div>
      </div>
    </main>
  );
}
