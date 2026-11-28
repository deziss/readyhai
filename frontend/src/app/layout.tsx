import type { Metadata, Viewport } from "next";
import { Archivo, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

/**
 * Archivo carries the interface: a grotesque with flat terminals and open apertures, which stays
 * legible at the 12-13px sizes a dense console runs at, and its bold steps give real hierarchy
 * without a second family. Plex Mono is only for real code and measurement (URLs, curl, ids,
 * timings). globals.css folds both into --font-sans / --font-mono.
 */
const sans = Archivo({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-archivo",
  display: "swap",
});

const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-plex-mono",
  display: "swap",
});

/**
 * Applies the persisted theme before first paint. Without it a light-theme user sees a graphite
 * flash on every reload, because the data-attribute is only written by initPrefs() after hydration.
 * Kept to the three attributes the pre-paint theme depends on.
 */
const themeBootstrap = `(function(){try{var r=document.documentElement;var p=JSON.parse(localStorage.getItem("readyhai_prefs_v1")||"{}");var t=p.theme||"dark";r.dataset.theme=t;r.dataset.resolved=t==="system"?(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"):t;r.dataset.scale=p.typeScale||"md";r.dataset.density=p.density||"comfortable";r.dataset.accent=p.accent||"saffron";r.dataset.verdicts=p.verdictPalette||"standard";r.dataset.motion=p.motion===false?"off":"on";}catch(e){}})();`;

export const metadata: Metadata = {
  title: "ReadyHai | QA and release readiness studio",
  description: "Run QA agents against your target, review the evidence, and sign off the release.",
  manifest: "/site.webmanifest",
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/favicon-32x32.png", sizes: "32x32", type: "image/png" },
      { url: "/favicon-16x16.png", sizes: "16x16", type: "image/png" },
      { url: "/icon.svg", type: "image/svg+xml" },
    ],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" }],
    shortcut: ["/favicon.ico"],
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#14161a" },
    { media: "(prefers-color-scheme: light)", color: "#f4f2ee" },
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${sans.variable} ${mono.variable} h-full`}
      data-theme="dark"
      data-scale="md"
      data-density="comfortable"
      data-accent="saffron"
      data-verdicts="standard"
      data-motion="on"
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body className="flex h-full flex-col overflow-hidden bg-rh-bg font-sans text-rh-text antialiased">
        {children}
      </body>
    </html>
  );
}
