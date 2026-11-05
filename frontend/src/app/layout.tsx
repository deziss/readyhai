import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import "./globals.css";

// IBM Plex Sans is the UI face; IBM Plex Mono is only for real code (URLs, curl commands, ids).
// globals.css folds these variables into the --font-sans / --font-mono theme tokens.
const plexSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex-sans",
  display: "swap",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "ReadyHai | QA and release readiness studio",
  description: "Run QA agents against your target, review the evidence, and sign off the release.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable} dark h-full`}>
      <body className="flex h-full flex-col overflow-hidden bg-rh-bg font-sans text-rh-text antialiased">
        {children}
      </body>
    </html>
  );
}
