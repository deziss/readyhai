import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ReadyHai · Agent Studio & Autonomous QA Gate",
  description: "Enterprise Autonomous QA and Red Team Engine with Grounded Verification & 4-Pillar Evidence Ledger",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark h-full">
      <body className="min-h-full bg-[#080c14] text-slate-100 antialiased font-sans flex flex-col">
        {children}
      </body>
    </html>
  );
}
