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
      <body className="h-full overflow-hidden bg-[#06080e] text-slate-100 antialiased flex flex-col">
        {children}
      </body>
    </html>
  );
}
