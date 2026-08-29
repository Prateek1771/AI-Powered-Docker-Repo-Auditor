import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";

import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Container Auditor",
  description:
    "Scans a container image for vulnerabilities, bloat, base image drift and CIS compliance, and tells you when the answer is incomplete.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="flex min-h-full flex-col bg-background">
        <header className="sticky top-0 z-10 border-b border-border bg-background/80 backdrop-blur">
          <div className="mx-auto flex h-14 max-w-5xl items-center gap-2 px-6">
            <Link
              href="/"
              className="flex items-center gap-2 text-sm font-semibold text-foreground"
            >
              <span aria-hidden className="text-accent">
                ◆
              </span>
              auditor
            </Link>
          </div>
        </header>

        <div className="flex-1">{children}</div>
      </body>
    </html>
  );
}
