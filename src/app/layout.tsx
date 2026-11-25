import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { title: { default: "SecureAI | Website Security", template: "%s | SecureAI" }, description: "Practical website security checks and URL assessment." };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
