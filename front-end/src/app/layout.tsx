import type { Metadata } from "next";
import { EB_Garamond, Source_Serif_4, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

const display = EB_Garamond({
  variable: "--font-display",
  subsets: ["latin"],
  style: ["normal", "italic"],
});

const serif = Source_Serif_4({
  variable: "--font-serif",
  subsets: ["latin"],
});

const mono = IBM_Plex_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  weight: ["400", "500"],
});

export const metadata: Metadata = {
  title: "FAPI Lens — A Visual Instrument for FAPI 2.0 Discovery Conformance",
  description:
    "Academic presentation of FAPI 2.0 adversarial scanner findings for authorisation-server discovery checks.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${display.variable} ${serif.variable} ${mono.variable} h-full`}
    >
      <body className="min-h-full">{children}</body>
    </html>
  );
}
