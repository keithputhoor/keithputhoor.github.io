import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Keith Puthoor | Cybersecurity Portfolio",
  description: "B.Sc. in Computer Science with a specialization in Cybersecurity",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark scroll-smooth">
      <body className={`${inter.className} bg-slate-950 text-slate-200 antialiased min-h-screen flex flex-col`}>
        {children}
      </body>
    </html>
  );
}
