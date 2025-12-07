import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Card Generator",
  description: "Create your custom business card",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
