"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface CardGeneratorProps {
  serverToken: string;
}

export default function CardGenerator({ serverToken }: CardGeneratorProps) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  const [name, setName] = useState(searchParams.get("fullname") || "John Doe");
  const [email, setEmail] = useState(
    searchParams.get("email") || "john@lilac.com",
  );
  const [colorFrom, setColorFrom] = useState(
    searchParams.get("gradient-from") || "#1a3051",
  );
  const [colorTo, setColorTo] = useState(
    searchParams.get("gradient-to") || "#8b5cf6",
  );
  const [angle, setAngle] = useState(
    parseInt(searchParams.get("gradient-angle") || "135") || 135,
  );
  const [bgImage, setBgImage] = useState(
    searchParams.get("bg-image") ||
      "linear-gradient(var(--gradient-angle),var(--gradient-from),var(--gradient-to))",
  );

  // Sync state to URL
  useEffect(() => {
    const params = new URLSearchParams(searchParams.toString());
    if (name) params.set("fullname", name);
    if (email) params.set("email", email);
    if (colorFrom) params.set("gradient-from", colorFrom);
    if (colorTo) params.set("gradient-to", colorTo);
    if (angle) params.set("gradient-angle", `${angle}deg`);
    if (bgImage) params.set("bg-image", bgImage);

    const newSearchString = params.toString();
    if (newSearchString !== searchParams.toString()) {
      router.replace(`${pathname}?${newSearchString}`, { scroll: false });
    }
  }, [
    name,
    email,
    colorFrom,
    colorTo,
    angle,
    bgImage,
    pathname,
    router,
    searchParams,
  ]);

  const previewStyle = {
    background: bgImage,
  } as React.CSSProperties;
  searchParams.forEach((value, key) => {
    if (key !== "fullname" && key !== "email" && key !== "bg-image") {
      // @ts-expect-error
      previewStyle[`--${key}`] = value;
    }
  });

  return (
    <div className="min-h-screen bg-gray-50 p-8 flex flex-col items-center">
      {/* Header */}
      <div className="text-center mb-12 space-y-2">
        <h1 className="text-4xl font-extrabold tracking-tight text-gray-900 sm:text-5xl">
          Card Generator
        </h1>
        <p className="text-lg text-gray-600">
          Design your personal business card in seconds.
        </p>
      </div>

      <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-2 gap-12 items-start">
        {/* Left Column: Preview */}
        <div className="flex flex-col items-center space-y-6 sticky top-8">
          <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wider">
            Live Preview
          </h2>

          {/* Business Card */}
          <div
            data-token={serverToken}
            className="w-full max-w-md aspect-[1.586/1] rounded-xl shadow-2xl overflow-hidden relative transition-all duration-300"
            style={previewStyle}
          >
            {/* Content */}
            <div className="relative z-10 h-full flex flex-col justify-between p-8 text-white">
              <div>
                <h1 className="text-3xl font-bold tracking-tight drop-shadow-sm">
                  {name}
                </h1>
                <p className="text-lg opacity-90 font-medium mt-1 drop-shadow-sm">
                  Cyber Security Researcher
                </p>
              </div>

              <div className="space-y-2 text-sm font-medium opacity-95">
                <div className="flex items-center gap-3 bg-white/10 backdrop-blur-sm w-fit px-3 py-1.5 rounded-full border border-white/10">
                  <span>✉️</span>
                  <span>{email}</span>
                </div>
              </div>
            </div>
          </div>

          <Button asChild>
            <a href={`/api/bot?${searchParams.toString()}`}>share with bot</a>
          </Button>
        </div>

        {/* Right Column: Editor */}
        <div className="flex flex-col justify-center w-full">
          <Card className="border-0 shadow-lg ring-1 ring-gray-200">
            <CardHeader className="pb-4 border-b border-gray-100">
              <CardTitle className="text-xl">Configuration</CardTitle>
            </CardHeader>
            <CardContent className="space-y-8 pt-6">
              {/* Personal Info Section */}
              <div className="space-y-5">
                <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                  Information
                </h3>
                <div className="grid gap-4">
                  <div className="grid gap-2">
                    <Label htmlFor="name" className="text-gray-600">
                      Full Name
                    </Label>
                    <Input
                      id="name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Enter your full name"
                      className="bg-gray-50/50 focus:bg-white transition-colors"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="email" className="text-gray-600">
                      Email Address
                    </Label>
                    <Input
                      id="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="name@example.com"
                      className="bg-gray-50/50 focus:bg-white transition-colors"
                    />
                  </div>
                </div>
              </div>

              {/* Style Section */}
              <div className="space-y-5">
                <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-purple-500"></span>
                  Appearance
                </h3>

                <div className="grid gap-2">
                  <Label htmlFor="bgImage" className="text-gray-600">
                    Background Style
                  </Label>
                  <select
                    id="bgImage"
                    value={bgImage}
                    onChange={(e) => setBgImage(e.target.value)}
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 bg-gray-50/50 focus:bg-white transition-colors"
                  >
                    <option value="linear-gradient(var(--gradient-angle),var(--gradient-from),var(--gradient-to))">
                      Linear Gradient
                    </option>
                    <option value="radial-gradient(circle at center, var(--gradient-from), var(--gradient-to))">
                      Radial Gradient
                    </option>
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-6">
                  {/* Color From */}
                  <div className="flex items-center justify-between p-3 rounded-lg border border-gray-100 bg-gray-50/50">
                    <Label
                      htmlFor="colorFrom"
                      className="text-gray-600 cursor-pointer"
                    >
                      From Color
                    </Label>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-400 font-mono uppercase">
                        {colorFrom}
                      </span>
                      <div className="relative w-8 h-8 rounded-full overflow-hidden ring-1 ring-gray-200 shadow-sm">
                        <Input
                          id="colorFrom"
                          type="color"
                          value={colorFrom}
                          onChange={(e) => setColorFrom(e.target.value)}
                          className="absolute inset-0 w-[150%] h-[150%] -top-1/4 -left-1/4 p-0 border-0 cursor-pointer"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Color To */}
                  <div className="flex items-center justify-between p-3 rounded-lg border border-gray-100 bg-gray-50/50">
                    <Label
                      htmlFor="colorTo"
                      className="text-gray-600 cursor-pointer"
                    >
                      To Color
                    </Label>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-400 font-mono uppercase">
                        {colorTo}
                      </span>
                      <div className="relative w-8 h-8 rounded-full overflow-hidden ring-1 ring-gray-200 shadow-sm">
                        <Input
                          id="colorTo"
                          type="color"
                          value={colorTo}
                          onChange={(e) => setColorTo(e.target.value)}
                          className="absolute inset-0 w-[150%] h-[150%] -top-1/4 -left-1/4 p-0 border-0 cursor-pointer"
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Angle Slider */}
                <div className="space-y-4 p-3 rounded-lg border border-gray-100 bg-gray-50/50">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="angle" className="text-gray-600">
                      Gradient Angle
                    </Label>
                    <span className="text-xs font-mono bg-white px-2 py-1 rounded border border-gray-200 text-gray-500">
                      {angle}°
                    </span>
                  </div>
                  <div className="px-1">
                    <input
                      type="range"
                      min="0"
                      max="360"
                      value={angle}
                      onChange={(e) => setAngle(Number(e.target.value))}
                      className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-gray-900"
                    />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
