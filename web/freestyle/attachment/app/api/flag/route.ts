import { type NextRequest, NextResponse } from "next/server";
import { validateToken } from "@/lib/token-store";

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const token = searchParams.get("token");

  if (!token) {
    return NextResponse.json({ error: "Missing token" }, { status: 400 });
  }

  if (validateToken(token)) {
    return NextResponse.json({
      flag: "flag{redacted_flag}",
    });
  } else {
    return NextResponse.json({ error: "Invalid token" }, { status: 403 });
  }
}
