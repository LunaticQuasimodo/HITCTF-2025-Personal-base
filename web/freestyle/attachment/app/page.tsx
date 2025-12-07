import { headers } from "next/headers";
import { Suspense } from "react";
import CardGenerator from "@/components/CardGenerator";
import { getToken } from "@/lib/token-store";

export default async function Home() {
  const headersList = await headers();
  const isPublicAccess = headersList.get("X-Public-Access") === "true";

  const token = getToken();
  const displayToken = isPublicAccess ? "<REDACTED>" : token;

  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center">
          Loading...
        </div>
      }
    >
      <CardGenerator serverToken={displayToken} />
    </Suspense>
  );
}
