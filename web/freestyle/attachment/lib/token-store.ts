declare global {
  var CTF_CHALLENGE_TOKEN: string | undefined;
  var CTF_CHALLENGE_LOCKED: boolean | undefined;
}

export function generateToken(): string {
  const token = Math.floor(Math.random() * 100).toString().padStart(2, '0');
  globalThis.CTF_CHALLENGE_TOKEN = token;
  globalThis.CTF_CHALLENGE_LOCKED = false;
  console.log(`[CTF] New token generated: ${token}`);
  return token;
}

export function getToken(): string {
  if (!globalThis.CTF_CHALLENGE_TOKEN) {
    return generateToken();
  }
  return globalThis.CTF_CHALLENGE_TOKEN;
}

export function validateToken(inputToken: string): boolean {
  if (globalThis.CTF_CHALLENGE_LOCKED) {
    return false;
  }

  const currentToken = getToken();
  if (inputToken === currentToken) {
    return true;
  }
  // Lock on failure
  globalThis.CTF_CHALLENGE_LOCKED = true;
  console.log(`[CTF] Challenge LOCKED due to invalid token attempt.`);
  return false;
}
