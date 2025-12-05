export async function hash(str) {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hashBuffer)]
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
}

export function generateToken() {
  return crypto.randomUUID().replace(/-/g, "");
}

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
