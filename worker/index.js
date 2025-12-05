import { hash, generateToken, json } from "./utils.js";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // --------------- REGISTER ------------------
    if (path === "/api/register" && request.method === "POST") {
      const { email, username, password } = await request.json();
      const password_hash = await hash(password);
      const token = generateToken();

      try {
        await env.DB.prepare(
          "INSERT INTO users (email, username, password_hash, verification_token) VALUES (?, ?, ?, ?)"
        ).bind(email, username, password_hash, token).run();
      } catch {
        return json({ error: "Email or username already exists" }, 400);
      }

      return json({
        message: "Account created. Verify email.",
        verification_url: `/login/verify/?token=${token}`
      });
    }

    // --------------- VERIFY EMAIL ------------------
    if (path === "/api/verify" && request.method === "POST") {
      const { token } = await request.json();
      const user = await env.DB.prepare(
        "SELECT * FROM users WHERE verification_token = ?"
      ).bind(token).first();

      if (!user) return json({ error: "Invalid token" }, 400);

      await env.DB.prepare(
        "UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?"
      ).bind(user.id).run();

      return json({ message: "Email verified." });
    }

    // --------------- LOGIN ------------------
    if (path === "/api/login" && request.method === "POST") {
      const { email, password } = await request.json();
      const user = await env.DB.prepare(
        "SELECT * FROM users WHERE email = ?"
      ).bind(email).first();

      if (!user) return json({ error: "Invalid credentials" }, 400);

      const ph = await hash(password);
      if (ph !== user.password_hash)
        return json({ error: "Invalid credentials" }, 400);

      if (user.verified !== 1)
        return json({ error: "Email not verified" }, 403);

      return json({
        message: "Login successful",
        user_id: user.id
      });
    }

    // --------------- PASSWORD RESET REQUEST ------------------
    if (path === "/api/reset/request" && request.method === "POST") {
      const { email } = await request.json();
      const token = generateToken();

      await env.DB.prepare(
        "UPDATE users SET reset_token = ? WHERE email = ?"
      ).bind(token, email).run();

      return json({
        message: "Password reset link created",
        reset_url: `/login/reset/?token=${token}`
      });
    }

    // --------------- PASSWORD RESET APPLY ------------------
    if (path === "/api/reset/apply" && request.method === "POST") {
      const { token, new_password } = await request.json();

      const user = await env.DB.prepare(
        "SELECT * FROM users WHERE reset_token = ?"
      ).bind(token).first();

      if (!user) return json({ error: "Invalid reset token" }, 400);

      const hp = await hash(new_password);

      await env.DB.prepare(
        "UPDATE users SET password_hash = ?, reset_token = NULL WHERE id = ?"
      ).bind(hp, user.id).run();

      return json({ message: "Password updated" });
    }

    // --------------- ADMIN LIST USERS ------------------
    if (path === "/api/admin/users") {
      const rows = await env.DB.prepare("SELECT id, email, username, verified FROM users").all();
      return json(rows);
    }

    return json({ error: "Not Found" }, 404);
  }
};
