// Dunellan Lodge No. 480: site API on Cloudflare Workers + D1.
// Static pages (index.html, admin.html) are served from ./public by the assets binding.

const SESSION_DAYS = 30;
const MAX_FAILS = 8;
const LOCK_MINUTES = 15;
const PBKDF2_ITER = 100000;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const err = (message, status = 400) => json({ error: message }, status);

const clean = (v, max) => String(v ?? "").trim().slice(0, max);
const validEmail = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254;
const validDate = v => /^\d{4}-\d{2}-\d{2}$/.test(v);
const KINDS = ["news", "newsletter", "charity"];

const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const randomToken = (n = 32) => b64(crypto.getRandomValues(new Uint8Array(n))).replace(/[+/=]/g, c => ({ "+": "-", "/": "_", "=": "" }[c]));

async function hashPassword(password, saltB64) {
  const salt = saltB64 ? unb64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITER }, key, 256);
  return { salt: b64(salt), hash: b64(bits) };
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function readJson(request) {
  const len = +(request.headers.get("content-length") || 0);
  if (len > 200000) throw new Error("too_large");
  try { return await request.json(); } catch { throw new Error("bad_json"); }
}

function getCookie(request, name) {
  const c = request.headers.get("cookie") || "";
  const m = c.match(new RegExp("(?:^|; )" + name + "=([^;]+)"));
  return m ? m[1] : null;
}
const cookie = (token, maxAge) => `dl_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

async function currentAdmin(request, env) {
  const token = getCookie(request, "dl_session");
  if (!token) return null;
  const now = Date.now();
  const row = await env.DB.prepare("SELECT s.email, a.name, a.must_change FROM sessions s JOIN admins a ON a.email = s.email WHERE s.token = ? AND s.expires > ?").bind(token, now).first();
  return row ? { ...row, token } : null;
}

// Same origin check on every state changing request, as a guard against cross site form posts.
// The public site may sit on another host (Vercel) that forwards /api/* here, so its address is allowed too.
function sameOrigin(request, env) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  if (origin === new URL(request.url).origin) return true;
  return String(env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean).includes(origin);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);
    if (method !== "GET" && !sameOrigin(request, env)) return err("Request blocked.", 403);

    try {
      // ---------- public ----------
      if (path === "/api/posts" && method === "GET") {
        const { results } = await env.DB.prepare("SELECT id, title, body, kind, date FROM posts ORDER BY date DESC, created_at DESC LIMIT 200").all();
        return json({ posts: results });
      }

      if (path === "/api/subscribe" && method === "POST") {
        const b = await readJson(request);
        if (b.website) return json({ ok: true }); // spam trap
        const email = clean(b.email, 254).toLowerCase(), name = clean(b.name, 120);
        if (!validEmail(email)) return err("Please enter a valid email address.");
        await env.DB.prepare("INSERT INTO subscribers (email, name) VALUES (?, ?) ON CONFLICT(email) DO UPDATE SET name = excluded.name").bind(email, name).run();
        return json({ ok: true });
      }

      if (path === "/api/enquire" && method === "POST") {
        const b = await readJson(request);
        if (b.website) return json({ ok: true });
        const e = {
          name: clean(b.name, 120), email: clean(b.email, 254).toLowerCase(), phone: clean(b.phone, 40),
          postcode: clean(b.postcode, 10), prefers: b.prefers === "phone" ? "phone" : "email", message: clean(b.message, 4000)
        };
        if (!e.name) return err("Please enter your name.");
        if (!validEmail(e.email)) return err("Please enter a valid email address.");
        await env.DB.prepare("INSERT INTO enquiries (id, name, email, phone, postcode, prefers, message) VALUES (?, ?, ?, ?, ?, ?, ?)")
          .bind(crypto.randomUUID(), e.name, e.email, e.phone, e.postcode, e.prefers, e.message).run();
        return json({ ok: true });
      }

      // ---------- sign in ----------
      if (path === "/api/login" && method === "POST") {
        const b = await readJson(request);
        const email = clean(b.email, 254).toLowerCase(), password = String(b.password || "");
        const now = Date.now();
        const lock = await env.DB.prepare("SELECT fails, locked_until FROM login_attempts WHERE email = ?").bind(email).first();
        if (lock && lock.locked_until > now) return err("Too many attempts. Please wait 15 minutes and try again.", 429);
        const admin = await env.DB.prepare("SELECT email, salt, hash FROM admins WHERE email = ?").bind(email).first();
        let ok = false;
        if (admin) { const h = await hashPassword(password, admin.salt); ok = safeEqual(h.hash, admin.hash); }
        else { await hashPassword(password); } // keep timing similar
        if (!ok) {
          const fails = (lock?.fails || 0) + 1;
          const until = fails >= MAX_FAILS ? now + LOCK_MINUTES * 60000 : 0;
          await env.DB.prepare("INSERT INTO login_attempts (email, fails, locked_until) VALUES (?, ?, ?) ON CONFLICT(email) DO UPDATE SET fails = excluded.fails, locked_until = excluded.locked_until")
            .bind(email, until ? 0 : fails, until).run();
          return err("That email and password do not match. Check both and try again.", 401);
        }
        await env.DB.prepare("DELETE FROM login_attempts WHERE email = ?").bind(email).run();
        await env.DB.prepare("DELETE FROM sessions WHERE expires < ?").bind(now).run();
        const token = randomToken();
        await env.DB.prepare("INSERT INTO sessions (token, email, expires) VALUES (?, ?, ?)").bind(token, email, now + SESSION_DAYS * 86400000).run();
        return json({ ok: true }, 200, { "set-cookie": cookie(token, SESSION_DAYS * 86400) });
      }

      if (path === "/api/logout" && method === "POST") {
        const token = getCookie(request, "dl_session");
        if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
        return json({ ok: true }, 200, { "set-cookie": cookie("", 0) });
      }

      // ---------- members only ----------
      const me = await currentAdmin(request, env);
      if (path === "/api/me" && method === "GET") return me ? json({ email: me.email, name: me.name, mustChange: !!me.must_change }) : err("Not signed in.", 401);
      if (!me) return err("Please sign in again.", 401);

      if (path === "/api/password" && method === "POST") {
        const b = await readJson(request);
        const next = String(b.newPassword || "");
        if (next.length < 10) return err("Choose a password of at least 10 characters.");
        const row = await env.DB.prepare("SELECT salt, hash FROM admins WHERE email = ?").bind(me.email).first();
        const cur = await hashPassword(String(b.currentPassword || ""), row.salt);
        if (!safeEqual(cur.hash, row.hash)) return err("Your current password is incorrect.", 401);
        const h = await hashPassword(next);
        await env.DB.prepare("UPDATE admins SET salt = ?, hash = ?, must_change = 0 WHERE email = ?").bind(h.salt, h.hash, me.email).run();
        await env.DB.prepare("DELETE FROM sessions WHERE email = ? AND token <> ?").bind(me.email, me.token).run();
        return json({ ok: true });
      }

      // posts
      if (path === "/api/posts" && method === "POST") {
        const b = await readJson(request);
        const p = { title: clean(b.title, 200), body: clean(b.body, 20000), kind: KINDS.includes(b.kind) ? b.kind : "news", date: clean(b.date, 10) };
        if (!p.title) return err("Add a title before publishing.");
        if (!validDate(p.date)) return err("Choose a date for the post.");
        const id = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO posts (id, title, body, kind, date) VALUES (?, ?, ?, ?, ?)").bind(id, p.title, p.body, p.kind, p.date).run();
        return json({ ok: true, id });
      }
      const postMatch = path.match(/^\/api\/posts\/([\w-]{1,64})$/);
      if (postMatch && method === "PUT") {
        const b = await readJson(request);
        const p = { title: clean(b.title, 200), body: clean(b.body, 20000), kind: KINDS.includes(b.kind) ? b.kind : "news", date: clean(b.date, 10) };
        if (!p.title) return err("Add a title before saving.");
        if (!validDate(p.date)) return err("Choose a date for the post.");
        const r = await env.DB.prepare("UPDATE posts SET title = ?, body = ?, kind = ?, date = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?").bind(p.title, p.body, p.kind, p.date, postMatch[1]).run();
        return r.meta.changes ? json({ ok: true }) : err("That post no longer exists.", 404);
      }
      if (postMatch && method === "DELETE") {
        await env.DB.prepare("DELETE FROM posts WHERE id = ?").bind(postMatch[1]).run();
        return json({ ok: true });
      }

      // subscribers
      if (path === "/api/subscribers" && method === "GET") {
        const { results } = await env.DB.prepare("SELECT email, name, created_at FROM subscribers ORDER BY created_at DESC").all();
        return json({ subscribers: results });
      }
      const subMatch = path.match(/^\/api\/subscribers\/(.+)$/);
      if (subMatch && method === "DELETE") {
        await env.DB.prepare("DELETE FROM subscribers WHERE email = ?").bind(decodeURIComponent(subMatch[1]).toLowerCase()).run();
        return json({ ok: true });
      }

      // enquiries
      if (path === "/api/enquiries" && method === "GET") {
        const { results } = await env.DB.prepare("SELECT * FROM enquiries ORDER BY created_at DESC LIMIT 500").all();
        return json({ enquiries: results });
      }
      const eqMatch = path.match(/^\/api\/enquiries\/([\w-]{1,64})$/);
      if (eqMatch && method === "PATCH") {
        const b = await readJson(request);
        await env.DB.prepare("UPDATE enquiries SET handled = ? WHERE id = ?").bind(b.handled ? 1 : 0, eqMatch[1]).run();
        return json({ ok: true });
      }
      if (eqMatch && method === "DELETE") {
        await env.DB.prepare("DELETE FROM enquiries WHERE id = ?").bind(eqMatch[1]).run();
        return json({ ok: true });
      }

      // members who can post
      if (path === "/api/admins" && method === "GET") {
        const { results } = await env.DB.prepare("SELECT email, name, created_at FROM admins ORDER BY created_at").all();
        return json({ admins: results, me: me.email });
      }
      if (path === "/api/admins" && method === "POST") {
        const b = await readJson(request);
        const email = clean(b.email, 254).toLowerCase(), name = clean(b.name, 120), password = String(b.password || "");
        if (!validEmail(email)) return err("Enter a valid email address.");
        if (password.length < 10) return err("The temporary password needs at least 10 characters.");
        const h = await hashPassword(password);
        await env.DB.prepare("INSERT INTO admins (email, name, salt, hash, must_change) VALUES (?, ?, ?, ?, 1) ON CONFLICT(email) DO UPDATE SET name = excluded.name, salt = excluded.salt, hash = excluded.hash, must_change = 1")
          .bind(email, name, h.salt, h.hash).run();
        await env.DB.prepare("DELETE FROM sessions WHERE email = ?").bind(email).run();
        return json({ ok: true });
      }
      const adMatch = path.match(/^\/api\/admins\/(.+)$/);
      if (adMatch && method === "DELETE") {
        const email = decodeURIComponent(adMatch[1]).toLowerCase();
        if (email === me.email) return err("You cannot remove your own access.");
        const { count } = await env.DB.prepare("SELECT COUNT(*) AS count FROM admins").first();
        if (count <= 1) return err("At least one member must keep access.");
        await env.DB.prepare("DELETE FROM admins WHERE email = ?").bind(email).run();
        await env.DB.prepare("DELETE FROM sessions WHERE email = ?").bind(email).run();
        return json({ ok: true });
      }

      return err("Not found.", 404);
    } catch (e) {
      if (e.message === "bad_json") return err("The request could not be read.");
      if (e.message === "too_large") return err("That is too long to save.", 413);
      console.error(e);
      return err("Something went wrong on our side. Please try again.", 500);
    }
  }
};
