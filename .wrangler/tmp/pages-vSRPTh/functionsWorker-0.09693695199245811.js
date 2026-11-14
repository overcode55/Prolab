var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// api/[[route]].js
var J = /* @__PURE__ */ __name((d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", ...h } }), "J");
var E = /* @__PURE__ */ __name((m, s = 400) => J({ error: m }, s), "E");
var hex = /* @__PURE__ */ __name((b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join(""), "hex");
var rnd = /* @__PURE__ */ __name((n) => hex(crypto.getRandomValues(new Uint8Array(n))), "rnd");
var now = /* @__PURE__ */ __name(() => Date.now(), "now");
async function hash(pw, salt) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: 1e5 }, k, 256));
}
__name(hash, "hash");
var isAdmin = /* @__PURE__ */ __name((env, email) => (env.ADMIN_EMAILS || "").toLowerCase().split(",").map((s) => s.trim()).includes(email.toLowerCase()), "isAdmin");
async function mail(env, to, subject, text) {
  if (!env.RESEND_API_KEY) return;
  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { authorization: "Bearer " + env.RESEND_API_KEY, "content-type": "application/json" },
    body: JSON.stringify({ from: env.MAIL_FROM, to, subject, text })
  });
}
__name(mail, "mail");
async function startSession(env, uid) {
  const t = rnd(32);
  await env.DB.prepare("INSERT INTO sessions VALUES(?,?,?)").bind(t, uid, now() + 30 * 864e5).run();
  return { "set-cookie": `s=${t}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000` };
}
__name(startSession, "startSession");
async function getUser(env, req) {
  const t = (req.headers.get("cookie") || "").match(/(?:^|; )s=([a-f0-9]+)/)?.[1];
  if (!t) return null;
  const u = await env.DB.prepare("SELECT u.id,u.email,u.name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?").bind(t, now()).first();
  return u ? { ...u, admin: isAdmin(env, u.email) } : null;
}
__name(getUser, "getUser");
async function unzip(buf, max = 26214400) {
  const v = new DataView(buf), u8 = new Uint8Array(buf);
  let e = buf.byteLength - 22;
  while (e >= 0 && v.getUint32(e, true) !== 101010256) e--;
  if (e < 0) throw new Error("This is not a valid zip file.");
  const n = v.getUint16(e + 10, true), out = [];
  let p = v.getUint32(e + 16, true);
  for (let i = 0; i < n && v.getUint32(p, true) === 33639248; i++) {
    const fl = v.getUint16(p + 8, true), method = v.getUint16(p + 10, true), cs = v.getUint32(p + 20, true), us = v.getUint32(p + 24, true), nl = v.getUint16(p + 28, true), xl = v.getUint16(p + 30, true), cl = v.getUint16(p + 32, true), off = v.getUint32(p + 42, true);
    const name = new TextDecoder().decode(u8.subarray(p + 46, p + 46 + nl));
    p += 46 + nl + xl + cl;
    if (name.endsWith("/") || name.startsWith("__MACOSX") || name.split("/").pop().startsWith(".") || fl & 1 || us > max || method !== 0 && method !== 8) continue;
    const s = off + 30 + v.getUint16(off + 26, true) + v.getUint16(off + 28, true), raw = u8.subarray(s, s + cs);
    out.push({ name, read: /* @__PURE__ */ __name(async () => method === 0 ? raw : new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).arrayBuffer()), "read") });
  }
  return out;
}
__name(unzip, "unzip");
var kv = /* @__PURE__ */ __name((B) => ({
  get: /* @__PURE__ */ __name(async (k) => {
    const s = await B.get(k, { type: "stream" });
    return s && { body: s };
  }, "get"),
  put: /* @__PURE__ */ __name((k, v) => B.put(k, v), "put"),
  delete: /* @__PURE__ */ __name(async (ks) => {
    for (const k of [].concat(ks)) await B.delete(k);
  }, "delete"),
  list: /* @__PURE__ */ __name(async ({ prefix }) => ({ objects: (await B.list({ prefix })).keys.map((x) => ({ key: x.name })) }), "list")
}), "kv");
async function onRequest({ request: req, env, waitUntil }) {
  if (env.FILES) env = { ...env, FILES: kv(env.FILES) };
  const url = new URL(req.url), p = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  const body = req.method === "POST" && (req.headers.get("content-type") || "").includes("json") ? await req.json().catch(() => ({})) : {};
  const [a, b, c] = p;
  if (a === "config") return J({ google: env.GOOGLE_CLIENT_ID || "" });
  if (a === "stats") return J(await env.DB.prepare("SELECT (SELECT COUNT(*) FROM orders) o,(SELECT COUNT(*) FROM orders WHERE kind='design') d,(SELECT COUNT(*) FROM orders WHERE status IN ('shipped','done')) c,(SELECT COUNT(*) FROM users) u").first());
  if (a === "auth") {
    if (b === "register" || b === "login") {
      const email = String(body.email || "").trim().toLowerCase(), pw = String(body.password || "");
      if (!/^\S+@\S+\.\S+$/.test(email)) return E("Enter a valid email address.");
      if (b === "register") {
        if (pw.length < 8) return E("Password must be at least 8 characters.");
        if (await env.DB.prepare("SELECT 1 FROM users WHERE email=?").bind(email).first()) return E("An account with this email already exists.");
        const salt2 = rnd(16), r = await env.DB.prepare("INSERT INTO users(email,name,pw,created) VALUES(?,?,?,?)").bind(email, String(body.name || "").slice(0, 80), salt2 + ":" + await hash(pw, salt2), now()).run();
        return J({ ok: 1 }, 200, await startSession(env, r.meta.last_row_id));
      }
      const u = await env.DB.prepare("SELECT id,pw FROM users WHERE email=?").bind(email).first();
      const [salt, h] = (u?.pw || ":").split(":");
      if (!u || !u.pw || await hash(pw, salt) !== h) return E("Wrong email or password.", 401);
      return J({ ok: 1 }, 200, await startSession(env, u.id));
    }
    if (b === "google") {
      const r = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(body.credential || ""));
      const g = await r.json();
      if (!r.ok || g.aud !== env.GOOGLE_CLIENT_ID || g.email_verified !== "true") return E("Google sign-in failed.", 401);
      const email = g.email.toLowerCase();
      let u = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
      if (!u) {
        const x = await env.DB.prepare("INSERT INTO users(email,name,created) VALUES(?,?,?)").bind(email, g.name || "", now()).run();
        u = { id: x.meta.last_row_id };
      }
      return J({ ok: 1 }, 200, await startSession(env, u.id));
    }
    if (b === "logout") return J({ ok: 1 }, 200, { "set-cookie": "s=; Path=/; Max-Age=0" });
  }
  const me = await getUser(env, req);
  if (a === "me") return J({ user: me });
  if (a === "mfile") {
    const key = "models/" + p.slice(1).join("/");
    const obj = await env.FILES?.get(key);
    if (!obj) return E("Not found.", 404);
    const ext = key.split(".").pop().toLowerCase();
    return new Response(obj.body, { headers: { "content-type": { webp: "image/webp", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg" }[ext] || "application/octet-stream", "cache-control": "public, max-age=86400", "x-content-type-options": "nosniff" } });
  }
  if (a === "models") {
    const Q = `SELECT m.*,(SELECT COUNT(*) FROM model_likes l WHERE l.model_id=m.id) likes,(SELECT COUNT(*) FROM orders o WHERE o.model_id=m.id AND o.status IN ('shipped','done')) prints,(SELECT COUNT(*) FROM orders o2 WHERE o2.model_id=m.id) ordered FROM models m`;
    if (!b && req.method === "GET") return J({ models: (await env.DB.prepare(Q + " ORDER BY m.id DESC").all()).results });
    if (!b && req.method === "POST") {
      if (!me?.admin) return E("Not allowed.", 403);
      const t = String(body.title || "").trim();
      if (!t) return E("Give the model a title.");
      const s = /* @__PURE__ */ __name((v, n) => String(v ?? "").slice(0, n), "s");
      const r = await env.DB.prepare("INSERT INTO models(title,cat,mat,hours,who,descr,lay,inf,walls,sup,tags,col,imgs,stls,views,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(s(t, 120), s(body.cat || "Other", 40), s(body.mat, 40), +body.hours || 0, s(body.who || "ProLab", 60), s(body.descr, 4e3), s(body.lay, 30), s(body.inf, 30), +body.walls || 0, s(body.sup, 60), s(body.tags, 200), /^#[0-9a-f]{6}$/i.test(body.col) ? body.col : "#00ae42", "[]", "[]", 0, now()).run();
      return J({ id: r.meta.last_row_id });
    }
    const m = await env.DB.prepare(Q + " WHERE m.id=?").bind(+b).first();
    if (!m) return E("Not found.", 404);
    if (!c && req.method === "GET") {
      m.liked = me ? !!await env.DB.prepare("SELECT 1 FROM model_likes WHERE model_id=? AND user_id=?").bind(m.id, me.id).first() : false;
      return J({ model: m });
    }
    if (c === "view") {
      await env.DB.prepare("UPDATE models SET views=views+1 WHERE id=?").bind(m.id).run();
      return J({ ok: 1 });
    }
    if (!me) return E("Sign in first.", 401);
    if (c === "like") {
      const had = await env.DB.prepare("SELECT 1 FROM model_likes WHERE model_id=? AND user_id=?").bind(m.id, me.id).first();
      await env.DB.prepare(had ? "DELETE FROM model_likes WHERE model_id=? AND user_id=?" : "INSERT INTO model_likes VALUES(?,?)").bind(m.id, me.id).run();
      return J({ liked: !had, likes: m.likes + (had ? -1 : 1) });
    }
    if (!me.admin) return E("Not allowed.", 403);
    if (c === "update" && req.method === "POST") {
      const s = /* @__PURE__ */ __name((v, n) => String(v ?? "").slice(0, n), "s"), t = s(body.title, 120).trim();
      if (!t) return E("Give the model a title.");
      await env.DB.prepare("UPDATE models SET title=?,cat=?,mat=?,hours=?,who=?,descr=?,lay=?,inf=?,walls=?,sup=?,tags=?,col=? WHERE id=?").bind(t, s(body.cat || "Other", 40), s(body.mat, 40), +body.hours || 0, s(body.who || "ProLab", 60), s(body.descr, 4e3), s(body.lay, 30), s(body.inf, 30), +body.walls || 0, s(body.sup, 60), s(body.tags, 200), /^#[0-9a-f]{6}$/i.test(body.col) ? body.col : "#00ae42", m.id).run();
      return J({ ok: 1 });
    }
    if (c === "files" && req.method === "POST") {
      if (!env.FILES) return E("File storage is not set up yet.", 503);
      const kind = req.headers.get("x-kind") === "stl" ? "stl" : "img";
      const name = decodeURIComponent(req.headers.get("x-filename") || "file").replace(/[^A-Za-z0-9._-]/g, "_").slice(-80);
      const zip = kind === "stl" && /\.zip$/i.test(name), lim = zip ? 52428800 : 26214400;
      if (!zip && !(kind === "stl" ? /\.(stl|3mf|obj|stp|step)$/i : /\.(png|jpe?g|webp)$/i).test(name)) return E("This file type is not allowed.");
      if (+req.headers.get("content-length") > lim) return E(`Max file size is ${lim >> 20} MB.`);
      const buf = await req.arrayBuffer();
      if (buf.byteLength > lim) return E(`Max file size is ${lim >> 20} MB.`);
      const imgs = JSON.parse(m.imgs || "[]"), stls = JSON.parse(m.stls || "[]");
      const put = /* @__PURE__ */ __name(async (nm, data, k) => {
        const path = `${m.id}/${rnd(6)}-${nm}`;
        await env.FILES.put("models/" + path, data);
        (k === "stl" ? stls : imgs).push("/api/mfile/" + path);
      }, "put");
      if (zip) {
        let ents;
        try {
          ents = await unzip(buf);
        } catch (x) {
          return E(x.message);
        }
        ents.sort((x, y) => x.name.localeCompare(y.name, void 0, { numeric: true }));
        let n = 0;
        for (const e of ents) {
          const base = e.name.split("/").pop(), ext = (base.match(/\.([a-z0-9]+)$/i) || [])[1]?.toLowerCase();
          const is3d = ["stl", "3mf", "obj", "stp", "step"].includes(ext);
          if (is3d || ["png", "jpg", "jpeg", "webp"].includes(ext)) {
            await put(base.replace(/[^A-Za-z0-9._-]/g, "_").slice(-80), await e.read(), is3d ? "stl" : "img");
            n++;
          }
        }
        if (!n) return E("No 3D files were found in the zip.");
      } else await put(name, buf, kind);
      await env.DB.prepare("UPDATE models SET imgs=?,stls=? WHERE id=?").bind(JSON.stringify(imgs), JSON.stringify(stls), m.id).run();
      return J({ ok: 1 });
    }
    if (c === "delete" && req.method === "POST") {
      if (env.FILES) {
        const l = await env.FILES.list({ prefix: `models/${m.id}/` });
        if (l.objects.length) await env.FILES.delete(l.objects.map((o) => o.key));
      }
      await env.DB.batch([env.DB.prepare("DELETE FROM model_likes WHERE model_id=?").bind(m.id), env.DB.prepare("DELETE FROM models WHERE id=?").bind(m.id)]);
      return J({ ok: 1 });
    }
    return E("Not found.", 404);
  }
  if (!me) return E("Sign in first.", 401);
  if (a === "files" && b) {
    const f = await env.DB.prepare("SELECT a.*,o.user_id ou FROM attachments a JOIN orders o ON o.id=a.order_id WHERE a.id=?").bind(+b).first();
    if (!f || !me.admin && f.ou !== me.id) return E("Not found.", 404);
    const obj = await env.FILES?.get(f.key);
    if (!obj) return E("File missing.", 404);
    return new Response(obj.body, { headers: { "content-type": "application/octet-stream", "content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(f.name)}`, "x-content-type-options": "nosniff" } });
  }
  if (a === "orders" && !b) {
    if (req.method === "POST") {
      const t = String(body.title || "").trim();
      if (!t) return E("Give your request a title.");
      const r = await env.DB.prepare("INSERT INTO orders(user_id,title,kind,details,material,qty,link,created,model_id) VALUES(?,?,?,?,?,?,?,?,?)").bind(me.id, t.slice(0, 120), body.kind === "design" ? "design" : "print", String(body.details || "").slice(0, 4e3), String(body.material || "PLA").slice(0, 30), Math.max(1, Math.min(500, +body.qty || 1)), String(body.link || "").slice(0, 500), now(), +body.model || null).run();
      return J({ id: r.meta.last_row_id });
    }
    const q = me.admin ? "SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200" : "SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.user_id=? ORDER BY o.id DESC";
    const s = env.DB.prepare(q);
    return J({ orders: (await (me.admin ? s : s.bind(me.id)).all()).results });
  }
  if (a === "orders" && b) {
    const o = await env.DB.prepare("SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?").bind(+b).first();
    if (!o || !me.admin && o.user_id !== me.id) return E("Not found.", 404);
    if (c === "messages" && req.method === "POST") {
      const text = String(body.body || "").trim().slice(0, 2e3);
      if (!text) return E("Message is empty.");
      await env.DB.prepare("INSERT INTO messages(order_id,sender_id,is_admin,body,created) VALUES(?,?,?,?,?)").bind(o.id, me.id, me.admin ? 1 : 0, text, now()).run();
      const link = `${url.origin}/#/order/${o.id}`;
      if (me.admin) waitUntil(mail(env, o.email, `New message about "${o.title}"`, `${text}

Reply here: ${link}`));
      else if (env.NOTIFY_EMAIL) waitUntil(mail(env, env.NOTIFY_EMAIL, `Customer message on #${o.id}`, `${me.email}: ${text}

${link}`));
      return J({ ok: 1 });
    }
    if (c === "files" && req.method === "POST") {
      if (!env.FILES) return E("File storage is not set up yet.", 503);
      const name = decodeURIComponent(req.headers.get("x-filename") || "file").replace(/[\\/]/g, "_").slice(0, 120);
      if (!/\.(stl|3mf|obj|step|stp|png|jpe?g|webp|pdf|zip|gcode)$/i.test(name)) return E("This file type is not allowed.");
      if (+req.headers.get("content-length") > 26214400) return E("Max file size is 25 MB.");
      if ((await env.DB.prepare("SELECT COUNT(*) n FROM attachments WHERE order_id=?").bind(o.id).first()).n >= 10) return E("Max 10 files per request.");
      const buf = await req.arrayBuffer();
      if (buf.byteLength > 26214400) return E("Max file size is 25 MB.");
      const key = `${o.id}/${rnd(8)}-${name}`;
      await env.FILES.put(key, buf);
      await env.DB.prepare("INSERT INTO attachments(order_id,user_id,name,size,key,created) VALUES(?,?,?,?,?,?)").bind(o.id, me.id, name, buf.byteLength, key, now()).run();
      return J({ ok: 1 });
    }
    if (c === "delete" && req.method === "POST") {
      if (!me.admin) return E("Not allowed.", 403);
      const ks = (await env.DB.prepare("SELECT key FROM attachments WHERE order_id=?").bind(o.id).all()).results;
      if (env.FILES && ks.length) await env.FILES.delete(ks.map((k) => k.key));
      await env.DB.batch([env.DB.prepare("DELETE FROM attachments WHERE order_id=?").bind(o.id), env.DB.prepare("DELETE FROM messages WHERE order_id=?").bind(o.id), env.DB.prepare("DELETE FROM orders WHERE id=?").bind(o.id)]);
      return J({ ok: 1 });
    }
    if (c === "status" && req.method === "POST") {
      if (!me.admin) return E("Not allowed.", 403);
      if (!["new", "quoted", "designing", "printing", "shipped", "done"].includes(body.status)) return E("Bad status.");
      await env.DB.prepare("UPDATE orders SET status=? WHERE id=?").bind(body.status, o.id).run();
      if (env.RESEND_API_KEY) waitUntil(mail(env, o.email, `"${o.title}" is now ${body.status}`, `Status changed to: ${body.status}
${url.origin}/#/order/${o.id}`));
      return J({ ok: 1 });
    }
    const m = await env.DB.prepare("SELECT id,is_admin,body,created FROM messages WHERE order_id=? ORDER BY id").bind(o.id).all();
    let fl = { results: [] };
    try {
      fl = await env.DB.prepare("SELECT id,name,size FROM attachments WHERE order_id=? ORDER BY id").bind(o.id).all();
    } catch {
    }
    return J({ order: o, messages: m.results, files: fl.results, user: me });
  }
  return E("Not found.", 404);
}
__name(onRequest, "onRequest");

// ../.wrangler/tmp/pages-vSRPTh/functionsRoutes-0.016741955883663562.mjs
var routes = [
  {
    routePath: "/api/:route*",
    mountPath: "/api",
    method: "",
    middlewares: [],
    modules: [onRequest]
  }
];

// ../../../Users/Darius/AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/path-to-regexp/dist.es2015/index.js
function lexer(str) {
  var tokens = [];
  var i = 0;
  while (i < str.length) {
    var char = str[i];
    if (char === "*" || char === "+" || char === "?") {
      tokens.push({ type: "MODIFIER", index: i, value: str[i++] });
      continue;
    }
    if (char === "\\") {
      tokens.push({ type: "ESCAPED_CHAR", index: i++, value: str[i++] });
      continue;
    }
    if (char === "{") {
      tokens.push({ type: "OPEN", index: i, value: str[i++] });
      continue;
    }
    if (char === "}") {
      tokens.push({ type: "CLOSE", index: i, value: str[i++] });
      continue;
    }
    if (char === ":") {
      var name = "";
      var j = i + 1;
      while (j < str.length) {
        var code = str.charCodeAt(j);
        if (
          // `0-9`
          code >= 48 && code <= 57 || // `A-Z`
          code >= 65 && code <= 90 || // `a-z`
          code >= 97 && code <= 122 || // `_`
          code === 95
        ) {
          name += str[j++];
          continue;
        }
        break;
      }
      if (!name)
        throw new TypeError("Missing parameter name at ".concat(i));
      tokens.push({ type: "NAME", index: i, value: name });
      i = j;
      continue;
    }
    if (char === "(") {
      var count = 1;
      var pattern = "";
      var j = i + 1;
      if (str[j] === "?") {
        throw new TypeError('Pattern cannot start with "?" at '.concat(j));
      }
      while (j < str.length) {
        if (str[j] === "\\") {
          pattern += str[j++] + str[j++];
          continue;
        }
        if (str[j] === ")") {
          count--;
          if (count === 0) {
            j++;
            break;
          }
        } else if (str[j] === "(") {
          count++;
          if (str[j + 1] !== "?") {
            throw new TypeError("Capturing groups are not allowed at ".concat(j));
          }
        }
        pattern += str[j++];
      }
      if (count)
        throw new TypeError("Unbalanced pattern at ".concat(i));
      if (!pattern)
        throw new TypeError("Missing pattern at ".concat(i));
      tokens.push({ type: "PATTERN", index: i, value: pattern });
      i = j;
      continue;
    }
    tokens.push({ type: "CHAR", index: i, value: str[i++] });
  }
  tokens.push({ type: "END", index: i, value: "" });
  return tokens;
}
__name(lexer, "lexer");
function parse(str, options) {
  if (options === void 0) {
    options = {};
  }
  var tokens = lexer(str);
  var _a = options.prefixes, prefixes = _a === void 0 ? "./" : _a, _b = options.delimiter, delimiter = _b === void 0 ? "/#?" : _b;
  var result = [];
  var key = 0;
  var i = 0;
  var path = "";
  var tryConsume = /* @__PURE__ */ __name(function(type) {
    if (i < tokens.length && tokens[i].type === type)
      return tokens[i++].value;
  }, "tryConsume");
  var mustConsume = /* @__PURE__ */ __name(function(type) {
    var value2 = tryConsume(type);
    if (value2 !== void 0)
      return value2;
    var _a2 = tokens[i], nextType = _a2.type, index = _a2.index;
    throw new TypeError("Unexpected ".concat(nextType, " at ").concat(index, ", expected ").concat(type));
  }, "mustConsume");
  var consumeText = /* @__PURE__ */ __name(function() {
    var result2 = "";
    var value2;
    while (value2 = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")) {
      result2 += value2;
    }
    return result2;
  }, "consumeText");
  var isSafe = /* @__PURE__ */ __name(function(value2) {
    for (var _i = 0, delimiter_1 = delimiter; _i < delimiter_1.length; _i++) {
      var char2 = delimiter_1[_i];
      if (value2.indexOf(char2) > -1)
        return true;
    }
    return false;
  }, "isSafe");
  var safePattern = /* @__PURE__ */ __name(function(prefix2) {
    var prev = result[result.length - 1];
    var prevText = prefix2 || (prev && typeof prev === "string" ? prev : "");
    if (prev && !prevText) {
      throw new TypeError('Must have text between two parameters, missing text after "'.concat(prev.name, '"'));
    }
    if (!prevText || isSafe(prevText))
      return "[^".concat(escapeString(delimiter), "]+?");
    return "(?:(?!".concat(escapeString(prevText), ")[^").concat(escapeString(delimiter), "])+?");
  }, "safePattern");
  while (i < tokens.length) {
    var char = tryConsume("CHAR");
    var name = tryConsume("NAME");
    var pattern = tryConsume("PATTERN");
    if (name || pattern) {
      var prefix = char || "";
      if (prefixes.indexOf(prefix) === -1) {
        path += prefix;
        prefix = "";
      }
      if (path) {
        result.push(path);
        path = "";
      }
      result.push({
        name: name || key++,
        prefix,
        suffix: "",
        pattern: pattern || safePattern(prefix),
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    var value = char || tryConsume("ESCAPED_CHAR");
    if (value) {
      path += value;
      continue;
    }
    if (path) {
      result.push(path);
      path = "";
    }
    var open = tryConsume("OPEN");
    if (open) {
      var prefix = consumeText();
      var name_1 = tryConsume("NAME") || "";
      var pattern_1 = tryConsume("PATTERN") || "";
      var suffix = consumeText();
      mustConsume("CLOSE");
      result.push({
        name: name_1 || (pattern_1 ? key++ : ""),
        pattern: name_1 && !pattern_1 ? safePattern(prefix) : pattern_1,
        prefix,
        suffix,
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    mustConsume("END");
  }
  return result;
}
__name(parse, "parse");
function match(str, options) {
  var keys = [];
  var re = pathToRegexp(str, keys, options);
  return regexpToFunction(re, keys, options);
}
__name(match, "match");
function regexpToFunction(re, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.decode, decode = _a === void 0 ? function(x) {
    return x;
  } : _a;
  return function(pathname) {
    var m = re.exec(pathname);
    if (!m)
      return false;
    var path = m[0], index = m.index;
    var params = /* @__PURE__ */ Object.create(null);
    var _loop_1 = /* @__PURE__ */ __name(function(i2) {
      if (m[i2] === void 0)
        return "continue";
      var key = keys[i2 - 1];
      if (key.modifier === "*" || key.modifier === "+") {
        params[key.name] = m[i2].split(key.prefix + key.suffix).map(function(value) {
          return decode(value, key);
        });
      } else {
        params[key.name] = decode(m[i2], key);
      }
    }, "_loop_1");
    for (var i = 1; i < m.length; i++) {
      _loop_1(i);
    }
    return { path, index, params };
  };
}
__name(regexpToFunction, "regexpToFunction");
function escapeString(str) {
  return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
__name(escapeString, "escapeString");
function flags(options) {
  return options && options.sensitive ? "" : "i";
}
__name(flags, "flags");
function regexpToRegexp(path, keys) {
  if (!keys)
    return path;
  var groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
  var index = 0;
  var execResult = groupsRegex.exec(path.source);
  while (execResult) {
    keys.push({
      // Use parenthesized substring match if available, index otherwise
      name: execResult[1] || index++,
      prefix: "",
      suffix: "",
      modifier: "",
      pattern: ""
    });
    execResult = groupsRegex.exec(path.source);
  }
  return path;
}
__name(regexpToRegexp, "regexpToRegexp");
function arrayToRegexp(paths, keys, options) {
  var parts = paths.map(function(path) {
    return pathToRegexp(path, keys, options).source;
  });
  return new RegExp("(?:".concat(parts.join("|"), ")"), flags(options));
}
__name(arrayToRegexp, "arrayToRegexp");
function stringToRegexp(path, keys, options) {
  return tokensToRegexp(parse(path, options), keys, options);
}
__name(stringToRegexp, "stringToRegexp");
function tokensToRegexp(tokens, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.strict, strict = _a === void 0 ? false : _a, _b = options.start, start = _b === void 0 ? true : _b, _c = options.end, end = _c === void 0 ? true : _c, _d = options.encode, encode = _d === void 0 ? function(x) {
    return x;
  } : _d, _e = options.delimiter, delimiter = _e === void 0 ? "/#?" : _e, _f = options.endsWith, endsWith = _f === void 0 ? "" : _f;
  var endsWithRe = "[".concat(escapeString(endsWith), "]|$");
  var delimiterRe = "[".concat(escapeString(delimiter), "]");
  var route = start ? "^" : "";
  for (var _i = 0, tokens_1 = tokens; _i < tokens_1.length; _i++) {
    var token = tokens_1[_i];
    if (typeof token === "string") {
      route += escapeString(encode(token));
    } else {
      var prefix = escapeString(encode(token.prefix));
      var suffix = escapeString(encode(token.suffix));
      if (token.pattern) {
        if (keys)
          keys.push(token);
        if (prefix || suffix) {
          if (token.modifier === "+" || token.modifier === "*") {
            var mod = token.modifier === "*" ? "?" : "";
            route += "(?:".concat(prefix, "((?:").concat(token.pattern, ")(?:").concat(suffix).concat(prefix, "(?:").concat(token.pattern, "))*)").concat(suffix, ")").concat(mod);
          } else {
            route += "(?:".concat(prefix, "(").concat(token.pattern, ")").concat(suffix, ")").concat(token.modifier);
          }
        } else {
          if (token.modifier === "+" || token.modifier === "*") {
            throw new TypeError('Can not repeat "'.concat(token.name, '" without a prefix and suffix'));
          }
          route += "(".concat(token.pattern, ")").concat(token.modifier);
        }
      } else {
        route += "(?:".concat(prefix).concat(suffix, ")").concat(token.modifier);
      }
    }
  }
  if (end) {
    if (!strict)
      route += "".concat(delimiterRe, "?");
    route += !options.endsWith ? "$" : "(?=".concat(endsWithRe, ")");
  } else {
    var endToken = tokens[tokens.length - 1];
    var isEndDelimited = typeof endToken === "string" ? delimiterRe.indexOf(endToken[endToken.length - 1]) > -1 : endToken === void 0;
    if (!strict) {
      route += "(?:".concat(delimiterRe, "(?=").concat(endsWithRe, "))?");
    }
    if (!isEndDelimited) {
      route += "(?=".concat(delimiterRe, "|").concat(endsWithRe, ")");
    }
  }
  return new RegExp(route, flags(options));
}
__name(tokensToRegexp, "tokensToRegexp");
function pathToRegexp(path, keys, options) {
  if (path instanceof RegExp)
    return regexpToRegexp(path, keys);
  if (Array.isArray(path))
    return arrayToRegexp(path, keys, options);
  return stringToRegexp(path, keys, options);
}
__name(pathToRegexp, "pathToRegexp");

// ../../../Users/Darius/AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/wrangler/templates/pages-template-worker.ts
var escapeRegex = /[.+?^${}()|[\]\\]/g;
function getOriginalPathPrefix(requestPath, normalizedPrefix) {
  let end = 0;
  for (let index = 0; index < normalizedPrefix.length; index++) {
    end++;
    if (normalizedPrefix[index] === "/") {
      while (requestPath[end] === "/") {
        end++;
      }
    }
  }
  return requestPath.slice(0, end);
}
__name(getOriginalPathPrefix, "getOriginalPathPrefix");
function* executeRequest(request) {
  const requestPath = new URL(request.url).pathname;
  const normalizedRequestPath = requestPath.replace(/\/+/g, "/");
  for (const route of [...routes].reverse()) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath) || routeMatcher(normalizedRequestPath);
    const originalMountMatch = mountMatcher(requestPath);
    const mountMatchResult = originalMountMatch || mountMatcher(normalizedRequestPath);
    if (matchResult && mountMatchResult) {
      const path = originalMountMatch ? originalMountMatch.path : getOriginalPathPrefix(requestPath, mountMatchResult.path);
      for (const handler of route.middlewares.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path
        };
      }
    }
  }
  for (const route of routes) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: true
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult && route.modules.length) {
      for (const handler of route.modules.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: matchResult.path
        };
      }
      break;
    }
  }
}
__name(executeRequest, "executeRequest");
var pages_template_worker_default = {
  async fetch(originalRequest, env, workerContext) {
    let request = originalRequest;
    const handlerIterator = executeRequest(request);
    let data = {};
    let isFailOpen = false;
    const next = /* @__PURE__ */ __name(async (input, init) => {
      if (input !== void 0) {
        let url = input;
        if (typeof input === "string") {
          url = new URL(input, request.url).toString();
        }
        request = new Request(url, init);
      }
      const result = handlerIterator.next();
      if (result.done === false) {
        const { handler, params, path } = result.value;
        const context = {
          request: new Request(request.clone()),
          functionPath: path,
          next,
          params,
          get data() {
            return data;
          },
          set data(value) {
            if (typeof value !== "object" || value === null) {
              throw new Error("context.data must be an object");
            }
            data = value;
          },
          env,
          waitUntil: workerContext.waitUntil.bind(workerContext),
          passThroughOnException: /* @__PURE__ */ __name(() => {
            isFailOpen = true;
          }, "passThroughOnException")
        };
        const response = await handler(context);
        if (!(response instanceof Response)) {
          throw new Error("Your Pages function should return a Response");
        }
        return cloneResponse(response);
      } else if ("ASSETS") {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      } else {
        const response = await fetch(request);
        return cloneResponse(response);
      }
    }, "next");
    try {
      return await next();
    } catch (error) {
      if (isFailOpen) {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      }
      throw error;
    }
  }
};
var cloneResponse = /* @__PURE__ */ __name((response) => (
  // https://fetch.spec.whatwg.org/#null-body-status
  new Response(
    [101, 204, 205, 304].includes(response.status) ? null : response.body,
    response
  )
), "cloneResponse");
export {
  pages_template_worker_default as default
};
