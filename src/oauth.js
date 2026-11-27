// OAuth provider integration follows Cloudflare's MIT-licensed workers-oauth-provider
// consent and upstream sign-in examples. GitHub is used for identity only.
import OAuthProvider from "@cloudflare/workers-oauth-provider";

export const OAUTH_PATH = "/mcp-oauth";
const ORIGIN = "https://telegram-notification-mcp.dvson-dev.workers.dev";
const RESOURCE = ORIGIN + OAUTH_PATH;
const CALLBACK = ORIGIN + "/callback";
const SCOPE = "telegram:publish";
const USER_ID = 106802443;
const USER_LOGIN = "kphayx";

export function isAllowedIdentity(user) {
  return user?.id === USER_ID && typeof user.login === "string" &&
    user.login.toLowerCase() === USER_LOGIN;
}

export function isAuthorizedGrant(ctx) {
  return isAllowedIdentity({ id: ctx.props?.githubId, login: ctx.props?.githubLogin }) &&
    ctx.auth?.userId === "github-" + USER_ID &&
    Array.isArray(ctx.auth.scope) && ctx.auth.scope.includes(SCOPE);
}

function escape(value) {
  return String(value).replace(/[&<>"']/g, char => "&#" + char.charCodeAt(0) + ";");
}

function safeHeaders(headers = new Headers()) {
  headers.set("Cache-Control", "no-store");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  return headers;
}

function redirect(location, headers = new Headers()) {
  headers.set("Location", location);
  return new Response(null, { status: 302, headers: safeHeaders(headers) });
}

function deny(original, headers) {
  const url = new URL(original.redirectUri);
  url.searchParams.set("error", "access_denied");
  if (original.state) url.searchParams.set("state", original.state);
  if (original.issuer) url.searchParams.set("iss", original.issuer);
  return redirect(url.href, headers);
}

function configured(env) {
  return Boolean(env.OAUTH_KV && env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET);
}

async function authorize(request, env) {
  const oauth = env.OAUTH_PROVIDER;
  if (request.method === "GET") {
    const original = await oauth.parseAuthRequest(request);
    const details = await oauth.describeConsent(original);
    const consent = await oauth.beginConsent(original);
    const domain = details.clientDomain ? escape(details.clientDomain) : "Self-registered client; name not verified";
    const warning = details.redirectIsLoopback ? "<p>Local app: continue only if you started this login.</p>" : "";
    const html = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Telegram Notification</title>' +
      '<h1>Authorize Telegram Notification</h1><p>Client: <strong>' + escape(details.clientName) +
      '</strong></p><p>Client domain: ' + domain + '</p><p>Redirect host: ' + escape(details.redirectHost) +
      '</p><p>Permission: send messages to the configured Telegram recipient (' + SCOPE + ').</p>' +
      warning + '<form method="post" action="/authorize"><input type="hidden" name="handle" value="' +
      escape(consent.handle) + '"><button name="decision" value="approve">Continue with GitHub</button> ' +
      '<button name="decision" value="deny">Deny</button></form></html>';
    const headers = safeHeaders(consent.headers);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(html, { headers });
  }
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const form = await request.formData();
  const handle = form.get("handle");
  if (typeof handle !== "string" || !handle) return new Response("Invalid consent", { status: 400 });
  if (form.get("decision") !== "approve") {
    const rejected = await oauth.denyConsent(request, handle);
    return new Response(null, { status: 302, headers: safeHeaders(rejected.headers) });
  }
  const approved = await oauth.approveConsent(request, handle, { scope: [SCOPE] });
  const verifier = crypto.randomUUID() + crypto.randomUUID();
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const challenge = btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const upstream = await oauth.beginUpstream(approved.request, { data: { verifier }, headers: approved.headers });
  const url = new URL("https://github.com/login/oauth/authorize");
  url.search = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    redirect_uri: CALLBACK,
    scope: "read:user",
    state: upstream.state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  return redirect(url.href, upstream.headers);
}

async function finish(request, env) {
  const oauth = env.OAUTH_PROVIDER;
  const { request: original, data, headers } = await oauth.finishUpstream(request);
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  if (!code || url.searchParams.has("error") || typeof data?.verifier !== "string") return deny(original, headers);
  try {
    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET,
        code, redirect_uri: CALLBACK, code_verifier: data.verifier,
      }),
      redirect: "error",
    });
    const token = await tokenResponse.json();
    if (!tokenResponse.ok || typeof token.access_token !== "string") return deny(original, headers);
    const profileResponse = await fetch("https://api.github.com/user", {
      headers: { Accept: "application/vnd.github+json", Authorization: "Bearer " + token.access_token,
        "User-Agent": "telegram-notification-mcp", "X-GitHub-Api-Version": "2022-11-28" },
      redirect: "error",
    });
    const profile = await profileResponse.json();
    if (!profileResponse.ok || !isAllowedIdentity(profile)) return deny(original, headers);
    const result = await oauth.completeAuthorization({
      request: original, userId: "github-" + USER_ID, metadata: { label: "KphayX" },
      scope: [SCOPE], props: { githubId: profile.id, githubLogin: profile.login },
    });
    return redirect(result.redirectTo, headers);
  } catch {
    return deny(original, headers);
  }
}

export function createOAuthRouter(handleMcp) {
  return new OAuthProvider({
    apiRoute: OAUTH_PATH,
    apiHandler: {
      async fetch(request, env, ctx) {
        if (!configured(env)) return new Response("OAuth is not configured", { status: 503 });
        if (new URL(request.url).pathname !== OAUTH_PATH) return new Response("Not found", { status: 404 });
        if (!isAuthorizedGrant(ctx)) return new Response("Forbidden", { status: 403 });
        return handleMcp(request, env, ctx);
      },
    },
    defaultHandler: {
      async fetch(request, env) {
        const path = new URL(request.url).pathname;
        if (path !== "/authorize" && path !== "/callback") return new Response("Not found", { status: 404 });
        if (!configured(env)) return new Response("OAuth setup incomplete", { status: 503, headers: safeHeaders() });
        try {
          if (path === "/authorize") return await authorize(request, env);
          if (request.method !== "GET") return new Response("Method not allowed", { status: 405 });
          return await finish(request, env);
        } catch {
          return new Response("Authorization could not be completed. Start again from your MCP client.", { status: 400, headers: safeHeaders() });
        }
      },
    },
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/token",
    clientRegistrationEndpoint: "/register",
    clientIdMetadataDocumentEnabled: true,
    scopesSupported: [SCOPE, "offline_access"],
    requiredScopes: [SCOPE],
    accessTokenTTL: 3600,
    refreshTokenTTL: 7 * 86400,
    clientRegistrationTTL: 90 * 86400,
    resourceMetadata: { resource: RESOURCE, authorization_servers: [ORIGIN], resource_name: "Telegram Notification" },
  });
}
