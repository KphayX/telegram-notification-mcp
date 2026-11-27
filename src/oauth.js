// OAuth provider integration follows Cloudflare's MIT-licensed workers-oauth-provider
// consent and upstream sign-in examples. GitHub is used for identity only.
import OAuthProvider from "@cloudflare/workers-oauth-provider";

export const OAUTH_PATH = "/mcp-oauth";
const ORIGIN = "https://telegram-notification-mcp.dvson-dev.workers.dev";
const RESOURCE = ORIGIN + OAUTH_PATH;
const CALLBACK = ORIGIN + "/callback";
import { SCOPE, USER_ID, isAllowedIdentity, isAuthorizedGrant } from "./oauth-identity.js";

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => "&#" + char.charCodeAt(0) + ";");
}

// Chromium applies form-action to POST redirects too. Allow only the known OAuth origins.
function safeHeaders(headers = new Headers()) {
  headers.set("Cache-Control", "no-store");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Content-Security-Policy", "default-src 'none'; form-action 'self' https://github.com https://chatgpt.com; frame-ancestors 'none'; base-uri 'none'");
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

// Report only fixed diagnostic codes; never echo tokens, cookies, URLs or raw exceptions.
class OAuthFlowError extends Error {
  constructor(stage, cause) {
    super("OAuth flow failed");
    this.stage = stage;
    const description = typeof cause?.description === "string" ? cause.description : "";
    this.code = description.includes("not started in this browser") ||
      description.includes("different browser session") ? "BROWSER_SESSION_MISMATCH" :
      description.includes("expired or was already used") ? "TRANSACTION_NOT_FOUND" :
      description.includes("Missing transaction handle") || description.includes("Missing state parameter") ? "TRANSACTION_MISSING" :
      description.includes("Approved scopes must") ? "INVALID_SCOPE" :
      "REQUEST_FAILED";
  }
}

async function flowStep(stage, action) {
  try {
    return await action();
  } catch (error) {
    throw new OAuthFlowError(stage, error);
  }
}

function flowErrorResponse(error) {
  const stage = error instanceof OAuthFlowError ? error.stage : "REQUEST";
  const code = error instanceof OAuthFlowError ? error.code : "REQUEST_FAILED";
  const advice = code === "BROWSER_SESSION_MISMATCH" ?
    "Allow first-party cookies for this site and restart the connection in the same browser." :
    code === "TRANSACTION_NOT_FOUND" ?
      "The session expired, was already used, or is not yet visible in KV. Restart from ChatGPT; do not reuse the old page." :
      "Restart the connection from your MCP client.";
  return new Response(`Authorization failed [${stage}:${code}]. ${advice}`, {
    status: 400,
    headers: safeHeaders(),
  });
}

async function authorize(request, env) {
  const oauth = env.OAUTH_PROVIDER;
  if (request.method === "GET") {
    if (!new URL(request.url).searchParams.has("client_id")) {
      return new Response("Start authorization from your MCP client. This URL cannot be opened directly. [AUTHORIZE:CLIENT_ID_MISSING]", { status: 400, headers: safeHeaders() });
    }
    const original = await flowStep("PARSE_REQUEST", () => oauth.parseAuthRequest(request));
    const details = await flowStep("CLIENT_METADATA", () => oauth.describeConsent(original));
    const consent = await flowStep("BEGIN_CONSENT", () => oauth.beginConsent(original));
    const domain = details.clientDomain ? escapeHtml(details.clientDomain) : "Self-registered client; name not verified";
    const warning = details.redirectIsLoopback ? "<p>Local app: continue only if you started this login.</p>" : "";
    const html = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Telegram Notification</title>' +
      '<h1>Authorize Telegram Notification</h1><p>Client: <strong>' + escapeHtml(details.clientName) +
      '</strong></p><p>Client domain: ' + domain + '</p><p>Redirect host: ' + escapeHtml(details.redirectHost) +
      '</p><p>Permission: send messages to the configured Telegram recipient (' + SCOPE + ').</p>' +
      warning + '<form method="post" action="/authorize"><input type="hidden" name="handle" value="' +
      escapeHtml(consent.handle) + '"><button name="decision" value="approve">Continue with GitHub</button> ' +
      '<button name="decision" value="deny">Deny</button></form></html>';
    const headers = safeHeaders(consent.headers);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(html, { headers });
  }
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const form = await flowStep("CONSENT_FORM", () => request.formData());
  const handle = form.get("handle");
  if (typeof handle !== "string" || !handle) return new Response("Invalid consent", { status: 400 });
  if (form.get("decision") !== "approve") {
    const rejected = await flowStep("DENY_CONSENT", () => oauth.denyConsent(request, handle));
    return new Response(null, { status: 302, headers: safeHeaders(rejected.headers) });
  }
  const approved = await flowStep("APPROVE_CONSENT", () => oauth.approveConsent(request, handle, { scope: [SCOPE] }));
  const verifier = crypto.randomUUID() + crypto.randomUUID();
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const challenge = btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const upstream = await flowStep("BEGIN_GITHUB", () => oauth.beginUpstream(approved.request, { data: { verifier }, headers: approved.headers }));
  const url = new URL("https://github.com/login/oauth/authorize");
  url.search = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID.trim(),
    redirect_uri: CALLBACK,
    scope: "read:user",
    state: upstream.state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  return redirect(url.href, upstream.headers);
}

// Record only fixed diagnostic enums, with no credential, identity, URL or session data.
// Short TTL and unique keys avoid overwriting a concurrent callback.
async function recordCallbackOutcome(env, outcome) {
  try {
    await env.OAUTH_KV.put(`diagnostic:callback:${crypto.randomUUID()}`, outcome, {
      expirationTtl: 1800,
      metadata: { outcome, at: new Date().toISOString() },
    });
  } catch {
    // Diagnostics must not block authentication.
  }
}

async function finish(request, env) {
  const oauth = env.OAUTH_PROVIDER;
  let resumed;
  try {
    resumed = await flowStep("GITHUB_CALLBACK", () => oauth.finishUpstream(request));
  } catch (error) {
    await recordCallbackOutcome(env, error instanceof OAuthFlowError ? `CALLBACK_${error.code}` : "CALLBACK_FAILED");
    throw error;
  }
  const { request: original, data, headers } = resumed;
  const reject = async (outcome) => {
    await recordCallbackOutcome(env, outcome);
    return deny(original, headers);
  };
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  if (!code || url.searchParams.has("error") || typeof data?.verifier !== "string") {
    return reject("GITHUB_CODE_MISSING_OR_DENIED");
  }
  let stage = "GITHUB_TOKEN_EXCHANGE";
  try {
    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "telegram-notification-mcp" },
      body: new URLSearchParams({
        client_id: env.GITHUB_CLIENT_ID.trim(), client_secret: env.GITHUB_CLIENT_SECRET.trim(),
        code, redirect_uri: CALLBACK, code_verifier: data.verifier,
      }),
      redirect: "error",
    });
    const token = await tokenResponse.json();
    if (!tokenResponse.ok || typeof token.access_token !== "string") {
      const known = {
        incorrect_client_credentials: "GITHUB_INCORRECT_CLIENT_CREDENTIALS",
        redirect_uri_mismatch: "GITHUB_REDIRECT_URI_MISMATCH",
        bad_verification_code: "GITHUB_BAD_VERIFICATION_CODE",
        unverified_user_email: "GITHUB_UNVERIFIED_USER_EMAIL",
        incorrect_code_verifier: "GITHUB_INCORRECT_CODE_VERIFIER",
        bad_code_verifier: "GITHUB_BAD_CODE_VERIFIER",
      };
      return reject(Object.hasOwn(known, token.error) ? known[token.error] : "GITHUB_TOKEN_REJECTED");
    }
    stage = "GITHUB_PROFILE_FETCH";
    const profileResponse = await fetch("https://api.github.com/user", {
      headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token.access_token}`,
        "User-Agent": "telegram-notification-mcp", "X-GitHub-Api-Version": "2022-11-28" },
      redirect: "error",
    });
    if (!profileResponse.ok) return reject("GITHUB_PROFILE_REJECTED");
    const profile = await profileResponse.json();
    if (!isAllowedIdentity(profile)) return reject("GITHUB_IDENTITY_NOT_ALLOWED");
    stage = "MCP_GRANT_CREATE";
    const result = await oauth.completeAuthorization({
      request: original, userId: `github-${USER_ID}`, metadata: { label: "KphayX" },
      scope: [SCOPE], props: { githubId: profile.id, githubLogin: profile.login },
    });
    await recordCallbackOutcome(env, "MCP_GRANT_CREATED");
    return redirect(result.redirectTo, headers);
  } catch {
    return reject(`${stage}_FAILED`);
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
        } catch (error) {
          return flowErrorResponse(error);
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
