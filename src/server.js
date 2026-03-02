import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";

import express from "express";
import httpProxy from "http-proxy";
import * as tar from "tar";

// Migrate deprecated CLAWDBOT_* env vars → OPENCLAW_* so existing Railway deployments
// keep working. Users should update their Railway Variables to use the new names.
for (const suffix of ["PUBLIC_PORT", "STATE_DIR", "WORKSPACE_DIR", "GATEWAY_TOKEN", "CONFIG_PATH"]) {
  const oldKey = `CLAWDBOT_${suffix}`;
  const newKey = `OPENCLAW_${suffix}`;
  if (process.env[oldKey] && !process.env[newKey]) {
    process.env[newKey] = process.env[oldKey];
    console.warn(`[migration] Copied ${oldKey} → ${newKey}. Please rename this variable in your Railway settings.`);
  }
}

// Prefer Railway's injected PORT (so the public domain routing works), with an
// override via OPENCLAW_PUBLIC_PORT for non-Railway environments.
const PORT = Number.parseInt(
  process.env.PORT ??
  process.env.OPENCLAW_PUBLIC_PORT?.trim() ??
  "8080",
  10,
);

// State/workspace
// OpenClaw defaults to ~/.openclaw.
function defaultStateDir() {
  // Prefer Railway volume when present so config/workspace persists across restarts.
  try {
    if (fs.existsSync("/data")) return "/data/.openclaw";
  } catch {
    // ignore
  }
  return path.join(os.homedir(), ".openclaw");
}

function defaultWorkspaceDir() {
  // Keep workspace under the same persistent volume when available.
  try {
    if (fs.existsSync("/data")) return "/data/workspace";
  } catch {
    // ignore
  }
  return path.join(STATE_DIR, "workspace");
}

const STATE_DIR = process.env.OPENCLAW_STATE_DIR?.trim() || defaultStateDir();

const WORKSPACE_DIR =
  process.env.OPENCLAW_WORKSPACE_DIR?.trim() || defaultWorkspaceDir();

// Optional: import Codex CLI OAuth into OpenClaw auth store (headless-friendly).
// Provide the raw JSON of ~/.codex/auth.json via Railway Variables.
const CODEX_CLI_AUTH_JSON = process.env.OPENCLAW_CODEX_CLI_AUTH_JSON?.trim();
const CODEX_CLI_AUTH_B64 = process.env.OPENCLAW_CODEX_CLI_AUTH_B64?.trim();

// Optional: default model + thinking level bootstrap (applied only when config is missing).
// Falls back to openai/gpt-4o when using a plain OpenAI API key instead of Codex OAuth.
const BOOTSTRAP_DEFAULT_MODEL =
  process.env.OPENCLAW_BOOTSTRAP_DEFAULT_MODEL?.trim() ||
  (process.env.OPENAI_API_KEY?.trim() ? "openai/gpt-4o" : "openai-codex/gpt-5.3-codex");
const BOOTSTRAP_THINKING_DEFAULT =
  process.env.OPENCLAW_BOOTSTRAP_THINKING_DEFAULT?.trim() || "high";

// ---------------------------------------------------------------------------
// Public URL resolution (for gateway.remote.url)
// ---------------------------------------------------------------------------
// Railway injects RAILWAY_PUBLIC_DOMAIN on every deployment.
// Users can also set OPENCLAW_PUBLIC_URL explicitly in Railway Variables.
// This is CRITICAL: without a correct remote.url the Control UI's WebSocket
// connects to ws://localhost:PORT which fails in production (browser can't
// reach the server's loopback interface).
// ---------------------------------------------------------------------------
function resolvePublicUrl() {
  const explicit = process.env.OPENCLAW_PUBLIC_URL?.trim();
  if (explicit) return explicit.replace(/\/$/, "");

  // Railway primary domain (e.g. "myapp-production.up.railway.app")
  const railwayDomain = process.env.RAILWAY_PUBLIC_DOMAIN?.trim();
  if (railwayDomain) {
    const bare = railwayDomain.replace(/^https?:\/\//, "").replace(/\/$/, "");
    return `https://${bare}`;
  }

  // Railway static URL fallback
  const railwayStatic = process.env.RAILWAY_STATIC_URL?.trim();
  if (railwayStatic) return railwayStatic.replace(/\/$/, "");

  return null;
}

function parseBoolEnv(v) {
  if (typeof v !== "string") return undefined;
  const s = v.trim().toLowerCase();
  if (!s) return undefined;
  if (["1", "true", "yes", "y", "on"].includes(s)) return true;
  if (["0", "false", "no", "n", "off"].includes(s)) return false;
  return undefined;
}

// Protect /setup with a user-provided password.
const SETUP_PASSWORD = process.env.SETUP_PASSWORD?.trim();

// Optional: Protect the entire non-setup surface (/, /openclaw, WS upgrade, etc.)
// with HTTP Basic Auth. This is independent of the gateway token.
//
// - If OPENCLAW_HTTP_AUTH_PASSWORD is unset, no extra HTTP auth is required.
// - If enabled, /setup uses the same HTTP auth (single login for everything).
// - If disabled, /setup falls back to SETUP_PASSWORD (legacy behavior).
const HTTP_AUTH_USER = process.env.OPENCLAW_HTTP_AUTH_USER?.trim() || "openclaw";
const HTTP_AUTH_PASSWORD = process.env.OPENCLAW_HTTP_AUTH_PASSWORD?.trim();

// Optional: skip Control UI device identity + pairing when using shared-secret auth.
// This is a security downgrade. Only enable if you trust your network boundary
// (e.g. you have HTTP Basic Auth in front of the service).
const CONTROL_UI_ALLOW_INSECURE_AUTH = parseBoolEnv(process.env.OPENCLAW_CONTROL_UI_ALLOW_INSECURE_AUTH);

// Gateway admin token (protects OpenClaw gateway + Control UI).
// Must be stable across restarts. If not provided via env, persist it in the state dir.
function resolveGatewayToken() {
  const envTok = process.env.OPENCLAW_GATEWAY_TOKEN?.trim();
  if (envTok) return envTok;

  const tokenPath = path.join(STATE_DIR, "gateway.token");
  try {
    const existing = fs.readFileSync(tokenPath, "utf8").trim();
    if (existing) return existing;
  } catch {
    // ignore
  }

  const generated = crypto.randomBytes(32).toString("hex");
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(tokenPath, generated, { encoding: "utf8", mode: 0o600 });
  } catch {
    // best-effort
  }
  return generated;
}

const OPENCLAW_GATEWAY_TOKEN = resolveGatewayToken();
process.env.OPENCLAW_GATEWAY_TOKEN = OPENCLAW_GATEWAY_TOKEN;

// Where the gateway will listen internally (we proxy to it).
const INTERNAL_GATEWAY_PORT = Number.parseInt(process.env.INTERNAL_GATEWAY_PORT ?? "18789", 10);
const INTERNAL_GATEWAY_HOST = process.env.INTERNAL_GATEWAY_HOST ?? "127.0.0.1";
const GATEWAY_TARGET = `http://${INTERNAL_GATEWAY_HOST}:${INTERNAL_GATEWAY_PORT}`;

// Always run the built-from-source CLI entry directly to avoid PATH/global-install mismatches.
function resolveOpenclawEntry() {
  const explicit = process.env.OPENCLAW_ENTRY?.trim();
  if (explicit) return explicit;

  // Dockerfile-based deployments clone/build OpenClaw into /openclaw.
  const dockerPath = "/openclaw/dist/entry.js";
  try {
    if (fs.existsSync(dockerPath)) return dockerPath;
  } catch {
    // ignore
  }

  // Railpack/Nixpacks deployments should have `openclaw` installed as a dependency.
  try {
    const require = createRequire(import.meta.url);
    return require.resolve("openclaw/dist/entry.js");
  } catch {
    return dockerPath;
  }
}

const OPENCLAW_ENTRY = resolveOpenclawEntry();
const OPENCLAW_NODE = process.env.OPENCLAW_NODE?.trim() || "node";

function clawArgs(args) {
  return [OPENCLAW_ENTRY, ...args];
}

function resolveConfigCandidates() {
  const explicit = process.env.OPENCLAW_CONFIG_PATH?.trim();
  if (explicit) return [explicit];

  return [path.join(STATE_DIR, "openclaw.json")];
}

function configPath() {
  const candidates = resolveConfigCandidates();
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      // ignore
    }
  }
  // Default to canonical even if it doesn't exist yet.
  return candidates[0] || path.join(STATE_DIR, "openclaw.json");
}

function isConfigured() {
  try {
    return resolveConfigCandidates().some((candidate) => fs.existsSync(candidate));
  } catch {
    return false;
  }
}

function resolveCodexHome() {
  // OpenClaw’s Codex CLI integration uses CODEX_HOME (default: ~/.codex).
  // On Railway, prefer persisting it on the /data volume when available.
  const configured = process.env.CODEX_HOME?.trim();
  if (configured) return configured;
  if (fs.existsSync("/data")) return "/data/.codex";
  return path.join(os.homedir(), ".codex");
}

function tryParseCodexAuthJson() {
  const raw = CODEX_CLI_AUTH_JSON
    ? CODEX_CLI_AUTH_JSON
    : CODEX_CLI_AUTH_B64
      ? Buffer.from(CODEX_CLI_AUTH_B64, "base64").toString("utf8")
      : null;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    const tokens = parsed.tokens;
    if (!tokens || typeof tokens !== "object") return null;
    const access = tokens.access_token;
    const refresh = tokens.refresh_token;
    const accountId = tokens.account_id;
    if (typeof access !== "string" || !access) return null;
    if (typeof refresh !== "string" || !refresh) return null;
    return {
      access,
      refresh,
      accountId: typeof accountId === "string" && accountId ? accountId : undefined,
      raw,
    };
  } catch {
    return null;
  }
}

function ensureDir700(dir) {
  fs.mkdirSync(dir, { recursive: true });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    // best-effort
  }
}

function writeFile600(filename, content) {
  fs.writeFileSync(filename, content, { encoding: "utf8", mode: 0o600 });
}

function resolveDefaultAgentDir() {
  // Mirrors OpenClaw default agent dir logic: $OPENCLAW_STATE_DIR/agents/main/agent
  // (respects OPENCLAW_AGENT_DIR if set).
  const override = process.env.OPENCLAW_AGENT_DIR?.trim();
  if (override) return override;
  return path.join(STATE_DIR, "agents", "main", "agent");
}

function ensureAuthProfilesCodex(creds) {
  const agentDir = resolveDefaultAgentDir();
  ensureDir700(agentDir);
  const authPath = path.join(agentDir, "auth-profiles.json");

  let store = { version: 1, profiles: {} };
  try {
    if (fs.existsSync(authPath)) {
      const parsed = JSON.parse(fs.readFileSync(authPath, "utf8"));
      if (parsed && typeof parsed === "object") {
        store = {
          version: typeof parsed.version === "number" ? parsed.version : 1,
          profiles: parsed.profiles && typeof parsed.profiles === "object" ? parsed.profiles : {},
          ...(parsed.order && typeof parsed.order === "object" ? { order: parsed.order } : {}),
          ...(parsed.lastGood && typeof parsed.lastGood === "object" ? { lastGood: parsed.lastGood } : {}),
          ...(parsed.usageStats && typeof parsed.usageStats === "object" ? { usageStats: parsed.usageStats } : {}),
        };
      }
    }
  } catch {
    // ignore; overwrite with a fresh store below
  }

  // Expires: follow OpenClaw’s Codex CLI behavior (file mtime + ~1h). We set a short-ish expiry
  // so OpenClaw refreshes normally using the refresh token.
  const expires = Date.now() + 55 * 60 * 1000;
  store.profiles["openai-codex:default"] = {
    type: "oauth",
    provider: "openai-codex",
    access: creds.access,
    refresh: creds.refresh,
    expires,
    ...(creds.accountId ? { accountId: creds.accountId } : {}),
  };

  writeFile600(authPath, JSON.stringify(store, null, 2));
}

function bootstrapCodexCliAuth() {
  const creds = tryParseCodexAuthJson();
  if (!creds) return;

  // Persist Codex CLI auth.json so OpenClaw wizards/tools can reuse it too.
  const codexHome = resolveCodexHome();
  process.env.CODEX_HOME = codexHome;
  ensureDir700(codexHome);
  writeFile600(path.join(codexHome, "auth.json"), creds.raw);

  // Also write OpenClaw’s token sink so the provider can refresh/rotate deterministically.
  ensureAuthProfilesCodex(creds);
}

function bootstrapConfigIfMissing() {
  if (isConfigured()) return;

  const allowInsecureAuth =
    CONTROL_UI_ALLOW_INSECURE_AUTH ??
    (isHttpAuthEnabled() ? true : false);

  // Detect public URL so the Control UI WebSocket connects to the correct host.
  // Without this the browser tries ws://localhost:PORT which fails in production.
  const publicUrl = resolvePublicUrl();
  if (publicUrl) {
    console.log(`[bootstrap] public URL detected: ${publicUrl}`);
  } else {
    console.warn("[bootstrap] WARNING: no public URL detected (set RAILWAY_PUBLIC_DOMAIN or OPENCLAW_PUBLIC_URL). Control UI WebSocket may fail in production.");
  }

  // Build the remote block: always include the token; add url when resolvable.
  const remoteBlock = { token: OPENCLAW_GATEWAY_TOKEN };
  if (publicUrl) remoteBlock.url = publicUrl;

  // When OPENAI_API_KEY is present and no Codex OAuth is configured, use the
  // plain OpenAI provider. We must NOT put providers inside agents.defaults.model
  // (that key is invalid there) — instead they go at the top-level models.providers.
  const hasApiKey = Boolean(process.env.OPENAI_API_KEY?.trim());
  const hasCodexCreds = Boolean(CODEX_CLI_AUTH_JSON || CODEX_CLI_AUTH_B64);
  const useOpenAi = hasApiKey && !hasCodexCreds;

  // Use gpt-4o when falling back to API key, regardless of OPENCLAW_BOOTSTRAP_DEFAULT_MODEL
  // (which may be set to the Codex model that requires expired OAuth).
  const effectiveModel = useOpenAi ? "openai/gpt-4o" : BOOTSTRAP_DEFAULT_MODEL;

  const modelsBlock = useOpenAi ? {
    mode: "merge",
    providers: {
      openai: {
        api: "openai-completions",
        apiKey: "${OPENAI_API_KEY}",
        baseUrl: "https://api.openai.com/v1",
        models: [
          { id: "gpt-4o", name: "GPT-4o" },
          { id: "gpt-4o-mini", name: "GPT-4o Mini" },
          { id: "gpt-4.1", name: "GPT-4.1" },
        ],
      },
    },
  } : undefined;

  if (useOpenAi) {
    console.log("[bootstrap] OPENAI_API_KEY detected — using openai/gpt-4o as default model");
  }

  // Minimal config that matches how we launch the gateway.
  const payload = {
    gateway: {
      mode: "local",
      bind: "loopback",
      port: INTERNAL_GATEWAY_PORT,
      controlUi: { basePath: "/openclaw", ...(allowInsecureAuth ? { allowInsecureAuth: true } : {}) },
      auth: { mode: "token", token: OPENCLAW_GATEWAY_TOKEN },
      remote: remoteBlock,
    },
    agents: {
      defaults: {
        workspace: WORKSPACE_DIR,
        model: { primary: effectiveModel },
        thinkingDefault: BOOTSTRAP_THINKING_DEFAULT,
      },
    },
    ...(modelsBlock ? { models: modelsBlock } : {}),
  };

  try {
    fs.mkdirSync(path.dirname(configPath()), { recursive: true });
    writeFile600(configPath(), JSON.stringify(payload, null, 2));
    console.log(`[bootstrap] wrote config to ${configPath()} (model=${effectiveModel})`);
  } catch (err) {
    console.warn(`[bootstrap] failed to write config: ${String(err)}`);
  }
}

function migrateThinkingDefaultKey() {
  // One-time repair for earlier template builds that wrote:
  //   agents.defaults.model.thinkingDefault
  // which fails OpenClaw config validation. Correct location is:
  //   agents.defaults.thinkingDefault
  const cfgPath = configPath();
  try {
    if (!fs.existsSync(cfgPath)) return;
  } catch {
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  } catch {
    return;
  }
  if (!parsed || typeof parsed !== "object") return;

  const defaults = parsed.agents?.defaults;
  if (!defaults || typeof defaults !== "object") return;

  const model = defaults.model;
  if (!model || typeof model !== "object") return;

  if (!Object.prototype.hasOwnProperty.call(model, "thinkingDefault")) return;

  const legacy = model.thinkingDefault;
  // Prefer the correct key if it already exists; otherwise migrate the value.
  if (
    !Object.prototype.hasOwnProperty.call(defaults, "thinkingDefault") &&
    typeof legacy === "string" &&
    legacy
  ) {
    defaults.thinkingDefault = legacy;
  }

  try {
    delete model.thinkingDefault;
  } catch {
    // ignore
  }

  try {
    writeFile600(cfgPath, JSON.stringify(parsed, null, 2));
    console.log("[migration] Repaired agents.defaults.model.thinkingDefault -> agents.defaults.thinkingDefault");
  } catch (err) {
    console.warn(`[migration] Failed to repair thinkingDefault: ${String(err)}`);
  }
}

function maybeEnableControlUiAllowInsecureAuth() {
  // If requested (or inferred via HTTP Basic Auth), set:
  //   gateway.controlUi.allowInsecureAuth = true
  // so the Control UI can connect without device pairing.
  //
  // NOTE: this only affects the Control UI; the gateway still requires a valid token/password.
  const allowInsecureAuth =
    CONTROL_UI_ALLOW_INSECURE_AUTH ??
    (isHttpAuthEnabled() ? true : false);
  if (!allowInsecureAuth) return;

  const cfgPath = configPath();
  try {
    if (!fs.existsSync(cfgPath)) return;
  } catch {
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  } catch {
    // If the operator edited the config as JSON5, we can't safely patch it here.
    return;
  }
  if (!parsed || typeof parsed !== "object") return;

  const gateway = parsed.gateway && typeof parsed.gateway === "object" ? parsed.gateway : null;
  if (!gateway) return;
  const controlUi =
    gateway.controlUi && typeof gateway.controlUi === "object" ? gateway.controlUi : {};

  if (controlUi.allowInsecureAuth === true) return;
  controlUi.allowInsecureAuth = true;
  // Ensure the UI stays reachable at the expected path when operators open the bare domain.
  if (!controlUi.basePath) controlUi.basePath = "/openclaw";
  gateway.controlUi = controlUi;
  parsed.gateway = gateway;

  try {
    writeFile600(cfgPath, JSON.stringify(parsed, null, 2));
    console.log("[migration] Enabled gateway.controlUi.allowInsecureAuth (skips pairing for Control UI)");
  } catch (err) {
    console.warn(`[migration] Failed to enable allowInsecureAuth: ${String(err)}`);
  }
}

function maybeSyncGatewayPort() {
  // Ensure the config port matches where we actually run the gateway. This avoids
  // "Application failed to respond" situations when Railway changes the public
  // port and we move the internal gateway off the default.
  const cfgPath = configPath();
  try {
    if (!fs.existsSync(cfgPath)) return;
  } catch {
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  } catch {
    return;
  }
  if (!parsed || typeof parsed !== "object") return;

  const gateway = parsed.gateway && typeof parsed.gateway === "object" ? parsed.gateway : null;
  if (!gateway) return;

  const want = INTERNAL_GATEWAY_PORT;
  const have = gateway.port;
  if (have === want) return;

  gateway.port = want;
  parsed.gateway = gateway;

  try {
    writeFile600(cfgPath, JSON.stringify(parsed, null, 2));
    console.log("[migration] Synced gateway.port to INTERNAL_GATEWAY_PORT");
  } catch (err) {
    console.warn(`[migration] Failed to sync gateway.port: ${String(err)}`);
  }
}

function maybeSetWorkspaceDir() {
  // If the config was bootstrapped without onboarding, it may be missing
  // agents.defaults.workspace. That breaks long-lived state (memory).
  const cfgPath = configPath();
  try {
    if (!fs.existsSync(cfgPath)) return;
  } catch {
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  } catch {
    // If the operator edited the config as JSON5, we can't safely patch it here.
    return;
  }
  if (!parsed || typeof parsed !== "object") return;

  const agents = parsed.agents && typeof parsed.agents === "object" ? parsed.agents : null;
  if (!agents) return;
  const defaults =
    agents.defaults && typeof agents.defaults === "object" ? agents.defaults : {};
  if (typeof defaults.workspace === "string" && defaults.workspace.trim()) return;

  defaults.workspace = WORKSPACE_DIR;
  agents.defaults = defaults;
  parsed.agents = agents;

  try {
    writeFile600(cfgPath, JSON.stringify(parsed, null, 2));
    console.log("[migration] Set agents.defaults.workspace from OPENCLAW_WORKSPACE_DIR");
  } catch (err) {
    console.warn(`[migration] Failed to set agents.defaults.workspace: ${String(err)}`);
  }
}

// One-time migration: rename legacy config files to openclaw.json so existing
// deployments that still have the old filename on their volume keep working.
(function migrateLegacyConfigFile() {
  // If the operator explicitly chose a config path, do not rename files in STATE_DIR.
  if (process.env.OPENCLAW_CONFIG_PATH?.trim()) return;

  const canonical = path.join(STATE_DIR, "openclaw.json");
  if (fs.existsSync(canonical)) return;

  for (const legacy of ["clawdbot.json", "moltbot.json"]) {
    const legacyPath = path.join(STATE_DIR, legacy);
    try {
      if (fs.existsSync(legacyPath)) {
        fs.renameSync(legacyPath, canonical);
        console.log(`[migration] Renamed ${legacy} → openclaw.json`);
        return;
      }
    } catch (err) {
      console.warn(`[migration] Failed to rename ${legacy}: ${err}`);
    }
  }
})();

function maybeUpgradeTelegramDmPolicy() {
  // If the config has channels.telegram.dmPolicy = "pairing", upgrade it to "open"
  // so the deployed bot actually replies to all incoming DMs without requiring
  // manual pairing approval for every user.
  const cfgPath = configPath();
  try {
    if (!fs.existsSync(cfgPath)) return;
  } catch {
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  } catch {
    return;
  }
  if (!parsed || typeof parsed !== "object") return;

  const tg = parsed.channels?.telegram;
  if (!tg || typeof tg !== "object") return;
  if (tg.dmPolicy !== "pairing") return;

  tg.dmPolicy = "open";
  parsed.channels.telegram = tg;

  try {
    writeFile600(cfgPath, JSON.stringify(parsed, null, 2));
    console.log("[migration] Upgraded channels.telegram.dmPolicy: pairing → open (bot will now reply to all DMs)");
  } catch (err) {
    console.warn(`[migration] Failed to upgrade telegram dmPolicy: ${String(err)}`);
  }
}

function maybeSyncRemoteUrl() {
  // THE FIX for "WebSocket connection to ws://localhost:PORT failed" in production.
  //
  // When the gateway config has no remote.url (or has localhost), the OpenClaw
  // Control UI's browser-side code tries to open a WebSocket to localhost:PORT.
  // That works on a local machine but ALWAYS fails in production because the
  // browser cannot reach the server's loopback interface.
  //
  // This migration detects the real public URL (from Railway env vars or
  // OPENCLAW_PUBLIC_URL) and writes it into gateway.remote.url so the Control
  // UI WebSocket connects via the correct external hostname.
  const publicUrl = resolvePublicUrl();
  if (!publicUrl) return; // nothing to do without a resolved URL

  const cfgPath = configPath();
  try {
    if (!fs.existsSync(cfgPath)) return;
  } catch {
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  } catch {
    // Config may be JSON5; we can't safely patch it.
    return;
  }
  if (!parsed || typeof parsed !== "object") return;

  const gateway = parsed.gateway && typeof parsed.gateway === "object" ? parsed.gateway : null;
  if (!gateway) return;

  const remote = gateway.remote && typeof gateway.remote === "object" ? gateway.remote : {};
  const currentUrl = remote.url;

  // Only update if the URL is missing or still pointing at localhost.
  const isLocalhost = !currentUrl ||
    currentUrl.includes("localhost") ||
    currentUrl.includes("127.0.0.1") ||
    currentUrl.includes("0.0.0.0");

  if (!isLocalhost && currentUrl === publicUrl) return; // already correct

  if (!isLocalhost && currentUrl && currentUrl !== publicUrl) {
    // There's already a non-localhost URL set. Don't override it — the operator
    // may have set a custom domain. Just log a notice.
    console.log(`[migration] gateway.remote.url already set to ${currentUrl} (public URL: ${publicUrl}). Skipping auto-update.`);
    return;
  }

  remote.url = publicUrl;
  gateway.remote = remote;
  parsed.gateway = gateway;

  try {
    writeFile600(cfgPath, JSON.stringify(parsed, null, 2));
    console.log(`[migration] Set gateway.remote.url = ${publicUrl} (fixes WebSocket in production)`);
  } catch (err) {
    console.warn(`[migration] Failed to set gateway.remote.url: ${String(err)}`);
  }
}

function maybeFixInvalidProvidersKey() {
  // EMERGENCY FIX: a previous deploy incorrectly placed a "providers" key inside
  // agents.defaults.model. OpenClaw's config schema does NOT allow that key there
  // (it lives at top-level models.providers). The bad key causes:
  //   "Config invalid: agents.defaults.model: Unrecognized key: providers"
  // which makes the gateway exit with code=1 immediately on every boot.
  // This migration removes it so the gateway can start normally.
  const cfgPath = configPath();
  try {
    if (!fs.existsSync(cfgPath)) return;
  } catch {
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  } catch {
    return;
  }
  if (!parsed || typeof parsed !== "object") return;

  const model = parsed.agents?.defaults?.model;
  if (!model || typeof model !== "object") return;
  if (!Object.prototype.hasOwnProperty.call(model, "providers")) return;

  delete model.providers;

  try {
    writeFile600(cfgPath, JSON.stringify(parsed, null, 2));
    console.log("[migration] Removed invalid agents.defaults.model.providers key (gateway can now start)");
  } catch (err) {
    console.warn(`[migration] Failed to remove invalid providers key: ${String(err)}`);
  }
}

function maybeRegisterOpenAiProvider() {
  // The bot receives messages but never replies when the configured model
  // (openai-codex/gpt-5.3-codex) needs Codex OAuth that has expired.
  //
  // If OPENAI_API_KEY is set in env, this migration:
  //   1. Registers it under models.providers.openai (the correct top-level path)
  //   2. Switches agents.defaults.model.primary to openai/gpt-4o (works with API key)
  //
  // This makes the bot reply using the standard OpenAI API — no Codex OAuth needed.
  const apiKey = process.env.OPENAI_API_KEY?.trim();
  if (!apiKey) return; // nothing to do without a key

  const cfgPath = configPath();
  try {
    if (!fs.existsSync(cfgPath)) return;
  } catch {
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  } catch {
    return; // JSON5 or corrupt — skip
  }
  if (!parsed || typeof parsed !== "object") return;

  // Only register if not already present (avoid overwriting user customisation).
  const existingProviders = parsed.models?.providers;
  if (existingProviders && typeof existingProviders === "object" && existingProviders.openai) {
    return; // already configured
  }

  // Write models.providers.openai at top level.
  if (!parsed.models || typeof parsed.models !== "object") parsed.models = {};
  if (!parsed.models.providers || typeof parsed.models.providers !== "object") {
    parsed.models.providers = {};
  }
  parsed.models.mode = parsed.models.mode || "merge";
  parsed.models.providers.openai = {
    api: "openai-completions",
    apiKey: "${OPENAI_API_KEY}",
    baseUrl: "https://api.openai.com/v1",
    models: [
      { id: "gpt-4o", name: "GPT-4o" },
      { id: "gpt-4o-mini", name: "GPT-4o Mini" },
      { id: "gpt-4.1", name: "GPT-4.1" },
    ],
  };

  // Switch default model to gpt-4o if it's still pointing at Codex.
  const defaults = parsed.agents?.defaults;
  if (defaults && typeof defaults === "object") {
    const model = defaults.model && typeof defaults.model === "object" ? defaults.model : {};
    const primary = model.primary || "";
    if (!primary || primary.startsWith("openai-codex/")) {
      model.primary = "openai/gpt-4o";
      defaults.model = model;
      if (!parsed.agents) parsed.agents = {};
      parsed.agents.defaults = defaults;
    }
  }

  try {
    writeFile600(cfgPath, JSON.stringify(parsed, null, 2));
    console.log("[migration] Registered OPENAI_API_KEY as models.providers.openai and set default model to openai/gpt-4o (bot will now reply)");
  } catch (err) {
    console.warn(`[migration] Failed to register OpenAI provider: ${String(err)}`);
  }
}

function maybeConfigureTelegramFromEnv() {
  // If TELEGRAM_BOT_TOKEN is set in the Railway environment, write it into the
  // OpenClaw config so the Telegram channel works without going through the /setup UI.
  // This is the most robust headless method — it persists across redeploys and
  // doesn't require browser auth.
  const botToken = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (!botToken) return;

  const cfgPath = configPath();
  try {
    if (!fs.existsSync(cfgPath)) return;
  } catch {
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  } catch {
    return;
  }
  if (!parsed || typeof parsed !== "object") return;

  // Don't overwrite if already configured with the same token.
  const existing = parsed.channels?.telegram;
  if (existing && typeof existing === "object" && existing.botToken === botToken && existing.enabled) {
    return;
  }

  if (!parsed.channels || typeof parsed.channels !== "object") parsed.channels = {};
  parsed.channels.telegram = {
    enabled: true,
    dmPolicy: "open",
    botToken,
    groupPolicy: "allowlist",
    streamMode: "partial",
  };

  try {
    writeFile600(cfgPath, JSON.stringify(parsed, null, 2));
    console.log("[migration] Configured Telegram channel from TELEGRAM_BOT_TOKEN env var");
  } catch (err) {
    console.warn(`[migration] Failed to configure Telegram: ${String(err)}`);
  }
}

// Run this FIRST before other migrations — it unblocks the gateway from crash-looping.
maybeFixInvalidProvidersKey();
migrateThinkingDefaultKey();
maybeEnableControlUiAllowInsecureAuth();
maybeSetWorkspaceDir();
maybeSyncGatewayPort();
maybeSyncRemoteUrl();
maybeUpgradeTelegramDmPolicy();
maybeRegisterOpenAiProvider();

let gatewayProc = null;
let gatewayStarting = null;

// Debug breadcrumbs for common Railway failures (502 / "Application failed to respond").
let lastGatewayError = null;
let lastGatewayExit = null;
let lastDoctorOutput = null;
let lastDoctorAt = null;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForGatewayReady(opts = {}) {
  const timeoutMs =
    opts.timeoutMs ??
    Number.parseInt(process.env.OPENCLAW_GATEWAY_READY_TIMEOUT_MS ?? "120000", 10);
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      // Don't assume HTTP: the gateway's primary transport is WebSocket.
      // A simple TCP connect check is enough for "is it up".
      if (await probeGateway()) return true;
    } catch {
      // not ready
    }
    await sleep(250);
  }
  return false;
}

async function startGateway() {
  if (gatewayProc) return;
  if (!isConfigured()) throw new Error("Gateway cannot start: not configured");

  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  const args = [
    "gateway",
    "run",
    "--bind",
    "loopback",
    "--port",
    String(INTERNAL_GATEWAY_PORT),
    "--auth",
    "token",
    "--token",
    OPENCLAW_GATEWAY_TOKEN,
  ];

  gatewayProc = childProcess.spawn(OPENCLAW_NODE, clawArgs(args), {
    stdio: "inherit",
    env: {
      ...process.env,
      OPENCLAW_STATE_DIR: STATE_DIR,
      OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
    },
  });

  gatewayProc.on("error", (err) => {
    const msg = `[gateway] spawn error: ${String(err)}`;
    console.error(msg);
    lastGatewayError = msg;
    gatewayProc = null;
  });

  gatewayProc.on("exit", (code, signal) => {
    const msg = `[gateway] exited code=${code} signal=${signal}`;
    console.error(msg);
    lastGatewayExit = { code, signal, at: new Date().toISOString() };
    gatewayProc = null;
  });
}

async function runDoctorBestEffort() {
  // Avoid spamming `openclaw doctor` in a crash loop.
  const now = Date.now();
  if (lastDoctorAt && now - lastDoctorAt < 5 * 60 * 1000) return;
  lastDoctorAt = now;

  try {
    const r = await runCmd(OPENCLAW_NODE, clawArgs(["doctor"]));
    const out = redactSecrets(r.output || "");
    lastDoctorOutput = out.length > 50_000 ? out.slice(0, 50_000) + "\n... (truncated)\n" : out;
  } catch (err) {
    lastDoctorOutput = `doctor failed: ${String(err)}`;
  }
}

async function ensureGatewayRunning() {
  if (!isConfigured()) return { ok: false, reason: "not configured" };
  if (gatewayProc) return { ok: true };
  if (!gatewayStarting) {
    gatewayStarting = (async () => {
      try {
        lastGatewayError = null;
        await startGateway();
        const ready = await waitForGatewayReady();
        if (!ready) {
          throw new Error("Gateway did not become ready in time");
        }
      } catch (err) {
        const msg = `[gateway] start failure: ${String(err)}`;
        lastGatewayError = msg;
        // Collect extra diagnostics to help users file issues.
        await runDoctorBestEffort();
        throw err;
      }
    })().finally(() => {
      gatewayStarting = null;
    });
  }
  await gatewayStarting;
  return { ok: true };
}

async function restartGateway() {
  if (gatewayProc) {
    try {
      gatewayProc.kill("SIGTERM");
    } catch {
      // ignore
    }
    // Give it a moment to exit and release the port.
    await sleep(750);
    gatewayProc = null;
  }
  return ensureGatewayRunning();
}

function requireSetupAuth(req, res, next) {
  // Single-login mode: when HTTP auth is enabled, reuse it for /setup as well.
  if (isHttpAuthEnabled()) {
    return requireHttpAuth(req, res, next);
  }

  if (!SETUP_PASSWORD) {
    return res
      .status(500)
      .type("text/plain")
      .send("SETUP_PASSWORD is not set. Set it in Railway Variables before using /setup.");
  }

  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) {
    res.set("WWW-Authenticate", 'Basic realm="OpenClaw Setup"');
    return res.status(401).send("Auth required");
  }
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const idx = decoded.indexOf(":");
  const password = idx >= 0 ? decoded.slice(idx + 1) : "";
  if (password !== SETUP_PASSWORD) {
    res.set("WWW-Authenticate", 'Basic realm="OpenClaw Setup"');
    return res.status(401).send("Invalid password");
  }
  return next();
}

function safeTimingEq(a, b) {
  const ab = Buffer.from(String(a), "utf8");
  const bb = Buffer.from(String(b), "utf8");
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function isHttpAuthEnabled() {
  return Boolean(HTTP_AUTH_PASSWORD);
}

function isHttpAuthOk(req) {
  if (!isHttpAuthEnabled()) return true;

  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) return false;

  let decoded = "";
  try {
    decoded = Buffer.from(encoded, "base64").toString("utf8");
  } catch {
    return false;
  }

  const idx = decoded.indexOf(":");
  const user = idx >= 0 ? decoded.slice(0, idx) : decoded;
  const pass = idx >= 0 ? decoded.slice(idx + 1) : "";

  return safeTimingEq(user, HTTP_AUTH_USER) && safeTimingEq(pass, HTTP_AUTH_PASSWORD);
}

function challengeHttpAuth(res) {
  res.set("WWW-Authenticate", 'Basic realm="OpenClaw"');
  return res.status(401).type("text/plain").send("Auth required");
}

function requireHttpAuth(req, res, next) {
  if (!isHttpAuthEnabled()) return next();
  if (!isHttpAuthOk(req)) return challengeHttpAuth(res);
  return next();
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// Minimal health endpoint for Railway.
app.get("/setup/healthz", (_req, res) => res.json({ ok: true }));

async function probeGateway() {
  // Don't assume HTTP — the gateway primarily speaks WebSocket.
  // A simple TCP connect check is enough for "is it up".
  const net = await import("node:net");

  return await new Promise((resolve) => {
    const sock = net.createConnection({
      host: INTERNAL_GATEWAY_HOST,
      port: INTERNAL_GATEWAY_PORT,
      timeout: 750,
    });

    const done = (ok) => {
      try { sock.destroy(); } catch { }
      resolve(ok);
    };

    sock.on("connect", () => done(true));
    sock.on("timeout", () => done(false));
    sock.on("error", () => done(false));
  });
}

// Public health endpoint (no auth) so Railway can probe without /setup.
// Keep this free of secrets.
app.get("/healthz", async (_req, res) => {
  let gatewayReachable = false;
  if (isConfigured()) {
    try {
      gatewayReachable = await probeGateway();
    } catch {
      gatewayReachable = false;
    }
  }

  // If the gateway is reachable now, clear any stale startup error so operators
  // don't chase a non-issue.
  if (gatewayReachable) {
    lastGatewayError = null;
    lastGatewayExit = null;
  }

  res.json({
    ok: true,
    wrapper: {
      configured: isConfigured(),
      stateDir: STATE_DIR,
      workspaceDir: WORKSPACE_DIR,
    },
    gateway: {
      target: GATEWAY_TARGET,
      reachable: gatewayReachable,
      lastError: lastGatewayError,
      lastExit: lastGatewayExit,
      lastDoctorAt,
    },
  });
});

// Optional auth gate for the public surface. Keep /healthz and /setup accessible so
// operators can bootstrap or debug without needing UI auth.
app.use((req, res, next) => {
  // /setup is protected by requireSetupAuth, which uses HTTP auth when enabled.
  // /setup/healthz must remain unauthenticated for Railway health checks.
  if (req.path === "/setup/healthz") return next();
  if (req.path.startsWith("/setup")) return next();
  return requireHttpAuth(req, res, next);
});

// The gateway Control UI is typically served at /openclaw. When operators visit the
// bare domain (/) after they've already configured the instance, redirect them to
// the UI instead of showing the gateway's default 404.
app.get("/", (req, res) => {
  if (!isConfigured()) return res.redirect(302, "/setup");
  return res.redirect(302, `/openclaw?__oc_tokened=1#token=${encodeURIComponent(OPENCLAW_GATEWAY_TOKEN)}`);
});

app.get("/setup/app.js", requireSetupAuth, (_req, res) => {
  // Serve JS for /setup (kept external to avoid inline encoding/template issues)
  res.type("application/javascript");
  res.send(fs.readFileSync(path.join(process.cwd(), "src", "setup-app.js"), "utf8"));
});

app.get("/setup", requireSetupAuth, (_req, res) => {
  // If we're already configured, default /setup to the main UI so operators don't
  // think they must re-run onboarding. Keep an escape hatch for recovery/import.
  if (isConfigured()) {
    try {
      const u = new URL(_req.originalUrl, "http://local");
      if (u.searchParams.get("advanced") !== "1") {
        return res.redirect(302, `/openclaw?__oc_tokened=1#token=${encodeURIComponent(OPENCLAW_GATEWAY_TOKEN)}`);
      }
    } catch {
      // ignore and fall through to the setup UI
    }
  }

  // No inline <script>: serve JS from /setup/app.js to avoid any encoding/template-literal issues.
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenClaw Setup</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 2rem; max-width: 900px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 1.25rem; margin: 1rem 0; }
    label { display:block; margin-top: 0.75rem; font-weight: 600; }
    input, select { width: 100%; padding: 0.6rem; margin-top: 0.25rem; }
    button { padding: 0.8rem 1.2rem; border-radius: 10px; border: 0; background: #111; color: #fff; font-weight: 700; cursor: pointer; }
    code { background: #f6f6f6; padding: 0.1rem 0.3rem; border-radius: 6px; }
    .muted { color: #555; }
  </style>
</head>
<body>
  <h1>OpenClaw Setup</h1>
  <p class="muted">This wizard configures OpenClaw by running the same onboarding command it uses in the terminal, but from the browser.</p>

  <div class="card">
    <h2>Status</h2>
    <div id="status">Loading...</div>
    <div id="statusDetails" class="muted" style="margin-top:0.5rem"></div>
    <div style="margin-top: 0.75rem">
      <a href="/openclaw" target="_blank">Open OpenClaw UI</a>
      &nbsp;|&nbsp;
      <a href="/setup/export" target="_blank">Download backup (.tar.gz)</a>
      &nbsp;|&nbsp;
      <a href="/setup?advanced=1">Setup/Recovery UI</a>
    </div>

    <div style="margin-top: 0.75rem">
      <div class="muted" style="margin-bottom:0.25rem"><strong>Import backup</strong> (advanced): restores into <code>/data</code> and restarts the gateway.</div>
      <input id="importFile" type="file" accept=".tar.gz,application/gzip" />
      <button id="importRun" style="background:#7c2d12; margin-top:0.5rem">Import</button>
      <pre id="importOut" style="white-space:pre-wrap"></pre>
    </div>
  </div>

  <div class="card">
    <h2>Debug console</h2>
    <p class="muted">Run a small allowlist of safe commands (no shell). Useful for debugging and recovery.</p>

    <div style="display:flex; gap:0.5rem; align-items:center">
      <select id="consoleCmd" style="flex: 1">
        <option value="gateway.restart">gateway.restart (wrapper-managed)</option>
        <option value="gateway.stop">gateway.stop (wrapper-managed)</option>
        <option value="gateway.start">gateway.start (wrapper-managed)</option>
        <option value="openclaw.status">openclaw status</option>
        <option value="openclaw.health">openclaw health</option>
        <option value="openclaw.models.list">openclaw models list</option>
        <option value="openclaw.models.status">openclaw models status --probe</option>
        <option value="openclaw.doctor">openclaw doctor</option>
        <option value="openclaw.logs.tail">openclaw logs --tail N</option>
        <option value="openclaw.config.get">openclaw config get &lt;path&gt;</option>
        <option value="openclaw.version">openclaw --version</option>
        <option value="openclaw.devices.list">openclaw devices list</option>
        <option value="openclaw.devices.approve">openclaw devices approve &lt;requestId&gt;</option>
        <option value="openclaw.plugins.list">openclaw plugins list</option>
        <option value="openclaw.plugins.enable">openclaw plugins enable &lt;name&gt;</option>
      </select>
      <input id="consoleArg" placeholder="Optional arg (e.g. 200, gateway.port)" style="flex: 1" />
      <button id="consoleRun" style="background:#0f172a">Run</button>
    </div>
    <pre id="consoleOut" style="white-space:pre-wrap"></pre>
  </div>

  <div class="card">
    <h2>Config editor (advanced)</h2>
    <p class="muted">Edits the full config file on disk (JSON5). Saving creates a timestamped <code>.bak-*</code> backup and restarts the gateway.</p>
    <div class="muted" id="configPath"></div>
    <textarea id="configText" style="width:100%; height: 260px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;"></textarea>
    <div style="margin-top:0.5rem">
      <button id="configReload" style="background:#1f2937">Reload</button>
      <button id="configSave" style="background:#111; margin-left:0.5rem">Save</button>
    </div>
    <pre id="configOut" style="white-space:pre-wrap"></pre>
  </div>

  <div class="card">
    <h2>1) Model/auth provider</h2>
    <p class="muted">Matches the groups shown in the terminal onboarding.</p>
    <label>Provider group</label>
    <select id="authGroup">
      <option>Loading providers…</option>
    </select>

    <label>Auth method</label>
    <select id="authChoice">
      <option>Loading methods…</option>
    </select>

    <label>Key / Token (if required)</label>
    <input id="authSecret" type="password" placeholder="Paste API key / token if applicable" />

    <label>Wizard flow</label>
    <select id="flow">
      <option value="quickstart">quickstart</option>
      <option value="advanced">advanced</option>
      <option value="manual">manual</option>
    </select>
  </div>

  <div class="card">
    <h2>2) Optional: Channels</h2>
    <p class="muted">You can also add channels later inside OpenClaw, but this helps you get messaging working immediately.</p>

    <label>Telegram bot token (optional)</label>
    <input id="telegramToken" type="password" placeholder="123456:ABC..." />
    <div class="muted" style="margin-top: 0.25rem">
      Get it from BotFather: open Telegram, message <code>@BotFather</code>, run <code>/newbot</code>, then copy the token.
    </div>

    <label>Discord bot token (optional)</label>
    <input id="discordToken" type="password" placeholder="Bot token" />
    <div class="muted" style="margin-top: 0.25rem">
      Get it from the Discord Developer Portal: create an application, add a Bot, then copy the Bot Token.<br/>
      <strong>Important:</strong> Enable <strong>MESSAGE CONTENT INTENT</strong> in Bot → Privileged Gateway Intents, or the bot will crash on startup.
    </div>

    <label>Slack bot token (optional)</label>
    <input id="slackBotToken" type="password" placeholder="xoxb-..." />

    <label>Slack app token (optional)</label>
    <input id="slackAppToken" type="password" placeholder="xapp-..." />
  </div>

  <div class="card">
    <h2>2b) Advanced: Custom OpenAI-compatible provider (optional)</h2>
    <p class="muted">Use this to configure an OpenAI-compatible API that requires a custom base URL (e.g. Ollama, vLLM, LM Studio, hosted proxies). You usually set the API key as a Railway variable and reference it here.</p>

    <label>Provider id (e.g. ollama, deepseek, myproxy)</label>
    <input id="customProviderId" placeholder="ollama" />

    <label>Base URL (must include /v1, e.g. http://host:11434/v1)</label>
    <input id="customProviderBaseUrl" placeholder="http://127.0.0.1:11434/v1" />

    <label>API (openai-completions or openai-responses)</label>
    <select id="customProviderApi">
      <option value="openai-completions">openai-completions</option>
      <option value="openai-responses">openai-responses</option>
    </select>

    <label>API key env var name (optional, e.g. OLLAMA_API_KEY). Leave blank for no key.</label>
    <input id="customProviderApiKeyEnv" placeholder="OLLAMA_API_KEY" />

    <label>Optional model id to register (e.g. llama3.1:8b)</label>
    <input id="customProviderModelId" placeholder="" />
  </div>

  <div class="card">
    <h2>3) Run onboarding</h2>
    <button id="run">Run setup</button>
    <button id="pairingApprove" style="background:#1f2937; margin-left:0.5rem">Approve pairing</button>
    <button id="reset" style="background:#444; margin-left:0.5rem">Reset setup</button>
    <pre id="log" style="white-space:pre-wrap"></pre>
    <p class="muted">Reset deletes the OpenClaw config file so you can rerun onboarding. Pairing approval lets you grant DM access when dmPolicy=pairing.</p>

    <details style="margin-top: 0.75rem">
      <summary><strong>Pairing helper</strong> (for “disconnected (1008): pairing required”)</summary>
      <p class="muted">This lists pending device requests and lets you approve them without SSH.</p>
      <button id="devicesRefresh" style="background:#0f172a">Refresh pending devices</button>
      <div id="devicesList" class="muted" style="margin-top:0.5rem"></div>
    </details>
  </div>

  <script src="/setup/app.js"></script>
</body>
</html>`);
});

// Auto-seed Control UI auth token into the browser URL hash on first page load.
// Hash fragments are not sent to the server, so we use a one-time query marker to avoid loops.
app.use((req, res, next) => {
  if (!isConfigured()) return next();
  if (req.method !== "GET") return next();
  if (!req.path.startsWith("/openclaw")) return next();

  const accept = req.headers.accept || "";
  if (!accept.includes("text/html")) return next();

  try {
    const u = new URL(req.originalUrl || req.url || "/", "http://local");
    if (u.searchParams.get("__oc_tokened") === "1") return next();
    u.searchParams.set("__oc_tokened", "1");
    const target = `${u.pathname}${u.search}#token=${encodeURIComponent(OPENCLAW_GATEWAY_TOKEN)}`;
    return res.redirect(302, target);
  } catch {
    return next();
  }
});

const AUTH_GROUPS = [
  {
    value: "openai", label: "OpenAI", hint: "Codex OAuth + API key", options: [
      { value: "codex-cli", label: "OpenAI Codex OAuth (Codex CLI)" },
      { value: "openai-codex", label: "OpenAI Codex (ChatGPT OAuth)" },
      { value: "openai-api-key", label: "OpenAI API key" }
    ]
  },
  {
    value: "anthropic", label: "Anthropic", hint: "Claude Code CLI + API key", options: [
      { value: "claude-cli", label: "Anthropic token (Claude Code CLI)" },
      { value: "token", label: "Anthropic token (paste setup-token)" },
      { value: "apiKey", label: "Anthropic API key" }
    ]
  },
  {
    value: "google", label: "Google", hint: "Gemini API key + OAuth", options: [
      { value: "gemini-api-key", label: "Google Gemini API key" },
      { value: "google-antigravity", label: "Google Antigravity OAuth" },
      { value: "google-gemini-cli", label: "Google Gemini CLI OAuth" }
    ]
  },
  {
    value: "openrouter", label: "OpenRouter", hint: "API key", options: [
      { value: "openrouter-api-key", label: "OpenRouter API key" }
    ]
  },
  {
    value: "ai-gateway", label: "Vercel AI Gateway", hint: "API key", options: [
      { value: "ai-gateway-api-key", label: "Vercel AI Gateway API key" }
    ]
  },
  {
    value: "moonshot", label: "Moonshot AI", hint: "Kimi K2 + Kimi Code", options: [
      { value: "moonshot-api-key", label: "Moonshot AI API key" },
      { value: "kimi-code-api-key", label: "Kimi Code API key" }
    ]
  },
  {
    value: "zai", label: "Z.AI (GLM 4.7)", hint: "API key", options: [
      { value: "zai-api-key", label: "Z.AI (GLM 4.7) API key" }
    ]
  },
  {
    value: "minimax", label: "MiniMax", hint: "M2.1 (recommended)", options: [
      { value: "minimax-api", label: "MiniMax M2.1" },
      { value: "minimax-api-lightning", label: "MiniMax M2.1 Lightning" }
    ]
  },
  {
    value: "qwen", label: "Qwen", hint: "OAuth", options: [
      { value: "qwen-portal", label: "Qwen OAuth" }
    ]
  },
  {
    value: "copilot", label: "Copilot", hint: "GitHub + local proxy", options: [
      { value: "github-copilot", label: "GitHub Copilot (GitHub device login)" },
      { value: "copilot-proxy", label: "Copilot Proxy (local)" }
    ]
  },
  {
    value: "synthetic", label: "Synthetic", hint: "Anthropic-compatible (multi-model)", options: [
      { value: "synthetic-api-key", label: "Synthetic API key" }
    ]
  },
  {
    value: "opencode-zen", label: "OpenCode Zen", hint: "API key", options: [
      { value: "opencode-zen", label: "OpenCode Zen (multi-model proxy)" }
    ]
  }
];

app.get("/setup/api/status", requireSetupAuth, async (_req, res) => {
  const version = await runCmd(OPENCLAW_NODE, clawArgs(["--version"]));
  const channelsHelp = await runCmd(OPENCLAW_NODE, clawArgs(["channels", "add", "--help"]));

  res.json({
    configured: isConfigured(),
    gatewayTarget: GATEWAY_TARGET,
    openclawVersion: version.output.trim(),
    channelsAddHelp: channelsHelp.output,
    authGroups: AUTH_GROUPS,
  });
});

app.get("/setup/api/auth-groups", requireSetupAuth, (_req, res) => {
  res.json({ ok: true, authGroups: AUTH_GROUPS });
});

function buildOnboardArgs(payload) {
  const args = [
    "onboard",
    "--non-interactive",
    "--accept-risk",
    "--json",
    "--no-install-daemon",
    "--skip-health",
    "--workspace",
    WORKSPACE_DIR,
    // The wrapper owns public networking; keep the gateway internal.
    "--gateway-bind",
    "loopback",
    "--gateway-port",
    String(INTERNAL_GATEWAY_PORT),
    "--gateway-auth",
    "token",
    "--gateway-token",
    OPENCLAW_GATEWAY_TOKEN,
    "--flow",
    payload.flow || "quickstart",
  ];

  if (payload.authChoice) {
    args.push("--auth-choice", payload.authChoice);

    // Map secret to correct flag for common choices.
    const secret = (payload.authSecret || "").trim();
    const map = {
      "openai-api-key": "--openai-api-key",
      "apiKey": "--anthropic-api-key",
      "openrouter-api-key": "--openrouter-api-key",
      "ai-gateway-api-key": "--ai-gateway-api-key",
      "moonshot-api-key": "--moonshot-api-key",
      "kimi-code-api-key": "--kimi-code-api-key",
      "gemini-api-key": "--gemini-api-key",
      "zai-api-key": "--zai-api-key",
      "minimax-api": "--minimax-api-key",
      "minimax-api-lightning": "--minimax-api-key",
      "synthetic-api-key": "--synthetic-api-key",
      "opencode-zen": "--opencode-zen-api-key",
    };

    const flag = map[payload.authChoice];

    // If the user picked an API-key auth choice but didn't provide a secret, fail fast.
    // Otherwise OpenClaw may fall back to its default auth choice, which looks like the
    // wizard "reverted" their selection.
    if (flag && !secret) {
      throw new Error(`Missing auth secret for authChoice=${payload.authChoice}`);
    }

    if (flag) {
      args.push(flag, secret);
    }

    if (payload.authChoice === "token") {
      // This is the Anthropic setup-token flow.
      if (!secret) throw new Error("Missing auth secret for authChoice=token");
      args.push("--token-provider", "anthropic", "--token", secret);
    }
  }

  return args;
}

function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 120_000;

    const proc = childProcess.spawn(cmd, args, {
      ...opts,
      env: {
        ...process.env,
        OPENCLAW_STATE_DIR: STATE_DIR,
        OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
      },
    });

    let out = "";
    proc.stdout?.on("data", (d) => (out += d.toString("utf8")));
    proc.stderr?.on("data", (d) => (out += d.toString("utf8")));

    let killTimer;
    const timer = setTimeout(() => {
      try { proc.kill("SIGTERM"); } catch { }
      killTimer = setTimeout(() => {
        try { proc.kill("SIGKILL"); } catch { }
      }, 2_000);
      out += `\n[timeout] Command exceeded ${timeoutMs}ms and was terminated.\n`;
      resolve({ code: 124, output: out });
    }, timeoutMs);

    proc.on("error", (err) => {
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      out += `\n[spawn error] ${String(err)}\n`;
      resolve({ code: 127, output: out });
    });

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      resolve({ code: code ?? 0, output: out });
    });
  });
}

app.post("/setup/api/run", requireSetupAuth, async (req, res) => {
  try {
    const safeWrite = (msg) => {
      try {
        if (!res.writableEnded) res.write(String(msg) + "\n");
      } catch { }
    };
    if (isConfigured()) {
      await ensureGatewayRunning();
      return res.json({ ok: true, output: "Already configured.\nUse Reset setup if you want to rerun onboarding.\n" });
    }

    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

    const payload = req.body || {};

    let onboardArgs;
    try {
      onboardArgs = buildOnboardArgs(payload);
    } catch (err) {
      return res.status(400).json({ ok: false, output: `Setup input error: ${String(err)}` });
    }

    safeWrite("[setup] running openclaw onboard...");
    const onboard = await runCmd(OPENCLAW_NODE, clawArgs(onboardArgs));

    let extra = "";

    const ok = onboard.code === 0 && isConfigured();

    // Optional setup (only after successful onboarding).
    if (ok) {
      // Ensure gateway token is written into config so the browser UI can authenticate reliably.
      // (We also enforce loopback bind since the wrapper proxies externally.)
      // IMPORTANT: Set both gateway.auth.token (server-side) and gateway.remote.token (client-side)
      // to the same value so the Control UI can connect without "token mismatch" errors.
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.auth.mode", "token"]));
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.auth.token", OPENCLAW_GATEWAY_TOKEN]));
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.remote.token", OPENCLAW_GATEWAY_TOKEN]));
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.bind", "loopback"]));
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.port", String(INTERNAL_GATEWAY_PORT)]));

      // Inject the public URL into gateway.remote.url so the Control UI WebSocket
      // connects to the Railway domain instead of ws://localhost:PORT (which always
      // fails in production because browsers cannot reach the server's loopback).
      const postOnboardPublicUrl = resolvePublicUrl();
      if (postOnboardPublicUrl) {
        const setUrl = await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.remote.url", postOnboardPublicUrl]));
        extra += `\n[remote.url] set to ${postOnboardPublicUrl} (exit=${setUrl.code})`;
      } else {
        extra += "\n[remote.url] WARNING: could not detect public URL. Set OPENCLAW_PUBLIC_URL in Railway Variables.";
      }

      // Railway runs behind a reverse proxy. Trust loopback as a proxy hop so local client detection
      // remains correct when X-Forwarded-* headers are present.
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "--json", "gateway.trustedProxies", JSON.stringify(["127.0.0.1"])]),
      );

      // Optional: configure a custom OpenAI-compatible provider (base URL) for advanced users.
      if (payload.customProviderId?.trim() && payload.customProviderBaseUrl?.trim()) {
        const providerId = payload.customProviderId.trim();
        const baseUrl = payload.customProviderBaseUrl.trim();
        const api = (payload.customProviderApi || "openai-completions").trim();
        const apiKeyEnv = (payload.customProviderApiKeyEnv || "").trim();
        const modelId = (payload.customProviderModelId || "").trim();

        if (!/^[A-Za-z0-9_-]+$/.test(providerId)) {
          extra += `\n[custom provider] skipped: invalid provider id (use letters/numbers/_/-)`;
        } else if (!/^https?:\/\//.test(baseUrl)) {
          extra += `\n[custom provider] skipped: baseUrl must start with http(s)://`;
        } else if (api !== "openai-completions" && api !== "openai-responses") {
          extra += `\n[custom provider] skipped: api must be openai-completions or openai-responses`;
        } else if (apiKeyEnv && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(apiKeyEnv)) {
          extra += `\n[custom provider] skipped: invalid api key env var name`;
        } else {
          const providerCfg = {
            baseUrl,
            api,
            apiKey: apiKeyEnv ? "${" + apiKeyEnv + "}" : undefined,
            models: modelId ? [{ id: modelId, name: modelId }] : undefined,
          };

          // Ensure we merge in this provider rather than replacing other providers.
          await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "models.mode", "merge"]));
          const set = await runCmd(
            OPENCLAW_NODE,
            clawArgs(["config", "set", "--json", `models.providers.${providerId}`, JSON.stringify(providerCfg)]),
          );
          extra += `\n[custom provider] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
        }
      }

      const channelsHelp = await runCmd(OPENCLAW_NODE, clawArgs(["channels", "add", "--help"]));
      const helpText = channelsHelp.output || "";

      const supports = (name) => helpText.includes(name);

      if (payload.telegramToken?.trim()) {
        if (!supports("telegram")) {
          extra += "\n[telegram] skipped (this openclaw build does not list telegram in `channels add --help`)\n";
        } else {
          // Avoid `channels add` here (it has proven flaky across builds); write config directly.
          const token = payload.telegramToken.trim();
          const cfgObj = {
            enabled: true,
            dmPolicy: "open",
            botToken: token,
            groupPolicy: "allowlist",
            streamMode: "partial",
          };
          const set = await runCmd(
            OPENCLAW_NODE,
            clawArgs(["config", "set", "--json", "channels.telegram", JSON.stringify(cfgObj)]),
          );
          const get = await runCmd(OPENCLAW_NODE, clawArgs(["config", "get", "channels.telegram"]));

          // Best-effort: enable the telegram plugin explicitly (some builds require this even when configured).
          const plug = await runCmd(OPENCLAW_NODE, clawArgs(["plugins", "enable", "telegram"]));

          extra += `\n[telegram config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
          extra += `\n[telegram verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
          extra += `\n[telegram plugin enable] exit=${plug.code} (output ${plug.output.length} chars)\n${plug.output || "(no output)"}`;
        }
      }

      if (payload.discordToken?.trim()) {
        if (!supports("discord")) {
          extra += "\n[discord] skipped (this openclaw build does not list discord in `channels add --help`)\n";
        } else {
          const token = payload.discordToken.trim();
          const cfgObj = {
            enabled: true,
            token,
            groupPolicy: "allowlist",
            dm: {
              policy: "pairing",
            },
          };
          const set = await runCmd(
            OPENCLAW_NODE,
            clawArgs(["config", "set", "--json", "channels.discord", JSON.stringify(cfgObj)]),
          );
          const get = await runCmd(OPENCLAW_NODE, clawArgs(["config", "get", "channels.discord"]));
          extra += `\n[discord config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
          extra += `\n[discord verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
        }
      }

      if (payload.slackBotToken?.trim() || payload.slackAppToken?.trim()) {
        if (!supports("slack")) {
          extra += "\n[slack] skipped (this openclaw build does not list slack in `channels add --help`)\n";
        } else {
          const cfgObj = {
            enabled: true,
            botToken: payload.slackBotToken?.trim() || undefined,
            appToken: payload.slackAppToken?.trim() || undefined,
          };
          const set = await runCmd(
            OPENCLAW_NODE,
            clawArgs(["config", "set", "--json", "channels.slack", JSON.stringify(cfgObj)]),
          );
          const get = await runCmd(OPENCLAW_NODE, clawArgs(["config", "get", "channels.slack"]));
          extra += `\n[slack config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
          extra += `\n[slack verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
        }
      }

      // Apply changes immediately.
      await restartGateway();

      // Ensure OpenClaw applies any "configured but not enabled" channel/plugin changes.
      // This makes Telegram/Discord pairing issues much less "silent".
      const fix = await runCmd(OPENCLAW_NODE, clawArgs(["doctor", "--fix"]));
      extra += `\n[doctor --fix] exit=${fix.code} (output ${fix.output.length} chars)\n${fix.output || "(no output)"}`;

      // Doctor may require a restart depending on changes.
      await restartGateway();
    }

    return res.status(ok ? 200 : 500).json({
      ok,
      output: `${onboard.output}${extra}`,
    });
  } catch (err) {
    console.error("[/setup/api/run] error:", err);
    return res.status(500).json({ ok: false, output: `Internal error: ${String(err)}` });
  }
});

app.get("/setup/api/debug", requireSetupAuth, async (_req, res) => {
  const v = await runCmd(OPENCLAW_NODE, clawArgs(["--version"]));
  const help = await runCmd(OPENCLAW_NODE, clawArgs(["channels", "add", "--help"]));

  // Channel config checks (redact secrets before returning to client)
  const tg = await runCmd(OPENCLAW_NODE, clawArgs(["config", "get", "channels.telegram"]));
  const dc = await runCmd(OPENCLAW_NODE, clawArgs(["config", "get", "channels.discord"]));

  const tgOut = redactSecrets(tg.output || "");
  const dcOut = redactSecrets(dc.output || "");

  res.json({
    wrapper: {
      node: process.version,
      port: PORT,
      publicPortEnv: process.env.PORT || null,
      stateDir: STATE_DIR,
      workspaceDir: WORKSPACE_DIR,
      configured: isConfigured(),
      configPathResolved: configPath(),
      configPathCandidates: typeof resolveConfigCandidates === "function" ? resolveConfigCandidates() : null,
      internalGatewayHost: INTERNAL_GATEWAY_HOST,
      internalGatewayPort: INTERNAL_GATEWAY_PORT,
      gatewayTarget: GATEWAY_TARGET,
      gatewayRunning: Boolean(gatewayProc),
      gatewayTokenFromEnv: Boolean(process.env.OPENCLAW_GATEWAY_TOKEN?.trim()),
      gatewayTokenPersisted: fs.existsSync(path.join(STATE_DIR, "gateway.token")),
      lastGatewayError,
      lastGatewayExit,
      lastDoctorAt,
      lastDoctorOutput,
      railwayCommit: process.env.RAILWAY_GIT_COMMIT_SHA || null,
    },
    openclaw: {
      entry: OPENCLAW_ENTRY,
      node: OPENCLAW_NODE,
      version: v.output.trim(),
      channelsAddHelpIncludesTelegram: help.output.includes("telegram"),
      channels: {
        telegram: {
          exit: tg.code,
          configuredEnabled: /"enabled"\s*:\s*true/.test(tg.output || "") || /enabled\s*[:=]\s*true/.test(tg.output || ""),
          botTokenPresent: /(\d{5,}:[A-Za-z0-9_-]{10,})/.test(tg.output || ""),
          output: tgOut,
        },
        discord: {
          exit: dc.code,
          configuredEnabled: /"enabled"\s*:\s*true/.test(dc.output || "") || /enabled\s*[:=]\s*true/.test(dc.output || ""),
          tokenPresent: /"token"\s*:\s*"?\S+"?/.test(dc.output || "") || /token\s*[:=]\s*\S+/.test(dc.output || ""),
          output: dcOut,
        },
      },
    },
  });
});

// --- Debug console (Option A: allowlisted commands + config editor) ---

function redactSecrets(text) {
  if (!text) return text;
  // Very small best-effort redaction. (Config paths/values may still contain secrets.)
  return String(text)
    .replace(/(sk-[A-Za-z0-9_-]{10,})/g, "[REDACTED]")
    .replace(/(gho_[A-Za-z0-9_]{10,})/g, "[REDACTED]")
    .replace(/(xox[baprs]-[A-Za-z0-9-]{10,})/g, "[REDACTED]")
    // Telegram bot tokens look like: 123456:ABCDEF...
    .replace(/(\d{5,}:[A-Za-z0-9_-]{10,})/g, "[REDACTED]")
    .replace(/(AA[A-Za-z0-9_-]{10,}:\S{10,})/g, "[REDACTED]");
}

function extractDeviceRequestIds(text) {
  const s = String(text || "");
  const out = new Set();

  for (const m of s.matchAll(/requestId\s*(?:=|:)\s*([A-Za-z0-9_-]{6,})/g)) out.add(m[1]);
  for (const m of s.matchAll(/"requestId"\s*:\s*"([A-Za-z0-9_-]{6,})"/g)) out.add(m[1]);

  return Array.from(out);
}

const ALLOWED_CONSOLE_COMMANDS = new Set([
  // Wrapper-managed lifecycle
  "gateway.restart",
  "gateway.stop",
  "gateway.start",

  // OpenClaw CLI helpers
  "openclaw.version",
  "openclaw.status",
  "openclaw.health",
  "openclaw.models.list",
  "openclaw.models.status",
  "openclaw.doctor",
  "openclaw.logs.tail",
  "openclaw.config.get",

  // Device management (for fixing "disconnected (1008): pairing required")
  "openclaw.devices.list",
  "openclaw.devices.approve",

  // Plugin management
  "openclaw.plugins.list",
  "openclaw.plugins.enable",
]);

app.post("/setup/api/console/run", requireSetupAuth, async (req, res) => {
  const payload = req.body || {};
  const cmd = String(payload.cmd || "").trim();
  const arg = String(payload.arg || "").trim();

  if (!ALLOWED_CONSOLE_COMMANDS.has(cmd)) {
    return res.status(400).json({ ok: false, error: "Command not allowed" });
  }

  try {
    if (cmd === "gateway.restart") {
      await restartGateway();
      return res.json({ ok: true, output: "Gateway restarted (wrapper-managed).\n" });
    }
    if (cmd === "gateway.stop") {
      if (gatewayProc) {
        try { gatewayProc.kill("SIGTERM"); } catch { }
        await sleep(750);
        gatewayProc = null;
      }
      return res.json({ ok: true, output: "Gateway stopped (wrapper-managed).\n" });
    }
    if (cmd === "gateway.start") {
      const r = await ensureGatewayRunning();
      return res.json({ ok: Boolean(r.ok), output: r.ok ? "Gateway started.\n" : `Gateway not started: ${r.reason}\n` });
    }

    if (cmd === "openclaw.version") {
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["--version"]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }
    if (cmd === "openclaw.status") {
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["status"]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }
    if (cmd === "openclaw.health") {
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["health"]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }
    if (cmd === "openclaw.models.list") {
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["models", "list"]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }
    if (cmd === "openclaw.models.status") {
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["models", "status", "--probe"]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }
    if (cmd === "openclaw.doctor") {
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["doctor"]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }
    if (cmd === "openclaw.logs.tail") {
      const lines = Math.max(50, Math.min(1000, Number.parseInt(arg || "200", 10) || 200));
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["logs", "--limit", String(lines), "--plain", "--no-color"]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }
    if (cmd === "openclaw.config.get") {
      if (!arg) return res.status(400).json({ ok: false, error: "Missing config path" });
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["config", "get", arg]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }

    // Device management commands (for fixing "disconnected (1008): pairing required")
    if (cmd === "openclaw.devices.list") {
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["devices", "list"]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }
    if (cmd === "openclaw.devices.approve") {
      const requestId = String(arg || "").trim();
      if (!requestId) {
        return res.status(400).json({ ok: false, error: "Missing device request ID" });
      }
      if (!/^[A-Za-z0-9_-]+$/.test(requestId)) {
        return res.status(400).json({ ok: false, error: "Invalid device request ID" });
      }
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["devices", "approve", requestId]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }

    // Plugin management commands
    if (cmd === "openclaw.plugins.list") {
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["plugins", "list"]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }
    if (cmd === "openclaw.plugins.enable") {
      const name = String(arg || "").trim();
      if (!name) return res.status(400).json({ ok: false, error: "Missing plugin name" });
      if (!/^[A-Za-z0-9_-]+$/.test(name)) return res.status(400).json({ ok: false, error: "Invalid plugin name" });
      const r = await runCmd(OPENCLAW_NODE, clawArgs(["plugins", "enable", name]));
      return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
    }

    return res.status(400).json({ ok: false, error: "Unhandled command" });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

app.get("/setup/api/config/raw", requireSetupAuth, async (_req, res) => {
  try {
    const p = configPath();
    const exists = fs.existsSync(p);
    const content = exists ? fs.readFileSync(p, "utf8") : "";
    res.json({ ok: true, path: p, exists, content });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.post("/setup/api/config/raw", requireSetupAuth, async (req, res) => {
  try {
    const content = String((req.body && req.body.content) || "");
    if (content.length > 500_000) {
      return res.status(413).json({ ok: false, error: "Config too large" });
    }

    fs.mkdirSync(STATE_DIR, { recursive: true });

    const p = configPath();
    // Backup
    if (fs.existsSync(p)) {
      const backupPath = `${p}.bak-${new Date().toISOString().replace(/[:.]/g, "-")}`;
      fs.copyFileSync(p, backupPath);
    }

    fs.writeFileSync(p, content, { encoding: "utf8", mode: 0o600 });

    // Apply immediately.
    if (isConfigured()) {
      await restartGateway();
    }

    res.json({ ok: true, path: p });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.post("/setup/api/pairing/approve", requireSetupAuth, async (req, res) => {
  const { channel, code } = req.body || {};
  if (!channel || !code) {
    return res.status(400).json({ ok: false, error: "Missing channel or code" });
  }
  const r = await runCmd(OPENCLAW_NODE, clawArgs(["pairing", "approve", String(channel), String(code)]));
  return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: r.output });
});

// Device pairing helper (list + approve) to avoid needing SSH.
app.get("/setup/api/devices/pending", requireSetupAuth, async (_req, res) => {
  const r = await runCmd(OPENCLAW_NODE, clawArgs(["devices", "list"]));
  const output = redactSecrets(r.output);
  const requestIds = extractDeviceRequestIds(output);
  return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, requestIds, output });
});

app.post("/setup/api/devices/approve", requireSetupAuth, async (req, res) => {
  const requestId = String((req.body && req.body.requestId) || "").trim();
  if (!requestId) return res.status(400).json({ ok: false, error: "Missing device request ID" });
  if (!/^[A-Za-z0-9_-]+$/.test(requestId)) return res.status(400).json({ ok: false, error: "Invalid device request ID" });
  const r = await runCmd(OPENCLAW_NODE, clawArgs(["devices", "approve", requestId]));
  return res.status(r.code === 0 ? 200 : 500).json({ ok: r.code === 0, output: redactSecrets(r.output) });
});

app.post("/setup/api/reset", requireSetupAuth, async (_req, res) => {
  // Reset: stop gateway (frees memory) + delete config file(s) so /setup can rerun.
  // Keep credentials/sessions/workspace by default.
  try {
    // Stop gateway to avoid running gateway + onboard concurrently on small Railway instances.
    try {
      if (gatewayProc) {
        try { gatewayProc.kill("SIGTERM"); } catch { }
        await sleep(750);
        gatewayProc = null;
      }
    } catch {
      // ignore
    }

    const candidates = typeof resolveConfigCandidates === "function" ? resolveConfigCandidates() : [configPath()];
    for (const p of candidates) {
      try { fs.rmSync(p, { force: true }); } catch { }
    }

    res.type("text/plain").send("OK - stopped gateway and deleted config file(s). You can rerun setup now.");
  } catch (err) {
    res.status(500).type("text/plain").send(String(err));
  }
});

app.get("/setup/export", requireSetupAuth, async (_req, res) => {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  res.setHeader("content-type", "application/gzip");
  res.setHeader(
    "content-disposition",
    `attachment; filename="openclaw-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.tar.gz"`,
  );

  // Prefer exporting from a common /data root so archives are easy to inspect and restore.
  // This preserves dotfiles like /data/.openclaw/openclaw.json.
  const stateAbs = path.resolve(STATE_DIR);
  const workspaceAbs = path.resolve(WORKSPACE_DIR);

  const dataRoot = "/data";
  const underData = (p) => p === dataRoot || p.startsWith(dataRoot + path.sep);

  let cwd = "/";
  let paths = [stateAbs, workspaceAbs].map((p) => p.replace(/^\//, ""));

  if (underData(stateAbs) && underData(workspaceAbs)) {
    cwd = dataRoot;
    // We export relative to /data so the archive contains: .openclaw/... and workspace/...
    paths = [
      path.relative(dataRoot, stateAbs) || ".",
      path.relative(dataRoot, workspaceAbs) || ".",
    ];
  }

  const stream = tar.c(
    {
      gzip: true,
      portable: true,
      noMtime: true,
      cwd,
      onwarn: () => { },
    },
    paths,
  );

  stream.on("error", (err) => {
    console.error("[export]", err);
    if (!res.headersSent) res.status(500);
    res.end(String(err));
  });

  stream.pipe(res);
});

function isUnderDir(p, root) {
  const abs = path.resolve(p);
  const r = path.resolve(root);
  return abs === r || abs.startsWith(r + path.sep);
}

function looksSafeTarPath(p) {
  if (!p) return false;
  // tar paths always use / separators
  if (p.startsWith("/") || p.startsWith("\\")) return false;
  // windows drive letters
  if (/^[A-Za-z]:[\\/]/.test(p)) return false;
  // path traversal
  if (p.split("/").includes("..")) return false;
  return true;
}

async function readBodyBuffer(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// Import a backup created by /setup/export.
// This is intentionally limited to restoring into /data to avoid overwriting arbitrary host paths.
app.post("/setup/import", requireSetupAuth, async (req, res) => {
  try {
    const dataRoot = "/data";
    if (!isUnderDir(STATE_DIR, dataRoot) || !isUnderDir(WORKSPACE_DIR, dataRoot)) {
      return res
        .status(400)
        .type("text/plain")
        .send("Import is only supported when OPENCLAW_STATE_DIR and OPENCLAW_WORKSPACE_DIR are under /data (Railway volume).\n");
    }

    // Stop gateway before restore so we don't overwrite live files.
    if (gatewayProc) {
      try { gatewayProc.kill("SIGTERM"); } catch { }
      await sleep(750);
      gatewayProc = null;
    }

    const buf = await readBodyBuffer(req, 250 * 1024 * 1024); // 250MB max
    if (!buf.length) return res.status(400).type("text/plain").send("Empty body\n");

    // Extract into /data.
    // We only allow safe relative paths, and we intentionally do NOT delete existing files.
    // (Users can reset/redeploy or manually clean the volume if desired.)
    const tmpPath = path.join(os.tmpdir(), `openclaw-import-${Date.now()}.tar.gz`);
    fs.writeFileSync(tmpPath, buf);

    await tar.x({
      file: tmpPath,
      cwd: dataRoot,
      gzip: true,
      strict: true,
      onwarn: () => { },
      filter: (p) => {
        // Allow only paths that look safe.
        return looksSafeTarPath(p);
      },
    });

    try { fs.rmSync(tmpPath, { force: true }); } catch { }

    // Restart gateway after restore.
    if (isConfigured()) {
      await restartGateway();
    }

    res.type("text/plain").send("OK - imported backup into /data and restarted gateway.\n");
  } catch (err) {
    console.error("[import]", err);
    res.status(500).type("text/plain").send(String(err));
  }
});

// Proxy everything else to the gateway.
const proxy = httpProxy.createProxyServer({
  target: GATEWAY_TARGET,
  ws: true,
  xfwd: true,
});

proxy.on("error", (err, _req, res) => {
  console.error("[proxy]", err);
  try {
    if (res && typeof res.writeHead === "function" && !res.headersSent) {
      res.writeHead(502, { "Content-Type": "text/plain" });
      res.end("Gateway unavailable\n");
    }
  } catch {
    // ignore
  }
});

app.use(async (req, res) => {
  // If not configured, force users to /setup for any non-setup routes.
  if (!isConfigured() && !req.path.startsWith("/setup")) {
    return res.redirect("/setup");
  }

  if (isConfigured()) {
    try {
      await ensureGatewayRunning();
    } catch (err) {
      const hint = [
        "Gateway not ready.",
        String(err),
        lastGatewayError ? `\n${lastGatewayError}` : "",
        "\nTroubleshooting:",
        "- Visit /setup and check the Debug Console",
        "- Visit /setup/api/debug for config + gateway diagnostics",
      ].join("\n");
      return res.status(503).type("text/plain").send(hint);
    }
  }

  return proxy.web(req, res, { target: GATEWAY_TARGET });
});

const server = app.listen(PORT, "0.0.0.0", async () => {
  console.log(`[wrapper] listening on :${PORT}`);
  console.log(`[wrapper] state dir: ${STATE_DIR}`);
  console.log(`[wrapper] workspace dir: ${WORKSPACE_DIR}`);

  // Harden state dir for OpenClaw and avoid missing credentials dir on fresh volumes.
  try {
    fs.mkdirSync(path.join(STATE_DIR, "credentials"), { recursive: true });
  } catch { }
  try {
    fs.chmodSync(path.join(STATE_DIR, "credentials"), 0o700);
  } catch { }
  try {
    fs.chmodSync(STATE_DIR, 0o700);
  } catch { }

  // Headless bootstrap: import Codex CLI auth + create minimal config so we skip /setup.
  try {
    bootstrapCodexCliAuth();
    bootstrapConfigIfMissing();
    // Run provider migration AFTER bootstrap so it can patch a config that was
    // just written moments ago (migrations at module-load time run before bootstrap).
    maybeRegisterOpenAiProvider();
    maybeConfigureTelegramFromEnv();
  } catch (err) {
    console.warn(`[bootstrap] failed: ${String(err)}`);
  }

  console.log(`[wrapper] gateway token: ${OPENCLAW_GATEWAY_TOKEN ? "(set)" : "(missing)"}`);
  console.log(`[wrapper] http auth: ${isHttpAuthEnabled() ? "enabled" : "disabled"}`);
  console.log(`[wrapper] gateway target: ${GATEWAY_TARGET}`);
  // /setup is protected by HTTP auth when enabled, otherwise it requires SETUP_PASSWORD.
  if (!SETUP_PASSWORD && !isHttpAuthEnabled()) {
    console.warn("[wrapper] WARNING: SETUP_PASSWORD is not set; /setup will error.");
  }

  // Auto-start the gateway if already configured so polling channels (Telegram/Discord/etc.)
  // work even if nobody visits the web UI.
  if (isConfigured()) {
    console.log("[wrapper] config detected; starting gateway...");
    try {
      await ensureGatewayRunning();
      console.log("[wrapper] gateway ready");
    } catch (err) {
      console.error(`[wrapper] gateway failed to start at boot: ${String(err)}`);
    }
  }
});

server.on("upgrade", async (req, socket, head) => {
  // Enforce HTTP auth for WS upgrades too (Control UI connects via WebSocket).
  try {
    const url = new URL(req.url || "/", "http://localhost");
    const pathname = url.pathname || "/";
    if (pathname !== "/healthz" && !pathname.startsWith("/setup")) {
      if (isHttpAuthEnabled() && !isHttpAuthOk(req)) {
        socket.write(
          'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="OpenClaw"\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nAuth required',
        );
        socket.destroy();
        return;
      }
    }
  } catch {
    // If parsing fails, default to requiring auth when enabled.
    if (isHttpAuthEnabled() && !isHttpAuthOk(req)) {
      try {
        socket.write(
          'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="OpenClaw"\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nAuth required',
        );
      } catch { }
      socket.destroy();
      return;
    }
  }

  if (!isConfigured()) {
    socket.destroy();
    return;
  }
  try {
    await ensureGatewayRunning();
  } catch {
    socket.destroy();
    return;
  }
  proxy.ws(req, socket, head, { target: GATEWAY_TARGET });
});

process.on("SIGTERM", () => {
  // Best-effort shutdown
  try {
    if (gatewayProc) gatewayProc.kill("SIGTERM");
  } catch {
    // ignore
  }

  // Stop accepting new connections; allow in-flight requests to complete briefly.
  try {
    server.close(() => process.exit(0));
  } catch {
    process.exit(0);
  }

  setTimeout(() => process.exit(0), 5_000).unref?.();
});
