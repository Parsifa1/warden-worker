#!/usr/bin/env node

import { webcrypto } from "node:crypto";
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const crypto = webcrypto;
const encoder = new TextEncoder();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");

function runCommand(command, args, cwd) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, {
      cwd,
      stdio: "inherit",
    });

    child.on("error", (err) => {
      rejectPromise(err);
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolvePromise();
      } else {
        rejectPromise(new Error(`${command} exited with code ${code ?? "unknown"}`));
      }
    });
  });
}

function parseArgs(argv) {
  const out = {
    baseUrl: "http://127.0.0.1:8787",
    email: "test@example.com",
    password: "TestPassword123!",
    name: "Local Test User",
    kdfIterations: 600000,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--base-url") {
      out.baseUrl = argv[++i];
    } else if (arg === "--email") {
      out.email = argv[++i];
    } else if (arg === "--password") {
      out.password = argv[++i];
    } else if (arg === "--name") {
      out.name = argv[++i];
    } else if (arg === "--kdf-iterations") {
      out.kdfIterations = Number(argv[++i]);
    } else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!Number.isFinite(out.kdfIterations) || out.kdfIterations <= 0) {
    throw new Error("--kdf-iterations must be a positive number");
  }

  return out;
}

function printHelp() {
  console.log(`Usage:
  node scripts/register-local-test-user.mjs [options]

Options:
  --base-url         API base URL (default: http://127.0.0.1:8787)
  --email            Test email (default: test@example.com)
  --password         Test password (default: TestPassword123!)
  --name             Display name (default: Local Test User)
  --kdf-iterations   KDF iterations (default: 600000)
  (always)           Reset local D1 using sql/schema_full.sql before registration
  -h, --help         Show this help

Example:
  node scripts/register-local-test-user.mjs --email qa@example.com --password 'Passw0rd!'
`);
}

function bytesToB64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function pkcs7Pad(bytes, blockSize = 16) {
  const remainder = bytes.length % blockSize;
  const padLen = remainder === 0 ? blockSize : blockSize - remainder;
  const out = new Uint8Array(bytes.length + padLen);
  out.set(bytes, 0);
  out.fill(padLen, bytes.length);
  return out;
}

async function pbkdf2Sha256(passwordBytes, saltBytes, iterations, lengthBytes) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

async function hmacSha256(macKeyBytes, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    macKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(sig);
}

async function hkdfExpandSha256(prkBytes, infoBytes, lengthBytes) {
  if (lengthBytes > 32) {
    throw new Error("HKDF-Expand length too large for this implementation");
  }
  const infoWithCounter = concatBytes(infoBytes, new Uint8Array([1]));
  const okm = await hmacSha256(prkBytes, infoWithCounter);
  return okm.subarray(0, lengthBytes);
}

async function stretchMasterKey(masterKeyBytes) {
  const encKey = await hkdfExpandSha256(masterKeyBytes, encoder.encode("enc"), 32);
  const macKey = await hkdfExpandSha256(masterKeyBytes, encoder.encode("mac"), 32);
  return { encKey, macKey };
}

async function aesCbcEncrypt(encKeyBytes, ivBytes, plainBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    encKeyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt"],
  );
  const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv: ivBytes }, key, plainBytes);
  return new Uint8Array(ct);
}

async function encryptEncString(plainBytes, encKeyBytes, macKeyBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const input = pkcs7Pad(plainBytes, 16);
  const ct = await aesCbcEncrypt(encKeyBytes, iv, input);
  const mac = await hmacSha256(macKeyBytes, concatBytes(iv, ct));
  return `2.${bytesToB64(iv)}|${bytesToB64(ct)}|${bytesToB64(mac)}`;
}

async function deriveMasterKey(email, password, kdfIterations) {
  const salt = encoder.encode(email.toLowerCase());
  const pw = encoder.encode(password);
  return pbkdf2Sha256(pw, salt, kdfIterations, 32);
}

async function deriveMasterPasswordHash(masterKeyBytes, password) {
  const pw = encoder.encode(password);
  const hash = await pbkdf2Sha256(masterKeyBytes, pw, 1, 32);
  return bytesToB64(hash);
}

async function generateUserAsymmetricKeys(userEncKey, userMacKey) {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-1",
    },
    true,
    ["encrypt", "decrypt"],
  );

  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));

  return {
    publicKey: bytesToB64(spki),
    encryptedPrivateKey: await encryptEncString(pkcs8, userEncKey, userMacKey),
  };
}

async function assertApiHealthy(baseUrl) {
  const resp = await fetch(`${baseUrl}/api/alive`);
  if (!resp.ok) {
    throw new Error(`/api/alive failed with ${resp.status}`);
  }
}

async function resetLocalDatabase() {
  const schemaPath = resolve(repoRoot, "sql/schema_full.sql");
  await runCommand("wrangler", [
    "d1",
    "execute",
    "vault1",
    "--local",
    "--file",
    schemaPath,
  ], repoRoot);
}

async function registerUser(baseUrl, payload) {
  const resp = await fetch(`${baseUrl}/identity/accounts/register/finish`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });

  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`register failed (${resp.status}): ${text}`);
  }
}

async function loginUser(baseUrl, email, masterPasswordHash) {
  const form = new URLSearchParams();
  form.set("grant_type", "password");
  form.set("username", email);
  form.set("password", masterPasswordHash);
  form.set("deviceIdentifier", "local-test-script-device");
  form.set("deviceName", "local-test-script");
  form.set("deviceType", "10");

  const resp = await fetch(`${baseUrl}/identity/connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`login failed (${resp.status}): ${text}`);
  }
  return JSON.parse(text);
}

async function main() {
  process.chdir(repoRoot);
  const args = parseArgs(process.argv);
  const email = args.email.toLowerCase();

  console.log("[1/5] Resetting local D1 database (local only)");
  await resetLocalDatabase();

  console.log(`[2/5] Checking local worker: ${args.baseUrl}`);
  await assertApiHealthy(args.baseUrl);

  console.log("[3/5] Deriving Bitwarden-compatible crypto payload");
  const masterKey = await deriveMasterKey(email, args.password, args.kdfIterations);
  const masterPasswordHash = await deriveMasterPasswordHash(masterKey, args.password);
  const masterStretched = await stretchMasterKey(masterKey);

  const userKey = crypto.getRandomValues(new Uint8Array(64));
  const userEncKey = userKey.subarray(0, 32);
  const userMacKey = userKey.subarray(32, 64);
  const userSymmetricKey = await encryptEncString(
    userKey,
    masterStretched.encKey,
    masterStretched.macKey,
  );
  const userAsymmetricKeys = await generateUserAsymmetricKeys(userEncKey, userMacKey);

  const registerPayload = {
    name: args.name,
    email,
    masterPasswordHash,
    masterPasswordHint: null,
    userSymmetricKey,
    userAsymmetricKeys,
    kdf: 0,
    kdfIterations: args.kdfIterations,
  };

  console.log("[4/5] Registering fake email account (no email sending involved)");
  await registerUser(args.baseUrl, registerPayload);

  console.log("[5/5] Verifying password login works");
  const token = await loginUser(args.baseUrl, email, masterPasswordHash);

  console.log("\nDone. Test account is ready:");
  console.log(`- Server:   ${args.baseUrl}`);
  console.log(`- Email:    ${email}`);
  console.log(`- Password: ${args.password}`);
  console.log(`- Token OK: ${Boolean(token.access_token)}`);
}

main().catch((err) => {
  console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
