import crypto from "node:crypto";
import { ethers } from "ethers";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const NONCE_TTL_MS = 5 * 60 * 1000; // 5 min
function timingSafeEqualStr(a, b) {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length)
        return false;
    return crypto.timingSafeEqual(bufA, bufB);
}
export function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.scryptSync(password, salt, 64).toString("hex");
    return `${salt}:${hash}`;
}
export function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(":");
    if (!salt || !hash)
        return false;
    const candidate = crypto.scryptSync(password, salt, 64).toString("hex");
    return timingSafeEqualStr(candidate, hash);
}
function sign(value, secret) {
    return crypto.createHmac("sha256", secret).update(value).digest("hex");
}
/** Stateless session token: "<expiryMs>.<hmac>" — no server-side store, survives restarts. */
export function createSessionToken(secret) {
    const payload = String(Date.now() + SESSION_TTL_MS);
    return `${payload}.${sign(payload, secret)}`;
}
export function verifySessionToken(token, secret) {
    if (!token)
        return false;
    const [payload, sig] = token.split(".");
    if (!payload || !sig)
        return false;
    if (!timingSafeEqualStr(sign(payload, secret), sig))
        return false;
    const expires = Number(payload);
    return Number.isFinite(expires) && Date.now() < expires;
}
export function parseCookies(header) {
    const out = {};
    if (!header)
        return out;
    for (const part of header.split(";")) {
        const idx = part.indexOf("=");
        if (idx === -1)
            continue;
        const k = part.slice(0, idx).trim();
        const v = part.slice(idx + 1).trim();
        if (k)
            out[k] = decodeURIComponent(v);
    }
    return out;
}
const nonceStore = new Map();
/**
 * Generates a sign-in challenge message embedding a fresh random nonce,
 * stores it keyed by address (one-time, 5-min TTL), and returns the message
 * to send to the client for signing.
 */
export function issueWalletChallenge(address) {
    const now = Date.now();
    for (const [k, v] of nonceStore)
        if (v.expiresAt < now)
            nonceStore.delete(k);
    const nonce = crypto.randomBytes(32).toString("hex");
    const message = `Sign in to Guardian Dashboard\n\nNonce: ${nonce}`;
    nonceStore.set(address.toLowerCase(), { message, expiresAt: now + NONCE_TTL_MS });
    return message;
}
/**
 * Retrieves and deletes (one-time use) the stored challenge for the given address.
 * Returns null when absent or expired.
 */
export function consumeWalletChallenge(address) {
    const key = address.toLowerCase();
    const entry = nonceStore.get(key);
    if (!entry || Date.now() > entry.expiresAt) {
        nonceStore.delete(key);
        return null;
    }
    nonceStore.delete(key);
    return entry.message;
}
/**
 * Recovers the signer address from an EIP-191 personal_sign signature and
 * compares it (case-insensitively) with the expected address.
 */
export function verifyWalletSignature(address, message, signature) {
    try {
        const recovered = ethers.verifyMessage(message, signature);
        return recovered.toLowerCase() === address.toLowerCase();
    }
    catch {
        return false;
    }
}
