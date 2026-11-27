import express, { Router } from "express";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { prisma } from "../db.js";
import { bearerToken, resolveDevice } from "../deviceAuth.js";
export const storageSyncRouter = Router();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
/** Uploaded file content lives outside the repo tree, under server/media-store/<deviceId>/<clientItemId>. */
export const MEDIA_STORE_DIR = path.join(__dirname, "../../media-store");
const MAX_CONTENT_BYTES = 150 * 1024 * 1024; // 150MB per file
const MAX_THUMBNAIL_BASE64_LEN = 200_000;
const SHA256_HEX = /^[a-f0-9]{64}$/;
// clientItemId becomes a filename on disk (see PUT .../content below) — restrict it to a safe,
// non-path-traversing charset rather than trusting whatever the client sends as a URL param.
const SAFE_CLIENT_ITEM_ID = /^[A-Za-z0-9_-]{1,128}$/;
export const StorageItemSchema = z.object({
    clientItemId: z.string().regex(SAFE_CLIENT_ITEM_ID),
    mediaType: z.enum(["image", "video", "audio", "document"]),
    uri: z.string().min(1),
    // nullish() = nullable + optional: the Android client (Moshi) OMITS null fields.
    displayName: z.string().nullish(),
    mimeType: z.string().nullish(),
    sizeBytes: z.number().int().nonnegative().nullish(),
    dateAddedMs: z.number().int().nullish(),
    dateModifiedMs: z.number().int().nullish(),
    width: z.number().int().nonnegative().nullish(),
    height: z.number().int().nonnegative().nullish(),
    durationMs: z.number().int().nonnegative().nullish(),
    thumbnailBase64: z.string().max(MAX_THUMBNAIL_BASE64_LEN).nullish(),
    contentHash: z.string().regex(SHA256_HEX).nullish(),
    capturedAt: z.number().int(),
    folderCategory: z.string().max(200).nullish(),
    relativePath: z.string().max(500).nullish(),
});
export const StorageNegotiateSchema = z.object({
    deviceId: z.string().min(1),
    items: z.array(StorageItemSchema).max(200),
});
export function deviceMediaDir(deviceId) {
    return path.join(MEDIA_STORE_DIR, deviceId);
}
/**
 * POST /v1/storage/sync/negotiate
 * Auth: Bearer <enrollmentToken>, same device-auth contract as /v1/ingest.
 *
 * Upserts metadata for a batch of candidate items (the device already filtered these down to
 * "new or modified" using local mtime/size before calling this) and reports back which ones
 * still need their content PUT — i.e. no stored content yet, or the incoming contentHash
 * differs from what's on record. When the hash matches an item already marked "uploaded", the
 * item is left alone: this is what makes a retried negotiate (e.g. after a lost ack) a no-op
 * instead of a duplicate upload.
 */
storageSyncRouter.post("/v1/storage/sync/negotiate", async (req, res) => {
    const token = bearerToken(req.header("authorization"));
    if (!token)
        return res.status(401).json({ error: "missing bearer token" });
    const parsed = StorageNegotiateSchema.safeParse(req.body);
    if (!parsed.success) {
        console.log("[storage/negotiate 400] zod:", JSON.stringify(parsed.error.flatten().fieldErrors));
        return res.status(400).json({ error: "invalid payload", details: parsed.error.flatten() });
    }
    const { deviceId, items } = parsed.data;
    const auth = await resolveDevice(deviceId, token, req.header("x-device-label"));
    if (!auth.ok)
        return res.status(403).json({ error: "device/token mismatch" });
    if (items.length === 0)
        return res.json({ needsContent: [], upToDate: [] });
    const existing = await prisma.mediaItem.findMany({
        where: { clientItemId: { in: items.map((it) => it.clientItemId) } },
        select: { clientItemId: true, contentHash: true, syncStatus: true },
    });
    const existingById = new Map(existing.map((e) => [e.clientItemId, e]));
    await prisma.$transaction(items.map((it) => {
        const prev = existingById.get(it.clientItemId);
        const hashMatches = Boolean(prev?.contentHash && it.contentHash && prev.contentHash === it.contentHash);
        const keepUploaded = prev?.syncStatus === "uploaded" && hashMatches;
        const commonFields = {
            deviceId,
            mediaType: it.mediaType,
            uri: it.uri,
            displayName: it.displayName ?? null,
            mimeType: it.mimeType ?? null,
            sizeBytes: it.sizeBytes != null ? BigInt(it.sizeBytes) : null,
            dateAddedMs: it.dateAddedMs != null ? BigInt(it.dateAddedMs) : null,
            dateModifiedMs: it.dateModifiedMs != null ? BigInt(it.dateModifiedMs) : null,
            width: it.width ?? null,
            height: it.height ?? null,
            durationMs: it.durationMs != null ? BigInt(it.durationMs) : null,
            thumbnailBase64: it.thumbnailBase64 ?? null,
            capturedAt: BigInt(it.capturedAt),
            folderCategory: it.folderCategory ?? null,
            relativePath: it.relativePath ?? null,
        };
        return prisma.mediaItem.upsert({
            where: { clientItemId: it.clientItemId },
            update: {
                ...commonFields,
                // A changed hash means new content is coming — drop back to pending until the PUT lands.
                contentHash: it.contentHash ?? prev?.contentHash ?? null,
                syncStatus: keepUploaded ? "uploaded" : "pending",
            },
            create: {
                ...commonFields,
                clientItemId: it.clientItemId,
                contentHash: it.contentHash ?? null,
                syncStatus: "pending",
            },
        });
    }));
    const refreshed = await prisma.mediaItem.findMany({
        where: { clientItemId: { in: items.map((it) => it.clientItemId) } },
        select: { clientItemId: true, syncStatus: true },
    });
    res.json({
        needsContent: refreshed.filter((r) => r.syncStatus !== "uploaded").map((r) => r.clientItemId),
        upToDate: refreshed.filter((r) => r.syncStatus === "uploaded").map((r) => r.clientItemId),
    });
});
/**
 * PUT /v1/storage/sync/:clientItemId/content
 * Auth: Bearer <enrollmentToken> + X-Device-Id header (the item must already exist for that
 * device — created by a prior call to /negotiate).
 * Body: raw file bytes, Content-Type: application/octet-stream. Streamed to a per-device
 * directory outside the repo tree, capped at MAX_CONTENT_BYTES, never buffered as JSON.
 */
storageSyncRouter.put("/v1/storage/sync/:clientItemId/content", express.raw({ type: "application/octet-stream", limit: MAX_CONTENT_BYTES }), async (req, res) => {
    const token = bearerToken(req.header("authorization"));
    const deviceId = req.header("x-device-id") ?? "";
    if (!token || !deviceId)
        return res.status(400).json({ error: "X-Device-Id header and bearer token required" });
    const auth = await resolveDevice(deviceId, token, req.header("x-device-label"));
    if (!auth.ok)
        return res.status(403).json({ error: "device/token mismatch" });
    const { clientItemId } = req.params;
    if (!SAFE_CLIENT_ITEM_ID.test(clientItemId)) {
        return res.status(400).json({ error: "invalid clientItemId" });
    }
    const item = await prisma.mediaItem.findUnique({ where: { clientItemId } });
    if (!item || item.deviceId !== deviceId) {
        return res.status(404).json({ error: "no matching item for this device — call /negotiate first" });
    }
    const body = req.body;
    if (!Buffer.isBuffer(body) || body.length === 0) {
        return res.status(400).json({ error: "expected a non-empty application/octet-stream body" });
    }
    const dir = deviceMediaDir(deviceId);
    await fsp.mkdir(dir, { recursive: true });
    const storedPath = path.join(dir, clientItemId);
    await fsp.writeFile(storedPath, body);
    await prisma.mediaItem.update({
        where: { clientItemId },
        data: {
            syncStatus: "uploaded",
            contentSizeBytes: BigInt(body.length),
            storedPath: path.relative(MEDIA_STORE_DIR, storedPath),
            syncedAt: new Date(),
        },
    });
    res.json({ ok: true, sizeBytes: body.length });
});
