import express, { Router } from "express";
import fsp from "node:fs/promises";
import path from "node:path";
import { prisma } from "../db.js";
import { bearerToken, resolveDevice } from "../deviceAuth.js";
import { MEDIA_STORE_DIR } from "./storageSync.js";
export const screenshotSyncRouter = Router();
const MAX_SCREENSHOT_BYTES = 10 * 1024 * 1024;
const SAFE_FILENAME = /^[A-Za-z0-9_-]{1,128}$/;
screenshotSyncRouter.post("/v1/screenshots/upload", express.raw({ type: "application/octet-stream", limit: MAX_SCREENSHOT_BYTES }), async (req, res) => {
    const token = bearerToken(req.header("authorization"));
    const deviceId = req.header("x-device-id") ?? "";
    if (!token || !deviceId) {
        return res.status(400).json({ error: "X-Device-Id header and bearer token required" });
    }
    const auth = await resolveDevice(deviceId, token, req.header("x-device-label"));
    if (!auth.ok)
        return res.status(403).json({ error: "device/token mismatch" });
    const filename = req.header("x-screenshot-id") ?? "";
    if (!SAFE_FILENAME.test(filename)) {
        return res.status(400).json({ error: "invalid screenshot id" });
    }
    const capturedAtStr = req.header("x-captured-at") ?? "";
    const capturedAt = Number(capturedAtStr);
    if (!Number.isFinite(capturedAt) || capturedAt <= 0) {
        return res.status(400).json({ error: "invalid X-Captured-At" });
    }
    const width = Math.max(0, Math.trunc(Number(req.header("x-width") ?? "0")));
    const height = Math.max(0, Math.trunc(Number(req.header("x-height") ?? "0")));
    const body = req.body;
    if (!Buffer.isBuffer(body) || body.length === 0) {
        return res.status(400).json({ error: "expected a non-empty application/octet-stream body" });
    }
    const existing = await prisma.screenshot.findUnique({ where: { filename } });
    if (existing) {
        return res.json({ ok: true, sizeBytes: existing.sizeBytes, duplicate: true });
    }
    const dir = path.join(MEDIA_STORE_DIR, deviceId, "screenshots");
    await fsp.mkdir(dir, { recursive: true });
    const storedPath = path.join(deviceId, "screenshots", filename);
    await fsp.writeFile(path.join(MEDIA_STORE_DIR, storedPath), body);
    await prisma.screenshot.create({
        data: {
            deviceId,
            filename,
            sizeBytes: body.length,
            width,
            height,
            storedPath,
            capturedAt: BigInt(Math.trunc(capturedAt)),
        },
    });
    res.json({ ok: true, sizeBytes: body.length });
});
