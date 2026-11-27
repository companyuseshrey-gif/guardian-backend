import express, { Router, type Request, type Response } from "express";
import fsp from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { prisma } from "../db.js";
import { bearerToken, resolveDevice } from "../deviceAuth.js";
import { MEDIA_STORE_DIR } from "./storageSync.js";

export const callSyncRouter = Router();

const CallLogEntrySchema = z.object({
  clientCallId: z.string().min(1),
  phoneNumber: z.string(),
  contactName: z.string().nullish(),
  callType: z.enum(["incoming", "outgoing", "missed", "rejected", "blocked"]),
  duration: z.number().int().min(0),
  callAt: z.number().int(),
});

const CallLogSyncSchema = z.object({
  deviceId: z.string().min(1),
  calls: z.array(CallLogEntrySchema).max(2000),
});

callSyncRouter.post("/v1/calls/sync", async (req: Request, res: Response) => {
  const token = bearerToken(req.header("authorization"));
  if (!token) return res.status(401).json({ error: "missing bearer token" });

  const parsed = CallLogSyncSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid payload", details: parsed.error.flatten() });
  }
  const { deviceId, calls } = parsed.data;

  const auth = await resolveDevice(deviceId, token, req.header("x-device-label"));
  if (!auth.ok) return res.status(403).json({ error: "device/token mismatch" });

  if (calls.length === 0) return res.json({ accepted: [] });

  await prisma.$transaction(
    calls.map((c) =>
      prisma.callLog.upsert({
        where: { clientCallId: c.clientCallId },
        // Update mutable fields that Android finalizes after the call ends.
        // phoneNumber is included so outgoing-call numbers (unknown at first sync)
        // get corrected when the device re-syncs after querying the call log.
        update: {
          phoneNumber: c.phoneNumber,
          contactName: c.contactName ?? null,
          callType: c.callType,
          duration: c.duration,
        },
        create: {
          clientCallId: c.clientCallId,
          deviceId,
          phoneNumber: c.phoneNumber,
          contactName: c.contactName ?? null,
          callType: c.callType,
          duration: c.duration,
          callAt: BigInt(c.callAt),
        },
      })
    )
  );

  const stored = await prisma.callLog.findMany({
    where: { clientCallId: { in: calls.map((c) => c.clientCallId) } },
    select: { clientCallId: true },
  });

  res.json({ accepted: stored.map((s) => s.clientCallId) });
});

const MAX_RECORDING_BYTES = 50 * 1024 * 1024;
const SAFE_REC_ID = /^[A-Za-z0-9_-]{1,128}$/;

callSyncRouter.post(
  "/v1/calls/recording/upload",
  express.raw({ type: "application/octet-stream", limit: MAX_RECORDING_BYTES }),
  async (req: Request, res: Response) => {
    const token = bearerToken(req.header("authorization"));
    const deviceId = req.header("x-device-id") ?? "";
    if (!token || !deviceId) {
      return res.status(400).json({ error: "X-Device-Id header and bearer token required" });
    }

    const auth = await resolveDevice(deviceId, token, req.header("x-device-label"));
    if (!auth.ok) return res.status(403).json({ error: "device/token mismatch" });

    const recId = req.header("x-recording-id") ?? "";
    if (!SAFE_REC_ID.test(recId)) {
      return res.status(400).json({ error: "invalid recording id" });
    }

    const callAtStr = req.header("x-call-at") ?? "";
    const callAt = Number(callAtStr);
    if (!Number.isFinite(callAt) || callAt <= 0) {
      return res.status(400).json({ error: "invalid X-Call-At" });
    }

    const phoneNumber = req.header("x-phone-number") ?? "unknown";
    const contactName = req.header("x-contact-name") || null;
    const callType = req.header("x-call-type") ?? "incoming";
    const duration = Math.max(0, Math.trunc(Number(req.header("x-duration") ?? "0")));

    const body = req.body;
    if (!Buffer.isBuffer(body) || body.length === 0) {
      return res.status(400).json({ error: "expected a non-empty application/octet-stream body" });
    }

    const existing = await prisma.callRecording.findUnique({ where: { clientRecId: recId } });
    if (existing) {
      return res.json({ ok: true, sizeBytes: existing.sizeBytes, duplicate: true });
    }

    const dir = path.join(MEDIA_STORE_DIR, deviceId, "call-recordings");
    await fsp.mkdir(dir, { recursive: true });
    const storedPath = path.join(deviceId, "call-recordings", recId);
    await fsp.writeFile(path.join(MEDIA_STORE_DIR, storedPath), body);

    await prisma.callRecording.create({
      data: {
        clientRecId: recId,
        deviceId,
        phoneNumber,
        contactName,
        callType,
        duration,
        sizeBytes: body.length,
        storedPath,
        callAt: BigInt(Math.trunc(callAt)),
      },
    });

    res.json({ ok: true, sizeBytes: body.length });
  }
);
