import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { bearerToken, resolveDevice } from "../deviceAuth.js";
export const ingestRouter = Router();
const EventSchema = z.object({
    clientEventId: z.string().min(1),
    packageName: z.string().min(1),
    appLabel: z.string(),
    // nullish() = nullable + optional: the Android client (Moshi) OMITS null fields, so
    // conversationTitle/sender arrive as a missing key for 1:1 chats, not as null.
    conversationTitle: z.string().nullish(),
    sender: z.string().nullish(),
    text: z.string(),
    isGroup: z.boolean(),
    postedAt: z.number().int(),
    capturedAt: z.number().int(),
});
const IngestSchema = z.object({
    deviceId: z.string().min(1),
    events: z.array(EventSchema).max(1000),
});
/**
 * POST /v1/ingest
 * Auth: Bearer <enrollmentToken>. The token must belong to the deviceId in the body.
 * Idempotent: dedupes on clientEventId, so retries never duplicate rows.
 * Returns the clientEventIds that are now durably stored so the client can mark them sent.
 */
ingestRouter.post("/v1/ingest", async (req, res) => {
    const token = bearerToken(req.header("authorization"));
    if (!token)
        return res.status(401).json({ error: "missing bearer token" });
    const parsed = IngestSchema.safeParse(req.body);
    if (!parsed.success) {
        // Log the validation shape only (field names + codes), never message content.
        console.log("[ingest 400] zod:", JSON.stringify(parsed.error.flatten().fieldErrors));
        return res.status(400).json({ error: "invalid payload", details: parsed.error.flatten() });
    }
    const { deviceId, events } = parsed.data;
    const auth1 = await resolveDevice(deviceId, token, req.header("x-device-label"));
    if (!auth1.ok)
        return res.status(403).json({ error: "device/token mismatch" });
    if (events.length === 0)
        return res.json({ accepted: [] });
    // Idempotent insert keyed on the unique clientEventId. upsert-with-empty-update is
    // provider-agnostic (works on Postgres in prod and SQLite locally) and, unlike
    // createMany+skipDuplicates, never errors on a repeated upload — it just no-ops.
    await prisma.$transaction(events.map((e) => prisma.event.upsert({
        where: { clientEventId: e.clientEventId },
        update: {}, // already stored → leave as-is
        create: {
            clientEventId: e.clientEventId,
            deviceId,
            packageName: e.packageName,
            appLabel: e.appLabel,
            conversationTitle: e.conversationTitle ?? null,
            sender: e.sender ?? null,
            text: e.text,
            isGroup: e.isGroup,
            postedAt: BigInt(e.postedAt),
            capturedAt: BigInt(e.capturedAt),
        },
    })));
    // Confirm what is actually stored (covers both new inserts and prior duplicates).
    const stored = await prisma.event.findMany({
        where: { clientEventId: { in: events.map((e) => e.clientEventId) } },
        select: { clientEventId: true },
    });
    res.json({ accepted: stored.map((s) => s.clientEventId) });
});
/**
 * POST /v1/heartbeat  — lightweight "I'm alive" ping so the dashboard can show the
 * device online even when no messages are arriving. Same bearer auth as ingest.
 */
ingestRouter.post("/v1/heartbeat", async (req, res) => {
    const token = bearerToken(req.header("authorization"));
    const deviceId = typeof req.body?.deviceId === "string" ? req.body.deviceId : "";
    if (!token || !deviceId)
        return res.status(400).json({ error: "deviceId and bearer token required" });
    const hb = await resolveDevice(deviceId, token, req.header("x-device-label"));
    if (!hb.ok)
        return res.status(403).json({ error: "device/token mismatch" });
    res.json({ ok: true });
});
