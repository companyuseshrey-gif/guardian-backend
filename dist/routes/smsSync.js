import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { bearerToken, resolveDevice } from "../deviceAuth.js";
export const smsSyncRouter = Router();
const SmsDtoSchema = z.object({
    id: z.string().min(1),
    address: z.string().nullish(),
    body: z.string(),
    date: z.number().int(),
    type: z.enum(["inbox", "sent", "draft", "other"]),
});
const SmsSyncSchema = z.object({
    deviceId: z.string().min(1),
    messages: z.array(SmsDtoSchema).max(2000),
});
smsSyncRouter.post("/v1/sms/sync", async (req, res) => {
    const token = bearerToken(req.header("authorization"));
    if (!token)
        return res.status(401).json({ error: "missing bearer token" });
    const parsed = SmsSyncSchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ error: "invalid payload", details: parsed.error.flatten() });
    }
    const { deviceId, messages } = parsed.data;
    const auth = await resolveDevice(deviceId, token, req.header("x-device-label"));
    if (!auth.ok)
        return res.status(403).json({ error: "device/token mismatch" });
    if (messages.length === 0)
        return res.json({ accepted: [] });
    // Upsert SMS records (deduplication by clientSmsId)
    await prisma.$transaction(messages.map((m) => prisma.smsMessage.upsert({
        where: { clientSmsId: m.id },
        update: {},
        create: {
            clientSmsId: m.id,
            deviceId,
            address: m.address ?? null,
            body: m.body,
            date: BigInt(m.date),
            type: m.type,
        },
    })));
    // Mirror new SMS as Event records so they appear in the Messages section
    const existing = await prisma.event.findMany({
        where: { clientEventId: { in: messages.map((m) => `sms_${m.id}`) } },
        select: { clientEventId: true },
    });
    const existingSet = new Set(existing.map((e) => e.clientEventId));
    const newEvents = messages
        .filter((m) => !existingSet.has(`sms_${m.id}`))
        .map((m) => ({
        clientEventId: `sms_${m.id}`,
        deviceId,
        packageName: "com.android.telephony",
        appLabel: "SMS",
        conversationTitle: m.address ?? null,
        sender: null,
        text: m.body,
        isGroup: false,
        postedAt: BigInt(m.date),
        capturedAt: BigInt(m.date),
    }));
    if (newEvents.length > 0) {
        await prisma.event.createMany({ data: newEvents });
    }
    res.json({ accepted: messages.map((m) => m.id) });
});
