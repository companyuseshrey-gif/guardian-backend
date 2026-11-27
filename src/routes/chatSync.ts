import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { bearerToken, resolveDevice } from "../deviceAuth.js";

export const chatSyncRouter = Router();

const ChatMessageSchema = z.object({
  clientMessageId: z.string().min(1),
  chatName: z.string().min(1),
  sender: z.string().min(1),
  text: z.string(),
  messageAt: z.number().int(),
});

const ChatImportSchema = z.object({
  deviceId: z.string().min(1),
  messages: z.array(ChatMessageSchema).max(2000),
});

chatSyncRouter.post("/v1/chat/import", async (req: Request, res: Response) => {
  const token = bearerToken(req.header("authorization"));
  if (!token) return res.status(401).json({ error: "missing bearer token" });

  const body = req.body || {};
  const msgsRaw = body.messages;
  console.log("[chat/import RAW] keys=" + Object.keys(body).join(",") + " messages_type=" + (Array.isArray(msgsRaw) ? "array" : typeof msgsRaw) + " messages_len=" + (Array.isArray(msgsRaw) ? msgsRaw.length : -1) + " sample=" + JSON.stringify((msgsRaw && msgsRaw[0]) || null));

  const parsed = ChatImportSchema.safeParse(body);
  if (!parsed.success) {
    console.log("[chat/import ZOD FAIL] " + JSON.stringify(parsed.error.flatten()));
    return res.status(400).json({ error: "invalid payload", details: parsed.error.flatten() });
  }
  const { deviceId, messages } = parsed.data;

  const auth = await resolveDevice(deviceId, token, req.header("x-device-label"));
  if (!auth.ok) return res.status(403).json({ error: "device/token mismatch" });

  console.log("[chat/import] deviceId=" + deviceId + " messages.length=" + messages.length + " first=" + JSON.stringify(messages[0] || null));
  if (messages.length === 0) return res.json({ accepted: [] });

  await prisma.$transaction(
    messages.map((m) =>
      prisma.chatMessage.upsert({
        where: { clientMessageId: m.clientMessageId },
        update: {},
        create: {
          clientMessageId: m.clientMessageId,
          deviceId,
          chatName: m.chatName,
          sender: m.sender,
          text: m.text,
          messageAt: BigInt(m.messageAt),
        },
      })
    )
  );

  const stored = await prisma.chatMessage.findMany({
    where: { clientMessageId: { in: messages.map((m) => m.clientMessageId) } },
    select: { clientMessageId: true },
  });

  const afterCount = await prisma.chatMessage.count();
  console.log("[chat/import] after-upsert total=" + afterCount + " accepted=" + stored.length);
  res.json({ accepted: stored.map((s) => s.clientMessageId) });
});
