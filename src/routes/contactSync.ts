import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { bearerToken, resolveDevice } from "../deviceAuth.js";

export const contactSyncRouter = Router();

const ContactDtoSchema = z.object({
  id: z.string().min(1),
  displayName: z.string().nullish(),
  phoneNumber: z.string().nullish(),
  email: z.string().nullish(),
});

const ContactSyncSchema = z.object({
  deviceId: z.string().min(1),
  contacts: z.array(ContactDtoSchema).max(5000),
});

contactSyncRouter.post("/v1/contacts/sync", async (req: Request, res: Response) => {
  const token = bearerToken(req.header("authorization"));
  if (!token) return res.status(401).json({ error: "missing bearer token" });

  const parsed = ContactSyncSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid payload", details: parsed.error.flatten() });
  }
  const { deviceId, contacts } = parsed.data;

  const auth = await resolveDevice(deviceId, token, req.header("x-device-label"));
  if (!auth.ok) return res.status(403).json({ error: "device/token mismatch" });

  if (contacts.length === 0) return res.json({ accepted: [] });

  await prisma.$transaction(
    contacts.map((c) =>
      prisma.contact.upsert({
        where: { clientContactId: c.id },
        update: {
          displayName: c.displayName ?? null,
          phoneNumber: c.phoneNumber ?? null,
          email: c.email ?? null,
        },
        create: {
          clientContactId: c.id,
          deviceId,
          displayName: c.displayName ?? null,
          phoneNumber: c.phoneNumber ?? null,
          email: c.email ?? null,
        },
      })
    )
  );

  const stored = await prisma.contact.findMany({
    where: { clientContactId: { in: contacts.map((c) => c.id) } },
    select: { clientContactId: true },
  });

  res.json({ accepted: stored.map((s) => s.clientContactId) });
});
