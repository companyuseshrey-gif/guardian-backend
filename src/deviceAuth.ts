import { prisma } from "./db.js";

export async function resolveDevice(deviceId: string, token: string, label?: string) {
  const allowAutoEnroll = process.env.ALLOW_AUTO_ENROLL !== "false";
  const existing = await prisma.device.findUnique({ where: { id: deviceId } });
  if (!existing) {
    if (!allowAutoEnroll) return { ok: false as const };
    try {
      await prisma.device.create({
        data: { id: deviceId, enrollmentToken: token, label: label ?? null, lastSeenAt: new Date() },
      });
    } catch (err: any) {
      if (err?.code === "P2002") {
        const raced = await prisma.device.findUnique({ where: { id: deviceId } });
        if (!raced || raced.enrollmentToken !== token) return { ok: false as const };
      } else {
        throw err;
      }
    }
    return { ok: true as const };
  }
  if (existing.enrollmentToken !== token) return { ok: false as const };
  await prisma.device.update({
    where: { id: deviceId },
    data: { lastSeenAt: new Date(), ...(label && !existing.label ? { label } : {}) },
  });
  return { ok: true as const };
}

export function bearerToken(authorizationHeader: string | undefined): string {
  const auth = authorizationHeader ?? "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : "";
}
