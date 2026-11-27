import { prisma } from "./db.js";
export async function resolveDevice(deviceId, token, label) {
    const allowAutoEnroll = process.env.ALLOW_AUTO_ENROLL !== "false";
    const existing = await prisma.device.findUnique({ where: { id: deviceId } });
    if (!existing) {
        if (!allowAutoEnroll)
            return { ok: false };
        try {
            await prisma.device.create({
                data: { id: deviceId, enrollmentToken: token, label: label ?? null, lastSeenAt: new Date() },
            });
        }
        catch (err) {
            if (err?.code === "P2002") {
                const raced = await prisma.device.findUnique({ where: { id: deviceId } });
                if (!raced || raced.enrollmentToken !== token)
                    return { ok: false };
            }
            else {
                throw err;
            }
        }
        return { ok: true };
    }
    if (existing.enrollmentToken !== token)
        return { ok: false };
    await prisma.device.update({
        where: { id: deviceId },
        data: { lastSeenAt: new Date(), ...(label && !existing.label ? { label } : {}) },
    });
    return { ok: true };
}
export function bearerToken(authorizationHeader) {
    const auth = authorizationHeader ?? "";
    return auth.startsWith("Bearer ") ? auth.slice(7) : "";
}
