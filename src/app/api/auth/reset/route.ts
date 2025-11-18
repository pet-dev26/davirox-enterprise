import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { verifyToken } from "@/lib/tokens";
import { hashPassword } from "@/lib/crypto";

export async function POST(req: Request) {
  try {
    const { email, code, newPassword } = await req.json();
    const normalizedEmail = String(email ?? "").trim().toLowerCase();
    await verifyToken({ email: normalizedEmail, type: "reset_password", code: String(code ?? "") });
    const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (user) {
      await prisma.user.update({
        where: { id: user.id },
        data: { passwordHash: hashPassword(String(newPassword ?? "")) },
      });
      // TODO: revoke sessions if you store them.
    }
    return NextResponse.json({ ok: true });
  } catch (e: any) {
    return NextResponse.json({ error: e.message ?? "Invalid code" }, { status: 400 });
  }
}
