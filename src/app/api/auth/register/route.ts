import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { hashPassword } from "@/lib/crypto";
import { issueToken } from "@/lib/tokens";
import { sendOtpEmail } from "@/lib/email";

export async function POST(req: Request) {
  try {
    const { email, password } = await req.json();
    if (typeof email !== "string" || typeof password !== "string") {
      return NextResponse.json({ error: "Invalid input." }, { status: 400 });
    }
    const normalizedEmail = email.trim().toLowerCase();
    const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (existing) return NextResponse.json({ error: "Email already registered." }, { status: 409 });

    const user = await prisma.user.create({
      data: { email: normalizedEmail, passwordHash: hashPassword(password) },
    });
    const { code } = await issueToken({ userId: user.id, email: user.email, type: "verify_email" });
    const actionUrl = `${process.env.APP_ORIGIN}/verify?email=${encodeURIComponent(user.email)}&type=verify_email`;
    await sendOtpEmail({
      to: user.email,
      subject: "Verify your email",
      code,
      actionUrl,
      expiresMinutes: Number(process.env.TOKEN_TTL_MINUTES ?? 15),
    });
    return NextResponse.json({ ok: true });
  } catch (e: any) {
    return NextResponse.json({ error: e.message ?? "Server error" }, { status: 400 });
  }
}
