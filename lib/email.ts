import nodemailer from "nodemailer";

const transport = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT ?? 587),
  secure: Number(process.env.SMTP_PORT ?? 587) === 465,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

export async function sendOtpEmail(opts: {
  to: string;
  subject: string;
  code: string;
  actionUrl: string;
  expiresMinutes: number;
}) {
  const { to, subject, code, actionUrl, expiresMinutes } = opts;
  const html = `
    <div style="font-family:ui-sans-serif">
      <h2>${subject}</h2>
      <p>Your code:</p>
      <div style="font-size:28px;font-weight:700;letter-spacing:3px">${code}</div>
      <p>Expires in ${expiresMinutes} minutes.</p>
      <p>Or click:</p>
      <p><a href="${actionUrl}">${actionUrl}</a></p>
      <p>If you didn’t request this, ignore this email.</p>
    </div>
  `;
  await transport.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject,
    html,
  });
}
