const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT) || 587,
  secure: Number(process.env.SMTP_PORT) === 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const sendEmail = async ({ to, subject, html }) => {
  const recipient = process.env.EMAIL_OVERRIDE_TO || to;
  if (!recipient) return null;
  try {
    const from = process.env.EMAIL_FROM || process.env.SMTP_USER;
    console.log(`[Email] from=${from} to=${recipient} subject="${subject}"`);
    const info = await transporter.sendMail({
      from: `CareLine360 <${from}>`,
      to: recipient,
      subject,
      html,
    });

    console.log("Email sent:", info.messageId);
    return info;
  } catch (error) {
    console.error("Email send error:", error.message);
  }
};

const getName = (user) => user?.fullName || user?.name || "User";

const formatDate = (date) =>
  new Date(date).toLocaleDateString("en-GB", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

const layout = (title, icon, color, body) => `
<!DOCTYPE html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/></head>
<body style="margin:0;padding:0;background:#f4f6f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8;padding:32px 16px;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.06);">
        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#0d9488,#0891b2);padding:32px 40px;text-align:center;">
            <div style="font-size:28px;margin-bottom:8px;">${icon}</div>
            <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700;letter-spacing:-0.3px;">${title}</h1>
          </td>
        </tr>
        <!-- Body -->
        <tr>
          <td style="padding:32px 40px;">
            ${body}
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="padding:24px 40px;border-top:1px solid #e5e7eb;text-align:center;">
            <p style="margin:0 0 4px;font-size:13px;color:#0d9488;font-weight:600;">CareLine360</p>
            <p style="margin:0;font-size:11px;color:#9ca3af;">Your health, our priority</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body></html>`;

const detailRow = (label, value) => `
  <tr>
    <td style="padding:10px 16px;font-size:13px;color:#6b7280;font-weight:600;border-bottom:1px solid #f3f4f6;width:140px;">${label}</td>
    <td style="padding:10px 16px;font-size:14px;color:#111827;border-bottom:1px solid #f3f4f6;">${value}</td>
  </tr>`;

const detailsTable = (rows) => `
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f9fafb;border-radius:12px;overflow:hidden;margin:20px 0;">
    ${rows}
  </table>`;

const sendAppointmentCreated = async (appointment, patient, doctor) => {
  const body = `
    <p style="margin:0 0 6px;font-size:15px;color:#374151;">Hi <strong>${getName(patient)}</strong>,</p>
    <p style="margin:0 0 20px;font-size:14px;color:#6b7280;line-height:1.6;">Your appointment has been booked successfully. Here are the details:</p>
    ${detailsTable(
      detailRow("Doctor", "Dr. " + getName(doctor)) +
      detailRow("Date", formatDate(appointment.date)) +
      detailRow("Time", appointment.time) +
      detailRow("Type", appointment.consultationType) +
      detailRow("Priority", appointment.priority)
    )}
    <p style="margin:20px 0 0;font-size:13px;color:#6b7280;line-height:1.5;">We'll send you a reminder before your appointment. If you need to make changes, please visit your dashboard.</p>`;

  await sendEmail({
    to: patient.email,
    subject: "Appointment Booked — CareLine360",
    html: layout("Appointment Booked", "📅", "#0d9488", body),
  });
};

const sendAppointmentConfirmed = async (appointment, patient, doctor) => {
  const body = `
    <p style="margin:0 0 6px;font-size:15px;color:#374151;">Hi <strong>${getName(patient)}</strong>,</p>
    <p style="margin:0 0 20px;font-size:14px;color:#6b7280;line-height:1.6;">Great news! <strong>Dr. ${getName(doctor)}</strong> has confirmed your appointment.</p>
    ${detailsTable(
      detailRow("Doctor", "Dr. " + getName(doctor)) +
      detailRow("Date", formatDate(appointment.date)) +
      detailRow("Time", appointment.time)
    )}
    <p style="margin:20px 0 0;font-size:13px;color:#6b7280;line-height:1.5;">Please make sure to be available on time. You can view or manage your appointment from your dashboard.</p>`;

  await sendEmail({
    to: patient.email,
    subject: "Appointment Confirmed — CareLine360",
    html: layout("Appointment Confirmed", "✅", "#0d9488", body),
  });
};

const sendAppointmentRescheduled = async (appointment, patient, doctor) => {
  const body = `
    <p style="margin:0 0 6px;font-size:15px;color:#374151;">Hi <strong>${getName(patient)}</strong>,</p>
    <p style="margin:0 0 20px;font-size:14px;color:#6b7280;line-height:1.6;">Your appointment with <strong>Dr. ${getName(doctor)}</strong> has been rescheduled to a new date and time.</p>
    ${detailsTable(
      detailRow("Doctor", "Dr. " + getName(doctor)) +
      detailRow("New Date", formatDate(appointment.date)) +
      detailRow("New Time", appointment.time)
    )}
    <p style="margin:20px 0 0;font-size:13px;color:#6b7280;line-height:1.5;">If this new time doesn't work for you, please contact us or reschedule from your dashboard.</p>`;

  await sendEmail({
    to: patient.email,
    subject: "Appointment Rescheduled — CareLine360",
    html: layout("Appointment Rescheduled", "🔄", "#0891b2", body),
  });
};

const sendAppointmentCancelled = async (appointment, patient, doctor) => {
  const body = `
    <p style="margin:0 0 6px;font-size:15px;color:#374151;">Hi <strong>${getName(patient)}</strong>,</p>
    <p style="margin:0 0 20px;font-size:14px;color:#6b7280;line-height:1.6;">Your appointment with <strong>Dr. ${getName(doctor)}</strong> has been cancelled.</p>
    ${detailsTable(
      detailRow("Doctor", "Dr. " + getName(doctor)) +
      detailRow("Date", formatDate(appointment.date)) +
      detailRow("Reason", appointment.cancellationReason || "Not specified")
    )}
    <p style="margin:20px 0 0;font-size:13px;color:#6b7280;line-height:1.5;">You can book a new appointment anytime from your dashboard.</p>`;

  await sendEmail({
    to: patient.email,
    subject: "Appointment Cancelled — CareLine360",
    html: layout("Appointment Cancelled", "❌", "#dc2626", body),
  });
};

const sendAppointmentReminder = async (appointment, patient, doctor) => {
  const body = `
    <p style="margin:0 0 6px;font-size:15px;color:#374151;">Hi <strong>${getName(patient)}</strong>,</p>
    <p style="margin:0 0 20px;font-size:14px;color:#6b7280;line-height:1.6;">This is a friendly reminder that your appointment is coming up soon.</p>
    ${detailsTable(
      detailRow("Doctor", "Dr. " + getName(doctor)) +
      detailRow("Date", formatDate(appointment.date)) +
      detailRow("Time", appointment.time) +
      detailRow("Type", appointment.consultationType)
    )}
    <p style="margin:20px 0 0;font-size:13px;color:#6b7280;line-height:1.5;">Please make sure to be available on time. Thank you for choosing CareLine360!</p>`;

  await sendEmail({
    to: patient.email,
    subject: "Appointment Reminder — CareLine360",
    html: layout("Appointment Reminder", "⏰", "#0d9488", body),
  });
};

module.exports = {
  sendEmail,
  sendAppointmentCreated,
  sendAppointmentConfirmed,
  sendAppointmentRescheduled,
  sendAppointmentCancelled,
  sendAppointmentReminder,
};
