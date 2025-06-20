const { Resend } = require("resend");
const resend = new Resend(process.env.RESEND_API_KEY);

exports.sendOtpEmail = async (email, otp) => {
  try {
    await resend.emails.send({
      from: "Your Agency <onboarding@resend.dev>",
      to: email,
      subject: "Your OTP Code",
      html: `<p>Your OTP code is: <strong>${otp}</strong>. It will expire in 5 minutes.</p>`,
    });
  } catch (error) {
    console.error("Error sending OTP email:", error);
  }
};
