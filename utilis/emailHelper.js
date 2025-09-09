
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config(); 
// Setup transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_SENDER,       
    pass: process.env.EMAIL_PASSWORD    
  }
});

// Reusable email sender function
const emailSender = async (to, subject, html) => {
  const mailOptions = {
    from: `<${process.env.EMAIL_USER}>`,
    to,
    subject,
    html
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(` Email sent to ${to}`);
  } catch (err) {
    console.error(` Error sending email to ${to}:`, err);
    throw err;
  }
};

// Export the utility
export default {
  emailSender
};
