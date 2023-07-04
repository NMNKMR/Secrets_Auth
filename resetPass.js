const nodemailer = require('nodemailer');

async function configureNodemailer() {
    // Create a Nodemailer transporter
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: 'namangoel55@gmail.com', // Replace with your Gmail address
        pass: process.env.PASS, // Replace with your Gmail password or an application-specific password if you have 2-Step Verification enabled
      },
    });
  
    return transporter;
}

async function sendEmail(email, userID, token) {
    const transporter = await configureNodemailer();
    const resetUrl = `http://localhost:3000/resetpassword/${userID}/${token}`;

    // Define the email details
    const mailOptions = {
      from: 'namangoel55@gmail.com', // Replace with your email address
      to: email, // Replace with the recipient's email address
      subject: 'Reset Password Link',
      html: `<p>Click the following link to reset your password ( valid upto 2 minutes ): <a href="${resetUrl}">${resetUrl}</a></p>`
    };
  
    // Send the email
    const info = await transporter.sendMail(mailOptions);
  
    console.log('Email sent:', info.messageId);
}

module.exports = {sendEmail};