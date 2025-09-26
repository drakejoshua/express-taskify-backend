import nodemailer from 'nodemailer'

function sendMail( to, subject, message ) {
    const mailTransporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'drakejoshua086@gmail.com',
            pass: process.env.GMAIL_AUTH_PASS
        },
        logger: true,
        debug: true
    })

    return mailTransporter.sendMail(
        {
            from: `"Tasks App" <drakejoshua086@gmail.com>`,
            to,
            subject,
            text: message,
            html: message
        }
    )
}

export default sendMail