import sendMail from "../configs/nodemailer.js"

async function sendVerificationEmail( email, emailVerificationToken, emailRedirectURL ) {
    // send verification email
    const verificationEmail = `
        <h1>
            Confirm Your Signup
        </h1>
        <p>
            Hello, Welcome to the Tasks App. Finish Your Registration
            using the link below
        </p>
        <a href="${emailRedirectURL}${ emailVerificationToken }">
            Finish Your Signup
        </a>
    `
    // return sendMail( email, 'Confirm Your Signup', verificationEmail )
    return true
}

async function sendPasswordResetEmail( email, passwordResetToken, passwordResetRedirectURL ) {
    // send verification email
    const passwordResetEmail = `
        <h1>
            Reset Your Password
        </h1>
        <p>
            You just requested to reset your password. 
            Use the link below to reset your password.

            <br />

            if this wasn't you, kindly ignore this email
        </p>
        <a href="${passwordResetRedirectURL}${ passwordResetToken }">
            Reset your password
        </a>
    `
    // return sendMail( email, 'Reset Your Password', passwordResetEmail )
    return true
}

async function sendMagicLinkEmail( email, magicLinkToken, magicLinkRedirectURL ) {
    // send verification email
    const magicLinkEmail = `
        <h1>
            Sign In To Your Account
        </h1>
        <p>
            You just requested a passwordless signin to your account.
            Use the link below to signin to your account

            <br />

            if this wasn't you, kindly ignore this email
        </p>
        <a href="${magicLinkRedirectURL}${ magicLinkToken }">
            sign in your account
        </a>
    `
    // return sendMail( email, 'Sign In To Your Account', magicLinkEmail )
    return true
}

export { sendVerificationEmail, sendPasswordResetEmail, sendMagicLinkEmail }