import express from 'express'
import upload from '../configs/multer.js'
import { body, param, query, validationResult, header } from 'express-validator'
import { error_def } from '../utils/error_def.js'
import bcrypt from '../configs/bcrypt.js'
import User from '../db/userSchema.js'
import Task from '../db/taskSchema.js'
import crypto from 'crypto'
import sendMail from '../configs/nodemailer.js'
import { cloudinaryDelete, cloudinaryUpload } from '../configs/cloudinary.js'
import { sendVerificationEmail, sendPasswordResetEmail, sendMagicLinkEmail } from '../utils/emails.js'
import { generateAccessToken, generateRefreshToken } from '../utils/tokens.js'
import { prepareUserResponse } from '../utils/prepareResponse.js'
import passport from 'passport'
import { reportAPIRateLimitError, reportEmailAlreadyExistsError, reportInvalidEmailError, reportInvalidPasswordLengthError, reportInvalidRedirectURLError, reportInvalidRequestTokenError, reportInvalidUserUpdateError, reportUserNotFoundError } from '../utils/errorReporters.js'
import jwt from 'jsonwebtoken';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit'


const router = express.Router()


// create rate limiter for Auth endpoints
const authRateLimiter = rateLimit({
    windowMs: 1000 * 60 * 15,
    max: 5,
    headers: false,
    keyGenerator: function( req, res ) {
        return req.user ? req.user.id : ipKeyGenerator( req, res )
    },
    handler: function( req, res, next, options ) {
        reportAPIRateLimitError( next )
    }
})

router.use( authRateLimiter )


router.post('/register-user',
    upload.single('photo'), 
    body('email').exists().withMessage( error_def.INVALID_EMAIL ).bail()
    .isEmail().normalizeEmail().withMessage(error_def.INVALID_EMAIL).bail(),
    body('password').exists().withMessage( error_def.INVALID_PASSWORD ).bail()
    .isLength({ min: 6 }).withMessage(error_def.INVALID_PASSWORD_LENGTH).bail(),
    body('name').isAlphanumeric().withMessage(error_def.INVALID_NAME).bail(),  
    async function( req, res, next ) {
        const errors = validationResult( req )
        const emailRedirectURL = decodeURIComponent(req.query.emailredirect)

        // validate incoming request data
        if ( !errors.isEmpty() ) {
            switch( errors.array()[0].msg ) {
                case "Invalid_Email_Address":
                    const invalidEmailError = new Error("invalid email found in signup")
                    invalidEmailError.errorCode = 'Invalid_Email_Address'
                    invalidEmailError.statusCode = 400
                return next( invalidEmailError )
                
                case "Invalid_Password_Length":
                    const invalidPasswordError = new Error("password must be greater than 6 characters")
                    invalidPasswordError.errorCode = 'Invalid_Password_Length'
                    invalidPasswordError.statusCode = 400
                return next( invalidPasswordError )
                
                case "Invalid_Name":
                    const invalidUsernameError = new Error("invalid user name found in signup")
                    invalidUsernameError.errorCode = 'Invalid_Name'
                    invalidUsernameError.statusCode = 400
                return next( invalidUsernameError )
            }
        }

        if ( !emailRedirectURL ) {
            const invalidRedirectURLError = new Error("invalid redirect url found in request")
            invalidRedirectURLError.errorCode = error_def.INVALID_REDIRECT
            invalidRedirectURLError.statusCode = 400
            return next( invalidRedirectURLError )
        }

        // initi variables for storing photo upload data
        let profilePublicURL = ''
        let profilePublicId = ''

        // upload user profile-photo and get the public URL
        try {
            const uploadResult =  await cloudinaryUpload( req.file.buffer )

            profilePublicId = uploadResult.public_id
            profilePublicURL = uploadResult.url

        } catch( error ) {
            error.errorCode = error_def.ERROR_FILE_UPLOAD
            error.statusCode = 500
            return next( error )
        }


        // get user registration data from request
        const newUserEmail = req.body.email
        const newUserName = req.body.name
        const newUserPassword = req.body.password

        try {
            // hash user password
            const hashedPassword = await bcrypt.hash( newUserPassword, 10 )

            // create email verification data
            const emailVerificationToken = crypto.randomBytes(32).toString('hex')
            const emailVerificationExpiry = Date.now() + 5 * 60 * 1000
            
            // create user in database
            const newUserData = await User.create({
                email: newUserEmail,
                password: hashedPassword,
                name: newUserName,
                provider: 'email',
                profileURL: profilePublicURL,
                profileId: profilePublicId,
                emailVerificationToken: emailVerificationToken,
                emailVerificationExpiry: emailVerificationExpiry
            })
            
            // send verification email
            const verificationEmail = `
                <h1>
                    Confirm Your Signup
                </h1>
                <p>
                    Hello, Welcome to the Tasks App. Finish Your Registration
                    using the link below
                </p>
                <a href="${ emailRedirectURL }${emailVerificationToken}">
                    Finish Your Signup
                </a>
            `
            await sendMail( newUserEmail, 'Confirm Your Signup', verificationEmail )

            // send success response since no errors
            res.status( 201 ).json({
                status: "success",
                data: "User account created"
            })
        } catch( err ) {
            // send any error encountered during execution
            err.errorCode = error_def.SERVER_ERROR
            next( err )
        }
    }
)

router.put("/update-user",
    passport.authenticate( 'jwt', { session: false} ),
    upload.single("photo"), [
    body("email")
        .optional()
        .isEmail()
        .normalizeEmail()
        .withMessage( error_def.INVALID_EMAIL )
        .bail(),
    body("password")
        .optional()
        .isLength({ min: 6 })
        .withMessage( error_def.INVALID_PASSWORD_LENGTH )
        .bail()
], async function( req, res, next ){
    // validate incoming data
    const errors = validationResult( req )

    // check for validation errors and report them if any
    if ( !errors.isEmpty() ) {
        switch( errors.array()[0].msg ) {
            case error_def.INVALID_EMAIL:
                return reportInvalidEmailError( next )
            case error_def.INVALID_PASSWORD_LENGTH:
                return reportInvalidPasswordLengthError( next )
        }
    }

    try {
        // retrieve new user data from request
        const newPhoto = req.file
        const newEmail = req.body.email
        const newPassword = req.body.password

        // get the user data from database
        const userToUpdate = await User.findOne({ _id: req.user._id })

        // check if user exists, if not, report user-not-found error
        if ( !userToUpdate ) {
            return reportUserNotFoundError( next )
        }

        // check if user is not using email provider( maybe google 
        // or magiclink ) to login, if so, report invalid user update error 
        if ( userToUpdate.provider !== 'email' ) {
            return reportInvalidUserUpdateError( next )
        }

        // check if any other user is using the new email, if so,
        // report email-already-exists error
        const otherUserWithNewEmail = await User.findOne({ email: newEmail })
        if ( otherUserWithNewEmail ) {
            return reportEmailAlreadyExistsError( next )
        }

        // since no errors, proceed to update user data
        
        // update user profile photo if any
        if ( newPhoto ) {
            // get cloudinary profile id from user data
            const profileId = userToUpdate.profileId

            // check if user has existing profile photo and delete it 
            // on cloudinary
            if ( profileId ) {
                await cloudinaryDelete( profileId )
            }

            // after delete operation, upload new profile photo
            const uploadResult = await cloudinaryUpload( newPhoto.buffer )

            userToUpdate.profileId = uploadResult.public_id
            userToUpdate.profileURL = uploadResult.url
        }

        // update user email if any
        if ( newEmail ) {
            userToUpdate.email = newEmail
        }

        // update user password if any
        if ( newPassword ) {
            const hashedPassword = await bcrypt.hash( newPassword, 10 )
            userToUpdate.password = hashedPassword
        }

        // save updated user data to database
        const savedUser = await userToUpdate.save()

        // information to return in response
        const { refreshToken, ...userData } = prepareUserResponse( savedUser )

        // send success response
        res.json({
            status: "success",
            data: userData
        })
    } catch( err ) {
        err.errorCode = error_def.SERVER_ERROR
        return next( err )
    }
})

router.post('/verify', 
    [
        body('email').exists().withMessage( error_def.INVALID_EMAIL ).bail()
        .isEmail().normalizeEmail().withMessage( error_def.INVALID_EMAIL ).bail()
    ],
    async function( req, res, next ) {
        // get request validation results
        const errors = validationResult( req )
        const emailRedirectURL = decodeURIComponent(req.query.emailredirect)

        // check if any errors in validation 
        // and send appropriate response
        if ( !errors.isEmpty() ) {
            const errorMessage = errors.array()[0]

            const invalidEmailError = new Error("invalid email found in signup")
            invalidEmailError.errorCode = errorMessage
            invalidEmailError.statusCode = 400
            return next( invalidEmailError )
        }

        if ( !emailRedirectURL ) {
            const invalidRedirectURLError = new Error("invalid redirect url found in request")
            invalidRedirectURLError.errorCode = error_def.INVALID_REDIRECT
            invalidRedirectURLError.statusCode = 400
            return next( invalidRedirectURLError )
        }

        try {
            // get user data to verify from database
            const userToVerifyEmail = await User.findOne({ email: req.body.email })

            if ( userToVerifyEmail ) {
                // create email verification data
                const emailVerificationToken = crypto.randomBytes(32).toString('hex')
                const emailVerificationExpiry = Date.now() + 5 * 60 * 1000

                userToVerifyEmail.emailVerificationToken = emailVerificationToken
                userToVerifyEmail.emailVerificationExpiry = emailVerificationExpiry

                await userToVerifyEmail.save()

                // send verification email
                await sendVerificationEmail( req.body.email, emailVerificationToken, emailRedirectURL )

                // send success response since no errors
                res.json({
                    status: "success",
                    data: "Email verification sent"
                })
            } else {
                const userNotFoundError = new Error("No user with that email was found")
                userNotFoundError.errorCode = error_def.USER_NOT_FOUND
                userNotFoundError.statusCode = 400
                next( userNotFoundError )
            }
        } catch( err ) {
            err.errorCode = error_def.SERVER_ERROR
            next( err )
        }
    }
)

router.get('/verify/:token', 
    async function( req, res, next ) {
        // get email verification token from frontend
        const token = req.params.token

        // validate verification token
        if ( !token ) {
            const invalidRequestTokenError = new Error("Invalid Email Verification Token")
            invalidRequestTokenError.errorCode = error_def.INVALID_REQUEST_TOKEN
            invalidRequestTokenError.statusCode = 400
            return next( invalidRequestTokenError )
        }

        try {
            // get user data to verify from database
            const userToVerifyEmail = await User.findOne({
                    emailVerificationToken: token,
                    emailVerificationExpiry: { $gt: Date.now() }
                })

            // check if there's any defined user
            if ( userToVerifyEmail ) {
                // reset verification data on user on database
                userToVerifyEmail.emailVerificationToken = ""
                userToVerifyEmail.emailVerificationExpiry = null

                // create welcome task for user
                await Task.create({
                    text: "Welcome to Tasks App! This is your first task. ",
                    user_id: userToVerifyEmail._id
                })

                // update user email verification status
                userToVerifyEmail.emailVerified = true

                // generate auth access and refresh tokens
                const accessToken = generateAccessToken( userToVerifyEmail._id )
                const refreshToken = generateRefreshToken( userToVerifyEmail._id )

                // update user with auth tokens
                userToVerifyEmail.refreshToken = refreshToken;

                // save data to database
                const updatedUser = await userToVerifyEmail.save()

                // prepare response data
                const userResponse = prepareUserResponse( updatedUser )

                // send success response with user and auth data since no errors
                res.json({
                    status: "success",
                    data: {
                        ...userResponse,
                        accessToken
                    }
                })
            } else {
                const userNotFoundError = new Error("No user requested email verification")
                userNotFoundError.errorCode = error_def.USER_NOT_FOUND
                userNotFoundError.statusCode = 400
                next( userNotFoundError )
            }
        } catch( err ) {
            err.errorCode = error_def.SERVER_ERROR
            next( err )
        }
    }
)

router.post('/forgot-password', [
    body('email').exists().withMessage( error_def.INVALID_EMAIL ).bail()
    .isEmail().normalizeEmail().withMessage( error_def.INVALID_EMAIL ).bail()
], async function( req, res, next ) {
    // retrieve reset details from request
    const emailRedirect = decodeURIComponent( req.query.emailredirect )
    
    // get validation data from request
    const errors = validationResult( req )

    // check if any validation errors
    if ( !errors.isEmpty() ) {
        const invalidEmailError = new Error("invalid email found in request")
        invalidEmailError.errorCode = error_def.INVALID_EMAIL
        invalidEmailError.statusCode = 400
        return next( invalidEmailError )
    }

    // check if email-redirect link is valid
    if ( !req.query.emailredirect ) {
        const invalidRedirectURLError = new Error("invalid redirect url found in request")
        invalidRedirectURLError.errorCode = error_def.INVALID_REDIRECT
        invalidRedirectURLError.statusCode = 400
        return next( invalidRedirectURLError )
    }

    try {
        // get user with email from database if any
        const email = req.body.email
        const userToForgetPassword = await User.findOne({ email: email })

        // check if any user was found and 
        // create password reset metadata and send email
        if ( userToForgetPassword ) {
            // create password reset token and expiry metadata
            const passwordResetToken = crypto.randomBytes(32).toString("hex")
            const passwordResetExpiry = Date.now() + 1 * 60 * 60 * 1000 // 1 hour expiry

            // save password reset metadata to user data
            userToForgetPassword.passwordResetToken = passwordResetToken
            userToForgetPassword.passwordResetExpiry = passwordResetExpiry

            // save updated user data to database
            await userToForgetPassword.save()

            // send password reset email to user email
            await sendPasswordResetEmail( email, passwordResetToken, emailRedirect )

            // send success responsse since no errors
            res.json({
                status: 'success',
                data: "Password Reset Email Sent Successfully"
            })
        } else {
            // if no user with email found, report user not found error
            const userNotFoundError = new Error("user with that email was not found")
            userNotFoundError.errorCode = error_def.USER_NOT_FOUND
            userNotFoundError.statusCode = 404
            return next( userNotFoundError )
        }
    } catch( err ) {
        // report any execution errors
        err.errorCode = error_def.SERVER_ERROR
        return next( err )
    }
})

router.post('/forgot-password/:token', [
    body('password').exists().withMessage( error_def.INVALID_PASSWORD ).bail()
    .isLength({ min: 6 }).withMessage( error_def.INVALID_PASSWORD_LENGTH ).bail()
], async function( req, res, next ) {
    // get validation errors from request
    const errors = validationResult( req )

    // get password reset token from request
    const token = req.params.token

    // validate the password metadata
    if ( !errors.isEmpty() ) {
        const invalidPasswordError = new Error("invalid password for reset operation")
        invalidPasswordError.errorCode = error_def.INVALID_PASSWORD
        invalidPasswordError.statusCode = 400
        return next( invalidPasswordError )
    }

    // validate the password reset token
    if ( !token ) {
        const invalidRequestTokenError = new Error("invalid password reeset token")
        invalidRequestTokenError.errorCode = error_def.INVALID_REQUEST_TOKEN
        invalidRequestTokenError.statusCode = 400
        return next( invalidRequestTokenError )
    }

    try {
        // get password reset metadata from the request
        const newPassword = req.body.password 

        // retrieve user from database based on password reset metadata
        const userToResetPassword = await User.findOne({
            passwordResetToken: token,
            passwordResetExpiry: { $gt: Date.now() }
        })

        if ( userToResetPassword ) {
            // hash new password
            const hashedPassword = await bcrypt.hash( newPassword, 10 )

            // update user data with new hashed password
            userToResetPassword.password = hashedPassword

            // reset the password reset metadata from user data
            userToResetPassword.passwordResetToken = ""
            userToResetPassword.passwordResetExpiry = null

            // generate new refresh and access token for user auth
            const accessToken = generateAccessToken()
            const refreshToken = generateRefreshToken()

            // update user with the access and refresh tokens
            userToResetPassword.refreshToken = refreshToken

            // save all user auth updates to database
            const updatedUser = await userToResetPassword.save()

            // prepare response data
            const userResponse = prepareUserResponse( updatedUser )

            // send success reponse since no errors
            res.json({
                status: "success",
                data: {
                    ...userResponse,
                    accessToken
                }
            })
        } else {
            const userNotFoundError = new Error('no user requested that password reset')
            userNotFoundError.errorCode = error_def.USER_NOT_FOUND
            userNotFoundError.statusCode = 404
            return next( userNotFoundError )
        }
    } catch( err ) {
        // report any errors during execution
        err.errorCode = error_def.SERVER_ERROR
        return next( err )
    }
})

router.post('/login-user', [
    body('email').exists().withMessage( error_def.INVALID_EMAIL ).bail()
    .isEmail().normalizeEmail().withMessage( error_def.INVALID_EMAIL ).bail(),
    body('password').exists().withMessage( error_def.INVALID_PASSWORD_LENGTH ).bail()
    .isLength({ min: 6 }).withMessage( error_def.INVALID_PASSWORD_LENGTH ).bail()
], 
    passport.authenticate('local', { session: false })
, async function( req, res, next ) {
    const errors = validationResult( req )

    if ( !errors.isEmpty() ) {
        switch( errors.array()[0] ) {
            case error_def.INVALID_EMAIL: 
                const invalidEmailError = new Error("invalid email address in request")
                invalidEmailError.errorCode = error_def.INVALID_EMAIL
                invalidEmailError.statusCode = 400
                return next( invalidEmailError )
            
            case error_def.INVALID_PASSWORD_LENGTH: 
                const invalidPasswordLengthError = new Error("invalid password: password must be at least 6 characters long")
                invalidPasswordLengthError.errorCode = error_def.INVALID_PASSWORD_LENGTH
                invalidPasswordLengthError.statusCode = 400
                return next( invalidPasswordLengthError )
        }
    }

    try {
        if ( req.user ) {
            const accessToken = generateAccessToken( req.user._id )
            const refreshToken = generateRefreshToken( req.user._id )

            const loginUser = await User.findOne( { email: req.user.email} )

            loginUser.refreshToken = refreshToken

            const updatedUser = await loginUser.save()

            res.json({
                status: "success",
                data: {
                    ...prepareUserResponse( updatedUser ),
                    accessToken
                }
            })
        } else {
            const userNotFoundError = new Error("no user with that login credentials was found")
            userNotFoundError.errorCode = error_def.USER_NOT_FOUND
            userNotFoundError.statusCode = 404
            return next( userNotFoundError )
        }
    } catch( err ) {
        err.errorCode = error_def.SERVER_ERROR
        return next( err )
    }
})

router.post("/magiclink", [
    body("email").exists().withMessage( error_def.INVALID_EMAIL ).bail()
    .isEmail().normalizeEmail().withMessage( error_def.INVALID_EMAIL ).bail(),
    query('emailredirect').exists().withMessage( error_def.INVALID_REDIRECT ).bail()
    .isString().withMessage( error_def.INVALID_REDIRECT ).bail()
], async function( req, res, next ) {
    // get validation results from the request
    const errors = validationResult( req )

    // check for validation errors and report them if any
    if ( !errors.isEmpty() ) {
        switch( errors.array()[0].msg ) {
            // report invalid email error
            case error_def.INVALID_EMAIL:
                return reportInvalidEmailError( next )

            // report invalid redirect url error
            case error_def.INVALID_REDIRECT:
                return reportInvalidRedirectURLError( next )
        }
    }

    // get the email redirect URL, email from the request body
    const emailRedirectURL = decodeURIComponent( req.query.emailredirect )
    const email = req.body.email

    // generate token for magic link login 
    const magicLinkToken = crypto.randomBytes( 32 ).toString("hex")

    try {
        // retrieve user with the email from the request in the database
        const userToSignUsingMagicLink = await User.findOne({ email: email })

        // check retrieved user, if any, 
        // if not, report user not found error
        if ( userToSignUsingMagicLink ) {
            // update retrieved user with magiclink auth metadata
            userToSignUsingMagicLink.magicLinkToken = magicLinkToken
            userToSignUsingMagicLink.magicLinkExpiry = Date.now() + ( 1 * 60 * 60 * 1000 ) // 1 hour expiry

            // save user with new auth metadata
            await userToSignUsingMagicLink.save()

            // send magiclink email to request email address
            await sendMagicLinkEmail( email, magicLinkToken, emailRedirectURL )

            // since no errors, send success reponse
            res.json({
                status: "success",
                data: "Magic Link sent successfully"
            })
        } else {
            // report user-not-found error since no user found
            reportUserNotFoundError( next )
        }
    } catch( err ) {
        // report any errors during code execution
        err.errorCode = error_def.SERVER_ERROR
        return next( err )
    }
})

router.get("/magiclink/:token", [
    param('token').exists().withMessage( error_def.INVALID_REQUEST_TOKEN ).bail()
    .isHexadecimal().withMessage( error_def.INVALID_REQUEST_TOKEN )
], async function( req, res, next ) {
    // get validation results from request
    const errors = validationResult( req )

    // check for validation errors, and report them if any
    if ( !errors.isEmpty() ) {
        reportInvalidRequestTokenError( next )
    }

    try {
        // retrieve magiclink token from request
        const token = req.params.token

        // retrieve user that requested magiclink 
        // using token and expiry metadata
        const userToSignIn = await User.findOne({
            magicLinkToken: token,
            magicLinkExpiry: { $gt: new Date() }
        })

        // check if retrieved user is valid, 
        // if not, report user-not-found error
        if ( userToSignIn )  {
            // remove the magiclink auth metadata from user 
            // database in database
            userToSignIn.magicLinkToken = ""
            userToSignIn.magicLinkExpiry = null

            // generate the accessToken and refreshToken for user
            const accessToken = generateAccessToken( userToSignIn._id )
            const refreshToken = generateRefreshToken( userToSignIn._id )

            // save refreshToken to user data on database 
            userToSignIn.refreshToken = refreshToken

            // save updated user data to database
            const updatedUser = await userToSignIn.save()

            // prepare user data for success response
            const userResponse = prepareUserResponse( updatedUser )

            // since no errors, send success response with user/auth data
            res.json({
                ...userResponse,
                accessToken
            })
        } else {
            // since no user found, report error
            reportUserNotFoundError( next )
        }
    } catch( err ) {
        // report any code execution error
        err.errorCode = error_def.SERVER_ERROR
        return next( err )
    }
})

router.get("/google",[
    query('redirect').exists().withMessage( error_def.INVALID_REDIRECT ).bail()
    .isURL({ require_tld: false }).withMessage(error_def.INVALID_REDIRECT)
], function( req, res, next ) {
    const errors = validationResult( req )

    if ( !errors.isEmpty() ) {
        return reportInvalidRedirectURLError( next )
    }

    passport.authenticate( "google", { 
        scope: [ "profile", "email" ], 
        state: encodeURIComponent( req.query.redirect )
    } )( req, res, next )
} )

router.get("/google/callback", 
    passport.authenticate( "google", { session: false } ),
    async function( req, res, next ) {
        try {
            // get auth redirect url from oauth state
            const redirect = decodeURIComponent( req.query.state )
            
            // get user details from oauth window
            const username = req.user.displayName
            const userEmail = req.user.emails[0].value
            const userProfileURL = req.user.photos[0].value
            
            // check if user email exists on the database and return
            // auth tokens, if not, create new user and return
            // auth tokens
            const authUser = await User.findOne({ email: userEmail })


            if ( authUser ) {
                // generate access and refresh tokens for user
                const accessToken = generateAccessToken( authUser._id )
                const refreshToken = generateAccessToken( authUser._id )

                // add refreshToken to user data on database
                authUser.refreshToken = refreshToken

                // save updated user data
                await authUser.save()

                // since no errors, redirect back to frontend with auth tokens
                res.redirect(`${ redirect }?a=${ accessToken }&r=${ refreshToken }`)
            } else {
                // add new user data to database
                const newUserData = await User.create({
                    email: userEmail,
                    provider: "google",
                    name: username,
                    profileURL: userProfileURL,
                    emailVerified: true
                })

                // create welcome task for user
                await Task.create({
                    text: "Welcome to Tasks App! This is your first task. ",
                    user_id: newUserData._id
                })

                // generate access and refresh tokens for new user
                const accessToken = generateAccessToken( newUserData._id )
                const refreshToken = generateAccessToken( newUserData._id )

                // update new user data with refresh token
                newUserData.refreshToken = refreshToken

                // save updated user data to database
                await newUserData.save()

                // since no errors, send success response with new user data
                res.redirect(`${ redirect }?a=${ accessToken }&r=${ refreshToken }`)
            }
        } catch ( err ) {
            err.errorCode = error_def.SERVER_ERROR
            return next( err )
        }
    }
)

router.post("/refresh-token", [
    body('refreshToken').exists().withMessage( error_def.INVALID_REQUEST_TOKEN ).bail()
    .isJWT().withMessage( error_def.INVALID_REQUEST_TOKEN ).bail()
], async function( req, res, next ) {
    try {
        // check if any validation errors
        const errors = validationResult( req )

        // report any validation errors if any
        if ( !errors.isEmpty() ) {
            return reportInvalidRequestTokenError( next )
        }

        // get refresh token from request body
        const refreshToken = req.body.refreshToken
        console.log( "refresh token: ", refreshToken )

        // get user with refresh token
        const userToRefresh = await User.findOne({ refreshToken: refreshToken })

        // generate  and return new access token if user exists, if not,
        // return user-not-found error
        if ( userToRefresh ) {
            // generate accessToken for user
            const accessToken = generateAccessToken( userToRefresh._id )

            // return generated access token
            return res.status( 201 ).json({
                accessToken
            })
        } else {
            return reportUserNotFoundError( next )
        }
    } catch( err ) {
        err.errorCode = error_def.SERVER_ERROR
        return next( err )
    }
})

router.post("/logout", [
    body('refreshToken').exists().withMessage( error_def.INVALID_REQUEST_TOKEN ).bail()
    .isJWT().withMessage( error_def.INVALID_REQUEST_TOKEN ).bail()
], async function( req, res, next ) {
    try { 
        // check for validation errors
        const errors = validationResult( req )

        console.log( "logout refresh token: ", req.body.refreshToken )

        // if any validation errors, report them
        if ( !errors.isEmpty() ) {
            return reportInvalidRequestTokenError( next )
        }

        // get refresh token from request body
        const refreshToken = req.body.refreshToken

        // get user with refresh token
        const userToLogout = await User.findOne({ refreshToken: refreshToken })

        // check if any user was found then remove refreshToken, if not,
        // report user-not-found error
        if ( userToLogout ) {
            // remove refreshToken from user data
            userToLogout.refreshToken = ""

            // save updated user data
            await userToLogout.save()

            // since no errors, send success response
            res.json({
                status: "success"
            })
        } else {
            return reportUserNotFoundError( next )
        }
    } catch( err ) {
        err.errorCode = error_def.SERVER_ERROR
        return next( err )
    }
})

router.get('/me', [
    header('authorization').exists().withMessage( error_def.INVALID_REQUEST_TOKEN ).bail()
    .matches(/^Bearer\s.+$/).withMessage( error_def.INVALID_REQUEST_TOKEN ).bail()
], async function( req, res, next ) {
    // check if any validation errors and report them
    const errors = validationResult( req )

    if ( !errors.isEmpty() ) {
        return reportInvalidRequestTokenError( next )
    }

    try {
        // get token from authorization header
        const accessToken = req.headers['authorization']

        // remove bearer ( Bearer <token> ) and extract actual token
        const token = accessToken.split(" ")[1]

        // decode JWT token from request
        const tokenData = jwt.verify( token, process.env.JWT_SECRET );

        // find user with id from the token
        const authUser = await User.findOne({ _id: tokenData.user_id })

        // check is user is found for token user_id and return user data,
        // if not, return user-not-found error
        if ( authUser )  {
            const userResponse = prepareUserResponse( authUser )

            res.json({
                status: "success",
                data: userResponse
            })
        } else {
            return reportUserNotFoundError( next )
        }
    } catch ( err ) {
        err.errorCode = error_def.SERVER_ERROR
        return next( err )
    }
})

export default router