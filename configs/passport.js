import { Strategy as LocalStrategy } from 'passport-local'
import { Strategy as JWTStrategy, ExtractJwt } from 'passport-jwt'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
// import passport from 'passport'
import User from '../db/userSchema.js'
import { error_def } from '../utils/error_def.js'
import bcrypt from './bcrypt.js'



function initPassportAuthStrategies( passport ) {
    // initialize passport local auth strategy for ( email/password login )
    passport.use( new LocalStrategy(
        // configure passport to check username field as email
        {
            usernameField: 'email'
        },
        // verify login details and return a valid user if any,
        // if not, return any errors
        async function( email, password, done ) {
            try {
                // retrieve user from database using email( check if email is valid )
                const userToAuthenticate = await User.findOne({ email: email })

                // if not user found, report "invalid email error"
                if ( !userToAuthenticate ) {
                    const invalidEmailError = new Error("No user account was found with that email address")
                    invalidEmailError.errorCode = error_def.INVALID_EMAIL
                    invalidEmailError.statusCode = 400
                    return done( invalidEmailError, false )
                }

                if (  userToAuthenticate.provider != "google" && userToAuthenticate.provider != "magiclink" ) {
                    // since a user is found, check if login password matches user password
                    const isPasswordsMatch = await bcrypt.compare( password, userToAuthenticate.password )
    
                    // if password do not match, report "invalid password error"
                    if ( !isPasswordsMatch ) {
                        const invalidPasswordError = new Error("invalid user password")
                        invalidPasswordError.errorCode = error_def.INVALID_PASSWORD
                        invalidPasswordError.statusCode = 400
                        return done( invalidPasswordError, false )
                    }
    
                    // since password and email checks are valid, 
                    // return verified user data back to passport auth system
                    return done( null, userToAuthenticate )
                } else {
                    return done( null, userToAuthenticate )
                }

            } catch( err ) {
                // report any execution errors if any
                err.errorCode = error_def.SERVER_ERROR
                return done( err, false )
            }
        }
    ))

    // initialize passport google oauth 2.0 strategy for ( sign in with google )
    passport.use( new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: process.env.GOOGLE_CALLBACK_URL
        },
        function( accessToken, refreshToken, profile, done ) {
            return done( null, profile )
        }
    ))

    // initialize passport jwt strategy for ( jwt auth on protected API routes )
    passport.use( new JWTStrategy(
        {
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: process.env.JWT_SECRET
        },
        async function( jwt_payload, done ) {
            try {
                const user = await User.findOne({ _id: jwt_payload.user_id })

                if ( user ) {
                    done( null, user )
                } else {
                    const userNotFoundError = new Error('user with credentials not found')
                    userNotFoundError.errorCode = error_def.USER_NOT_FOUND
                    userNotFoundError.statusCode = 404
                    return done( userNotFoundError, false )
                }
            } catch ( err ) {
                err.errorCode = error_def.SERVER_ERROR
                done( err, false )
            }
        }
    ))
}

export default initPassportAuthStrategies