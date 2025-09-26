import jwt from "jsonwebtoken"

export function generateAccessToken( user_id ) {
    return jwt.sign(
        {
            user_id
        },
        process.env.JWT_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

export function generateRefreshToken( user_id ) {
    return jwt.sign(
        {
            user_id
        },
        process.env.JWT_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}