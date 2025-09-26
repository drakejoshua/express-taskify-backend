import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String
    },
    provider: {
        type: String,
        required: true
    },
    profileURL: {
        type: String,
        required: true,
        default: "https://www.shutterstock.com/image-vector/default-avatar-profile-icon-social-600nw-1906669723.jpg"
    },
    profileId: {
        type: String
    },
    refreshToken: {
        type: String
    },
    emailVerified: {
        type: Boolean,
        required: true,
        default: false
    },
    emailVerificationToken: {
        type: String
    },
    emailVerificationExpiry: {
        type: Date
    },
    passwordResetToken: {
        type: String
    },
    passwordResetExpiry: {
        type: Date
    },
    magicLinkToken: {
        type: String
    },
    magicLinkExpiry: {
        type: Date
    },
    apiKey: {
        type: String
    }
})


export default mongoose.model('users', userSchema)