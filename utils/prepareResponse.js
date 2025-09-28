function prepareUserResponse( userData ) {
    const { 
        emailVerificationExpiry,
        emailVerificationToken,
        passwordResetExpiry,
        passwordResetToken,
        accessToken,
        magicLinkExpiry,
        magicLinkToken,
        __v,
        profileId,
        ...responseData
    } = userData.toObject()

    return responseData
}

function prepareTaskResponse( taskData ) {
    const { 
        __v,
        ...responseData
    } = taskData.toObject()

    return responseData
}

export { prepareUserResponse, prepareTaskResponse }