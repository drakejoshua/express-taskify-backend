import { error_def } from '../utils/error_def.js'


function reportInvalidEmailError( next ) {
    const invalidEmailError = new Error("invalid email address in request")
    invalidEmailError.errorCode = error_def.INVALID_EMAIL
    invalidEmailError.statusCode = 400
    return next( invalidEmailError )
}

function reportUserNotFoundError( next ) {
    const userNotFoundError = new Error("no user with credentials was found")
    userNotFoundError.errorCode = error_def.USER_NOT_FOUND
    userNotFoundError.statusCode = 404
    return next( userNotFoundError )
}

function reportInvalidPasswordLengthError( next ) {
    const invalidPasswordLengthError = new Error("invalid password: password must be at least 6 characters long")
    invalidPasswordLengthError.errorCode = error_def.INVALID_PASSWORD_LENGTH
    invalidPasswordLengthError.statusCode = 400
    return next( invalidPasswordLengthError )
}

function reportInvalidPasswordError( next ) {
    const invalidPasswordError = new Error("invalid password for reset operation")
    invalidPasswordError.errorCode = error_def.INVALID_PASSWORD
    invalidPasswordError.statusCode = 400
    return next( invalidPasswordError )
}

function reportInvalidRequestTokenError( next ) {
    const invalidRequestTokenError = new Error("invalid token for operation")
    invalidRequestTokenError.errorCode = error_def.INVALID_REQUEST_TOKEN
    invalidRequestTokenError.statusCode = 400
    return next( invalidRequestTokenError )
}

function reportInvalidRedirectURLError( next ) {
    const invalidRedirectURLError = new Error("invalid redirect url found in request")
    invalidRedirectURLError.errorCode = error_def.INVALID_REDIRECT
    invalidRedirectURLError.statusCode = 400
    return next( invalidRedirectURLError )
}

function reportInvalidRequestLimitError( next ) {
    const invalidRequestLimitError = new Error("invalid limit query found in request")
    invalidRequestLimitError.errorCode = error_def.INVALID_REQUEST_LIMIT
    invalidRequestLimitError.statusCode = 400
    return next( invalidRequestLimitError )
}

function reportInvalidRequestSortError( next ) {
    const invalidRequestSortError = new Error("invalid sort query found in request")
    invalidRequestSortError.errorCode = error_def.INVALID_REQUEST_SORT
    invalidRequestSortError.statusCode = 400
    return next( invalidRequestSortError )
}

function reportInvalidRequestOrderError( next ) {
    const invalidRequestOrderError = new Error("invalid order query found in request")
    invalidRequestOrderError.errorCode = error_def.INVALID_REQUEST_ORDER
    invalidRequestOrderError.statusCode = 400
    return next( invalidRequestOrderError )
}

function reportInvalidRequestFilterError( next ) {
    const invalidRequestFilterError = new Error("invalid filter query found in request")
    invalidRequestFilterError.errorCode = error_def.INVALID_REQUEST_LIMIT
    invalidRequestFilterError.statusCode = 400
    return next( invalidRequestFilterError )
}

function reportInvalidTaskObjectiveError( next ) {
    const invalidTaskObjectiveError = new Error("invalid task objective/text found in request")
    invalidTaskObjectiveError.errorCode = error_def.INVALID_TASK_OBJECTIVE
    invalidTaskObjectiveError.statusCode = 400
    return next( invalidTaskObjectiveError )
}

function reportInvalidTaskDateError( next ) {
    const invalidTaskDateError = new Error("invalid task date found in request")
    invalidTaskDateError.errorCode = error_def.INVALID_TASK_DATE
    invalidTaskDateError.statusCode = 400
    return next( invalidTaskDateError )
}

function reportInvalidRequestTaskIdError( next ) {
    const invalidRequestTaskIdError = new Error("invalid task id found in request")
    invalidRequestTaskIdError.errorCode = error_def.INVALID_REQUEST_TASK_ID
    invalidRequestTaskIdError.statusCode = 400
    return next( invalidRequestTaskIdError )
}

function reportTaskNotFoundError( next ) {
    const taskNotFoundError = new Error("task with id was not found")
    taskNotFoundError.errorCode = error_def.TASK_NOT_FOUND
    taskNotFoundError.statusCode = 404
    return next( taskNotFoundError )
}

function reportAPIRateLimitError( next ) {
    const APIRateLimitError = new Error("api rate limit encoutered")
    APIRateLimitError.errorCode = error_def.API_RATE_LIMIT
    APIRateLimitError.statusCode = 429
    return next( APIRateLimitError )
}

function reportInvalidUserUpdateError( next ) {
    const invalidUserUpdateError = new Error("invalid user update operation, only users that sign up with email and password can update their email or password")
    invalidUserUpdateError.errorCode = error_def.INVALID_UPDATE
    invalidUserUpdateError.statusCode = 400
    return next( invalidUserUpdateError )
}

function reportEmailAlreadyExistsError( next ) {
    const emailAlreadyExistsError = new Error("email address already exists")
    emailAlreadyExistsError.errorCode = error_def.EMAIL_ALREADY_EXISTS
    emailAlreadyExistsError.statusCode = 400
    return next( emailAlreadyExistsError )
}


export {
    reportInvalidEmailError,
    reportInvalidPasswordError,
    reportUserNotFoundError,
    reportInvalidPasswordLengthError,
    reportInvalidRequestTokenError,
    reportInvalidRedirectURLError,
    reportInvalidRequestFilterError,
    reportInvalidRequestLimitError,
    reportInvalidRequestOrderError,
    reportInvalidRequestSortError,
    reportInvalidTaskObjectiveError,
    reportInvalidTaskDateError,
    reportInvalidRequestTaskIdError,
    reportTaskNotFoundError,
    reportAPIRateLimitError,
    reportInvalidUserUpdateError,
    reportEmailAlreadyExistsError
}