import { error_def } from "../utils/error_def.js"

function errorHandler( error, req, res, next ) {
    if ( error.statusCode ) {
        res.status( error.statusCode ).send({
            status: "error",
            data: null,
            error: {
                message: error.message || "",
                code: error.errorCode || ""
            }
        })
    } else {
        console.log( error )
        res.status( 500 ).send({
            status: "error",
            data: null,
            error: {
                code: error_def.SERVER_ERROR,
                message: error.message || ""
            }
        })
    }

    next()
}

export default errorHandler