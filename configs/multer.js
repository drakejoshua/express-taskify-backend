import multer from "multer";
import { error_def } from "../utils/error_def.js";

function fileFilterFunction( req, file, cb ) {
    if ( file.mimetype.startsWith("image/") ) {
        cb( null, true )
    } else {
        const fileFilterError = new Error("Invalid File Type Prepared for upload")
        fileFilterError.statusCode = 400
        fileFilterError.errorCode = error_def.INVALID_FILE_TYPE
        cb( fileFilterError, false )
    }
}

const upload = multer({
    storage: multer.memoryStorage(),
    fileFilter: fileFilterFunction,
    limits: {
        fileSize: 1024 * 1024 * 2 // 2 MB
    }
})


export default upload