import { v2 as cloudinary } from 'cloudinary'

// console.log( "cloud_name: ", process.env.CLOUDINARY_CLOUD_NAME )
// console.log( "api_key: ", process.env.CLOUDINARY_API_KEY )
// console.log( "api_secret: ", process.env.CLOUDINARY_API_SECRET )

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
})

function cloudinaryUpload( buffer ) {
    return new Promise( function( resolve, reject ) {
        cloudinary.uploader.upload_stream( {}, 
            function( error, result ) {
                if ( error ) {
                    return reject( error )
                }
                resolve( result )
            } 
        ).end( buffer )
    })
}

function cloudinaryDelete( public_id ) {
    return new Promise( function( resolve, reject ) {
        cloudinary.uploader.destroy( public_id, function( error, result ) {
            if ( error ) {
                return reject( error )
            }
            resolve( result )
        })
    })
}

export default cloudinary
export { cloudinaryUpload, cloudinaryDelete }