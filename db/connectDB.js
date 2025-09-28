import mongoose from "mongoose";

async function connectDB() {
    try {
        await mongoose.connect(`${process.env.MONGO_URI}`) 
        console.log("DB connected successfully")
    } catch( err ) {
        console.log("DB connection error: ", err.message )
        process.exit(1)
    }
}


export default connectDB