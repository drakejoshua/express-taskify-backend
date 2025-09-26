import mongoose from "mongoose";

async function connectDB() {
    try {
        await mongoose.connect('mongodb+srv://joshuanathan086_db_user:OTiOswkhIObyfAfH@cluster0.wnbvsti.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
        console.log("DB connected successfully")
    } catch( err ) {
        console.log("DB connection error: ", err.message )
        process.exit(1)
    }
}


export default connectDB