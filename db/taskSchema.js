import mongoose from "mongoose";

const taskSchema = new mongoose.Schema({
    text: {
        type: String,
        required: true,
        default: "New Task"
    },
    date: {
        type: Date,
        required: true,
        default: function() {
            return new Date().toISOString()
        }
    },
    user_id: {
        type: mongoose.SchemaTypes.ObjectId,
        required: true
    }
})


export default mongoose.model('tasks', taskSchema)