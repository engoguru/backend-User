import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name:{
      type:String,
    },
    email: {
        type: String,
        lowercase: true,
        trim: true,
        unique: true,
        sparse: true,
        match: [/\S+@\S+\.\S+/, 'Invalid email']
    },
    whatsApp_Number: {
        type: String,
        unique: true,
        sparse: true,

    },

    otp: {
        code: {
            type: String,
        },
        expiresAt: {
            type: Date,
        },
        attempts: {
            type: Number,
            default: 0,
        }
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    role: {
        type: String,
        default: "User"
    },
    lastlogin: {
        type: Date,
    }
}, { timestamps: true })

const userModel = mongoose.model("userData", userSchema);
export default userModel;