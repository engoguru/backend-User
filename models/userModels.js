// import mongoose from "mongoose";

// const userSchema = new mongoose.Schema({
//     name:{
//       type:String,
//     },
//     email: {
//         type: String,
//         lowercase: true,
//         trim: true,
//         unique: true,
//         sparse: true,
//         match: [/\S+@\S+\.\S+/, 'Invalid email']
//     },
//     whatsApp_Number: {
//         type: String,
//         unique: true,
//         sparse: true,

//     },
//     gender:{

//     },
//     address:[string],

//     otp: {
//         code: {
//             type: String,
//         },
//         expiresAt: {
//             type: Date,
//         },
//         attempts: {
//             type: Number,
//             default: 0,
//         }
//     },
//     isVerified: {
//         type: Boolean,
//         default: false,
//     },
//     role: {
//         type: String,
//         default: "User"
//     },
//     lastlogin: {
//         type: Date,
//     }
// }, { timestamps: true })

// const userModel = mongoose.model("userData", userSchema);
// export default userModel;


import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name: {
    type: String,
  },

  email: {
    type: String,
    lowercase: true,
    trim: true,
    unique: true,
    sparse: true,
    match: [/\S+@\S+\.\S+/, 'Invalid email'],
  },

  whatsApp_Number: {
    type: String,
    unique: true,
    sparse: true,
    match: [/^\+?[1-9]\d{1,14}$/, 'Invalid phone number'],
  },

  contactNumber: {
    type: String,
    match: [/^\+?[0-9]{7,15}$/, 'Invalid contact number'],
    required: false, // explicitly not required
  },

  gender: {
    type: String,
    enum: ['Male', 'Female', 'NA'],
  },

  address: [String],
  password: {
    type: String,
    required: true,
    trim: true,
    minlength: 5,
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
    },
  },

  isVerified: {
    type: Boolean,
    default: false,
  },

  role: {
    type: String,
    default: 'User',
  },

  lastlogin: {
    type: Date,
  },
}, { timestamps: true });

const userModel = mongoose.model('userData', userSchema);
export default userModel;
