import Joi from "joi";
import userModel from "../models/userModels.js";
import emailHelper from "../utilis/emailHelper.js";
import jwtToken from "../auth/jwtToken.js";
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken';
import { isValidObjectId } from "mongoose";

const loginSchema = Joi.object({
  email: Joi.string().email(),
  whatsApp_Number: Joi.string().pattern(/^[1-9]\d{9,14}$/),
  name: Joi.string().min(2).max(50).optional()
}).or('email', 'whatsApp_Number'); // At least one of them is required

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000);
}



// const generateTokenAndSetCookie = (user, res) => {
//   const token = jwt.sign(
//     {
//       sub: user.id,       // subject (user id)
//       email: user.email,
//       roles: user.roles,  // e.g. ["admin","editor"]
//       name: user.name,
//     },
//     process.env.JWT_SECRET, // keep this strong & private
//     {
//       algorithm: "HS256",
//       expiresIn: "15d",      //  valid for 15 days
//       issuer: "user-service" // optional, helps verify
//     }
//   );
// }



const userLogin = async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { email, whatsApp_Number } = value;
    const otpCode = generateOtp(); // 6-digit number
    const saltRounds = 10;

    const hashedOtp = await bcrypt.hash(otpCode.toString(), saltRounds);
    const otpData = {
      code: hashedOtp,
      expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
      attempts: 0,
    };

    let user;

    // Login with Email
    if (email) {
      user = await userModel.findOne({ email });

      if (!user) {
        // New user
        const newUser = new userModel({
          email,
          otp: otpData,
        });

        await newUser.save();
      } else {
        // Existing user
        user.otp = otpData;
        await user.save();
      }

      await emailHelper.emailSender(
        email,
        "Your OTP Code",
        `<p>Your OTP code is: <strong>${otpCode}</strong></p><p>This OTP is valid for 30 minutes.</p>`
      );

      return res.status(200).json({ message: "Please check your email for the OTP." });
    }

    // Login with WhatsApp Number
    if (whatsApp_Number) {
      user = await userModel.findOne({ whatsApp_Number });

      if (!user) {
        // New user
        const newUser = new userModel({
          whatsApp_Number,
          otp: otpData,
        });

        await newUser.save();
      } else {
        // Existing user
        user.otp = otpData;
        await user.save();
      }

      // TODO: Send OTP via WhatsApp (API like Twilio or WhatsApp Cloud API)
      console.log(`OTP for WhatsApp ${whatsApp_Number}: ${otpCode}`);

      return res.status(200).json({ message: "OTP sent to your WhatsApp number." });
    }

    // Should not reach here
    return res.status(400).json({ message: "Email or WhatsApp number is required." });

  } catch (err) {
    console.error("Login Error:", err);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

const userOtpVerify = async (req, res) => {
  try {
    const { email, whatsApp_Number, otp } = req.body;

    if (!otp || (!email && !whatsApp_Number)) {
      return res.status(400).json({ message: "OTP and identifier are required." });
    }

    // 1. Find user by email or WhatsApp number
    const user = await userModel.findOne(email ? { email } : { whatsApp_Number });

    if (!user || !user.otp || !user.otp.code) {
      return res.status(404).json({ message: "No OTP found or user not found." });
    }

    // 2. Check OTP expiration
    if (user.otp.expiresAt < new Date()) {
      return res.status(400).json({ message: "OTP has expired." });
    }

    // 3. Compare OTP
    const isValid = await bcrypt.compare(otp.toString(), user.otp.code);
    console.log(otp, "otp");

    if (!isValid) {
      user.otp.attempts = (user.otp.attempts || 0) + 1;
      await user.save();
      return res.status(401).json({ message: "Invalid OTP." });
    }

    // 4. OTP is valid 
    user.isVerified = true;
    user.lastlogin = new Date();
    user.otp = undefined; // Clear OTP
    await user.save();

    // Build JWT payload
    const jwtPayload = {
      id: user._id,
      role: user.role || "user"
    };

    if (user.email) {
      jwtPayload.email = user.email;
    } else if (user.whatsApp_Number) {
      jwtPayload.whatsApp_Number = user.whatsApp_Number;
    }

    // Sign token with HS256 algorithm explicitly
    const token = jwt.sign(
      jwtPayload,
      process.env.JWT_SECRET,
      {
        expiresIn: '30d',
        algorithm: 'HS256'
      }
    );

    // Assuming jwtToken sets the token in a cookie or similar
    jwtToken(res, token);

    return res.status(200).json({
      message: "OTP verified successfully!",
      user: {
        id: user._id,
        email: user.email,
        whatsApp_Number: user.whatsApp_Number,
        role: user.role,
        token
      }
    });

  } catch (error) {
    console.error("OTP Verify Error:", error);
    res.status(500).json({ message: "Internal Server Error!" });
  }
};


const GetOne=async(req,res)=>{
  try {
    const id=req.params.id;
    if(!id || !isValidObjectId(id)){
      return res.status(400).json({message:"Invalid id"})
    }
    const user=await userModel.findById(id)
    if(!user){
      return res.status(404).json({message:"User not found"})
    }
    res.status(200).json({message:"User found",user})
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "Internal Server Error!" });
  }
}

const GetAll=async(req,res)=>{
  try{
  const page=parseInt(req.query.page) || 1;
  const limit=parseInt(req.query.limit) || 10;
  const skip=(page-1)*limit;

 
  const [totalUsers, users] = await Promise.all([
    userModel.countDocuments(),
    userModel.find().skip(skip).limit(limit)
  ]);
  res.status(200).json({
    users,
    currentPage:page,
    totalPages:Math.ceil(totalUsers/limit)
  });
  }catch(error){
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Internal Server Error!" });
  }
}

   
export default {
  userLogin,
  userOtpVerify,
  GetOne,
  GetAll
};
