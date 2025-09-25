import Joi from "joi";
import userModel from "../models/userModels.js";
import emailHelper from "../utilis/emailHelper.js";
import jwtToken from "../auth/jwtToken.js";
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken';
import { isValidObjectId } from "mongoose";


const RegisterSchema = Joi.object({
  email: Joi.string().email().optional(),

  whatsApp_Number: Joi.string()
    .pattern(/^[1-9]\d{9,14}$/)
    .optional(),

  contactNumber: Joi.string()
    .pattern(/^\+?[0-9]{7,15}$/)
    .optional(),

  name: Joi.string()
    .min(2)
    .max(50)
    .optional(),

  gender: Joi.string()
    .valid('Male', 'Female', 'Other', 'NA')
    .optional(),

  address: Joi.array()
    .items(Joi.string().min(3).max(255))
    .optional(),

  password: Joi.string()
    .min(5)
    .required(),  // mark required or optional as you want

}).or('email', 'whatsApp_Number'); // Require at least one of these


const loginSchema = Joi.object({
  email: Joi.string().email().optional(),
  whatsApp_Number: Joi.string().pattern(/^[1-9]\d{9,14}$/).optional(),
  password: Joi.string().min(5).required(),
}).or('email', 'whatsApp_Number');

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000);
}

const userRegister = async (req, res) => {
  try {
    // Validate incoming request
    console.log(req.body, "fgghgir")
    if (typeof req.body.email === 'string' && req.body.email.trim() === '') {
  delete req.body.email;
}

if (typeof req.body.whatsApp_Number === 'string' && req.body.whatsApp_Number.trim() === '') {
  delete req.body.whatsApp_Number;
}


    if (Array.isArray(req.body.data .address)) {
      req.body.data .address = req.body.data .address.filter(
        line => typeof line === 'string' && line.trim() !== ''
      );
    }

    const { error, value } = RegisterSchema.validate(req.body.data );

    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const {
      email,
      whatsApp_Number,
      contactNumber,
      name,
      gender,
      address,
      password
    } = value;

    // Check if user already exists by email or WhatsApp_Number
    let existingUser = null;
    if (email) {
      existingUser = await userModel.findOne({ email });
    } else if (whatsApp_Number) {
      existingUser = await userModel.findOne({ whatsApp_Number });
    }

    if (existingUser && existingUser.isVerified === true) {
      console.log(existingUser, "hgdf")
      return res.status(409).json({ message: "User already exists. Please login instead." });
    }
    if (existingUser && existingUser.isVerified === false) {
      const otpCode = generateOtp();
      const hashedOtp = await bcrypt.hash(otpCode.toString(), 10);
      const otpData = {
        code: hashedOtp,
        expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
        attempts: 0,
      };

      existingUser.otp = otpData;
      await existingUser.save()

      if (email) {
        await emailHelper.emailSender(
          email,
          "Your OTP Code",
          `<p>Your OTP code is: <strong>${otpCode}</strong></p><p>This OTP is valid for 30 minutes.</p>`
        );
        return res.status(201).json({ message: "User registered. Please check your email for the OTP." });
      }

      if (whatsApp_Number) {
        // TODO: Send OTP via WhatsApp API here
        console.log(`OTP for WhatsApp ${whatsApp_Number}: ${otpCode}`);
        return res.status(201).json({ message: "User registered. OTP sent to your WhatsApp number." });
      }

      // Fallback (should not reach here)
      return res.status(400).json({ message: "Email or WhatsApp number is required." });

    }
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create OTP
    const otpCode = generateOtp();
    const hashedOtp = await bcrypt.hash(otpCode.toString(), 10);
    const otpData = {
      code: hashedOtp,
      expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
      attempts: 0,
    };

    // Create new user document
    const newUser = new userModel({
      email,
      whatsApp_Number,
      contactNumber,
      name,
      gender,
      address,
      password: hashedPassword,
      otp: otpData,
      isVerified: false,
      role: "User",
    });

    await newUser.save();

    // Send OTP
    if (email) {
      await emailHelper.emailSender(
        email,
        "Your OTP Code",
        `<p>Your OTP code is: <strong>${otpCode}</strong></p><p>This OTP is valid for 30 minutes.</p>`
      );
      return res.status(201).json({ message: "User registered. Please check your email for the OTP." });
    }

    if (whatsApp_Number) {
      // TODO: Send OTP via WhatsApp API here
      console.log(`OTP for WhatsApp ${whatsApp_Number}: ${otpCode}`);
      return res.status(201).json({ message: "User registered. OTP sent to your WhatsApp number." });
    }

    // Fallback (should not reach here)
    return res.status(400).json({ message: "Email or WhatsApp number is required." });

  } catch (err) {
    console.error("Registration Error:", err);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

const userLogin = async (req, res) => {
  try {
    const { email, whatsApp_Number, password } = req.body.data;
// console.log(req.body.data)
    // Find user by email or WhatsApp number
    let user = null;
    if (email) {
      user = await userModel.findOne({ email });
    } else if (whatsApp_Number) {
      user = await userModel.findOne({ whatsApp_Number });
    }
  // console.log(user,"user")
    // User not found
    if (!user) {
      return res.status(401).json({ message: "register" });
    }

    // User not verified
    if (user.isVerified === false) {
      return res.status(401).json({ message: "Please verify your email or whatsAPp number" });
    }

    // Compare passwords (FIXED)
    const isMatch = await bcrypt.compare(password, user.password);
    // console.log(isMatch,"jk")
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    // Update last login time
    user.lastlogin = new Date();
    await user.save();

    // Prepare JWT payload
    const jwtPayload = {
      id: user._id,
      role: user.role || "User",
      email: user.email,
      whatsApp_Number: user.whatsApp_Number,
      name: user.name,
      gender: user.gender,
      contactNumber: user.contactNumber,
      address: user.address?.length ? user.address : undefined,
    };

    // Generate token
    const token = jwt.sign(jwtPayload, process.env.JWT_SECRET, {
      expiresIn: '30d',
      algorithm: 'HS256',
    });

    // Set token in cookie
    jwtToken(res, token); // <- This function should set the cookie with `httpOnly`, `secure`, etc.

    // Return response
    return res.status(200).json({
      message: "Login successful.",
      user: {
        id: user._id,
        email: user.email,
        whatsApp_Number: user.whatsApp_Number,
        role: user.role,
        token, // Optional to include if you're already setting it in cookies
      },
    });
  } catch (err) {
    console.error("Login Error:", err);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

const adminLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    // Find user by email
    const user = await userModel.findOne({ email });

    // User not found
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    // IMPORTANT: Check if the user has the 'Admin' role
    if (user.role !== 'Admin') {
      return res.status(403).json({ message: "Access denied. Not an admin." });
    }

    // User not verified (optional, but good practice)
    if (user.isVerified === false) {
      return res.status(401).json({ message: "Please verify your account first." });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    // Update last login time
    user.lastlogin = new Date();
    await user.save();

    // Prepare JWT payload
    const jwtPayload = {
      id: user._id,
      role: user.role,
      email: user.email,
      name: user.name,
    };

    // Generate token
    const token = jwt.sign(jwtPayload, process.env.JWT_SECRET, {
      expiresIn: '1d', // Admin sessions can be shorter
      algorithm: 'HS256',
    });

    // Set token in an HTTP-Only cookie for security
    jwtToken(res, token);

    // Return response
    return res.status(200).json({
      message: "Admin login successful.",
      token, // Send token for frontend to store
    });
  } catch (err) {
    console.error("Admin Login Error:", err);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

const userOtpVerify = async (req, res) => {
  try {
    // console.log(req.body)
    const { email, whatsApp_Number, otp } = req.body.otp;

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
    // console.log(otp, "otp");

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
      role: user.role || "User",
    };

    // Conditionally include optional fields
    if (user.email) {
      jwtPayload.email = user.email;
    }

    if (user.whatsApp_Number) {
      jwtPayload.whatsApp_Number = user.whatsApp_Number;
    }

    if (user.name) {
      jwtPayload.name = user.name;
    }

    if (user.gender) {
      jwtPayload.gender = user.gender;
    }

    if (user.contactNumber) {
      jwtPayload.contactNumber = user.contactNumber;
    }

    if (user.address && user.address.length > 0) {
      jwtPayload.address = user.address;
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

const GetOne = async (req, res) => {
  try {
    const id = req.params.id;
    if (!id || !isValidObjectId(id)) {
      return res.status(400).json({ message: "Invalid id" })
    }
    const user = await userModel.findById(id)
    if (!user) {
      return res.status(404).json({ message: "User not found" })
    }
    res.status(200).json({ message: "User found", user })
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "Internal Server Error!" });
  }
}

const GetAll = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const sortBy = req.query.sort || 'latest'; // Default to 'latest'
    const skip = (page - 1) * limit;

    let sortOption = {};
    switch (sortBy) {
      case 'a-z':
        sortOption = { name: 1 };
        break;
      case 'z-a':
        sortOption = { name: -1 };
        break;
      case 'oldest':
        sortOption = { createdAt: 1 }; // Assumes you have a createdAt field
        break;
      case 'latest':
      default:
        sortOption = { createdAt: -1 }; // Assumes you have a createdAt field
        break;
    }

    const [totalUsers, users] = await Promise.all([
      userModel.countDocuments(),
      userModel.find().sort(sortOption).skip(skip).limit(limit)
    ]);
    res.status(200).json({
      users,
      currentPage: page,
      totalPages: Math.ceil(totalUsers / limit)
    });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Internal Server Error!" });
  }
}



const forgetPassword = async (req, res) => {
  try {
    const { email, whatsApp_Number } = req.body.data;

    // Check if at least one identifier is provided
    if (!email && !whatsApp_Number) {
      return res.status(400).json({
        message: "Please provide either email or WhatsApp number",
      });
    }

    // Find the user by email or WhatsApp number
    const user = await userModel.findOne({
      $or: [
        email ? { email } : null,
        whatsApp_Number ? { whatsApp_Number } : null,
      ].filter(Boolean),
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found with provided email or WhatsApp number",
      });
    }

    // Generate OTP
    const otp = await generateOtp(); // Should return a numeric or alphanumeric OTP

     const hashedOtp = await bcrypt.hash(otp.toString(), 10);
      const otpData = {
        code: hashedOtp,
        expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
        attempts: 0,
      };

    user.otp = otpData;
   
    await user.save();

   // Send OTP
    if (email) {
      await emailHelper.emailSender(
        email,
        "Your OTP Code",
        `<p>Your OTP code is: <strong>${otp}</strong></p><p>This OTP is valid for 30 minutes.</p>`
      );
      return res.status(201).json({ message: "User registered. Please check your email for the OTP." });
    }

    if (whatsApp_Number) {
      // TODO: Send OTP via WhatsApp API here
      console.log(`OTP for WhatsApp ${whatsApp_Number}: ${otpCode}`);
      return res.status(201).json({ message: "User registered. OTP sent to your WhatsApp number." });
    }

    return res.status(200).json({
      message: "OTP sent successfully",
    });

  } catch (error) {
    console.error('Forget password error:', error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
};

const newPassword = async (req, res) => {
  console.log(req.body, "ghgrgh");
  try {
    const { otp, password, email, whatsApp_Number } = req.body.data;
    console.log(otp, password, email);

    if (!otp || !password) {
      return res.status(400).json({
        message: "Check input!",
      });
    }

    const user = await userModel.findOne(email ? { email } : { whatsApp_Number });

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    if (!user.otp || !user.otp.code || !user.otp.expiresAt) {
      return res.status(400).json({ message: "OTP not set or invalid." });
    }

    if (user.otp.expiresAt < new Date()) {
      return res.status(400).json({ message: "OTP has expired." });
    }

    const isValid = await bcrypt.compare(otp.toString(), user.otp.code);

    if (!isValid) {
      user.otp.attempts = (user.otp.attempts || 0) + 1;
      await user.save();
      return res.status(401).json({ message: "Invalid OTP." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user.isVerified = true;
    user.password = hashedPassword;
    user.lastlogin = new Date();
    user.otp = undefined; // Clear OTP
    await user.save();

    return res.status(200).json({ message: "Password reset successfully." });

  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error!",
    });
  }
};


const userUpdate=async(req,res)=>{
  try {
    const id=req.params;
    if(!isValidObjectId(id)){
      return res.status(400).json({
        message:"Invalid id"
      })
    }
  const{}=req.body;
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      mmessage:"Internal server error !"
    })
  }
}

export default {
  userRegister,
  userLogin,
  adminLogin,
  userOtpVerify,
  GetOne,
  GetAll,
  forgetPassword,
  newPassword
};