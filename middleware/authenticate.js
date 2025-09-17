import userModel from "../models/userModels.js";
import jwt from 'jsonwebtoken';


export async function authenticate(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    let token = auth.startsWith("Bearer ") ? auth.slice(7) : null;


    if (!token && req.cookies?.token) token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: "Unauthorized: missing token" });
    }

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: ['HS256']
      });
    } catch (err) {
      console.error("JWT verification error:", err.message);
      return res.status(401).json({ message: "Unauthorized: invalid or expired token" });
    }

    const user = await userModel.findById(payload.id).select('-password -otp');

    if (!user) {
      return res.status(401).json({ message: "Unauthorized: user not found" });
    }

    req.user = {
      id: user._id,
      email: user.email,
      whatsApp_Number: user.whatsApp_Number,
      name: user.name,
      isVerified: user.isVerified,
      role: user.role,
      gender: user.gender,
      contactNumber: user.contactNumber,
      address: user.address
    };

    return next();
  } catch (e) {
    console.error("Authentication middleware error:", e);
    return res.status(500).json({ message: "Internal Server Error" });
  }
}
