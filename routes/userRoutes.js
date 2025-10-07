import { Router } from "express";
import userController from "../controllers/userController.js";
import { authenticate } from "../middleware/authenticate.js";
import { isValidObjectId } from "mongoose";
import userModel from "../models/userModels.js";

const routes = Router();


routes.post('/register',userController.userRegister)
routes.post('/userLogin', userController.userLogin);
routes.post('/admin/login', userController.adminLogin);
routes.post('/userOtpVerify', userController.userOtpVerify);

routes.get('/GetOne/:id',userController.GetOne);
routes.get('/GetAll',userController.GetAll);


routes.post("/forget-password",userController.forgetPassword);
routes.post("/setPassword",userController.newPassword)


routes.get("/me", authenticate, async (req, res) => {
  const id = req.user.id;
  if (!id || !isValidObjectId(id)) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const userData = await userModel.findOne({ _id: id }).lean();  // lean returns plain JS object

  if (!userData) {
    return res.status(404).json({ message: "User not found" });
  }

  // Remove _id from each address object
  if (userData.address && Array.isArray(userData.address)) {
    userData.address = userData.address.map(({ _id, ...rest }) => rest);
  }

  return res.status(200).json({
    message: "User authenticated",
    user: userData,
  });
});



routes.get("/out", async (req, res) => {
  try {
    // Clear the cookie named 'token' (or whatever your cookie name is)
    res.clearCookie("token", {
      // httpOnly: true,
      // secure: true, // use true if your app is served over HTTPS
      // sameSite: "Strict", // or "Lax" or "None" depending on your setup
    });

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({ message: "Server error during logout" });
  }
});



routes.put("/updateUserAddress",authenticate,userController.UpdateAddresses)










export default routes;
