import { Router } from "express";
import userController from "../controllers/userController.js";
import { authenticate } from "../middleware/authenticate.js";
import { isValidObjectId } from "mongoose";
import userModel from "../models/userModels.js";

const routes = Router();


routes.post('/register',userController.userRegister)
routes.post('/userLogin', userController.userLogin);
routes.post('/userOtpVerify', userController.userOtpVerify);

routes.get('/GetOne/:id',userController.GetOne);
routes.get('/GetAll',userController.GetAll);


routes.post("/forget-password",userController.forgetPassword);
routes.post("/setPassword",userController.newPassword)


routes.get("/me", authenticate, async(req, res) => {

  const id=req.user.id;
  if(!id && !isValidObjectId(id)){
    return res.status(401).json({message:"Unauthorized"})
  }
  const userData=await userModel.findOne({_id:id})
  return res.status(200).json({
    message: "User authenticated",
    user: userData  
  });
});


routes.put("/updateUserAddress",authenticate,userController.UpdateAddresses)










export default routes;
