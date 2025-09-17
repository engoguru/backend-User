import { Router } from "express";
import userController from "../controllers/userController.js";
import { authenticate } from "../middleware/authenticate.js";

const routes = Router();


routes.post('/register',userController.userRegister)
routes.post('/userLogin', userController.userLogin);
routes.post('/userOtpVerify', userController.userOtpVerify);

routes.get('/GetOne/:id',userController.GetOne);
routes.get('/GetAll',userController.GetAll);


routes.post("/forget-password",userController.forgetPassword);
routes.post("/setPassword",userController.newPassword)


routes.get("/me", authenticate, (req, res) => {
  return res.status(200).json({
    message: "User authenticated",
    user: req.user
  });
});










export default routes;
