import { Router } from "express";
import userController from "../controllers/userController.js";

const routes = Router();

routes.post('/userLogin', userController.userLogin);
routes.post('/userOtpVerify', userController.userOtpVerify);

routes.get('/GetOne/:id',userController.GetOne);
routes.get('/GetAll',userController.GetAll);


export default routes;
