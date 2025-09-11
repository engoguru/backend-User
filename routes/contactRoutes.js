import contactController from '../controllers/contactController';

const express = require('express');
const contactRouter = express.Router();

contactRouter.post('/', contactController.createContact);
contactRouter.get('/getAll',contactController.getAllContacts);
contactRouter.get('/getById/:id',contactController.getContactById);
contactRouter.put('/update/:id',contactController.updateContact);
contactRouter.delete('/delete/:id',contactController.deleteContact); 


export default contactRouter