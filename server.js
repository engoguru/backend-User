import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import connectDB from './db/connectDB.js';
import cors from 'cors';
const PORT = process.env.PORT || 5001;
import userRoutes from "./routes/userRoutes.js"
import contactRoutes from "./routes/contactRoutes.js"
// import { notFound, errorHandler } from '@your-scope/common/src/errors.js';
import cookieParser from 'cookie-parser';


const app = express();

//  db connect
connectDB()
// app.use(cors({
//   origin: ['http://localhost:5173', 'http://localhost:5174'],
//   credentials: true
// }));
app.use(cookieParser());
 app.use(express.json());

app.get('/userhealth', (_,res)=>res.json({ok:true, service:'user-service'}));
app.use('/account', userRoutes);
app.use('/contact',contactRoutes);
// app.use(notFound); app.use(errorHandler);

// await mongoose.connect(process.env.MONGO_URI || 'mongodb://mongo:27017/users');

app.listen(PORT, ()=> console.log(`user-service :${PORT}`));
