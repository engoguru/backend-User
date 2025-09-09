import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import connectDB from './db/connectDB.js';
import cors from 'cors';
const PORT = process.env.PORT || 5001;
import userRoutes from "./routes/userRoutes.js"
// import { notFound, errorHandler } from '@your-scope/common/src/errors.js';

const app = express();

//  db connect
connectDB()
app.use(cors());
 app.use(express.json());

app.get('/userhealth', (_,res)=>res.json({ok:true, service:'user-service'}));
app.use('/account', userRoutes);
// app.use(notFound); app.use(errorHandler);

// await mongoose.connect(process.env.MONGO_URI || 'mongodb://mongo:27017/users');

app.listen(PORT, ()=> console.log(`user-service :${PORT}`));
