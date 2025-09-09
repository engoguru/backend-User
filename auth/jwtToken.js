import jwt from 'jsonwebtoken';

const jwtToken = (res, token) => {
  res.cookie('token', token, {
    // httpOnly: true,
    // secure: process.env.NODE_ENV === 'production',
    // sameSite: 'Strict',
    maxAge: 30*24 * 60 * 60 * 1000, // 30 day
  });
};


export default jwtToken;
