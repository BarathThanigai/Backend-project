const jwt = require('jsonwebtoken');
require('dotenv').config();

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.sendStatus(401);

  const token = authHeader.split(' ')[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.log('JWT Verify Error:', err); // <-- Add this to console the error
      return res.sendStatus(403); // Forbidden
    }
    req.user = decoded.UserInfo.username;
    next();
  });
};

module.exports = verifyJWT;

