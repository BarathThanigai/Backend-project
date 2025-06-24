const usersDB = {
  users: require("../models/users.json"),
  setUsers: function (data) {
    this.users = data;
  }
};

const fsPromises = require('fs').promises;
const path = require('path');
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
require('dotenv').config();

const handleLogin = async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  const foundUser = usersDB.users.find(user => user.username === username);
  if (!foundUser) return res.sendStatus(401);

  const roles = Object.values(foundUser.roles || { user: "user" }); // Default role fallback

  const match = await bcrypt.compare(password, foundUser.password);
  if (match) {
    if (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
      console.error('Missing ACCESS_TOKEN_SECRET or REFRESH_TOKEN_SECRET in environment variables.');
      return res.status(500).json({ message: "Internal Server Error: Missing token secret." });
    }

    const accessToken = jwt.sign(
      {
        "UserInfo": {
          'username': foundUser.username,
          "roles": roles
        }
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '10m' }
    );

    const refreshToken = jwt.sign(
      { 'username': foundUser.username },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '1d' }
    );

    const otherUsers = usersDB.users.filter(person => person.username !== foundUser.username);
    const currentUser = { ...foundUser, refreshToken };

    usersDB.setUsers([...otherUsers, currentUser]);

    try {
      await fsPromises.writeFile(
        path.join(__dirname, '..', 'models', 'users.json'),
        JSON.stringify(usersDB.users, null, 2)
      );
    } catch (err) {
      console.error("Failed to save users file:", err);
      return res.status(500).json({ message: "Internal Server Error: Failed to save user." });
    }

    res.cookie('jwt', refreshToken, {
      httpOnly: true,
      sameSite: 'None',
      secure: true
    });

    res.json({ accessToken });
  } else {
    res.sendStatus(401);
  }
};

module.exports = { handleLogin };
