const express = require('express')
const authRouter = express.Router()
const path = require('path')

const authController = require('../controllers/authController')

authRouter.post('/',authController.handleLogin)

module.exports = authRouter