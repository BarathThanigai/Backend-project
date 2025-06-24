const express = require('express')
const refreshRouter = express.Router()
const refreshController = require('../controllers/refreshController')
const path = require('path')

refreshRouter.get('/',refreshController.handleRefreshToken)

module.exports = refreshRouter