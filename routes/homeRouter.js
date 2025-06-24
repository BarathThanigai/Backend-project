const express = require('express')
const homeRouter = express.Router()
const path = require('path')

homeRouter.get(/^\/$|^\/index(\.html)?/,(req,res)=>{ 
    res.sendFile(path.join(__dirname,'..','views','index.html'))
})

module.exports = homeRouter