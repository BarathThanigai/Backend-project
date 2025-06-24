const usersDB = {
  users: require("../models/users.json"),
  setUsers : function(data) {this.users = data}
};

const fsPromises = require('fs').promises
const path = require('path')
const bcrypt = require("bcrypt")

const handleNewUser = async(req,res)=>{
    const {username,password} = req.body
    if(!username || !password)
        return res.status(400).josn({"message":"Username and password required"})
    const duplicate = usersDB.users.find(user=> user.username===username)
    if(duplicate)
        return res.sendStatus(409)
    try {
        const hashedPassword = await bcrypt.hash(password,10)
        const newUser = {username,password:hashedPassword,roles:{ "User": 2001 }}   
        usersDB.setUsers([...usersDB.users,newUser])
        console.log(newUser)
        await fsPromises.writeFile(path.join(__dirname,'..','models','users.json'),JSON.stringify(usersDB.users))
        res.status(201).json({"message":`new user is created`})
    } catch (error) {
        res.status(500).json({"message":error.message})
    }
}

module.exports = {handleNewUser}