const express = require("express");
const app = express();
const path = require("path");
const cookieParser = require('cookie-parser')
require('dotenv').config();

const verifyJWT = require('./middleware/verifyJWT')

const homeRouter = require("./routes/homeRouter"); 
const employeeRouter = require('./routes/api/employeeRouter')

const registerRouter = require('./routes/registerRouter')
const authRouter = require('./routes/authrouter')

const { logger } = require("./middleware/logEvents");
const errorHandler = require("./middleware/errHandler");

const port = process.env.PORT || 3000;

// built in middlewares
app.use(express.urlencoded({ extended: false })); //parses data from body of req
app.use(express.json()); //parses json
app.use(cookieParser())

app.use("/", express.static(path.join(__dirname, "public"))); //helps us serve static files
app.use("/subdir", express.static(path.join(__dirname, "public")));

// 3rd party middleware const
const cors = require("cors"); 
const corsOptions = require('./config/corsOptions')
app.use(cors(corsOptions));

// custom middleware
app.use(logger);
app.use(require('./middleware/credentials'))

// routes
app.use("/", homeRouter);
app.use('/register', registerRouter)
app.use('/auth', authRouter)
app.use('/refresh', require('./routes/refreshRouter'))
app.use('/logout', require('./routes/logoutRouter'))



//api routes
app.use('/api/employee', verifyJWT, employeeRouter)
app.get('/protected', verifyJWT, (req, res) => {
  res.json({ message: `Welcome ${req.user}` });
});

app.all(/^\/.*/, (req, res) => {
  res.status(404);
  if (req.accepts("html"))
    res.sendFile(path.join(__dirname, "views", "404.html"));
  else if (req.accepts("json")) res.send({ error: "404 Not Found" });
  else res.type("txt"), send("404 Not Found");
});

app.use(errorHandler);
app.listen(port, () => {
  console.log("server running");
  console.log(`Server running at: http://localhost:${port}`);
});


