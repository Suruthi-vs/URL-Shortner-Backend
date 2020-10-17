const express= require("express")
const cors= require("cors");
const bodyParser= require("body-parser");
const mongoose= require("mongoose");
require('dotenv').config()
const app=express()

app.use(bodyParser.json())
app.use(cors())

app.use(
  bodyParser.urlencoded({
    extended:false
  })
)

const userroute= require("./routes/userroutes")
const urlroute= require("./routes/urlroute");

const chartroute= require("./routes/chartroute")
app.use("/",userroute)
app.use("/url",urlroute)
app.use("/visual",chartroute)
app.listen(process.env.PORT||8080,()=>{
  console.log("Server connected!!!")
})

const mongoURI= "mongodb+srv://suji:suji@cluster0-lvdpv.mongodb.net/loginurldb?retryWrites=true&w=majority"

mongoose.connect(mongoURI,{useNewUrlParser:true})
.then(()=>console.log("MongoDB Database connected"))
.catch(err=>console.log(err))

