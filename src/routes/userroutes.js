const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("../models/usermodel");
const nodemailer = require("nodemailer");
const _= require("lodash");
const { result } = require("lodash");
// const passport = require("passport");

process.env.SECRET_key = "secret";
process.env.RESET_key="secret123secret"

const userroute = express.Router();
userroute.use(cors());
userroute.get("/", (req, res) => {
  res.send("Url Shortner Backend!!");
});

userroute.get("/dashboard", (req, res) => {
  res.send("Welcomee");
});

//Register

userroute.post("/register", (req, res) => {
  const { Firstname, Lastname, email, password } = req.body;
  User.findOne({ email: email }).then((user) => {
    if (user) {
      res.send({ error: "Email ID Already Registerd" });
    } else {
      const token = jwt.sign(
        { Firstname, Lastname, email, password },
        process.env.SECRET_key,
        { expiresIn: "3 hours" }
      );
      const CLIENT_URL = "http://" + req.headers.host;
      const output = `
                <h2>Please click on below link to activate your account</h2>
                <p>${CLIENT_URL}/activate/${token}</p>
                <p><b>NOTE: </b> The above activation link expires in 30 minutes.</p>
                `;
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: "nodejsa@gmail.com",
          pass: "nodejs123"
        }
      });
      const mailOptions = {
        from: '"Auth Admin" <nodejsa@gmail.com>', // sender address
        to: email, // list of receivers
        subject: "Account Verification: NodeJS Auth ✔", // Subject line
        html: output // html body
      };
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.log(error);
          res.json({
            msg: "Something went wrong on our end. Please register again."
          });
          res.redirect("/login");
        } else {
          console.log("Mail sent : %s", info.response);
          res.json({
            msg: "Activation link sent to email ID. Please activate to log in."
          });
          res.redirect("/login");
        }
      });
    }
  });
});

//---------------------------------------------------
//Activate Token

userroute.get("/activate/:token", (req, res) => {
  const token = req.params.token;
  if (token) {
    jwt.verify(token, process.env.SECRET_key, (err, decodedToken) => {
      if (err) {
        req.flash(
          "error_msg",
          "Incorrect or expired link! Please register again."
        );
        res.redirect("/register");
      } else {
        const { Firstname, Lastname, email, password } = decodedToken;
        User.findOne({ email: email }).then((user) => {
          if (user) {
            //------------ User already exists ------------//
            res.send({ msg: "Email ID already registered! Please log in." });
            res.redirect("/login");
          } else {
            const newUser = new User({
              Firstname,
              Lastname,
              email,
              password
            });

            bcrypt.genSalt(10, (err, salt) => {
              bcrypt.hash(newUser.password, salt, (err, hash) => {
                if (err) throw err;
                newUser.password = hash;
                newUser
                  .save()
                  .then((user) => {
                    res.send(res.redirect("https://ydibz.csb.app/login"));
                    // res.redirect('https://ydibz.csb.app/login');
                  })
                  .catch((err) => console.log(err));
              });
            });
          }
        });
      }
    });
  } else {
    console.log("Account activation error!");
  }
});

//---------------------------------------------------------

//Login

userroute.post("/login", async (req, res) => {
  const existingUser = await User.findOne({ email: req.body.email });
  try {
    if (!existingUser) {
      res.json({
        msg: "No such user exist"
      });
    } else {
      const checkuser = await bcrypt.compare(
        req.body.password,
        existingUser.password
      );
      if (!checkuser) {
        res.json({
          msg: "Password invalid"
        });
      } else {
        res.json({
          msg: "Login successfull"
        });
      }
    }
  } catch (err) {
    res.send(err);
  }
});

//Forgot---------------------------

userroute.post("/forgot",(req,res)=>{
  const {email}=req.body;
  User.findOne({email},(err,user)=>{
    if(err || !user){
      res.status(400).json({
        msg:"User doen not exist"
      })
    }
    else{
      const token = jwt.sign(
        {_id:user._id},
        process.env.RESET_key,
        { expiresIn: "3 hours" }
      );
      const CLIENT_URL = "http://" + req.headers.host;
      const output = `
                <h2>Please click on below link to activate your account</h2>
                <p>${CLIENT_URL}/forgot/${token}</p>
                <p><b>NOTE: </b> The above activation link expires in 30 minutes.</p>
                `;
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: "nodejsa@gmail.com",
          pass: "nodejs123"
        }
      });
      const mailOptions = {
        from: '"Auth Admin" <nodejsa@gmail.com>', // sender address
        to: email, // list of receivers
        subject: "Account Reset: NodeJS Auth ✔", // Subject line
        html: output // html body
      };

      return user.updateOne({resetLink:token},(err,success)=>{
        if(err){
          return res.status(400).json({ msg:"Error"})
        }
        else{
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.log(error);
              res.json({
                msg: "Something went wrong on our end. Please register again."
              });
              res.redirect("/login");
            } else {
              console.log("Mail sent : %s", info.response);
              res.json({
                msg: "Activation link sent to email ID. Please activate to log in."
              });
              res.redirect("/login");
            }
          });
        }
      })
      
    }

  })
})

//-- Page refreshing on clicking and going to reset page..........

userroute.get("/forgot/:token",(req,res)=>{
  const {token}= req.params
  if(token){
    jwt.verify(token,process.env.RESET_key,(err,decodetoken)=>{
      if(err){
         console.log(err)
          res.status(400).json({
            msg:"Incorrect or expired Link please try again later!"
          })
      }
      else{
        const {_id}=decodetoken;
        User.findById(_id,(err,user)=>{
          if(err){
            req.status(400).json({
              msg:"User with this email Id does not exist. Please try again Later"
            })
          }
          else{
            res.redirect("https://ydibz.csb.app/reset")
          }
        })
      }
    })
  }
})


userroute.post("/reset", async (req, res) => {
  const existingUser = await User.findOne({ email: req.body.email });
  try {
    if (!existingUser) {
      res.json({
        msg: "No such user exist"
      });
    } else {
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(req.body.password, salt, (err, hash) => {
          User.findOne({email:req.body.email},(err,user)=>{
            if(err || !user){
           console.log(err)
            return res.json({msg:"User with this token does not exist"})
            }
            else{
              const obj={
                password:hash
              }
              user=_.extend(user,obj);
            user.save((err,result)=>{
              if(err){
              console.log(err)
                res.json({msg:"Error resetting password!"})
              }
              else{
                res.json({msg:"Password Changed successfully!"})
              }
            })
            }
          })
        });

      });
    }
  } catch (err) {
    res.send(err);
  }
});


module.exports = userroute;