const mongoose= require("mongoose");
const UserSchema= mongoose.Schema({
    Firstname:{
      type:String,
      required:true
    },
    Lastname:{
      type:String,
      required:true
    },
    email:{
      type:String,
      required:true,
      unique: true
    },
    password:{
      type:String,
      required:true
    },
    verified: {
      type: Boolean,
      default: false
    },
    resetLink: {
      type: String,
      default: ''
    },
    date:{
      type:Date,
      default:Date.now
    }
})

module.exports= mongoose.model("User",UserSchema)