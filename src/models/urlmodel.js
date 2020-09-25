const mongoose= require("mongoose");
const shortid = require('shortid');
const Urlschema=mongoose.Schema({
  full:{
    type:String,
    required:true
  },
  short:{
    type:String,
    required:true,
    default:shortid.generate
  },
  clicks:{
    type:Number,
    required:true,
    default:0
  },
  date: {
    type: Date,
    default: Date.now
  },
})



module.exports= mongoose.model("ShortUrl",Urlschema)