const express = require("express");
const ShortUrl= require("../models/urlmodel");
const Chartroute= express.Router()

Chartroute.get("/chart",(req,res)=>{
  
  ShortUrl.aggregate(
    [
      {$project:{day:{$dayOfMonth:'$date'},month:{$month:'$date'},year:{$year:'$date'}}},
{$group:{_id:{day:'$day',month:'$month',year:'$year'}, count: {$sum:1}}}
    ]).exec()
    .then(result=>{
      res.json(result)
    })
    .catch(err=>{
      console.log(err)
    })
  
})



module.exports= Chartroute