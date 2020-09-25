const express = require("express");
const cors = require("cors");
const ShortUrl= require("../models/urlmodel");


const Urlroute= express.Router()

Urlroute.get("/",async(req,res)=>{
    try{
      const posts= await ShortUrl.find({})
      res.status(200).json({
        posts
      })
    }
    catch(e){
      console.error(e)
      res.status(500).send("Error")
    }
  })

Urlroute.post("/urlshort",async(req,res)=>{
  
  await ShortUrl.create({full:req.body.full})
  res.json({
    msg:"Short Url Created!!"
  })
  res.redirect("/")
})

Urlroute.get("/:shorturl",async(req,res)=>{
  
  const shorturl= await ShortUrl.findOne({ short : req.params.shorturl})
  if(shorturl===null) return res.status(400).json({msg:"NO such Id created"})
  shorturl.clicks++
  shorturl.save()
  res.redirect(shorturl.full)
})




Urlroute.get("/chart",(req,res)=>{
  
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



module.exports= Urlroute