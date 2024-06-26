import express from "express";
import User from "./user.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const router=express.Router();


//? register user 

router.post("/user/register",async(req,res)=>{
    // extract ner user from req.body 

    const newUser=req.body;

    //check if user with provided email already exist 
    const user=await User.findOne({email: newUser.email});

    // if user,throw error
    if (user){
        return res.status(409).send({message:"email already exist"});
    }

    //hash password before saving user 
    const plainPassword =newUser.password;

    //salt round => adds randoms to generate password
    const saltround=10;//1 to 32

    const hashedpassword=await bcrypt.hash(plainPassword,saltround);

    //update user password with hases password
    newUser.password=hashedpassword;

    // save user  
    await User.create(newUser);

    return res.status(201).send({message:"user is register sucessfully."});
});

// ? login user 
router.post("/user/login",async(req,res)=>{
    // extract login credential from req.body
    const loginCredential=req.body;


    //find user using email 
    const user=await User.findOne({email:loginCredential.email});

    //if not user,throw error
    if (!user){
        return res.status(404).send({message:"invalid credentials"})
    }
    // check for password match 
    const plainPassword=loginCredential.password;
    const hashedPassword=user.password;
    const ispasswordMatch=await bcrypt.compare(plainPassword,hashedPassword);
    // if not password match ,throw error 
    if(!ispasswordMatch){
        return res.status(409).send({message:"invalid Credential"});
    }
    //generate token 
    const payload={email:user.email};
    const signature= "jdshijchsdjhsjdhfdsjhfj";
    const token =jwt.sign(payload,signature);
    // hide hash password
    user.password=undefined;

    //send res
    return res
    .status(200)
    .send({message:"sucess",accessToken:token,userDetail:user});


})

export default router;