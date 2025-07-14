const router = require("express").Router();
const User = require("../models/userModel");
const CryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");

// REGISTER
router.post("/register", async (req,res)=>{
    const newUser = new User({
        username: req.body.username,
        password: CryptoJS.AES.encrypt(				// to make password encrypted
            req.body.password, 
            process.env.PASS_SEC					
        ).toString(),
    });

    try{
        const savedUser = await newUser.save();			// async finc
        res.status(201).json(savedUser);
    } catch(err){
        res.status(500).json(err);
    }    
});


// LOGIN

router.post("/login", async (req,res)=>{
    try{
        const user = await User.findOne({username: req.body.username});		//find whether user exist
        !user && res.status(401).json("Wrong Credentials!")
        const hashedPwd = CryptoJS.AES.decrypt(						// decode the the original password
            user.password, 
            process.env.PASS_SEC
        );					
        const originalPwd = hashedPwd.toString(CryptoJS.enc.Utf8);	
        originalPwd !== req.body.password && 				//matching with org pwd
            res.status(401).json("Wrong Password");

        const accessToken = jwt.sign(						// using jwt for more security
          {
              id: user._id,
              isAdmin: user.isAdmin,
          }, 
          process.env.JWT_SEC,
          {expiresIn: "3d"}
        );
        const {password, ...others} = user._doc;
        res.status(200).json({...others, accessToken});

    } catch(err){
        console.log("fail");
        res.status(500).json(err);
    }
});


module.exports = router