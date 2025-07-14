const router = require("express").Router();
const User = require("../models/userModel");
const CryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");


router.get("/getallusers", async (req, res) => {
    try {
      const users = await User.find();
      res.send(users);
    //   console.log(users);
    } catch (err) {
      return res.status(400).json(err);
    }
  });

  router.post("/editMyProfile", async(req, res) =>{

    try{
      const user = await User.findOne({_id: req.body._id})
      user.username = req.body.username;
      user.image = req.body.image,
      user.rentPerHour = req.body.rentPerHour;
      user.contactNumber= req.body.contactNumber
      user.location = req.body.location
      user.isDriver = req.body.isDriver
  
      await user.save();
  
      res.send("User details updated successfully");
    }catch(err)
    {
        console.log("User updation failed");
        return res.status(400).json(error);
    }
  });


// REGISTER
router.post("/register", async (req,res)=>{
    if(req.body.password !== req.body.cpassword){
        // console.log(req.body.password, req.body.cpassword)
        return res.status(400).json("Password and Confirm passwords are not same!");
    }
    const newUser = new User({
        username: req.body.username,
        email: req.body.email,
        isDriver: req.body.isDriver,
        contactNumber: req.body.contactNumber,
        location: req.body.location,
        password: CryptoJS.AES.encrypt(				// to make password encrypted
            req.body.password, 
            process.env.PASS_SEC					
        ).toString(),
    });


    // console.log(newUser);

    try{
        const savedUser = await newUser.save();			// async finc
        res.status(201).json(savedUser);
    } catch(err){
        // console.log(req);
        console.log("Error ye h");
        console.log(err);
        res.status(400).json(err);
    }    
});


// LOGIN

router.post("/login", async (req,res)=>{
    try{
        const user = await User.findOne({username: req.body.username});		//find whether user exist
        if(!user){
            return res.status(400).json("Wrong Credentials!");
        } 
        const hashedPwd = CryptoJS.AES.decrypt(						// decode the the original password
            user.password, 
            process.env.PASS_SEC
        );					
        const originalPwd = hashedPwd.toString(CryptoJS.enc.Utf8);	
        if(originalPwd !== req.body.password){       		//matching with org pwd
            return res.status(400).json("Wrong Password");
        }
        const accessToken = jwt.sign(						// using jwt for more security
          {
            id: user._id,
            isAdmin: user.isAdmin,
          }, 
          process.env.JWT_SEC,
          {expiresIn: "3d"}
        );
        const {password, ...others} = user._doc;
        return res.status(200).json({...others, accessToken});

    } catch(err){
        console.log("normal login failed");
        return res.status(400).json(err);
    }
});

//LOGIN Using Google

router.post("/google", async(req, res)=>{
    try{
        // console.log("email is " + req.body.email);
        const user = await User.findOne({email: req.body.email});
        if(user){
            // console.log(user);
            // console.log("google user already exist");
            
            const accessToken = jwt.sign(						// using jwt for more security
            {
                id: user._id,
                isAdmin: user.isAdmin,
            }, 
            process.env.JWT_SEC,
            {expiresIn: "3d"}
            );
            res.cookie("access_token", accessToken, {
                httpOnly: true,
            }).status(200).json(user._doc);
        }
        else{
            const newUser = new User({
                ...req.body,
                fromGoogle: true
            });
            const savedUser = await newUser.save();
            // console.log("google creating new user");
            // console.log(savedUser);

            const accessToken = jwt.sign(						// using jwt for more security
            {
                id: savedUser._id,
                isAdmin: savedUser.isAdmin,
            }, 
            process.env.JWT_SEC,
            {expiresIn: "3d"}
            );
            res.cookie("access_token", accessToken, {
                httpOnly: true,
            }).status(200).json(savedUser._doc);
        }
    } catch(err){
        console.log("google auth failed backend");
        return res.status(400).json(err);
    }
})

module.exports = router