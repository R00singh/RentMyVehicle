const jwt = require("jsonwebtoken");


/*************  ✨ Windsurf Command ⭐  *************/
/**
 * Middleware to verify a JWT token from the request headers.
 * If a valid token is provided, the user information is added to the request object.
 * Proceeds to the next middleware if successful, otherwise sends an error response.
 *
 * @param {Object} req - The request object from the client.
 * @param {Object} res - The response object to send feedback to the client.
 * @param {Function} next - The callback to pass control to the next middleware.
 */

/*******  80fe652c-8a4b-4874-af3f-52878b878fc7  *******/
const verifyToken = (req,res,next)=>{
    const authHeader = req.headers.token;
    if(authHeader){
        const token = authHeader.split(" ")[1];
        jwt.verify(token,process.env.JWT_SEC, (err,user) => {
            if(err) res.status(403).json("Token is not valid");
            req.user = user;
            next();
        });
    } else{
        return res.status(401).json("You are not authenticated!");
    }
}

const verifyTokenAndAuthorization = (req, res, next)=>{
    verifyToken(req, res, () => {
        if(req.user.id === req.params.id || req.user.isAdmin){
            next();
        } else{
            res.status(403).json("You are not allowed to do that!");
        }
    })
}
const verifyTokenAndAdmin = (req, res, next)=>{
    verifyToken(req, res, () => {
        if(req.user.isAdmin){
            next();
        } else{
            res.status(403).json("You are not allowed to do that!");
        }
    })
}

module.exports = {
    verifyToken, 
    verifyTokenAndAuthorization,
    verifyTokenAndAdmin,
};
