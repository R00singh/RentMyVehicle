const mongoose = require("mongoose");

const carSchema = new mongoose.Schema({

    name : {
        type : String , 
        required : true
    } ,
    image : {
        type : String 
        // required : true
    } , 
    myOwner:{
        type : mongoose.Schema.Types.ObjectID , 
        ref:'users',
        // required: true
    },
    capacity : {
        type : Number , 
        required : true
    },
    fuelType : {
        type : String , 
        required : true
    } , 
    ratings :{
        type: Number,
        default : 4
    },
    raters :{
        type: Number,
        default : 0
    },
    bookedTimeSlots : [
        {
            from : {type : String , required : true},
            to : {type : String , required : true}
        }
    ] , 

    rentPerHour : {type : Number , required : true}


}, {timestamps : true}

)
const carModel = mongoose.model('cars' , carSchema)
module.exports = carModel