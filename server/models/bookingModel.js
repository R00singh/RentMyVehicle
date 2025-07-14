const mongoose = require("mongoose");

const bookingSchema = new mongoose.Schema({

    car : {
        type : mongoose.Schema.Types.ObjectID , 
        ref:'cars'
    },
    user : {
        type : mongoose.Schema.Types.ObjectID , 
        ref:'users'
    },
    bookedTimeSlots : {
        from : {type : String, default: "hbuuhbjn"} ,
        to : {type : String}
    },
    star : {type: Number, default: 0},
    totalHours : {type : Number},
    totalAmount : {type : Number},
    driverRequired : {type : Boolean}

},
  {timestamps : true}
)

const bookingModel = mongoose.model('bookings' , bookingSchema)

module.exports = bookingModel