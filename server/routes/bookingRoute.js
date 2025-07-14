const express = require("express");
const router = express.Router();
const Booking = require("../models/bookingModel");
const Car = require("../models/carModel");
const moment = require("moment");

router.post("/bookcar", async (req, res) => {
  // console.log(req.body);

  try {
      const newbooking = new Booking(req.body);
      await newbooking.save();
      const car = await Car.findOne({ _id: req.body.car });

      car.bookedTimeSlots.push(req.body.bookedTimeSlots);

      await car.save();
      res.send("Your booking is successfull");

  } catch (error) {
    console.log(error);
    return res.status(400).json(error);
  }
});


router.post("/deleteBooking", async (req, res) => {
  try {
    const car = await Car.findOne({_id: req.body.carid});
    // console.log(car.bookedTimeSlots)
    car.bookedTimeSlots = car.bookedTimeSlots.filter(function(el) { 
      return !moment(el.from).isSame(req.body.bookedSlotFrom) || !moment(el.to).isSame(req.body.bookedSlotTo);
    }); 
    // console.log(car.bookedTimeSlots);
    car.save();
    console.log(car.bookedTimeSlots);
    await Booking.findOneAndDelete({ car: req.body.carid, user: req.body.userid, bookedTimeSlots:{from: req.body.bookedSlotFrom, to: req.body.bookedSlotTo}});
    res.send("Booking deleted Successfully");
  } catch (err) {
    console.log(err);
    res.status(400).json(err);
  }
});



router.post("/ratecar", async (req, res) => {
  // console.log(req.body);
  // console.log(req.body.car);
  try {
    const booking = await Booking.findOne({car: req.body.car, user: req.body.user, bookedTimeSlots:{from: req.body.bookedSlotFrom, to: req.body.bookedSlotTo} });
    const car = await Car.findOne({_id: req.body.car});
    if(req.body.rate>5)
    {
      req.body.rate=5;
    }
    // console.log(req.body.rate);
    car.ratings = (car.ratings*car.raters + req.body.rate)/(car.raters+1);
    car.raters = car.raters+1;
    booking.star = req.body.rate;
    // console.log(booking);
    // console.log(req.body.car);
    // console.log(car);
    await booking.save();
    await car.save();
    res.send("Booking details updated successfully");
    // console.log(booking);
    console.log("Booking route(ratecar): Tu b thk aaja ab");
  } catch (error) {
    console.log(error);
    console.log("dikkt aai booking route of ratecar me");
    return res.status(400).json(error);
  }
});



router.get("/getallbookings", async (req, res) => {
  try {
    const bookings = await Booking.find().populate("car");
    res.send(bookings);
  } catch (error) {
    return res.status(400).json(error);
  }
});

module.exports = router;