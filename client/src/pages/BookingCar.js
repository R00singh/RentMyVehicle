import React ,{ useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import DefaultLayout from '../components/DefaultLayout';
import { useSelector, useDispatch } from 'react-redux';
import { getAllCars } from '../redux/actions/carsActions';
import Spinner from '../components/Spinner';
import { Row, Col, Divider, DatePicker, Checkbox, Modal } from 'antd';
import moment, { relativeTimeRounding } from 'moment';
import { bookCar } from '../redux/actions/bookingActions';
import StripeCheckout from "react-stripe-checkout";

const {RangePicker} = DatePicker;

const BookingCar = (match) =>{
  const { cars } = useSelector(state => state.carsReducer);
  const { loading } = useSelector(state => state.alertsReducer);
  const [car, setCar] = useState({});
  const dispatch = useDispatch();
  const [from, setFrom] = useState()
  const [to , setTo] = useState();
  const [totalHours, setTotalHours] = useState(0);
  const [driver, setDriver] = useState(false);
  const [totalAmount, setTotalAmount] = useState(0);
  const [showModal, setShowModal] = useState(false);
  const { carid } = useParams();
  
  useEffect(() => {
    if(cars.length==0){
      dispatch(getAllCars());
    }
    else {
      setCar(cars.find(o=>o._id==carid))
    }
  }, [cars]);
    
  useEffect(() =>{

    setTotalAmount((totalHours* car.rentPerHour) )

    if(driver)
    {
      setTotalAmount(totalAmount + (30*totalHours))
    }
  }, [driver, totalHours]);

  function selectTimeSlots(values)
  {
    var selectedFrom = moment(values[0].$d).format("MMM DD YYYY HH:mm");
    var selectedTo = moment(values[1].$d).format("MMM DD YYYY HH:mm");

    for (let booking of car.bookedTimeSlots) {

      var bookedFrom = moment(booking.from).format("MMM DD YYYY HH:mm");
      var bookedTo = moment(booking.to).format("MMM DD YYYY HH:mm");

      if (
        moment(selectedFrom).isBetween(moment(booking.from), moment(booking.to)) ||
        moment(selectedTo).isBetween(moment(booking.from), moment(booking.to)) ||
        moment(bookedFrom).isBetween(moment(selectedFrom), moment(selectedTo)) ||
        moment(bookedTo).isBetween(moment(selectedFrom), moment(selectedTo))
      ) {

        alert("Car already booked in this time slot, kindly choose another one!");
        return;
      }
    }
    setFrom(selectedFrom);
    setTo(selectedTo);
    setTotalHours(values[1].diff(values[0], 'hours'))
  }

  function onClick(e){
    e.preventDefault();
    const reqObj={
      user : JSON.parse(localStorage.getItem('user'))._id,
      car : carid,
      totalHours,
      totalAmount,
      driverRequired: driver,
      bookedTimeSlots: {
        from,
        to,
      }
    }
    console.log(reqObj);
    dispatch(bookCar(reqObj));
  }

  return (
    <DefaultLayout>
      {loading && <Spinner/>}
      <Row justify='center' className='d-flex align-items-center p-2' style={{minHeight:'90vh'}}>
        <Col lg={10} sm={24} xs={24}>
          <img src={car.image} className='carimg2 bs1'/>
        </Col>
        <Col lg={10} sm={24} xs={24} style={{textAlign:'right'}}>
          <Divider type='horizontal' dashed><h4><b>Car Info</b></h4></Divider>
          <div className='text-right'>
            <p>{car.name}</p>
            <p>{car.rentPerHour} Rent Per Hour /-</p>
            <p>Fuel: {car.fuelType}</p>
            <p>Max Capacity: {car.capacity}</p>
          </div>

          <Divider type='horizontal' dashed><h4><b>Select Time Slots</b></h4></Divider>
          <RangePicker showTime={{format: 'HH:mm'}} format ='MMM DD YYYY HH:mm' onChange={selectTimeSlots}/>
          <br/>
          <button className='btn1 mt-3' onClick={()=>{setShowModal(true)}}>Show Booked Slots</button>
          
          {from && to && (<div>
              <p>Total Hours: <b>{totalHours}</b></p>
              <p>Rent per Hour: <b>{car.rentPerHour}</b></p>
              <p>Driver charges per Hour: <b>30</b></p>
              <Checkbox onChange={(e)=>{
                if(e.target.checked)
                {
                  setDriver(true);
                }
                else
                {
                  setDriver(false);
                }
              }}>Driver required</Checkbox>

              <h3>Total Amount : {totalAmount}</h3>
              <button className="btn1" style={{fontWeight:"bold"}} onClick={onClick}>Book Now</button>
          </div>)}
          
        </Col>

      {car.name && <Modal open={showModal} closable={false} footer={false} title='Booked Time Slots'>
              <div className='p-2'>
                {car.bookedTimeSlots.map(slot=>{
                  return <p className='mt-3'><b>{slot.from} - {slot.to}</b></p>
                })}
                <div className='text-right mt-3'>
                  <button className='btn1' onClick={()=>{setShowModal(false)}}>Close</button>
                </div>
              </div>
      </Modal>}
      </Row>

    </DefaultLayout>
  )
}

export default BookingCar