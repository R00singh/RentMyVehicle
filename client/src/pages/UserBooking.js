import React, { useState, useEffect } from 'react'
import { useDispatch, useSelector } from 'react-redux'
import DefaultLayout from '../components/DefaultLayout'
import { getAllBookings,  deleteBooking } from '../redux/actions/bookingActions';
import {Row, Col, Form} from 'antd';
import { Link } from "react-router-dom";
import { DeleteOutlined , EditOutlined } from '@ant-design/icons';
import { message, Popconfirm } from 'antd';
import moment, { relativeTimeRounding } from 'moment';
import Spinner from '../components/Spinner';
import Star from "../components/Star";
import Help from '../components/Help';


function UserBooking() {

    const dispatch = useDispatch();
    const {bookings} = useSelector(state =>state.bookingsReducer)
    const user= JSON.parse(localStorage.getItem("user"))
    const [rate, setRate] = useState();
    const { loading } = useSelector((state) => state.alertsReducer);
    const userid = JSON.parse(localStorage.getItem("user"))._id;

    useEffect(() =>{
        dispatch(getAllBookings())
    }, []);

  return (
    <DefaultLayout>

        {loading === true && <Spinner />}
        <h3 className='text-center mt-2'>My Bookings</h3>

        <Row justify='center' gutter={16}>

            <Col lg={20} sm={24}>

                    <h1>Checking</h1>


                    {bookings.filter(o=>o.user==user._id).map(booking =>{
                        return  (                       
                        <Row gutter={16} className='bs1 m-4 text-left p-2' >
                        
                            <Col lg={7} sm={24}>

                                <p><b>{booking.car.name}</b></p>
                                <p>Total Hours: <b>{booking.totalHours}</b></p>
                                <p>Rent per Hour: <b>{booking.car.rentPerHour}</b></p>
                                <p>Total Amount: <b>{booking.totalAmount}</b></p>
                                <input type='number' onChange={(e) => {setRate(e.target.value)}}/>
                                <Help car= {booking.car._id} user ={booking.user} bookedSlotFrom={booking.bookedTimeSlots.from} bookedSlotTo={booking.bookedTimeSlots.to} rate ={rate} />
                                <p>Your ratings: <Star star={rate} raters={1} /></p>
                            </Col>

                            <Col lg={10} sm={24}>
                                {/* <p>TransactionId: <b>{booking.transactionId}</b></p> */}
                                <p>From: <b>{booking.bookedTimeSlots.from}</b></p>
                                <p>To: <b>{booking.bookedTimeSlots.to}</b></p>
                                <p>Date of Booking: <b> {moment(booking.createdAt).format('MMM DD YYYY')}</b></p>
                            </Col>

                            <Col lg={7} sm={24}>
                                <img src={booking.car.image} height="125" width= "200" classname="p-4" /> 
                             </Col>
                             <div className="mr-4">
                                <Popconfirm
                                    title="Delete the booking?"
                                    description="Are you sure to delete this booking?"
                                    onConfirm={()=>{dispatch(deleteBooking({carid : booking.car._id, userid: userid, bookedSlotFrom:booking.bookedTimeSlots.from, bookedSlotTo:booking.bookedTimeSlots.to }))}}
                                    okText="Yes"
                                    cancelText="No"
                                >
                                    <DeleteOutlined style={{color:'red', cursor:'pointer'}}/>
                                </Popconfirm>
                                
                            </div>
                        </Row>
                        )
                    })}
        
            </Col>

        </Row>
    </DefaultLayout>
  )
}

export default UserBooking