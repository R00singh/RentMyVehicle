import axios from "axios";
import {message} from 'antd'


export const bookCar = (reqObj) => async dispatch => {
    dispatch({type: 'LOADING', payload: true});
    try {
        console.log("inside carActions");
        console.log(reqObj);
        const response = await axios.post("/api/bookings/bookcar", reqObj);
        message.success("Your car booked successfully");
        setTimeout(() =>{
            window.location.href="/userBooking"
        }, 500);

       
    } catch (err) {
        console.log(err);
        dispatch({type: 'LOADING', payload: false});
        message.error("Something went wrong, please try later");
    }
}


export const rateCar = (reqObj) => async dispatch => {
    dispatch({type: 'LOADING', payload: true});
    console.log(reqObj);
    try {
        const response = await axios.post("/api/bookings/ratecar", reqObj);
        // console.log("yghvjh");
        message.success("Your ratings saved successfully");
        // setTimeout(() =>{
        //     window.location.href="/userBooking"
        // }, 500);
        console.log("Yha aaya");
    } catch (err) {
        console.log(err);
        dispatch({type: 'LOADING', payload: false});
        message.error("Something went wrong, please try later");
        console.log("ni aya");
    }
}


export const getAllBookings = () => async dispatch => {
    dispatch({type: 'LOADING', payload: true});
    try {
        const response = await axios.get("/api/bookings/getallbookings");
        dispatch({type: 'GET_ALL_BOOKINGS', payload: response.data});
        dispatch({type: 'LOADING', payload: false});
        
    } catch (err) {
        console.log(err);
        dispatch({type: 'LOADING', payload: false});
        
    }
}


export const deleteBooking =(reqObj) => async dispatch =>{
    dispatch({type: 'LOADING', payload: true});
    try {
        console.log("booking actions");
        console.log(reqObj);
        const response = await axios.post("/api/bookings/deleteBooking", reqObj);

        dispatch({type: 'LOADING', payload: false});
        message.success('Booking deleted successfully');
        // setTimeout(()=> {
        //     window.location.reload()
        // }, 500);
    } catch (err) {
        console.log(err);
        console.log("gltii");
        message.error(err.response.data);
        dispatch({type: 'LOADING', payload: false});
    }
}