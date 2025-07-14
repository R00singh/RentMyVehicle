import { message } from "antd";
import axios from "axios";

export const getAllCars = () => async dispatch => {
    dispatch({type: 'LOADING', payload: true});
    try 
    {
        const response = await axios.get("/api/cars/getallcars");
        // console.log(response);
        dispatch({type: 'GET_ALL_CARS', payload: response.data});
        dispatch({type: 'LOADING', payload: false});
    } catch (err) {
        console.log(err);
        dispatch({type: 'LOADING', payload: false});
    }
}


export const addCar =(reqObj) => async dispatch =>{
    dispatch({type: 'LOADING', payload: true});
    console.log("ReqObj: Car Actions")
    console.log(reqObj)
    try {
        const response = await axios.post("/api/cars/addcar", reqObj);

        dispatch({type: 'LOADING', payload: false});
        console.log('CCC')
        message.success('New Car added successfully');
        setTimeout(()=> {
            window.location.href ='/admin'
        }, 500);
    } catch (err) {
        console.log(err);
        console.log("gltii");
        dispatch({type: 'LOADING', payload: false});
    }
}


export const editCar =(reqObj) => async dispatch =>{
    dispatch({type: 'LOADING', payload: true});
    try {
        const response = await axios.post("/api/cars/editcar", reqObj);

        dispatch({type: 'LOADING', payload: false});
        console.log('CCC')
        message.success('Car details updated successfully');
        setTimeout(()=> {
            window.location.href ='/admin'
        }, 500);
    } catch (err) {
        console.log(err);
        console.log("gltii");
        dispatch({type: 'LOADING', payload: false});
    }
}


export const deleteCar =(reqObj) => async dispatch =>{
    dispatch({type: 'LOADING', payload: true});
    try {
        const response = await axios.post("/api/cars/deletecar", reqObj);

        dispatch({type: 'LOADING', payload: false});
        console.log('CCC')
        message.success('Car deleted successfully');
        setTimeout(()=> {
            window.location.reload()
        }, 500);
    } catch (err) {
        // console.log(err.response.data);
        // console.log("gltii");
        message.error(err.response.data);
        dispatch({type: 'LOADING', payload: false});
    }
}