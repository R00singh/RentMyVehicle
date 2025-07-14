import axios from "axios";
import {message} from "antd"



export const getAllUsers = () => async dispatch => {
    dispatch({type: 'LOADING', payload: true});
    try 
    {
        const response = await axios.get("/api/users/getallusers");
        // console.log(response);
        dispatch({type: 'GET_ALL_USERS', payload: response.data});
        dispatch({type: 'LOADING', payload: false});
    } catch (err) {
        console.log("Yha glti h");
        console.log(err);
        dispatch({type: 'LOADING', payload: false});
    }
}

export const editMyProfile =(reqObj) => async dispatch =>{
    dispatch({type: 'LOADING', payload: true});
    try {
        console.log(reqObj);
        const response = await axios.post("/api/users/editMyProfile", reqObj);

        dispatch({type: 'LOADING', payload: false});
        // console.log('CCC')
        message.success('User details updated successfully');
        // setTimeout(()=> {
        //     window.location.href ='/myProfile'
        // }, 500);
    } catch (err) {
        console.log(err);
        console.log("gltii");
        dispatch({type: 'LOADING', payload: false});
    }
}


export const userLogin=(reqObj)=>async dispatch=>{
    dispatch({type: 'LOADING', payload: true});
    try {
        const response = await axios.post("/api/users/login",reqObj);
        localStorage.setItem('user' , JSON.stringify(response.data))
        message.success('Login success')
        dispatch({type: 'LOADING', payload: false});
        setTimeout(()=>{
            window.location.href='/'
        }, 500);
    } catch (err) {
        message.error(err.data);
        console.log(err);
        dispatch({type: 'LOADING', payload: false});
        
    }
}


export const googleAuth=(reqObj)=>async dispatch=>{
    dispatch({type: 'LOADING', payload: true});
    try {
        const response = await axios.post("/api/users/google",reqObj);
        console.log("inside google userActions.js" );
        console.log(response);

        localStorage.setItem('user' , JSON.stringify(response.data))
        message.success('Login success with Google');
        dispatch({type: 'LOADING', payload: false});
        setTimeout(()=>{
            window.location.href='/'
        }, 500);
    } catch (err) {
        message.error("Something went wrong");
        console.log(err);
        dispatch({type: 'LOADING', payload: false});
    }
}


export const userRegister=(reqObj)=>async dispatch=>{
    // console.log("inside userRegiser userActions");
    // console.log(reqObj);
    dispatch({type: 'LOADING', payload: true});
    try {
        const response = await axios.post("/api/users/register",reqObj);
        message.success('Successfully registered')
        setTimeout(()=>{
            window.location.href='/login'
        }, 500);
        
        dispatch({type: 'LOADING', payload: false});
        
    } catch (err) {
        message.error(err.data);
        console.log(err);
        dispatch({type: 'LOADING', payload: false});
        
    }
}