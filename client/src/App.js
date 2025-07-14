import './App.css';
import React, {Fragment} from 'react';
import {Route, Routes, BrowserRouter, Navigate, Outlet} from "react-router-dom"
import Home from './pages/Home';
import Login from './pages/Login';
import Register from './pages/Register';
import BookingCar from './pages/BookingCar';
import antd from "antd"
import UserBooking from './pages/UserBooking';
import AddCars from './pages/AddCars';
import AdminHome from './pages/AdminHome';
import EditCar from './pages/EditCar';
import Drivers from './pages/Drivers';
import MyProfile from './pages/MyProfile';


const auth = localStorage.getItem('user');

function App() {
  return (
    <div >
      <BrowserRouter>
        <Routes>
          <Route path='/' element = { auth?<Home/>:<Login/>}/>
          <Route path='/login' element = {<Login/>}/>
          <Route path='/register' element = {<Register/>}/>
          <Route path='/booking/:carid' element = { auth?
              <BookingCar/> : <Login/>
          }/>
          <Route path='/userBooking' element = {auth ? <UserBooking/> : <Login/>}/>
          <Route path='/addcar' element ={auth ? <AddCars/> : <Login/>}/>
          <Route path='/editcar/:carid' element={auth ? <EditCar/> : <Login/>}/>
          <Route path='/admin' element={auth ? <AdminHome/> : <Login/>} />
          <Route path='/drivers' element={auth ? <Drivers/> : <Login/> } />
          <Route path='/myProfile' element={auth ? <MyProfile/> : <Login/> } />

        </Routes> 
      </BrowserRouter>

    </div>
  );
}

export default App;

