import React, { useState } from 'react'
import { useDispatch, useSelector } from 'react-redux'
import { rateCar } from '../redux/actions/bookingActions';
import {message} from 'antd'

function Help( { car, user, bookedSlotFrom, bookedSlotTo , rate }) {

    const dispatch = useDispatch();
    const { loading } = useSelector(state => state.alertsReducer);
    const [re,setRe] = useState(0);

    function send(){
        const reqObj = 
        {
            car,
            user,
            bookedSlotFrom,
            bookedSlotTo,
            rate,
        }
        console.log(reqObj);
        
        if(re==1)
            message.send("You have already rated");
        else
            dispatch(rateCar(reqObj));
        setRe(1);

        // console.log("Thk hua sb");
    }

  return (
    <div>
      {rate && re==0 && send()}
    </div>
  )
}

export default Help
