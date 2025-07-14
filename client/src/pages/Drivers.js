import React, { useState, useEffect } from "react";
import DefaultLayout from "../components/DefaultLayout";
import moment from "moment";
import { useSelector, useDispatch } from "react-redux";
import { getAllUsers } from "../redux/actions/userActions";
import { Row, Col, DatePicker } from "antd";
import { Link } from "react-router-dom";
import Spinner from "../components/Spinner";



function Drivers() {

  // Here the name should be same as that of the initialData Reducer.
  const { users } = useSelector((state) => state.usersReducer);

  const { loading } = useSelector((state) => state.alertsReducer);
  const [totalUsers, setTotalUsers] = useState([]);
  const dispatch = useDispatch();
  const drivers= []
  useEffect(() => {
    dispatch(getAllUsers());
  }, []);

  useEffect(() => {
    setTotalUsers(users);
  }, [users]);


  for(var i=0;i<totalUsers.length; i++)
  {
      if(totalUsers[i].isDriver)
        drivers.push(totalUsers[i]);
  }


  return (
    <DefaultLayout>


      {/* <div>length of drivers array is  {users.length}</div> */}

      {loading === true && <Spinner />}

      <Row justify="center mt-1" gutter={16}>

      <Col lg={20} sm={24}>
        {drivers.map((car) => {
          return (

            <Row gutter={16} className='bs1 m-4 text-left p-2' >

              <Col lg={7} sm={24}>
                  Username:
                <p><b>{car.username}</b></p>
              </Col>

              <Col lg={10} sm={24}>
                <p><b>Contact Number:  </b>{car.contactNumber}</p>
                <p><b>Email:  </b>{car.email}</p>
                <p><b>Location:  </b>{car.location}</p>
              </Col>

              <Col lg={7} sm={24}>
                <img src={car.image} height="125" width="200" classname="p-4" />
              </Col>
            </Row>
          );
        })}

        </Col>
      </Row>
    </DefaultLayout>
  )
}

export default Drivers
