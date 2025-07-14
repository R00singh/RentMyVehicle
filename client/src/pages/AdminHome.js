import React, { useState, useEffect } from "react";
import DefaultLayout from "../components/DefaultLayout";
import moment from "moment";
import { useSelector, useDispatch } from "react-redux";
import { getAllCars ,deleteCar} from "../redux/actions/carsActions";
import { Row, Col, DatePicker, Button } from "antd";
import { DeleteOutlined , EditOutlined } from '@ant-design/icons';
import { Link } from "react-router-dom";
import Spinner from "../components/Spinner";
import { message, Popconfirm } from 'antd';
const { RangePicker } = DatePicker;

const AdminHome = () => {
  const { cars } = useSelector((state) => state.carsReducer);
  const { loading } = useSelector((state) => state.alertsReducer);
  const [totalCars, setTotalCars] = useState([]);
  // const [ myCars, setMyCars ] = useState([]);
  const myCars= [];

  const dispatch = useDispatch();

  useEffect(() => {
    dispatch(getAllCars());
  }, []);

  useEffect(() => {
    setTotalCars(cars);
  }, [cars]);

  for(var i=0; i<cars.length; i++)
  {
    if(cars[i].myOwner== JSON.parse(localStorage.getItem('user'))._id)
    {
      // console.log(cars[i]);
      myCars.push(cars[i]);
    }
  }


  // console.log(myCars.length);
  // function findingMyCars()
  // {
  //   console.log(JSON.parse(localStorage.getItem('user'))._id); 
  //     setMyCars(cars.find(o=>o.myOwner ==JSON.parse(localStorage.getItem('user'))._id));
  // }
  // useEffect(() =>{
  //     console.log(JSON.parse(localStorage.getItem('user'))._id);
  //     console.log(cars.myOwner)
  //   // setMyCars(cars.find(o=>o.myOwner ==JSON.parse(localStorage.getItem('user'))._id));
  // });

  return (
    <DefaultLayout>
      {/* <div>length of cars array is  {cars.length}</div> */}

      <Row justify="center mt-3" gutter={16}>

        <Col lg={20} sm={24}>
          <div className="text-right">
            <Button className="btn1" style={{textAlign:"center"}}><a href='/addcar'>ADD CAR</a></Button>
          </div>
        </Col>
      </Row>

      {loading === true && <Spinner />}

      <Row justify="center mt-1" gutter={16}>
        {myCars.map((car) => {
          return (
            <Col lg={5} sm={24} xs={24}>
              <div className="car p-2 bs1 mt-3">
                <img src={car.image} alt="a car" className="carimg" />

                <div className="car-content d-flex align-items-center justify-content-between">
                  <div>
                    <p>{car.name}</p>
                    <p>{car.rentPerHour} Rent Per Hour /-</p>
                  </div>
                  <div className="mr-4">
                        <Link to ={`/editcar/${car._id}`}><EditOutlined className="mr-3" style={{color:'green', cursor:'pointer'}}/></Link>

                        <Popconfirm
                            title="Delete the task"
                            description="Are you sure to delete this car?"
                            onConfirm={()=>{dispatch(deleteCar({carid : car._id}))}}
                            okText="Yes"
                            cancelText="No"
                          >
                            <DeleteOutlined style={{color:'red', cursor:'pointer'}}/>
                          </Popconfirm>
                        
                  </div>
                </div>
              </div>
            </Col>
          );
        })}
      </Row>
    </DefaultLayout>
  );
};

export default AdminHome;
