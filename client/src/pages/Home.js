import React, { useState, useEffect } from "react";
import DefaultLayout from "../components/DefaultLayout";
import moment from "moment";
import { useSelector, useDispatch } from "react-redux";
import { getAllCars } from "../redux/actions/carsActions";
import { Row, Col, DatePicker } from "antd";
import { Link } from "react-router-dom";
import Spinner from "../components/Spinner";
import Star from "../components/Star";
const { RangePicker } = DatePicker;

const Home = () => {
  const { cars } = useSelector((state) => state.carsReducer);
  const { loading } = useSelector((state) => state.alertsReducer);
  const [totalCars, setTotalCars] = useState([]);
  const dispatch = useDispatch();

  useEffect(() => {
    dispatch(getAllCars());
  }, []);

  useEffect(() => {
    setTotalCars(cars);
  }, [cars]);


  // console.log(cars);
  function setFilter(values) {

    var selectedFrom = moment(values[0].$d).format("MMM DD YYYY HH:mm");
    var selectedTo = moment(values[1].$d).format("MMM DD YYYY HH:mm");

    // console.log(selectedFrom + "\n" + selectedTo);
    var temp = [];

    for (let car of cars) {
      if (car.bookedTimeSlots.length === 0){

        temp.push(car);
      } 
      else {

        var flag = false;
        for (let booking of car.bookedTimeSlots) {

          var bookedFrom = moment(booking.from).format("MMM DD YYYY HH:mm");
          var bookedTo = moment(booking.to).format("MMM DD YYYY HH:mm");

          // var bookedFrom = booking.from;
          // var bookedTo = booking.to;

          // console.log(bookedFrom + "\n" + bookedTo);
          if (
            moment(selectedFrom).isBetween(moment(booking.from), moment(booking.to)) ||
            moment(selectedTo).isBetween(moment(booking.from), moment(booking.to)) ||
            moment(bookedFrom).isBetween(moment(selectedFrom), moment(selectedTo)) ||
            moment(bookedTo).isBetween(moment(selectedFrom), moment(selectedTo))
          ) {
            // console.log("condition checked no push");
            // break;
            flag=true;
          } else {

          }
        }
        if(!flag)
        {
          temp.push(car);
        }
      }
    }

    setTotalCars(temp);
  }

  return (
    <DefaultLayout>
      {/* <div>length of cars array is  {cars.length}</div> */}

      <Row className="mt-4" justify="center">
        <Col lg={20} sm={24} className="d-flex justify-content-left">
          <p className="home-p">Choose your time slot first: </p>
          <RangePicker
            showTime={{ format: "HH:mm" }}
            format="MMM DD YYYY HH:mm"
            onChange={setFilter}
          />
        </Col>
      </Row>


      {loading === true && <Spinner />}

      <Row justify="center mt-1" gutter={16}>
        {totalCars.map((car) => {
          return (
            <Col lg={5} sm={24} xs={24}>

              <div className="car p-2 bs1 mt-3">
                <img src={car.image} alt="a car" className="carimg"/>

                <div className="car-content d-flex align-items-center justify-content-between">
                  <div>
                    <p>{car.name}</p>
                    <p>{car.rentPerHour} Rent Per Hour /-</p>
                    <Star star={car.ratings} raters= {car.raters} />
                  </div>
                  <div>
                      <Link to={`/booking/${car._id}`} style={{textDecoration:'none'}}><button className="btn1">BOOK NOW</button>
                      </Link>
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

export default Home;
