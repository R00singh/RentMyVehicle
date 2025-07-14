import React from 'react'
import BookingCar from '../pages/BookingCar';
import { Menu, Dropdown, Button , Row, Col} from 'antd';
import { Link } from 'react-router-dom';

const DefaultLayout = (props) => {

  const user =JSON.parse(localStorage.getItem('user'))

  const items = (
    <Menu>
      <Menu.Item>
      <a href="/">
          Home
        </a>
      </Menu.Item>
      <Menu.Item>
        <a href="/userBooking">
          My Bookings
        </a>
      </Menu.Item>
      <Menu.Item>
        <a  href="/admin">
          My Cars
        </a>
      </Menu.Item>
      <Menu.Item>
        <a  href="/myProfile">
          My Profile
        </a>
      </Menu.Item>
      <Menu.Item onClick={()=>{
        localStorage.removeItem('user')
        window.location.href='/login'
      }}>
        
        <li>LogOut</li>

      </Menu.Item>
    </Menu>
  );
  return (
    <div>
        <div className='header bs1'>

          <Row gutter ={16} justify='center'>
            <Col lg={20} sm={24} xs={24}>
              <div className='d-flex justify-content-between'>
                <a href='/' style={{"textDecoration":"none"}}>
                  <h1>rentMyVehicle</h1>
                </a>

                {/* <Dropdown menu={{items}} placement="bottom">
                  <Button>{user.username}</Button>
                </Dropdown> */}

                <Dropdown overlay={items} placement="bottomCenter">
                    <Button>{user.username}</Button>
                </Dropdown>
              </div>            
            </Col>
          </Row>

        </div>
        <div className='content'>
            {props.children}
        </div>

        <div className='footer'>
          <p>Designed and developed by: <b>Rupesh</b></p>
        </div>

    </div>
  )
}

export default DefaultLayout


