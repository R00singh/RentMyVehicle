import React from 'react'
import { Row, Col, Form, Input } from 'antd'
import { Link } from 'react-router-dom'
import {useDispatch, useSelector} from 'react-redux'
import { userRegister } from '../redux/actions/userActions'
import { userLogin } from '../redux/actions/userActions'
import AOS from 'aos';
import Spinner from '../components/Spinner'
import 'aos/dist/aos.css'; // You can also use <link> for styles
// ..
AOS.init();

const Register = () => {

  const [checked, setChecked] = React.useState(false);
  const dispatch = useDispatch()
  const {loading} = useSelector(state => state.alertsReducer)
  

  const handleChange = () => {
    setChecked(!checked);
  };
  
  function onFinish(values){
    values.isDriver = checked;
      console.log(values);
      dispatch(userRegister(values))
  }



  return (
    <div className='login'>
      {loading && (<Spinner/>)}
      <Row gutter={16}>

        <Col lg={16} style={{position: "relative"}}>

          <img 
          data-aos= 'slide-right'
          data-aos-duration='1500'
          src="https://t3.ftcdn.net/jpg/09/59/48/50/360_F_959485026_HU6hetaJPcNp119uWqlRwrKxwiFu2PpE.jpg" height="100%" width="100%"/>
        </Col>
        <Col lg={8} className='text-left p-5'>
          <Form layout='vertical' className='login-form p-5' onFinish={onFinish}>
        <h1>Register</h1>
        <hr/>
            <Form.Item name="username" label="Username" rules={[{required: true}]}>
              <Input/>
            </Form.Item>
            <Form.Item name="email" label="Email" rules={[{required: true}]}>
              <Input type='email'/>
            </Form.Item>

            <Form.Item name="contactNumber" label="Contact Number" rules={[{required: true}]}>
              <Input type='number'/>
            </Form.Item>

            <Form.Item name="location" label="Location" rules={[{required: true}]}>
              <Input/>
            </Form.Item>

            <Form.Item name="password" label="Password" rules={[{required: true}]}>
              <Input type='password'/>
            </Form.Item>

            <Form.Item name="cpassword" label="Confirm Password" rules={[{required: true}]}>
              <Input type='password'/>
            </Form.Item>

            <Form.Item name="isDriver" label="Are you a driver?" className='d-flex' >
                  <Input type='checkbox' 
                    checked={checked}
                    onChange={handleChange} 
                    rules={[{required: true}]}
                  />
            </Form.Item>


            <button className='btn1 mt-2 mh-5'>Register</button>
            <hr/>
            <Link to="/login">Click here to login</Link>

          </Form>
        </Col>
      </Row>
    </div>
  )
}

export default Register