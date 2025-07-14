import React from 'react'
import { Row, Col, Form, Input } from 'antd'
import { Link } from 'react-router-dom'
import { useDispatch, useSelector } from 'react-redux'
import { userLogin, googleAuth } from '../redux/actions/userActions'
import AOS from 'aos';
import Spinner from '../components/Spinner'
import 'aos/dist/aos.css'; // You can also use <link> for styles
import { auth, provider } from "../firebase";
import { signInWithPopup } from 'firebase/auth'
import axios from 'axios'


AOS.init();
const Login = () => {
    
  const dispatch = useDispatch();
  const { loading } = useSelector(state => state.alertsReducer)
  function onFinish(values){
    dispatch(userLogin(values))
    // console.log(values)
  }

  const signInWithGoogle = ()=>{
    signInWithPopup(auth, provider)
    .then((result)=>{
  
      // console.log(result.user.email.split("@")[0]);
      result.username = result.user.email.split("@")[0];
      result.email = result.user.email;
      // console.log(result);
      dispatch(googleAuth(result));
    }).catch((err)=>{
      console.log(err)
    });
  };


  return (
    <div className='login'>
      {loading && (<Spinner/>)}
      <Row gutter={16}>

        <Col lg={16} style={{position: "relative"}}>

          <img 
          data-aos='slide-right'
          data-aos-duration='1500'
          src="https://t3.ftcdn.net/jpg/09/59/48/50/360_F_959485026_HU6hetaJPcNp119uWqlRwrKxwiFu2PpE.jpg" height="100%" width="100%"/>
        </Col>
        <Col lg={8} className='text-left p-5'>
          <Form layout='vertical' className='login-form p-5' onFinish={onFinish}>
            <h1>Login</h1>
            <hr/>
            <Form.Item name="username" label="Username" rules={[{required: true}]}>
              <Input/>
            </Form.Item>
            <Form.Item name="password" label="Password" rules={[{required: true}]}>
              <Input type='password'/>
            </Form.Item>
            <button className='btn1 mt-3'>Login</button>
            <hr/>
            <button className='btn1' onClick={signInWithGoogle}>Signin With Google</button>
            <hr/>
            <Link to="/register">Click here to register</Link>
          </Form>
        </Col>
      </Row>
    </div>
  )
}

export default Login