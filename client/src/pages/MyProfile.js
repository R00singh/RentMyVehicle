import { Col, Row, Form, Input } from "antd";
import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import DefaultLayout from "../components/DefaultLayout";
import Spinner from "../components/Spinner";
import { editMyProfile, getAllUsers } from "../redux/actions/userActions";
// import { useParams } from "react-router-dom";
import {
  ref,
  uploadBytesResumable,
  getDownloadURL,
  getStorage,
  uploadBytes,
} from "firebase/storage";

const MyProfile = ({ match }) => {
  const dispatch = useDispatch();
  const { users } = useSelector((state) => state.usersReducer);
  const { loading } = useSelector((state) => state.alertsReducer);
  const [user, setuser] = useState();
  const [totalusers, settotalusers] = useState([]);
  const userid = JSON.parse(localStorage.getItem("user"))._id;
  const [file, setFile] = useState("");
  const [percent, setPercent] = useState(0);
  const [url, setURL] = useState("");
  const [checked, setChecked] = React.useState(false);
  //   console.log(userid);

  useEffect(() => {
    if (users.length == 0) {
      dispatch(getAllUsers());
    } else {
      settotalusers(users);
      setuser(users.find((o) => o._id == userid));
      // console.log(user);
    }
  }, [users]);

  function handleChange(event) {
    setFile(event.target.files[0]);
  }

  const handleUpload = () => {
    if (!file) {
      alert("Please upload an image first!");
      return;
    }
    console.log("File is not empty");

    const storage = getStorage();
    const storageRef = ref(storage, `userImages/${file.name}`);

    const metadata = {
      contentType: "userImages/jpeg",

    };

    const uploadTask = uploadBytesResumable(storageRef, file, metadata);
    uploadTask.on(
      "state_changed",
      (snapshot) => {
        // Get task progress, including the number of bytes uploaded and the total number of bytes to be uploaded
        const progress =
          (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
        setPercent(progress);
        console.log("Upload is " + progress + "% done");
        switch (snapshot.state) {
          case "paused":
            console.log("Upload is paused");
            break;
          case "running":
            console.log("Upload is running");
            break;
        }
      },
      (error) => {
        // A full list of error codes is available at
        // https://firebase.google.com/docs/storage/web/handle-errors
        switch (error.code) {
          case "storage/unauthorized":
            // User doesn't have permission to access the object
            break;
          case "storage/canceled":
            // User canceled the upload
            break;

          // ...

          case "storage/unknown":
            // Unknown error occurred, inspect error.serverResponse
            break;
        }
      },
      () => {
        // Upload completed successfully, now we can get the download URL
        getDownloadURL(uploadTask.snapshot.ref).then((downloadURL) => {
          console.log("File is available at", downloadURL);
          setURL(downloadURL);
        });
      }
    );
    
  };
  const onFinish = async(values) => {
    if(url===""){
      return;
    }
    values._id = user._id;
    values.image = url;
    console.log(values);
    dispatch(editMyProfile(values));
  };

  return (
    <DefaultLayout>
      {loading && <Spinner />}
      <Row justify="center mt-5">
        <Col lg={12} sm={24} xs={24} className="p-2">
          {totalusers.length > 0 && (
            <Form
              initialValues={user}
              className="bs1 p-2"
              layout="vertical"
              onFinish={onFinish}
            >
              <h3>Edit User</h3>

              <hr />
              <Form.Item
                name="username"
                label="Username"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="email"
                label="Email"
                rules={[{ required: true }]}
              >
                <Input disabled={true}/>
              </Form.Item>
              <Form.Item name="Image" label="Upload image">
                <Input type="file" accept="image/*" onChange={handleChange} />
                <button onClick={handleUpload}>Upload</button>
                <p>{percent} "% done"</p>
              </Form.Item>

              <Form.Item
                name="rentPerHour"
                label="Rent per hour"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="contactNumber"
                label="Contact Number"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="location"
                label="Location"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <div className="text-right">
                <button className="btn1">
                  Edit user
                </button>
              </div>
            </Form>
          )}
        </Col>
      </Row>
    </DefaultLayout>
  );
};

export default MyProfile;
