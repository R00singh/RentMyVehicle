import { Row, Col, Form, Input } from "antd";
import { React, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import DefaultLayout from "../components/DefaultLayout";
import Spinner from "../components/Spinner";
import { addCar } from "../redux/actions/carsActions";
// import storage from "../../src/firebase.js"
import {
  ref,
  uploadBytesResumable,
  getDownloadURL,
  getStorage,
  uploadBytes,
} from "firebase/storage";

const AddCars = () => {
  const dispatch = useDispatch();
  const { loading } = useSelector((state) => state.alertsReducer);
  const [file, setFile] = useState("");
  const [percent, setPercent] = useState(0);
  const [url, setURL] = useState("");
  // const url="";

  function handleChange(event) {
    setFile(event.target.files[0]);
  }

  const handleUpload = () => {
    if (!file) {
      alert("Please upload an image first!");
    } else {
      console.log("file khali nhi h");
      const storage = getStorage();
      const storageRef = ref(storage, `carImages/${file.name}`);
      const metadata = {
        contentType: "carImages/jpeg",
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
            console.log("File available at", downloadURL);
            setURL(downloadURL);
          });
        }
      );
    }
  };

  const onFinish = (values) => {
    values.bookedTimeSlots = [];
    values.myOwner = JSON.parse(localStorage.getItem("user"))._id;
    values.image = url;
    dispatch(addCar(values));
    console.log(values);
  };
  return (
    <DefaultLayout>
      {loading && <Spinner />}
      <Row justify="center mt-3">
        <Col lg={12} sm={24} xs={24} className="p-2">
          <Form className="bs1 p-2" layout="vertical" onFinish={onFinish}>
            <h3>Add New Car</h3>
            <hr />
            <Form.Item
              name="name"
              label="Car name"
              rules={[{ required: true }]}
            >
              <Input />
            </Form.Item>

            <Form.Item name="Image" label="Upload image">
              <Input type="file" accept="image/*" onChange={handleChange} />
              <button onClick={handleUpload}>Upload</button>
              <p>{percent} "% done"</p>
            </Form.Item>

            <Form.Item
              name="rentPerHour"
              label="Rent Per Hour"
              rules={[{ required: true }]}
            >
              <Input />
            </Form.Item>

            <Form.Item
              name="capacity"
              label="Capacity"
              rules={[{ required: true }]}
            >
              <Input />
            </Form.Item>
            <Form.Item
              name="fuelType"
              label="Fuel Type"
              rules={[{ required: true }]}
            >
              <Input />
            </Form.Item>

            <div className="text-right">
              <button className="btn1" justify="center">
                ADD CAR
              </button>
            </div>
          </Form>
        </Col>
      </Row>
    </DefaultLayout>
  );
};

export default AddCars;
