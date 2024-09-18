import { Router } from "express";
import ApiController from "../controllers/api.controller.js";
const router = Router();

// Endpoint http://localhost:5000/create-expired
// router.post("/create-expired", ApiController.createExpiredAt);

//Endpoint http://localhost:5000/pin
router.post("/pin", ApiController.createPin);

//Endpoint http://localhost:5000/device
router.post("/device", ApiController.createDevice);

//Endpoint http://localhost:5000/version
router.post("/version", ApiController.createVersion);

//Endpoint http://localhost:5000/pin/encrypt
router.post("/encrypt", ApiController.E2ee);

//Endpoint: http://localhost:5000/detect-slip
//Method: POST
//Body: form -> key : image, value : ภาพสลิป
router.post("/detect-slip", ApiController.slip);

router.post("/check-slip", ApiController.code);

export default router;
