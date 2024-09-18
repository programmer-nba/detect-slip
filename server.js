import express from "express";
import bodyParser from "body-parser";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import { TABLE_USERS } from "./config/database.js";
import dotenv from "dotenv";
dotenv.config();

const app = express();

// Middlewares
app.use(bodyParser.json({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan("tiny"));
app.use(cors());

//Routes (Dynamic import)
fs.readdirSync("./routes").map((route) => {
  import(`./routes/${route}`).then((routeFile) => {
    app.use(routeFile.default);
  });
});

// Start the server
app.listen(process.env.PORT, () => {
  TABLE_USERS();
  console.log(`Server running URL -> http://localhost:${process.env.PORT}`);
});
