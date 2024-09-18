import axios from "axios";
import qs from "qs";
import Jimp from "jimp";
import multer from "multer";
import jsQr from "jsqr";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';
import QrCodeReader from "qrcode-reader";

import { db } from "../config/database.js";
import ame2ee from "../ame2ee.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const uploadFolder = path.join(__dirname, "../assets/slip");
fs.mkdirSync(uploadFolder, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadFolder)
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '.jpg');
  },
});

const login = async (device, version) => {
  try {
    const results = await new Promise((resolve, reject) => {
      db.all("SELECT * FROM `pin`", (error, results, fields) => {
        if (error) reject(error);
        else resolve(results);
      });
    });

    const pin = results[0].data;

    const preLoginConfig = {
      method: "POST",
      url: `${process.env.API_ENDPOINT}/v1/auth/prelogin/grant?grant_type=client_credentials`,
      headers: {
        "Accept-Language": process.env.ACCEPT_LANGUAGE,
        "X-Client-Version": version,
        "X-Device-Id": device,
        authorization: process.env.AUTH_BASIC,
      },
    };

    const preLoginResponse = await axios(preLoginConfig);
    const accessToken = preLoginResponse.data.access_token;

    const pinPreAuthConfig = {
      method: "POST",
      url: `${process.env.API_ENDPOINT}/api/auth/v1/pin/preauth`,
      headers: {
        "Accept-Language": process.env.ACCEPT_LANGUAGE,
        "X-Client-Version": version,
        "X-Device-Id": device,
        authorization: `Bearer ${accessToken}`,
      },
      data: {
        loginModuleId: "PseuE2EE",
      },
    };

    const pinPreAuthResponse = await axios(pinPreAuthConfig);
    const { oaepHashAlgo, e2eeSid, serverRandom, pubKey } =
      pinPreAuthResponse.data;

    const encryptConfig = {
      method: "POST",
      url: `${process.env.ENCRYPT_URL}/encrypt`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: qs.stringify({
        Sid: e2eeSid,
        ServerRandom: serverRandom,
        pubKey: pubKey,
        pin: pin,
        hashType: oaepHashAlgo,
      }),
    };

    const encryptResponse = await axios(encryptConfig);
    const encryptedPin = encryptResponse.data;

    const finalAuthConfig = {
      method: "POST",
      url: `${process.env.API_ENDPOINT}/v1/auth/pin/grant?grant_type=password`,
      headers: {
        "Accept-Language": process.env.ACCEPT_LANGUAGE,
        "X-Client-Version": version,
        "X-Device-Id": device,
        authorization: process.env.AUTH_BASIC,
      },
      data: {
        e2eeSid: e2eeSid,
        pin: encryptedPin,
      },
    };

    const finalAuthResponse = await axios(finalAuthConfig);
    return { access_token: finalAuthResponse.data.access_token };
  } catch (error) {
    console.error(error);
    throw new Error("Login process failed");
  }
};

const ApiController = {
  createPin: async (req, res) => {
    try {
      if (!req.body.pin) {
        return res.send({ message: "Bad Request!" });
      } else {
        const pin = req.body.pin;
        db.all("SELECT * FROM `pin`", async (error, results, fields) => {
          if (results.length === 0) {
            db.run(
              "INSERT INTO `pin` (`data`) VALUES (?)",
              [pin],
              async (error, results, fields) => {
                if (error) throw error;
                return res.send({ message: `Create Success! ${pin}` });
              }
            );
          } else {
            db.run(
              "UPDATE `pin` SET `data` = ?",
              [pin],
              async (error, results, fields) => {
                if (error) throw error;
                return res.send({ message: `Update Success! ${pin}` });
              }
            );
          }
        });
      }
    } catch (error) {
      // res.send({ message: "Internal Server Error!" });
      console.log(error);
    }
  },

  createDevice: async (req, res) => {
    try {
      if (!req.body.device) {
        return res.send({ message: "Bad Request!" });
      } else {
        const device = req.body.device;
        db.all("SELECT * FROM `device`", async (error, results, fields) => {
          if (results.length === 0) {
            db.run(
              "INSERT INTO `device` (`data`) VALUES (?)",
              [device],
              async (error, results, fields) => {
                if (error) throw error;
                return res.send({ message: `Create Success! ${device}` });
              }
            );
          } else {
            db.run(
              "UPDATE `device` SET `data` = ?",
              [device],
              async (error, results, fields) => {
                if (error) throw error;
                return res.send({ message: `Update Success! ${device}` });
              }
            );
          }
        });
      }
    } catch (error) {
      // res.send({ message: "Internal Server Error!" });
      console.log(error);
    }
  },

  createVersion: async (req, res) => {
    try {
      if (!req.body.version) {
        return res.send({ message: "Bad Request!" });
      } else {
        const version = req.body.version;
        db.all("SELECT * FROM `version`", async (error, results, fields) => {
          if (results.length === 0) {
            db.run(
              "INSERT INTO `version` (`data`) VALUES (?)",
              [version],
              async (error, results, fields) => {
                if (error) throw error;
                return res.send({ message: `Create Success! ${version}` });
              }
            );
          } else {
            db.run(
              "UPDATE `version` SET `data` = ?",
              [version],
              async (error, results, fields) => {
                if (error) throw error;
                return res.send({ message: `Update Success! ${version}` });
              }
            );
          }
        });
      }
    } catch (error) {
      // res.send({ message: "Internal Server Error!" });
      console.log(error);
    }
  },

  createExpiredAt: async (req, res) => {
    try {
      if (!req.body.exp) {
        return res.send({ message: "Bad Request!" });
      } else {
        const expiredAt = req.body.exp;
        db.all("SELECT * FROM `jwt`", async (error, results, fields) => {
          if (error) throw error;
          if (results.length === 0) {
            const token = jwt.sign(
              {
                data: "foobar",
              },
              process.env.JWT_SECRET,
              { expiresIn: expiredAt }
            );
            db.run(
              "INSERT INTO `jwt` (`token`) VALUES (?)",
              [token],
              async (error, results, fields) => {
                if (error) throw error;
                return res.send({ message: `Create Success! ${expiredAt}` });
              }
            );
          } else {
            const token = jwt.sign(
              {
                data: "foobar",
              },
              process.env.JWT_SECRET,
              { expiresIn: expiredAt }
            );
            db.run(
              "UPDATE `jwt` SET `token` = ?",
              [token],
              async (error, results, fields) => {
                if (error) throw error;
                return res.send({ message: `Update Success! ${expiredAt}` });
              }
            );
          }
        });
      }
    } catch (error) {
      // res.send({ message: "Internal Server Error!" });
      console.log(error);
    }
  },

  slip: async (req, res) => {
    try {
      // Step 1: Verify JWT token
      // db.all("SELECT * FROM `jwt`", async (error, results) => {
      //   if (error) throw new Error("Failed to retrieve JWT token.");

      //   jwt.verify(results[0].token, process.env.JWT_SECRET, async (err) => {
      //     if (err) {
      //       return res.status(401).send({ status: "error", message: "Token หมดอายุ!" });
      //     }

      try {
        // Step 2: Fetch access token and other necessary data
        db.all("SELECT * FROM `access_token`", async (error, results) => {
          if (error) throw new Error("Failed to retrieve access token.");

          const access_token = results[0].data;

          // Helper function to fetch device data
          const getDevice = () => {
            return new Promise((resolve, reject) => {
              db.all("SELECT * FROM `device`", (error, results) => {
                if (error) return reject(new Error("Failed to retrieve device data."));
                resolve(results[0].data);
              });
            });
          };

          // Helper function to fetch version data
          const getVersion = () => {
            return new Promise((resolve, reject) => {
              db.all("SELECT * FROM `version`", (error, results) => {
                if (error) return reject(new Error("Failed to retrieve version data."));
                resolve(results[0].data);
              });
            });
          };

          // Step 3: Await device and version data
          const DEVICE = await getDevice();
          const VERSION = await getVersion();

          // Step 4: Handle image upload
          const upload = multer({ storage: storage }).single("image");

          upload(req, res, async (err) => {
            if (err) {
              console.error("Image upload error:", err);
              return res.send({ status: "error", message: "Error uploading image!" });
            }

            try {
              // console.log(req.file)
              // Step 5: Process QR code
              // const { QR } = req.body; // Assuming QR is passed in the body 
              const data = await fs.promises.readFile(req.file.path);

              // โหลดภาพด้วย Jimp
              const image = await Jimp.read(data);

              // สร้าง Promise ถอดรหัส QR code
              const code = await new Promise((reslove, reject) => {
                const qr = new QrCodeReader();
                qr.callback = (err, value) => {
                  if (err) {
                    console.error(err);
                  }
                  reslove(value.result);
                };
                qr.decode(image.bitmap);
              })

              // fs.readFile(req.file.path, function (err, data) {
              // if (err) {
              // console.error('Error reading image file', err);
              // return;
              // }
              // ใช้ Jimp เพื่อโหลดและจัดการภาพ
              // Jimp.read(data, async (err, image) => {
              // if (err) {
              // console.error('Error processing image', err);
              // return;
              // }

              // สร้างตัวอ่าน QR code
              // const qr = new QrCodeReader();

              // qr.callback = function (err, value) {
              // if (err) {
              // console.error(err);
              // }
              // console.log(value.result);
              // code = value.result;
              // };
              // qr.decode(image.bitmap);
              // })
              // })

              // Step 6: Prepare and send API request
              const config = {
                method: "POST",
                url: `${process.env.API_ENDPOINT}/api/qr/v1/transaction-details`,
                headers: {
                  "Accept-Language": process.env.ACCEPT_LANGUAGE,
                  "X-Client-Version": VERSION,
                  "X-Device-Id": DEVICE,
                  authorization: "Bearer " + access_token,
                },
                data: { QR: code },
              };
              console.log(config)
              const response = await axios(config);
              res.send({ status: "success", data: response.data });
            } catch (error) {
              console.log(error)
              console.error("Error processing QR code:", error);

              if (!error.response) {
                return res.send({ status: "error", message: "Invalid slip!" });
              }

              // Handle access token expiration or invalid token
              if (error.response && error.response.status === 401) {
                login(DEVICE, VERSION).then((login) => {
                  db.all("SELECT * FROM `access_token`", async (error, results) => {
                    if (error) {
                      console.error("Error fetching access token:", error);
                      return;
                    }
                    const newToken = login.access_token;
                    if (results.length === 0) {
                      db.run("INSERT INTO `access_token` (`data`) VALUES (?)", [newToken], (error) => {
                        if (error) {
                          console.error("Error inserting new access token:", error);
                          return;
                        }
                        res.send({ message: `Created access token successfully! ${newToken}` });
                      });
                    } else {
                      db.run("UPDATE `access_token` SET `data` = ?", [newToken], (error) => {
                        if (error) {
                          return res.send({ message: "Error updating access token!" });
                        }
                        res.send({ message: `Updated access token successfully! ${newToken}` });
                      });
                    }
                  });
                });
              } else {
                return res.send({ status: "error", message: "Invalid slip!" });
              }
            }
          });
        });
      } catch (error) {
        return res.send({ status: "error", message: error.message });
      }
      //   });
      // });
    } catch (error) {
      return res.send({ status: "error", message: error.message });
    }
  },

  code: async (req, res) => {
    try {
      db.all("SELECT * FROM `access_token`", async (error, results) => {
        if (error) throw new Error("Failed to retrieve access token.");
        const access_token = results[0].data;
        // Helper function to fetch device data
        const getDevice = () => {
          return new Promise((resolve, reject) => {
            db.all("SELECT * FROM `device`", (error, results) => {
              if (error) return reject(new Error("Failed to retrieve device data."));
              resolve(results[0].data);
            });
          });
        };
        // Helper function to fetch version data
        const getVersion = () => {
          return new Promise((resolve, reject) => {
            db.all("SELECT * FROM `version`", (error, results) => {
              if (error) return reject(new Error("Failed to retrieve version data."));
              resolve(results[0].data);
            });
          });
        };
        // Step 3: Await device and version data
        const DEVICE = await getDevice();
        const VERSION = await getVersion();

        // Step 4: Process QR code
        const code = req.body.code;
        try {
          // Step 5: Prepare and send API request
          const config = {
            method: "POST",
            url: `${process.env.API_ENDPOINT}/api/qr/v1/transaction-details`,
            headers: {
              "Accept-Language": process.env.ACCEPT_LANGUAGE,
              "X-Client-Version": VERSION,
              "X-Device-Id": DEVICE,
              authorization: "Bearer " + access_token,
            },
            data: { QR: code },
          };
          // console.log(config)
          const response = await axios(config);
          res.send({ status: "success", data: response.data });
        } catch (error) {
          console.log(error)
          console.error("Error processing QR code:", error);
          if (!error.response) {
            return res.send({ status: "error", message: "Invalid slip!" });
          }
          // Handle access token expiration or invalid token
          if (error.response && error.response.status === 401) {
            login(DEVICE, VERSION).then((login) => {
              db.all("SELECT * FROM `access_token`", async (error, results) => {
                if (error) {
                  console.error("Error fetching access token:", error);
                  return;
                }
                const newToken = login.access_token;
                if (results.length === 0) {
                  db.run("INSERT INTO `access_token` (`data`) VALUES (?)", [newToken], (error) => {
                    if (error) {
                      console.error("Error inserting new access token:", error);
                      return;
                    }
                    res.send({ message: `Created access token successfully! ${newToken}` });
                  });
                } else {
                  db.run("UPDATE `access_token` SET `data` = ?", [newToken], (error) => {
                    if (error) {
                      return res.send({ message: "Error updating access token!" });
                    }
                    res.send({ message: `Updated access token successfully! ${newToken}` });
                  });
                }
              });
            });
          } else {
            return res.send({ status: "error", message: "Invalid slip!" });
          }
        }
      });
    } catch (error) {
      return res.send({ status: "error", message: error.message });
    }
  },


  E2ee: async (req, res) => {
    try {
      let regex = /([^,]+),([^,]+)/;
      let m;
      let e2Module;
      let e2RsaExponent;

      const pinEncrypt = (
        Sid,
        ServerRandom,
        e2Module,
        e2RsaExponent,
        pin,
        hashType
      ) => {
        return ame2ee.encryptPinForAM(
          Sid,
          e2Module + "," + e2RsaExponent,
          ServerRandom,
          pin,
          hashType
        );
      };

      if ((m = regex.exec(req.body.pubKey)) !== null) {
        m.forEach((match, groupIndex) => {
          if (match !== "undefined" && groupIndex == 1) {
            e2Module = match;
          }
          if (match !== "undefined" && groupIndex == 2) {
            e2RsaExponent = match;
          }
        });
      }
      await res.send(
        pinEncrypt(
          req.body.Sid,
          req.body.ServerRandom,
          e2Module,
          e2RsaExponent,
          req.body.pin,
          req.body.hashType
        )
      );
    } catch (error) {
      console.error(error);
      res.send({ message: "Internal Server Error!" });
    }
  },
};

export default ApiController;
