const express = require("express")
const app = express()
require("dotenv/config")
const cors = require("cors")
const { OAuth2Client } = require("google-auth-library")
const jwt = require("jsonwebtoken")

//middleware for origin & methods that are allowed
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: "GET,POST,PUT,DELETE,OPTIONS",
  })
)
app.use(express.json())

let collection = []

// Google Account Verification
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
const client_id = new OAuth2Client(GOOGLE_CLIENT_ID)

async function GoogleTokenVerification(token) {
  try {
    const ticket = await client_id.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    })
    return { payload: ticket.getPayload() }
  } catch (err) {
    return { err: "Oops! Invalid Token" }
  }
}

// signup route
app.post("/signup", async (req, res) => {
  try {
    if (req.body.credential) {
      const verifyRes = await GoogleTokenVerification(req.body.credential)
      if (verifyRes.error) {
        return res.status(400).json({
          message: verifyRes.error,
        })
      }
      const user = verifyRes?.payload
      // push it to collection
      collection.push(user)
      res.status(201).json({
        message: "Congrats! Signup was successful",
        user: {
          firstName: user?.given_name,
          lastName: user?.family_name,
          picture: user?.picture,
          email: user?.email,
          // jwt token
          token: jwt.sign({ email: user?.email }, "myScret", {
            expiresIn: "1d",
          }),
        },
      })
    }
  } catch (error) {
    res.status(500).json({
      message: "Oops! An error has occured, Try again",
    })
  }
})

// login route
app.post("/login", async (req, res) => {
  try {
    if (req.body.credential) {
      const verifyRes = await GoogleTokenVerification(req.body.credential)
      if (verifyRes.error) {
        return res.status(400).json({
          message: verifyRes.error,
        })
      }
      const user = verifyRes?.payload
      const isInCollection = collection.find((person) => person?.email === user?.email)
      if (!isInCollection) {
        return res.status(400).json({
          message: "You have not signed up yet. Please sign up first",
        })
      }
      res.status(201).json({
        message: "Signed in successfully",
        user: {
          firstName: user?.given_name,
          lastName: user?.family_name,
          picture: user?.picture,
          email: user?.email,
          // jwt token
          token: jwt.sign({ email: user?.email }, process.env.JWT_SECRET, {
            expiresIn: "1d",
          }),
        },
      })
    }
  } catch (error) {
    res.status(500).json({
      message: "An error has occured",
    })
  }
})

//Running the app on PORT Number 5152
app.listen("5152", () => console.log("Server running on port 5152"))
