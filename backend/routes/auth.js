const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Register a new user
router.post("/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const newUser = new User({ username, email, password: hashedPassword });
        const savedUser = await newUser.save();

        res.status(200).json(savedUser);
    } catch (err) {
        console.error("Error during registration:", err);
        res.status(500).json({ message: "Internal server error." });
    }
});

// User login
router.post("/login", async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });

        if (!user) {
            return res.status(404).json({ message: "User not found!" });
        }

        // Check if password matches
        const match = await bcrypt.compare(req.body.password, user.password);

        if (!match) {
            return res.status(401).json({ message: "Wrong credentials!" });
        }

        // Generate JWT token
        const token = jwt.sign(
            { _id: user._id, username: user.username, email: user.email },
            process.env.SECRET,
            { expiresIn: "3d" }
        );

        const { password, ...info } = user._doc;

        // Set the cookie with the token
        res.cookie("token", token, {
            httpOnly: true,  // Prevent JavaScript access
            secure: process.env.NODE_ENV === 'production',  // Send over HTTPS only in production
            sameSite: "strict"
        }).status(200).json(info);

    } catch (err) {
        console.error("Error during login:", err);
        res.status(500).json({ message: "Internal server error." });
    }
});

// User logout
router.get("/logout", async (req, res) => {
    try {
        res.clearCookie("token", {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: "strict"
        }).status(200).send("User logged out successfully!");
    } catch (err) {
        console.error("Error during logout:", err);
        res.status(500).json({ message: "Internal server error." });
    }
});

// Refetch user
router.get("/refetch", (req, res) => {
    const token = req.cookies.token;
    
    if (!token) {
        return res.status(401).json({ message: "No token, authorization denied." });
    }

    jwt.verify(token, process.env.SECRET, {}, async (err, data) => {
        if (err) {
            return res.status(403).json({ message: "Token is not valid." });
        }

        res.status(200).json(data);
    });
});

module.exports = router;
