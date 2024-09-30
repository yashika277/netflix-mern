import { User } from "../models/user.model.js"
import { generateTokenSetCookie } from "../utilities/generateToken.js";
import bcryptjs from "bcryptjs"

/* --------------------------------- signup --------------------------------- */
export async function signup(req, res) {
    try {
        const { email, password, username } = req.body;

        if (!email || !password || !username) {
            return res.status(400).json({ success: false, message: "All fields are required" })
        }
        const emailRegex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: "Invalid Email" })
        }
        if (password.length < 6) {
            return res.status(400).json({ success: false, message: "password must be at least 6 characters" })
        }
        const existingUserByEmail = await User.findOne({ email: email })
        if (existingUserByEmail) {
            return res.status(400).json({ success: false, message: "Email already exist" })
        }
        const existingUserByUsername = await User.findOne({ username: username })
        if (existingUserByUsername) {
            return res.status(400).json({ success: false, message: "Username already exist" })
        }
        /* --------------------------------- bcrypt --------------------------------- */
        const salt = await bcryptjs.genSalt(10);
        const hashedPassword = await bcryptjs.hash(password, salt);

        const PROFILE_PICS = ["/avatar1.png", "/avatar2.png", "/avatar3.png"];
        const image = PROFILE_PICS[Math.floor(Math.random() * PROFILE_PICS.length)]
        const newUser = new User({
            email,
            password: hashedPassword,
            username,
            image
        })

        generateTokenSetCookie(newUser._id, res)
        await newUser.save();

        /* ----------------------------- remove password ---------------------------- */
        res.status(201).json({
            success: true,
            user: {
                ...newUser._doc,
                password: "",
            },
        })


    } catch (error) {
        console.log("Error in signup Controller", error.message);
        res.status(500).json({ success: false, message: "Internal Server Error" })
    }
}

/* ---------------------------------- login --------------------------------- */
export async function login(req, res) {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "All fields are required" })
        }

        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(404).json({ success: false, message: "Invalid credentials" })
        }

        const isPasswordCorrect = await bcryptjs.compare(password, user.password)
        if (!isPasswordCorrect) {
            return res.status(400).json({ success: false, message: "Invalid credentials" })

        }
        generateTokenAndSetCookie(user._id, res)
        res.status(200).json({
            success: true,
            user: {
                ...user._doc,
                password: "",
            },
        })
    } catch (error) {
        console.log("Error in login Controller", error.message);
        res.status(500).json({ success: false, message: "Internal Server Error" })
    }
}

/* --------------------------------- logout --------------------------------- */
export async function logout(req, res) {
    try {
        res.clearCookie("jwt-netflix");
        res.status(200).json({ success: true, message: "Logged out Successfully" })
    } catch (error) {
        console.log("Error in logout Controller", error.message);
        res.status(500).json({ success: false, message: "Internal Server Error" })
    }
}