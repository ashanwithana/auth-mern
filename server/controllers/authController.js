import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";


export const register = async (req, res) => {
    const { name, email, password } = req.body

    if (!name || !email || !password) {
        return res.status(400).json({ sucess: false, message: 'All fields are required' })
    }

    try {
        const existingUser = await userModel.findOne({ email })
        if (existingUser) {
            return res.status(400).json({ sucess: false, message: 'User already exists' })
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const user = new userModel({ name, email, password: hashedPassword })
        await user.save()

        const token = createToken(user._id);
        setCookie(res, token);


        return res.status(201).json({ success: true, message: 'User created successfully', user })


    } catch (err) {
        return res.status(500).json({ success: false, message: err.message })
    }
}


export const login = async (req, res) => {
    const { email, password } = req.body

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required' })
    }

    try {
        const existingUser = await userModel.findOne({ email })
        if (!existingUser) {
            return res.status(404).json({ success: false, message: 'User does not exist' })
        }

        const isMatch = await bcrypt.compare(password, existingUser.password)
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Invalid credentials' })
        }

        const token = createToken(existingUser._id);
        setCookie(res, token);

        return res.status(200).json({ success: true, message: 'Login successful', token })

    } catch (err) {
        return res.status(500).json({ success: false, message: err.message })
    }

}

export const logout = async (req, res) => {
    try {
        res.clearCookie("token", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "prod",
            sameSite: process.env.NODE_ENV === "prod" ? "none" : "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        })
        return res.status(200).json({ success: true, message: 'Logout successful' })
    } catch (err) {
        return res.status(500).json({ success: false, message: err.message })
    }
}


const createToken = (userId) =>
    jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: "7d" });

const setCookie = (res, token) => {
    res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "prod",
        sameSite: process.env.NODE_ENV === "prod" ? "none" : "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });
};

