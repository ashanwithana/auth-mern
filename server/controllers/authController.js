import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import { text } from "drizzle-orm/gel-core";
import transpoter from "../config/mail.js";


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

        const welcomeEmail = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Auth Platform',
            text: `Welcome to Auth Platform Web. Your Account has been created with this email Id: ${email}`
        }

        await transpoter.sendMail(welcomeEmail)

        return res.status(201).json({ success: true, message: 'User created successfully', user })


    } catch (err) {
        return res.status(401).json({ success: false, message: err.message })
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
        return res.status(401).json({ success: false, message: err.message })
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
        return res.status(401).json({ success: false, message: err.message })
    }
}

export const sendVerifyOTP = async (req, res) => {
    try {
        const { id: userId } = req.user;
        const user = await userModel.findById(userId)
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' })
        }
        if (user.isAccountVerified) {
            return res.status(208).json({ success: false, message: 'Account already verified' })
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000))
        user.verifyOtp = otp
        user.verifyOtpExpireAt = new Date(Date.now() + 60 * 60 * 1000);
        await user.save()

        const verifyOtp = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Your OTP is ${otp}. Verify your account with this OTP.`
        }

        await transpoter.sendMail(verifyOtp)

        return res.status(200).json({ success: true, message: 'OTP sent successfully' })

    } catch (err) {
        return res.status(401).json({ success: false, message: err.message })
    }
}

export const verfiyEmail = async (req, res) => {
    const { otp } = req.body
    const { id: userId } = req.user;

    if (!userId || !otp) {
        return res.status(400).json({ success: false, message: 'Missing Details' })
    }

    try {
        const user = await userModel.findById(userId)

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' })
        }
        if (user.verifyOtp === "" || user.verifyOtp !== otp) {
            return res.status(400).json({ success: false, message: 'Invalid OTP' })
        }
        if (user.verifyOtpExpireAt < Date.now()) {
            return res.status(400).json({ success: false, message: 'OTP expired' })
        }
        user.isAccountVerified = true
        user.verifyOtp = ""
        user.verifyOtpExpireAt = ""
        await user.save()

        return res.status(200).json({ success: true, message: 'Account verified successfully' })

    } catch (err) {
        return res.status(401).json({ success: false, message: err.message })
    }
}

export const isAuthenticated = async (req, res) => {
    try {
        return res.status(200).json({ success: true, message: 'User is authenticated' })
    } catch (err) {
        return res.status(401).json({ success: false, message: err.message })
    }
}

export const sendResetOTP = async (req, res) => {
    const { email } = req.body
    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required' })
    }
    try {
        const user = await userModel.findOne({ email })
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' })
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000))
        user.resetOtp = otp
        user.resetOtpExpireAt = new Date(Date.now() + 15 * 60 * 1000);
        await user.save()

        const verifyPassword = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your OTP is ${otp}. Reset your password with this OTP.`
        }

        await transpoter.sendMail(verifyPassword)

        return res.status(200).json({ success: true, message: 'OTP sent successfully' })
    }
    catch (err) {
        return res.status(401).json({ success: false, message: err.message })
    }
}

export const resetPassword = async (req, res) => {
    const { otp, email, newPassword } = req.body
    if (!otp || !email || !newPassword) {
        return res.status(400).json({ success: false, message: 'All fields are required' })
    }

    try {
        const user = await userModel.findOne({ email })
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' })
        }
        if (user.resetOtp === "" || user.resetOtp !== otp) {
            return res.status(400).json({ success: false, message: 'Invalid OTP' })
        }
        if (user.resetOtpExpireAt < Date.now()) {
            return res.status(400).json({ success: false, message: 'OTP expired' })
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10)

        user.password = hashedPassword
        user.resetOtp = ""
        user.resetOtpExpireAt = ""
        await user.save()

        return res.status(200).json({ success: true, message: 'Password reset successfully' })
    }
    catch (err) {
        return res.status(401).json({ success: false, message: err.message })
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

