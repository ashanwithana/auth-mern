import express from 'express'
import { isAuthenticated, login, logout, register, resetPassword, sendResetOTP, sendVerifyOTP, verfiyEmail } from '../controllers/authController.js'
import userAuth from '../middleware/userAuth.js'

const authRouter = express.Router()

authRouter.post('/register', register)
authRouter.post('/login', login)
authRouter.post('/logout', logout)
authRouter.post('/send-verify-otp', userAuth, sendVerifyOTP)
authRouter.post('/verify-account', userAuth, verfiyEmail)
authRouter.post('/isAuthenticated', userAuth, isAuthenticated)
authRouter.post('/reset-password-otp', sendResetOTP)
authRouter.post('/reset-password', resetPassword)

export default authRouter

