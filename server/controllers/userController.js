import userModel from "../models/userModel.js";

export const getUserData = async (req, res) => {
    try {
        const { id: userId } = req.user;
        const user = await userModel.findById(userId)
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" })
        }
        return res.status(200).json({ success: true, user: user })
    }
    catch (err) {
        return res.status(401).json({ success: false, message: err.message })
    }
}