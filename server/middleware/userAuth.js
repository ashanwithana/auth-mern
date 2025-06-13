import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ success: false, message: 'Unauthorized - Token missing' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (decoded.id) {
            req.user = { id: decoded.id };
            next();
        } else {
            return res.status(401).json({ success: false, message: 'Unauthorized - Invalid or expired token' });
        }
    } catch (err) {
        return res.status(401).json({ success: false, message: err.message });
    }
};

export default userAuth;
