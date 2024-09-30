import jwt from "jsonwebtoken"
import { ENV_VARS } from "../config/envVars.js"

export const generateTokenSetCookie = (userid, res) => {
    const token = jwt.sign({ userid }, ENV_VARS.JWT_SECRET, { expiresIn: "15d" })

    res.cookie("jwt-netflix", token, {
        maxAge: 15 * 24 * 60 * 60 * 1000,
        httponly:true,
        samesite:"strict",
        secure:ENV_VARS.NODE_ENV !== "development"
    });

    return token;
}