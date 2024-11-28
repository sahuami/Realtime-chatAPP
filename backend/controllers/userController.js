import { User } from "../models/userModel.js"; // Importing the User model for database operations
import bcrypt from "bcryptjs"; // Importing bcrypt for password hashing and comparison
import jwt from "jsonwebtoken"; // Importing jwt for generating and verifying tokens

// Function to handle user registration
export const register = async (req, res) => {
    try {
        // Extracting user details from the request body
        const { fullName, username, password, confirmPassword, gender } = req.body;

        // Validate that all required fields are present
        if (!fullName || !username || !password || !confirmPassword || !gender) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Check if passwords match
        if (password !== confirmPassword) {
            return res.status(400).json({ message: "Password do not match" });
        }

        // Check if the username already exists in the database
        const user = await User.findOne({ username });
        if (user) {
            return res.status(400).json({ message: "Username already exists, try a different one" });
        }

        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate default profile photo URLs based on gender
        const maleProfilePhoto = `https://avatar.iran.liara.run/public/boy?username=${username}`;
        const femaleProfilePhoto = `https://avatar.iran.liara.run/public/girl?username=${username}`;

        // Create and save the new user in the database
        await User.create({
            fullName,
            username,
            password: hashedPassword,
            profilePhoto: gender === "male" ? maleProfilePhoto : femaleProfilePhoto,
            gender,
        });

        // Respond with success message
        return res.status(201).json({
            message: "Account created successfully.",
            success: true,
        });
    } catch (error) {
        console.log(error); // Log any errors for debugging purposes
    }
};

// Function to handle user login
export const login = async (req, res) => {
    try {
        // Extract username and password from the request body
        const { username, password } = req.body;

        // Validate that all required fields are present
        if (!username || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Check if the user exists in the database
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({
                message: "Incorrect username or password",
                success: false,
            });
        }

        // Compare the provided password with the stored hashed password
        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.status(400).json({
                message: "Incorrect username or password",
                success: false,
            });
        }

        // Prepare token data with user ID
        const tokenData = { userId: user._id };

        // Generate JWT token with a 1-day expiration
        const token = await jwt.sign(tokenData, process.env.JWT_SECRET_KEY, { expiresIn: "1d" });

        // Respond with the token in a cookie and user details
        return res
            .status(200)
            .cookie("token", token, {
                maxAge: 1 * 24 * 60 * 60 * 1000, // Token valid for 1 day
                httpOnly: true, // Ensures cookie is only accessible via HTTP(S), not JavaScript
                sameSite: "strict", // Prevents cross-site request forgery (CSRF)
            })
            .json({
                _id: user._id,
                username: user.username,
                fullName: user.fullName,
                profilePhoto: user.profilePhoto,
            });
    } catch (error) {
        console.log(error); // Log any errors for debugging purposes
    }
};

// Function to handle user logout
export const logout = (req, res) => {
    try {
        // Clear the authentication cookie by setting its max age to 0
        return res.status(200).cookie("token", "", { maxAge: 0 }).json({
            message: "Logged out successfully.",
        });
    } catch (error) {
        console.log(error); // Log any errors for debugging purposes
    }
};

// Function to fetch other users except the logged-in user
export const getOtherUsers = async (req, res) => {
    try {
        // Extract the logged-in user's ID from the request (assumed to be set by authentication middleware)
        const loggedInUserId = req.id;

        // Fetch all users except the logged-in user
        const otherUsers = await User.find({ _id: { $ne: loggedInUserId } }).select("-password");

        // Respond with the list of other users
        return res.status(200).json(otherUsers);
    } catch (error) {
        console.log(error); // Log any errors for debugging purposes
    }
};
