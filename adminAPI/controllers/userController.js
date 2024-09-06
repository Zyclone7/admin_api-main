const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const mongoose = require('mongoose');

// Generate token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '30d',
    });
};

// Middleware to authenticate user token
const authenticateToken = (req, res, next) => {
    // Your token authentication logic here
    next(); // Assuming you have implemented token authentication middleware
};

// Middleware to authorize user access based on role
const authorizeUser = (req, res, next) => {
    // Your authorization logic here
    next(); // Assuming you have implemented authorization middleware
};

// @desc Register new user
// @route POST /api/users
// @access Public
const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        res.status(400);
        throw new Error('Please enter all fields');
    }

    // Password validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
    if (!passwordRegex.test(password)) {
        res.status(400);
        throw new Error('Password must be at least 8 characters long and contain lowercase, uppercase letters, and a number');
    }

    // Check if user exists
    const userExist = await User.findOne({ email });

    if (userExist) {
        res.status(400);
        throw new Error('User already exists');
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create User
    const user = await User.create({
        name,
        email,
        password: hashedPassword,
    });

    if (user) {
        res.status(201).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            token: generateToken(user._id),
        });
    } else {
        res.status(400);
        throw new Error('Invalid Users');
    }
});

// @desc  Authentication user
// @route POST /api/users/login 
// @access Public
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Check for email
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
        const userData = {
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role, // Include the user's role in the response
            token: generateToken(user._id),
        };

        res.json(userData);
    } else {
        res.status(400);
        throw new Error('Invalid Credentials');
    }
});

// @desc Get user data
// @route GET /api/users/me
// @access Private
const getMe = asyncHandler(async (req, res) => {
    res.status(200).json(req.user);
});

// @desc Read user data (only accessible by admins)
// @route GET /api/users/:id
// @access Private (only accessible by admins)
const readUser = asyncHandler(async (req, res) => {
    const userId = req.params.id;

    // Check if the logged-in user has admin role
    if (req.user.role !== 'admin') {
        res.status(403);
        throw new Error('Unauthorized access');
    }

    // Find the user by ID
    const user = await User.findById(userId);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    res.status(200).json(user);
});

// @desc Read all users with their roles (only accessible by admins)
// @route GET /api/users/all
// @access Private (only accessible by admins)
const readAllUsersWithRoles = asyncHandler(async (req, res) => {
  // Check if the logged-in user has admin role
  if (req.user.role !== 'admin') {
      res.status(403);
      throw new Error('Unauthorized access');
  }

  // Fetch all users with their roles excluding admin role
  const users = await User.find({ role: { $ne: 'admin' } }).select('_id name email role');

  res.status(200).json(users);
});

// @desc Get user by ID
// @route GET /api/users/:id
// @access Private
const getUserById = asyncHandler(async (req, res) => {
    const userId = req.params.id;

    // Check if the logged-in user is requesting their own data or is an admin
    if (req.user._id.toString() !== userId && req.user.role !== 'admin') {
        res.status(403);
        throw new Error('Unauthorized access');
    }

    // Find the user by ID
    const user = await User.findById(userId).select('-password'); // Exclude password field

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    res.status(200).json(user);
});
// @desc Update user by ID
// @route PUT /api/users/:id
// @access Private
const updateUser = asyncHandler(async (req, res) => {
    const userId = req.params.id;
    const { name, email, password } = req.body;

    // Check if the logged-in user is requesting their own data
    if (req.user._id.toString() !== userId) {
        res.status(403);
        throw new Error('Unauthorized access');
    }

    // Find the user by ID
    const user = await User.findById(userId);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    // Update user information
    user.name = name || user.name;
    user.email = email || user.email;
    if (password) {
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
    }

    const updatedUser = await user.save();

    res.status(200).json({
        _id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role, // Keep role in the response, but do not allow it to be updated
    });
});



// @desc Delete user by ID (only accessible by admins)
// @route DELETE /api/users/:id
// @access Private (only accessible by admins)
const deleteUser = asyncHandler(async (req, res) => {
    const userId = req.params.id;

    // Check if the logged-in user has admin role
    if (req.user.role !== 'admin') {
        res.status(403);
        throw new Error('Unauthorized access');
    }

    // Find the user by ID and delete
    const user = await User.findByIdAndDelete(userId);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    res.status(200).json({ message: 'User deleted successfully' });
});


module.exports = {
    registerUser,
    loginUser,
    getMe,
    readUser,
    readAllUsersWithRoles,
    deleteUser,
    getUserById,
    updateUser,
};

