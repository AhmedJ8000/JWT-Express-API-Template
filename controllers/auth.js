const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');

router.post('/sign-up', async (req, res) => {
    try {
        const { username, password } = req.body;
        // make sure the user does not exist
        const userInDatabase = await User.findOne({ username });

        if (userInDatabase) {
            return res.status(409).json({ err: 'Invalid Username or Password' });
        }

        // take the password and encrypt in some way.
        const hashPassword = bcrypt.hashSync(password, 10);

        // If the above passes, then let's create the account
        // with the encrypted password.
        req.body.password = hashPassword;

        const user = await User.create(req.body);

        // Construct the payload
        const payload = { username: user.username, _id: user._id };

        // Create the token, attaching the payload
        const token = jwt.sign({ payload }, process.env.JWT_SECRET);

    } catch (error) {
        console.error(error);
        res.send('Something went wrong with registration!');
    }
});

module.exports = router;