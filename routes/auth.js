const joi = require('joi');
const { user, User } = require('../models/user');
const validate = require('../middleware/validate');
const bcrypt = require('bcrypt');
const express = require('express');
const jwt = require('jsonwebtoken');
const config = require('config');
const router = express.Router();

router.post('/', validate(validateAuth), async (req,res) => {
    let user = await User.findOne({email: req.body.email});
    if(!user) return res.status(400).send('Invalid email or password');

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).send('Invalid email or password');
    const token = User.generateAuthToken(user._id);
    const refreshToken = User.generateRefreshToken(user._id);

    res.send({jwtToken: token, refreshToken: refreshToken});
});
router.post('/refresh-token', async (req,res) => {
    try {
        const refreshToken = req.header('X-refresh-token');
        if (!refreshToken) return res.send(401).send('No token provided');

        const payload = jwt.verify(refreshToken, config.get('jwtRefreshkey'));
        const token = User.generateAuthToken(payload._id);
        res.send({jwtToken: token});
    }
    catch (error) {
        res.send(400).send('Invalid Token');
    }
});
function validateAuth(req) {
    const schema = {
        email: joi.string().min(5).max(255).required().email(),
        password: joi.string().min(5).max(255).required()
    };
    return joi.validate(req, schema);
}
module.exports= router;