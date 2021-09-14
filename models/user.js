const joi = require('joi');
const mongoose = require('mongoose');
const config = require('config');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
    name : { 
        type: String,
        required: true,
        minlength: 5,
        maxlength: 50
    },
    email : {
        type: String,
        required: true,
        minlength: 5,
        maxlength: 50,
        unique: true
    },
    password : {
        type: String,
        required: true,
        minlength: 6,
        maxlength: 255
    }
});
userSchema.statics.generateAuthToken = function(userId) {
    const token = jwt.sign({_id: userId}, config.get('jwtPrivateKey'), {expiresIn: '15m'});
    return token;
}
userSchema.statics.generateRefreshToken = function(userId){
    const token = jwt.sign({_id: userId}, config.get('jwtRefreshKey'), {expiresIn: '5d'});
    return token;
}
const User = mongoose.model('User', userSchema);

function validateUser(user) {
    const Schema = {
        name: joi.String().min(5).max(50).required(),
        email: joi.String().min(5).max(50).required(),
        password: joi.String().min(6).max(255).required() 
    };
    return joi.validate(User, Schema);
}

exports.User = User;
exports.validate = validateUser;


