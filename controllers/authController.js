const {
    promisify
} = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const sendEmail = require('./../utils/email');
const crypto = require('crypto');



const signToken = id => {
    return jwt.sign({
        id
    }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};

const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    const cookieOptions = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
        // secure: true, //will be sent only on https on local will not be 
        httpOnly: true // can t be modified by browser
    };

if(process.env.NODE_ENV === 'production') cookieOptions.secure = true;
    res.cookie('jwt', token, cookieOptions);
//Remove the password from the output
    user.password = undefined;

    res.status(statusCode).json({
        status: 'success',
        token,
        data: {
            user
        }
    });
}

exports.signup = catchAsync(async (req, res, next) => {
    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm
    });
    createSendToken(newUser, 201, res);


});

exports.login = catchAsync(async (req, res, next) => {
    const {
        email,
        password
    } = req.body;

    //1) Check if email and password exist
    if (!email || !password) {
        return next(new AppError('Please provide email and password', 400));
    }
    //2) Check if the user exists && password is correct\
    const user = await User.findOne({
        email
    }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
        return next(new AppError('Incorrect email or password', 401));
    }
    // 3) If everything ok. send token to client

    createSendToken(user, 200, res);
});


exports.protect = catchAsync(async (req, res, next) => {

    // 1) Getting token and check if it s there
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return next(new AppError('You are not logged in! Please login to get access.', 401));
    }
    // 2) Verification token (if token was not manipulated by malitious party)

    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    //De aici nu prea gasesti tutoriale 
    // 3) Check is user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) return next(new AppError('The user belonging ot this token does no longer exists'));
    // 4) Check if user changed password after the token was issued 
    if (currentUser.changedPasswordAfter(decoded.iat)) return next(new AppError('User recently changed password. Please login again', 401));

    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    next();
});

exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        // roles ['admin', 'lead-guide']. role='user'
        if (!roles.includes(req.user.role)) {
            return next(new AppError('You do not have permission to perform this action', 403));
        }
        next();
    };
};


exports.forgotPassword = catchAsync(async (req, res, next) => {

    // 1) Get user based on posted email
    const user = await User.findOne({
        email: req.body.email
    });
    if (!user) return next(new AppError('There is no user with that email address', 404));
    // 2) Generate the random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({
        validateBeforeSave: false
    }); //validateBeforeSave ->>>>>> very yimportant!!!!
    // 3) Send it to user' s email
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;

    const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to : ${resetURL}.\nIf you
didn't forget your password, please ignore this email!`;

    try {
        await sendEmail({
            email: user.email,
            subject: 'Your password reset token (valid for 10 min)',
            message
        });

        res.status(200).json({
            status: 'success',
            message: 'Token sent to email'
        });

    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({
            validateBeforeSave: false
        });

        return next(new AppError("There was an error sendin the email. Try again later", 500));
    }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
    //1) get user based on the token

    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: {
            $gt: Date.now()
        }
    });

    // 2) If token has not expired, and there is a user, set the new password

    if (!user) return next(new AppError('Token is invalid or has expired', 400));

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // 3) Update changedPasswordAt property for the user

    // 4) Log the user in, send JWT to the client
    createSendToken(user, 200, res);


});

exports.updatePassword = catchAsync(async (req, res, next) => {

    // 1) Get user from collection
    const user = await User.findById(req.user.id).select('+password');
    // 2) Check if the posted current password is correct 
    if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
        return next(new AppError('Your current password is wrong', 401));
    }

    // 3) If so, update the password
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();
    // User.findByIdAndUpdate -> we can t use that because this.password is not defined when update (from userModel) also the pre middlewares will not work (from userModel)

    // 4) Log user in, send JWT

    createSendToken(user, 200, res);

});