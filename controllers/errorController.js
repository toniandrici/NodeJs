const AppError = require('./../utils/appError');

const handleCastErrorDB = err => {
    const message = `Invalid ${err.path}: ${err.value}`;
    return new AppError(message, 404);
};

const handleDuplicateFieldsDb = err => {


    const value = err.errmsg.match(/(["'])(\\?.)*?\1/)[0];

    const message = `Duplicate field value: ${value}. Please use another value!`;
    return new AppError(message, 400);
};

const handleValidationErrorDb = err => {
const errors = Object.values(err.errors).map(el => el.message);
const message = `Invalid input data. ${errors.join('. ')}`;
return new AppError(message, 400);
};

const handleJWTError = () => new AppError('Invalid token. Please log in again!', 401);
const handleTokenExpiredError = () => new AppError('Token expired. Please login again!', 401);

const sendErrorDev = (err, res) => {

    res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
        error: err,
        stack: err.stack,
    });
};

const sendErrorProd = (err, res) => {
    //Operational, trusted error: send message to client
    if (err.isOperational) {
        res.status(err.statusCode).json({
            status: err.status,
            message: err.message
        });

        // Programming or other unknown error: don t leak error details
    } else {

        //1) Log error
        console.error('ERROR', err);

        //2)Send generic message
        res.status(500).json({
            status: 'error',
            message: 'Something went very wrong!'
        });
    }

};

module.exports = (err, req, res, next) => {

    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';
    if (process.env.NODE_ENV === 'development') {
        sendErrorDev(err, res);
    } else if (process.env.NODE_ENV === 'production') {
        let error = {
            ...err
        };


        if (error.name === 'CastError')  error = handleCastErrorDB(error);
        if (error.code === 11000) error = handleDuplicateFieldsDb(error);
        if (error.name === 'ValidationError') error = handleValidationErrorDb(error);
        if (error.name === 'JsonWebTokenError') error = handleJWTError(error);
        if (error.name === 'TokenExpiredError') error = handleTokenExpiredError(error);
        sendErrorProd(error, res);
    }

};