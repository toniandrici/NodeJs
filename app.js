const express = require('express');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const tourRouter = require('./routes/tourRoutes');
const userRouter = require('./routes/userRoutes');
const reviewRouter = require('./routes/reviewRoutes');
const app = express();

//1)Global Middlewares

//Set security HTTP headers
app.use(helmet());
//Development loggin
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}
//Limit request from same API
const limiter = rateLimit({
    max: 100,
    windowMs: 60 * 60 * 1000,
    message:'Too many requests from this IP, please try again in an hour!' 
});
app.use('/api', limiter );

//Body parser, reading data from body into req.body
app.use(express.json({ limit : '10kb'}));

//Data sanitization agains NoSQL query injection
app.use(mongoSanitize()); //Mongo query injection
//Data sanitization against XSS
app.use(xss()); //HTML INJECTION FOR EXAMPLE

//Prevent parameter pollution - paramteriii din url
app.use(hpp({
    whitelist:['duration', 'ratingsQuantity', 'ratingsAverage', 'maxGroupSize', 'difficulty', 'price']   
}));
//Serving static files
app.use(express.static(`${__dirname}/public`));


//Test middleware
app.use((req, res, next) => {
    req.requestTime = new Date().toISOString();
    // console.log(req.headers);
    
    next();
});

//Routes

app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);

app.all('*', (req, res, next) => {
    next(new AppError(`Can t find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

//START SERVER
module.exports = app;