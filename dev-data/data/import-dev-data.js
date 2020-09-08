const fs = require('fs');
const Tour = require('./../../models/tourModel');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config({
    path: './config.env'
});

const DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);

mongoose.connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false
}).then(() => {
    console.log('DB connection successful');
});

//READ JSON FILE

const tours = JSON.parse(fs.readFileSync(`${__dirname}/tours.json`, 'utf-8'));

//IMPORT DATA INTRO DB

const importData = async () => {
    try {
        await Tour.create(tours);
        console.log('Data successfully imported!');
        
    } catch (err) {
        console.log(err);
    }
    process.exit();
};

//DELETE DATA FROM DB

const deleteData = async () =>{
   
    try {
        await Tour.deleteMany();
        console.log('Data successfully deleted!');
     
    } catch (err) {
        console.log(err);
    }
    process.exit();
};

if(process.argv[2]=== '--import'){
    importData();
}else if(process.argv[2] === '--delete') deleteData();

console.log(process.argv);