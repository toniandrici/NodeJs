
const APIFeatures = require('./../utils/apiFeatures');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');



exports.deleteOne = Model => catchAsync(  async (req, res, next) => {
  
    const doc = await Model.findByIdAndDelete(req.params.id);


    if(!doc){
        return next(new AppError('No document found with that ID', 404));  
       }

    res.status(204).json({
        status: 'success',
        data: null
    });

});


exports.updateOne  = Model => 
catchAsync(  async (req, res, next) => {

    const doc = await Model.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });


    if(!doc){
        return next(new AppError('No tour found with that ID', 404));  
       }

    res.status(200).json({
        status: 'success',
        data: {
        data: doc
        }
    });

});


exports.createOne = Model => catchAsync(  async (req, res, next) => {

    // const newTours = new Tour({});
    // newTours.save(

    // )
   
        const doc = await Model.create(req.body);

        res.status(201).json({
            status: 'success',
            data: {
                data: doc
            }
        });
});

exports.getOne = (Model, popOptions) => catchAsync( async (req, res, next) => {
   
    let query = Model.findById(req.params.id);
    if(popOptions) query = query.populate(popOptions);
    const doc = await query;
    // Tour.findOne({_id:req.params.id})

    if(!doc){
     return next(new AppError('No tour found with that ID', 404));  
    }

    res.status(200).json({
        status: 'success',
        data: {
            data: doc
        }
    });

// const tour = tours.find(el => el.id === id);
// if (!tour) {
//     return res.status(404).json({
//         status: 'Fail',
//         message: "Could not find that id"
//     });
// }
// res.status(200).json({
//     status: 'success',
//     data: {
//         tour
//     }
// });
});


exports.getAll = Model => catchAsync(async (req, res, next) => {

    //To allow for nested GET reviews on tour (hack)
    let filter = {}
    if (req.params.tourId) filter = {
        tour: req.params.tourId
    };

    const features = new APIFeatures(Model.find(filter), req.query)
    .filter()
    .sort()
    .limitFields()
    .paginate();
    const doc = await features.query;
    //query.sort().select().skip().limit()
    //SEND RESPONSE
    res.status(200).json({
        status: 'success',
        time: req.requestTime,
        results: doc.length,
        data: {
            data: doc
        }
    });

});
