const reviewController = require('./../controllers/reviewController');
const authController = require('./../controllers/authController');
const express= require('express');



const router = express.Router({ mergeParams: true });

// POST /tour/234gdfg34/reviews
// GET /tour/234gdfg34/reviews
// POST /reviews
router.route('/')
.get( reviewController.getAllReviews)
.post(
    authController.protect, 
    authController.restrictTo('user'), 
    reviewController.setTourUserIds,
    reviewController.createReview
    );

router.route('/:id').get(reviewController.getReview).patch(reviewController.updateReview).delete(reviewController.deleteReview);

module.exports = router;