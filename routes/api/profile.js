const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');

const Profile = require('../../models/Profile');
const User = require('../../models/User');

//  @route   GET api/profile/me
//  @desc    Get current users profile
//  @access  Private
router.get('/me', auth, (req, res) => {
//    res.send('Profile route')
    try {
        const profile = await Profile.findOne({ user: req.user.id}).populate(
            'user',
            ['name', 'avatar']
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


module.exports = router;