const express = require('express');
const router = express.Router(); 
const auth = require('../../middleware/auth');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');
const config = require('config');
const jwt = require('jsonwebtoken');


const User = require('../../models/User');

//  @route   GET api/auth
//  @desc    Test route
//  @access  Public
router.get('/', auth, async(req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
    //res.send('Auth route')});
});


//  @desc    Authentic user and get token
//  @route   POST api/auth
//  @access  Public
router.post(
    '/',
        check('email', 'Please  include a valid email').isEmail(),
        check('password','Password is required').exists(),
    async (req, res) => {
      // console.log(req.body);
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
  
      const { email, password } = req.body;
  
      try {
          //Check if user exist
          let user = await User.findOne({ email });
  
          if (!user){
              return res
                .status(400)
                .json({ errors: [ {msg: 'Invalid Credentials' }] });
          }

          // Compares the plain text  pswd and its equivalent salted jwt token
          const isMatch = await bcrypt.compare(password, user.password);

            if(!isMatch){
                return res
                .status(400)
                .json({ errors: [ {msg: 'Invalid Credentials' }] });  
            }
  
          // Return jsonwebtoken to backend
          const payload = {
            user: {
              id: user.id
            }
          }
  
         // Signing the web token
          jwt.sign(
            payload,
            config.get('jwtSecret'), 
            { expiresIn: 36000},// How long the token lasts
            (err, token) => {
              if(err) throw err;
              res.json({ token });
            });
  
        } catch (err) {
            console.error(err.message);
            res.status(500).send("Server error"); 
        }
      }
    
  );
  
module.exports = router;