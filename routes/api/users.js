const express = require('express');
const router = express.Router();
const gravatar  = require('gravatar');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');
// included after seeing jsonwebtoken not defined
const config = require('config');
const jwt = require('jsonwebtoken');


const User = require('../../models/User');
//  @desc    Register user
//  @route   POST api/users
//  @access  Public
router.post(
  '/',
  
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please  include a valid email').isEmail(),
    check(
      'password',
      'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 }),
  async (req, res) => {
    // console.log(req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
        //Check if user exist
        let user = await User.findOne({ email });

        if (user){
            return res
              .status(400)
              .json({ errors: [ {msg: 'User already exists'}] });
        }

        // get users gravatar
        const avatar = gravatar.url( email, {
            s: '200', //avatar size
            r: 'pg', // avatar rating
            d: 'mm' 
        })

        //create the user
        user = new User({
            name, 
            email, 
            avatar,
            password
        });

        // Encrypt password || Hash the password
        const salt = await bcrypt.genSalt(10); 

        user.password = await bcrypt.hash(password, salt); 

        await  user.save();

        // Return jsonwebtoken
        const payload = {
          user: {
            id: user.id
          }
        }

        //
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
