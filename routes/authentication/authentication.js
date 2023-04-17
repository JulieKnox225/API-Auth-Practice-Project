const bcrypt = require('bcrypt');
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
require('dotenv').config();


router.use(express.json());

router.post('/create/user', async (req, res) => {
    try {
        const { name } = req.body;
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        const query = await req.db.query(
            `INSERT INTO users (name, password)
                VALUES (:name, :hashedPassword)`,
            {
                name,
                hashedPassword
            }
        );
        res.json({success: true, message: 'User Created!', data: null});
    } catch(err) {
        res.json({success: false, message: err, data: null})
    }
});

router.post('/user/login', async (req, res) => {
    try {
        const { name, userPassword } = req.body;
        const temp = await req.db.query(
            `SELECT password FROM users WHERE name = :name`,
            { name }
        );

        if(temp[0].length === 0) {
            return res.json({success: false, message: 'User not found!', data: null})
        }
        
        const { password } = temp[0][0];
            
        if(await bcrypt.compare(userPassword, password)) {
            const accessToken = jwt.sign(name, process.env.ACCESS_TOKEN_SECRET);
            
            res.json({success: true, message: 'Logged In!', accessToken: accessToken, data: null});
        } else {
            res.json({success: false, message: 'Incorrect Password!', data: null});
        }
        
    } catch(err) {
        res.json({success: false, message: err, data: null});
    }
});

module.exports = router;