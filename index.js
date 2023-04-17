const express = require('express');
const app = express();
const cors = require('cors');
const db = require('./Config/DBConfig');
require('dotenv').config();

const PORT = process.env.PORT;

app.use(cors());
app.use(express.json());
app.use(db);
app.use('/', require('./routes/authentication/authentication'));
app.use('/', require('./routes/api/cars'));


app.listen(PORT, () => console.log(`Server started on Port ${PORT}`));