const path = require('path');
const express = require('express');
const colors = require('colors');
const dotenv = require('dotenv').config();
const { errorHandler } = require('./middleware/errorMiddleware');
const connectDB = require('./config/db');
const cors = require('cors');
const morgan = require('morgan'); // Import Morgan
const port = process.env.PORT || 5001;

connectDB();

const app = express();

// Use Morgan for HTTP request logging
app.use(morgan('dev'));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());

app.use('/api/users', require('./routes/userRoutes'));
app.use(express.static(path.join(__dirname, 'public')));


app.use(errorHandler);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`.green.bold);
  console.log(`Running USERS API.......... :D`.blue.bold);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`.yellow.bold);
});
