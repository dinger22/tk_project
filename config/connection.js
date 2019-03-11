const mysql = require('mysql');
const nodemailer = require("nodemailer");
var ses = require('nodemailer-ses-transport');

const pool = mysql.createConnection({
  host     : 'aafgkr37cy10os.cbtsk1otpffc.us-east-2.rds.amazonaws.com',
  port     : 3306,
  user     : 'tkdb',
  password : '11235813',
  database : 'ebdb'
});

var transporter = nodemailer.createTransport(ses({
  accessKeyId: 'AKIAISTUORNGGK2RMNSQ',
  secretAccessKey: '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'
}));

var connection = {
  transporter: transporter,
  pool: pool
}

module.exports = connection;