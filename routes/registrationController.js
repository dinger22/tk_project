var express       = require('express');
const passport    = require('passport');
const connection  = require('../config/connection.js');
const nodemailer  = require("nodemailer");
var ses           = require('nodemailer-ses-transport');
var router        = express.Router();
var bcrypt        = require('bcryptjs');
const salt        = 10;
var url           = require('url');

router.get('/', function(req, res, next) {
    res.render('index',{
      user: req.user
    });
});
  
router.get('/login',function(req, res) {
    var messages = req.flash('flashMessage');
    if(req.isAuthenticated()){
        res.redirect('/')
    }
    else{
        res.render('login',{
        flashMessage: messages
        });
    }
});

router.post('/login', 
  passport.authenticate('local-login', {
    successRedirect : '/', 
    failureRedirect : '/login', 
    failureFlash : true 
  })
);

router.get('/signup', function(req, res) {
  var messages = req.flash('flashMessage');
  if(req.isAuthenticated()){
    res.redirect('/')
  }
  else{
    res.render('signup', {
      flashMessage: messages
    });
  }
});

router.post('/signup',
  passport.authenticate('local-signup', 
  {  
    failureRedirect : '/signup', 
    failureFlash : true 
  }),
  function(req, res) {
    var host=req.get('host');
    var link="http://"+host+"/verify?source_application_key="+bcrypt.hashSync(req.user.email, salt)
    +"&source_application_id="+req.user.email_verified_code;
    connection.transporter.sendMail({
      from: 'dingyinghao@hotmail.com',
      to: 'dingyinghaoamazon@gmail.com',//req.user.email,
      subject: '您好',
      html: `<p>您好! 请点<a  href=`+link+`> 这个链接</a>以验证您的邮箱地址`
    });
    res.redirect(url.format({
      pathname:"/verify",
      query:{
        message: "checkemail"
      }
    }));
  }
);

router.get('/verify', function(req, res) {
    var result = url.parse(req.url,true).query;
    if( !result['source_application_id']){
      if(!!result['message'] && result['message'] === "checkemail"){
        res.render('verify',{
          message:"请检查邮箱，通过链接验证您的邮箱"
        });
      }else{
        res.render('verify',{
          message:"无权限浏览此页面"
        });
      }
    }else{
      connection.pool.query(`SELECT user_id, 
                                    email, 
                                    first_name, 
                                    last_name,  
                                    is_email_verified,
                                    email_verified_code 
                            FROM users 
                            WHERE email_verified_code = ?`,
                      [result['source_application_id']],
      function(err, rows) {
        if (err) {
          res.render('verify',{message:'错误-无该邮箱相关记录'});
        }
        else if (bcrypt.compareSync(rows[0].email, result['source_application_key']) && rows[0].is_email_verified === 0) {
          connection.pool.query(`
            UPDATE users 
            SET 
              is_email_verified = 1,
              is_active = 1 
            where user_id = ?`, [rows[0].user_id],
            function(err){
              if(err){
                res.render('verify',{message:'错误-无法更新用户状态'});
              }else{
                const User = {
                  user_id: rows[0].user_id,
                  first_name: rows[0].first_name,
                  last_name: rows[0].last_name,
                  email: rows[0].email
                };
                res.render('verify',{
                  message : '邮箱认证成功！请重新登入'
                });
              }
            }
          )
        } 
        else if(bcrypt.compareSync(rows[0].email, result['source_application_key']) && rows[0].is_email_verified === 1)  {
          const User = {
            user_id: rows[0].user_id,
            first_name: rows[0].first_name,
            last_name: rows[0].last_name,
            email: rows[0].email
          };
          res.render('verify',{message:'以验证用户，请前往主页登录'});
        } else {
          res.render('verify',{message:'未知错误'});
        }
      })
    }
  
});
  
router.get('/logout', function(req, res) {
    req.session.destroy(function (err) {
        res.redirect('/'); //Inside a callback… bulletproof!
    });
    req.logout();
});
  