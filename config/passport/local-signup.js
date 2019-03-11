const connection    = require('../connection.js').pool;
const passport      = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt        = require('bcryptjs');

module.exports = function(salt) {
  passport.use('local-signup', new LocalStrategy({
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true
  }, function(req, email, password, done) {
    connection.query("SELECT * FROM users WHERE email = ?",
    //TODO:query escaping
      [email],
      function(err, rows) {
        if (err) {
          return done(err);
        }
        if (rows.length) {
          return done(null, false, req.flash('flashMessage', '您所使用的邮箱已经存在于我们系统的用户库，请点击 登陆 - 忘记密码 来重新设置您的密码和登陆'));
        } else {
          //save user's info for the whole session, no need to contain the whole thing.
          const User = {
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            email: req.body.email
          };

          const insertQuery = `INSERT INTO users 
                              (first_name, 
                                last_name, 
                                email, 
                                password, 
                                phone_number, 
                                ref_num, 
                                year_of_grade, 
                                major_in_school,
                                create_date) 
                              values (?,?,?,?,?,?,?,?, Now())`;

          connection.query(insertQuery, [req.body.first_name, 
                                        req.body.last_name, 
                                        req.body.email, 
                                        bcrypt.hashSync(req.body.password, salt), 
                                        req.body.phone_number, 
                                        req.body.ref_num, 
                                        req.body.year_of_grade, 
                                        req.body.major_in_school
                                      ],
            function(err, rows) {
              if (err) {
                return done(null, false, req.flash('flashMessage', 'Sorry! Error.'));
              }
              User.user_id = rows.insertId;
              User.email_verified_code = bcrypt.hashSync(User.user_id+"", salt);
              connection.query(
                  `UPDATE users 
                  SET email_verified_code = ? 
                  WHERE user_id = ?`,
                  [
                    User.email_verified_code,
                    User.user_id
                  ],
                  function(err,rows){
                    if(err){
                      return done(null,false,req.flash('flashMessage', 'Sorry! Error.'))
                    }
                    return done(null, User);
                  }
              )

          });

        }
      })
  }));
}
