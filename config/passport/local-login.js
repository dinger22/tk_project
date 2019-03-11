const connection    = require('../connection.js').pool;
const passport      = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt        = require('bcryptjs');

module.exports = function(salt) {

  passport.use('local-login', new LocalStrategy({
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true
  }, function(req, email, password, done) {
    connection.query(`SELECT u.user_id,
                            u.first_name,
                            u.last_name,
                            u.email,
                            u.password,
                            u.ref_num,
                            u.is_active,
                            u.is_email_verified,
                            c.cart_id
                      FROM users u
                      left join carts c on c.user_id = u.user_id and c.status_id = 1
                      WHERE email = ?`,
      [email],
      function(err, rows) {
        if (err)
          return done(err);
        if (!rows.length) {
          return done(null, false, req.flash('flashMessage', 'Invalid login details'));
        }
        else if (bcrypt.compareSync(password, rows[0].password) && !(rows[0].is_email_verified && rows[0].is_active)){
          return done(null, false, req.flash('flashMessage', '请先验证邮箱'));
        }
        else if (bcrypt.compareSync(password, rows[0].password)) {
          const User = {
            user_id: rows[0].user_id,
            first_name: rows[0].first_name,
            last_name: rows[0].last_name,
            cart_id: rows[0].cart_id,
            email: rows[0].email,
            wechat_id: rows[0].ref_num,
          };
          return done(null, User);
        }
        else{
          return done(null, false, req.flash('flashMessage', '登入信息有误'));
        }

      })
  }));
}
