const connection    = require('../connection.js').pool;
const passport      = require('passport');
const LocalStrategy = require('passport-local').Strategy;

passport.serializeUser(function(user, done) {
  done(null, user.user_id);
});

passport.deserializeUser(function(user_id, done) {
  connection.query(`SELECT u.user_id,
  u.first_name,
  u.last_name,
  u.email,
  u.is_email_verified,
  u.is_active,
  u.phone_number,
  u.ref_num,
  c.cart_id
  FROM users u
  left join carts c on c.user_id = u.user_id and c.status_id = 1
  WHERE  u.user_id = ? `,
    [user_id],
    function(err, rows) {
      done(err, rows[0]);
  });
});
