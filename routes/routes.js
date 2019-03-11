var express       = require('express');
var httpsRedirect = require('express-https-redirect');
const passport    = require('passport');
const connection  = require('../config/connection.js');
const nodemailer  = require("nodemailer");
var ses           = require('nodemailer-ses-transport');
var router        = express.Router();
var bcrypt        = require('bcryptjs');
const salt        = 10;
var url           = require('url');
var ejs = require('ejs');
var fs = require('fs');
var uniqid = require('uniqid');

router.use('/', httpsRedirect());

router.get('/', function(req, res, next) {
  res.render('index',{
    user: req.user
  });
});

router.get('/login',function(req, res) {
  var messages = req.flash('flashMessage');
  if(req.isAuthenticated()){
    res.redirect('/');
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
    if(req.user.is_email_verified && req.user.is_active){
      res.redirect('/');
    }
    else{
      res.redirect(url.format({
        pathname:"/verify",
        query:{
          message: "checkemail"
        }
      }));
    }
  }
  else{
    res.render('signup', {
      flashMessage: messages
    });
  }
});

router.get('/reset_password', function(req, res) {
  var messages = req.flash('flashMessage');
    res.render('reset_password', {
      flashMessage: messages
    });
});

router.post('/reset_password',
  function(req, res) {
    var host=req.get('host');
    connection.pool.query(`SELECT email_verified_code from users where email = ? `,[req.body.email],
      function(err,result){
        if(err){//direct to error page
          renderInfo(res, '未知错误');
        }else if(result.length === 1){        
          var link="http://"+host+"/input_new_password?source_application_id="+result[0].email_verified_code;
          connection.transporter.sendMail({
            from: 'register@tk-course.com',
            to: req.body.email,
            subject: '重设密码',
            html: `<p>您好! 
            <br><br>您刚在 www.tk-course.com 网站申请了重新设置用户登陆密码，请点击以下链接来完成密码重设<br><br><a  href=`+link+`> `+link+`</a>
            <br><br>
            谢谢！<br><br>Top Knowledge Inc.`
          });
          res.redirect(url.format({
            pathname:"/verify",
            query:{
              message: "checkemail_reset"
            }
          }));
        }else if(result.length === 0){
          res.render('reset_password', {
            flashMessage: '您所输入的邮箱没有被注册过'
          });
        }
    });
  }
);

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
      from: 'register@tk-course.com',
      to: req.user.email,
      subject: '请核实您的邮箱',
      html: `<p>您好! 请点击以下链接已完成您在www.tk-course.com网站的新用户注册
      <br>`+`<a href = "`+link+`">`+link+`</a>`+`<br><br>谢谢<br>Top Knowledge Inc.`
    });
    req.logout();
    res.redirect(url.format({
      pathname:"/verify",
      query:{
        message: "checkemail"
      }
    }));
  }
);
router.post('/input_new_password', function(req, res) {
  connection.pool.query(`
    update users
    set password = ?
    where email = ?
  `,
    [bcrypt.hashSync(req.body.password, salt), req.body.email],
    function(err, result){
      if(err){
        renderInfo(res, '未知错误');
      }
      else{
        if(result.changedRows === 1){
          renderInfo(res, '密码重设成功！请使用新的密码登陆');
        }else{
          renderInfo(res, '未知错误');
        }
      }
    }
  )
});

function renderInfo(res, message){
  res.render('info',{
    message: message
  });
}

router.get('/input_new_password', function(req, res) {
  var result = url.parse(req.url,true).query;
  if( !result['source_application_id']){
    renderInfo(res, '无权限浏览此页面');
  }else{
    connection.pool.query(`
      SELECT user_id, 
              email, 
              first_name, 
              last_name,  
              is_email_verified,
              email_verified_code 
      FROM users 
      WHERE email_verified_code = ?
      `,
      [result['source_application_id']],
      function(err, result_user){
        if(err){
          renderInfo(res, '未知错误');
        }else{
          if(!!result_user){
            res.render('input_new_password',{
              email: result_user[0].email
            });
          }else{
            enderInfo(res, '未知错误');
          }
        }
      })
  }
});


router.get('/verify', function(req, res) {
  var result = url.parse(req.url,true).query;
  if( !result['source_application_id']){
    if(!!result['message'] && result['message'] === "checkemail"){
      res.render('verify',{
        message:"谢谢！请查收我们给您邮箱发送的邮件，点击邮件里的链接来完成注册"
      });
    }else if (!!result['message'] && result['message'] === "checkemail_reset"){
      res.render('verify',{
        message:"请检查邮箱，通过链接重设密码"
      });
    }
    else{
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
        renderInfo(res, '错误-无该邮箱相关记录');
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
              renderInfo(res, '错误-无法更新用户状态');
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
        renderInfo(res, '未知错误');
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

router.get('/checkout', function(req, res) {
  if(req.isAuthenticated()){
    if(!(req.user.is_email_verified && req.user.is_active)){
      res.redirect(url.format({
        pathname:"/verify",
        query:{
          message: "checkemail"
        }
      }));
    } else{
      var user_id = ((req.user && req.user.user_id) ? req.user.user_id : "");
      var first_name = ((req.user && req.user.first_name) ? req.user.first_name : "");
      var last_name = ((req.user && req.user.last_name) ? req.user.last_name : "");
      var phone = ((req.user && req.user.phone_number) ? req.user.phone_number : "");

      var cart_id = "";
      var flashMessage = "";

      var message = req.query.message;

      if (message == "failed") {
          flashMessage = "课程支付没有成功，请重试";
      }
      if (req.user && req.user.user_id) {
          connection.pool.query(`select status_id, ref_num, employee_id from carts where user_id = ? and status_id = 1`, [user_id], function(err,inProgressCart){
              if(inProgressCart.length > 0){
                  cart_id = inProgressCart[0].ref_num;
                  connection.pool.query(`select user_id, first_name from employees where is_active = 1 ORDER BY sort_order`, [], function(err,employees){
                      res.render('checkout', { user: req.user, user_id: user_id, cart_id: cart_id, first_name: first_name, last_name: last_name, phone: phone, flashMessage: flashMessage, employees: employees, current_employee_id: inProgressCart[0].employee_id });
                  });
              }
              else if (inProgressCart.length === 0){
                  connection.pool.query(`select user_id, first_name from employees where is_active = 1 ORDER BY sort_order`, [], function(err,employees){
                      res.render('checkout', { user: req.user, user_id: user_id, cart_id: cart_id, first_name: first_name, last_name: last_name, phone: phone, flashMessage: flashMessage, employees: employees });
                  });
              }
          });
      } else {
          res.render('checkout', { user: req.user, user_id: user_id, cart_id: cart_id, first_name: first_name, last_name: last_name, phone: phone, flashMessage: flashMessage });
      }
    }
  }
  else{
    res.render('login',{
      flashMessage: '请登入以便查看课程信息'
    });
  }
});

router.post('/saveEmployee', function(req, res) {
    console.log(req.body);
    var user_id = ((req.user && req.user.user_id) ? req.user.user_id : "");
    connection.pool.query(`select status_id, ref_num from carts where user_id = ? and status_id = 1`, [user_id], function(err,inProgressCart){
        cart_id = inProgressCart[0].ref_num;

        connection.pool.query(
            `update carts SET employee_id = ? WHERE ref_num = ?`,
            [req.body.employee_id, cart_id],
            function (err, result) {}
        );
    });
});

router.get('/courses', function(req, res, next) {
  var messages = '请登入以便查看课程信息';
  if(req.isAuthenticated()){
    if(!(req.user.is_email_verified && req.user.is_active)){
      res.redirect(url.format({
        pathname:"/verify",
        query:{
          message: "checkemail"
        }
      }));
    } else{
      connection.pool.query(`SELECT is_email_verified
      FROM users where user_id = ? `,
      [req.user.user_id],function(err,rows){
        if(rows[0].is_email_verified){
          res.render('courses',{
            user: req.user
          });
        }else{
          res.redirect(url.format({
            pathname:"/verify",
            query:{
              message: "checkemail"
            }
          }));
        }
      });
    }
  }
  else{
    res.render('login',{
      flashMessage: messages
    });
  }

});

function getCartItems(user_id, successHandler, errHandler){
	connection.pool.query(`
    select * from courses c inner 
    join course_prices cp on c.id = cp.course_id
		where cp.course_id in 
		(
		  SELECT cit.product_id as course_id
		  FROM cart_items cit
		  inner join carts cs on cit.cart_id = cs.cart_id 
		  where cs.status_id = 1 and cs.user_id = ?
		)
		`,
		[user_id],function(err,rows){
			if(err){errHandler(err);}
			else{
				successHandler(rows);
			}

	});
}

function sumPrices(items){
  var totalPrice = 0;
  items.forEach(item => {
    totalPrice += item.regular_price
  });
  return totalPrice;
}

router.get('/getCartItems', function(req, res, next) {
	getCartItems(req.user && req.user.user_id || 0,
		function(items){
      var templateString = fs.readFileSync('./views/partials/cart_item.ejs', 'utf-8');
      var totalPrice = sumPrices(items).toFixed(2);
      items.forEach(course => {
        course.regular_price = course.regular_price.toFixed(2);
      });
      var html = ejs.render(templateString, {products: items});

      var result = {
        html: html,
        totalPrice: totalPrice
      }
			res.send(JSON.stringify(result));
		},
		function(err){
			renderInfo(res, '未知错误');
		}
	);
});

router.get('/getMiniCartItems', function(req, res, next) {
	getCartItems(!!req.user && req.user.user_id || 0,
		function(items){
      var totalPrice = sumPrices(items).toFixed(2);
      items.forEach(course => {
        course.regular_price = course.regular_price.toFixed(2);
      });
      var result = {
        items : items,
        price : totalPrice
      }
			res.send(JSON.stringify(result));
		},
		function(err){
			renderInfo(res, '未知错误');
		}
	);
});


router.get('/getCourses/:category', function(req, res, next) {
  if(req.isAuthenticated()){
    if(!(req.user.is_email_verified && req.user.is_active)){
      res.redirect(url.format({
        pathname:"/verify",
        query:{
          message: "checkemail"
        }
      }));
    } else{
      var templateString = fs.readFileSync('./views/partials/single_course.ejs', 'utf-8');
      var categoryCondition = req.params.category === 'all' ? '' : `and c.ref_num like '`+req.params.category+`%'` ;
      //check loginn first
      connection.pool.query(`
        SELECT c.id as courses_id,
          c.title,
          c.description,
          c.ref_num,
          c.start_date,
          c.end_date,
          c.duration,
          c.location,
          c.sort_order,
          cp.regular_price,
          ca.status_id,
          ci.cart_item_id
        FROM courses c
        inner join course_prices cp on c.id = cp.course_id
        left join carts ca on ca.user_id = ? and ca.status_id = 1
        left join cart_items ci on ci.product_id = c.id and ci.cart_id = ca.cart_id
        Where 1=1 `+categoryCondition+`
        group by c.id
        `,
        [(!!req.user && req.user.user_id)|| 0],function(err,rows){//req.user.user_id
          rows.forEach(course => {
            course.regular_price = course.regular_price.toFixed(2);
          });
          var html = ejs.render(templateString, {courses: rows});
          //var prod = new EJS({url: 'products.ejs'}).render(rows);
          res.send(html);
      });
    }

  }else{
    res.send('');
  }

});

router.get('/terms_and_conditions', function(req, res) {
  res.render('terms_and_conditions',{
  });
});

router.get('/privacy_policy', function(req, res) {
  res.render('privacy_policy',{
  });
});

function addCartItems(cart_id, product_id, quantity){
	return new Promise(
		function(resolve, reject){
			connection.pool.query(`          
				INSERT INTO cart_items 
				(cart_id, product_id, quantity) VALUES
				(?, ?, ?)
				`,
				[cart_id, product_id, quantity],
				function(err, insertResult){
				  if(err){
					reject(err);
				  }
				  else{
					resolve(product_id);
				  }
			});
		}
	);

}

function getCourseById(product_id, successHandler, errorHandler){
	connection.pool.query(`          
  SELECT * FROM courses c inner join course_prices cp on c.id = cp.course_id where c.id = ?
		`,
		[product_id],function(err,responseProduct){
		  if(err){
        renderInfo(res, '未知错误');
		  }
		  else{
			successHandler(responseProduct[0]);
		  }
	});
}

function removeCartItem(cart_id, product_id){
	return new Promise(
		function(resolve, reject){
			connection.pool.query(`          
        DELETE FROM cart_items 
        WHERE  cart_id = ? and product_id = ? 
				`,
				[cart_id, product_id],
				function(err, removeResult){
				  if(err){
					reject(err);
				  }
				  else{
					resolve(product_id);
				  }
			});
		}
	);  
}

router.post('/removeCourse', function(req, res) {
  connection.pool.query(`          
  select status_id, cart_id from carts where user_id = ? and status_id = 1
  `,
  [(req.user && req.user.user_id)|| 0],function(err,inProgressCart){
    if(err){
      renderInfo(res, '未知错误');
    }
    else if(inProgressCart.length === 1){
		var removeCartItemPromise = removeCartItem(inProgressCart[0].cart_id, req.body.product_id, req.body.quantity);
		removeCartItemPromise.then(function(result){
			getCourseById(result, 
				function(responseData){
          responseData.totalPrice = req.body.totalPrice/1.0 - responseData.regular_price || 0;
					res.send(JSON.stringify(responseData));
			})
		});
		
    }
  });
});

router.post('/addCourse', function(req, res) {
  connection.pool.query(`          
  select status_id, cart_id from carts where user_id = ? and status_id = 1
  `,
  [(!!req.user && req.user.user_id) || 0],function(err,inProgressCart){
    if(err){
      renderInfo(res, '未知错误');
    }
    else if(inProgressCart.length > 0){
		var addCartItemPromise = addCartItems(inProgressCart[0].cart_id, req.body.product_id, req.body.quantity);
		addCartItemPromise.then(function(result){
			getCourseById(result, 
				function(responseData){
          responseData.totalPrice = req.body.totalPrice/1.0 + responseData.regular_price;
					res.send(JSON.stringify(responseData));
			})
		});
		
    }else if(inProgressCart.length === 0){
        var cart_refnum = uniqid.time("ORD");
      connection.pool.query(`          
        INSERT INTO carts 
        (user_id, status_id, ref_num) VALUES
        (?, 1, ?)
        `,
        [req.user.user_id, cart_refnum],
        function(err, insertedCarts){
          if(err){
            renderInfo(res, '未知错误');
          }
          else{
            req.user.cart_id = insertedCarts.insertId;
			var addCartItemPromise = addCartItems(insertedCarts.insertId, req.body.product_id, req.body.quantity);
			addCartItemPromise.then(function(result){
				getCourseById(result, 
					function(responseData){
            responseData.totalPrice = req.body.totalPrice/1.0 + responseData.regular_price;
            res.send(JSON.stringify(responseData));
				})
			});
          }
      });
    }
  });
});

router.post('/checkout', function(req, res) {
    console.log(req.body);
    res.redirect(url.format({
        pathname:"/checkout",
        query:{
            message: "failed"
        }
    }));
});

router.post('/payment-success', function(req, res) {
    if (req.body.result=="1") {
        connection.pool.query(
            `select * from carts where ref_num = ? AND status_id = 1`,
            [req.body.response_order_id],
            function(err,cart){
                var order_id = "";

                if (err) {
                    res.redirect(url.format({
                        pathname:"/checkout",
                        query:{
                            message: "failed"
                        }
                    }));
                }
                connection.pool.query(
                    `update carts SET status_id = 2 WHERE ref_num = ?`,
                    [req.body.response_order_id],
                    function (err, result) {}
                );

                if (req.body.card=="M") {
                    card_type = "Mastercard";
                } else if (req.body.card=="V") {
                    card_type = "Visa";
                } else if (req.body.card=="AX") {
                    card_type = "American Express";
                } else if (req.body.card=="DC") {
                    card_type = "Diners Card";
                } else if (req.body.card=="NO") {
                    card_type = "Novus / Discover";
                } else if (req.body.card=="SE") {
                    card_type = "Sears";
                } else {
                    card_type = "Unknown";
                }


                connection.pool.query(
                    `INSERT INTO orders (payment_id, user_id, order_total, order_date, order_status, card_last4, card_type, employee_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [req.body.response_order_id, cart[0].user_id, req.body.charge_total, req.body.date_stamp+" "+req.body.time_stamp, 1, req.body.f4l4.substr(req.body.f4l4.length - 4), card_type, cart[0].employee_id],
                    function (err, result) {
                        order_id = result.insertId;
                    }
                );
                var email_body = "";

                connection.pool.query(
                    `select cart_items.* from cart_items INNER JOIN carts ON carts.cart_id = cart_items.cart_id WHERE carts.ref_num = ?`,
                    [req.body.response_order_id],
                    function(err,cartItems){
                        var total_record = cartItems.length;
                        var current_record = 0;
                        var order_refnum = null;


                        Object.keys(cartItems).forEach(function(key) {
                            var row = cartItems[key];
                            var course_title = "";
                            var course_price = "";
                            var courses_refnum = "";
                            var currentYear = new Date().getFullYear().toString().substr(-2);

                            connection.pool.query(
                                `select c.title, c.ref_num, cp.regular_price FROM courses c INNER JOIN course_prices cp ON c.id = cp.course_id WHERE c.id =?`,
                                [row['product_id']],
                                function (err, courses) {
                                    course_title = courses[0].title;
                                    course_price = courses[0].regular_price;
                                    courses_refnum = courses[0].ref_num;

                                    connection.pool.query(
                                        `select ref_num from order_items WHERE ref_num LIKE ? ORDER BY ref_num DESC LIMIT 1`,
                                        [currentYear+'%'],
                                        function (err, orderrefnum) {
                                            if (order_refnum !== null) {
                                                order_refnum = parseInt(order_refnum)+1;
                                            } else {
                                                if (err) {
                                                    order_refnum = currentYear + '00001';
                                                } else {
                                                    order_refnum = parseInt(orderrefnum[0].ref_num)+1;
                                                }
                                            }

                                            connection.pool.query(
                                                `INSERT INTO order_items (order_id, course_id, course_refnum, quantity, product_cost, product_name, ref_num) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                                                [order_id, row['product_id'], courses_refnum, row['quantity'], course_price, course_title, order_refnum]
                                            );

                                            email_body = email_body + '<tr style="border: 1px solid black;">' +
                                                '<td style="padding: 5px 10px;">'+row['quantity']+'</td>' +
                                                '<td style="padding: 5px 10px;">'+courses_refnum+'</td>' +
                                                '<td style="padding: 5px 10px;">'+course_title+'</td>' +
                                                '<td style="padding: 5px 10px;">$'+course_price.toFixed(2)+'</td>' +
                                                '<td style="padding: 5px 10px;">$'+course_price.toFixed(2)+'</td>' +
                                                '<td style="padding: 5px 10px;">REG'+order_refnum+'</td>' +
                                                '<td style="padding: 5px 10px;">'+req.user.ref_num+'</td>' +
                                                '</tr>';

                                            if (current_record == total_record -1) {
                                                var mail_html = '<p>'+req.user.first_name+' '+req.user.last_name+', 您好！'+
                                                    '<p>请查收您在www.tk-course.com 购买课程的收据：</p>' +
                                                    '<p>用户信息:</p>' +
                                                    '<br/>' +
                                                    '<table border="1" style="border-collapse: collapse;">' +
                                                    '<tr style="border: 1px solid black;">' +
                                                    '<td width="30%" style="padding: 5px 10px;">名字</td>'+
                                                    '<td width="70%" style="padding: 5px 10px;">'+req.user.first_name+'</td>'+
                                                    '</tr>' +
                                                    '<tr style="border: 1px solid black;">' +
                                                    '<td width="30%" style="padding: 5px 10px;">姓</td>'+
                                                    '<td width="70%" style="padding: 5px 10px;">'+req.user.last_name+'</td>'+
                                                    '</tr>' +
                                                    '<tr style="border: 1px solid black;">' +
                                                    '<td width="30%" style="padding: 5px 10px;">电子邮件</td>'+
                                                    '<td width="70%" style="padding: 5px 10px;">'+req.user.email+'</td>'+
                                                    '</tr>' +
                                                    '</table>' +
                                                    '<br/>' +
                                                    '<p>购买细节：</p>' +
                                                    '<br/>' +
                                                    '<table border="1" style="border-collapse: collapse;">' +
                                                    '<tr style="border: 1px solid black;">' +
                                                    '<td width="10%" style="padding: 5px 10px;">数量</td>'+
                                                    '<td width="10%" style="padding: 5px 10px;">课程号</td>'+
                                                    '<td width="30%" style="padding: 5px 10px;">课程名称</td>'+
                                                    '<td width="10%" style="padding: 5px 10px;">单价</td>'+
                                                    '<td width="10%" style="padding: 5px 10px;">总价</td>'+
                                                    '<td width="10%" style="padding: 5px 10px;">注册号</td>'+
                                                    '<td width="20%" style="padding: 5px 10px;">注册人微信号</td>'+
                                                    '</tr>' +
                                                    email_body +
                                                    '<tr>' +
                                                    '<td colspan="4" style="border: 1px solid black; padding: 5px 10px; text-align: right">全价 (CAD) (包含HST)</td>' +
                                                    '<td colspan="3" style="border: 1px solid black; padding: 5px 10px;">$'+req.body.charge_total+'</td>' +
                                                    '</tr>'+
                                                    '<tr>' +
                                                    '<td colspan="4" style="border: 1px solid black; padding: 5px 10px; text-align: right">付款额 (使用 '+card_type+' 尾号'+req.body.f4l4.substr(req.body.f4l4.length - 4)+')</td>' +
                                                    '<td colspan="3" style="border: 1px solid black; padding: 5px 10px;">$'+req.body.charge_total+'</td>' +
                                                    '</tr>' +
                                                    '</table>' +
                                                    '<p>&nbsp;</p>' +
                                                    '<p><strong>Top Knowledge Inc.</strong></p>' +
                                                    '<p>208 Bloor Street West</p>' +
                                                    '<p>Unit 501</p>' +
                                                    '<p>Toronto, Ontario M5S 1T8</p>' +
                                                    '<p>HST #: 78812 5896 RT0001</p>' +
                                                    '<p><a href="mailto:register@tk-course.com" target="_blank">register@tk-course.com</a></p>';

                                                connection.transporter.sendMail({
                                                    from: 'register@tk-course.com',
                                                    to: req.user.email,
                                                    cc: 'register@tk-course.com',
                                                    subject: '感谢您的购买！',
                                                    html: mail_html
                                                });
                                            }

                                            current_record = current_record + 1;
                                        });

                                }
                            );
                        });

                        res.redirect(url.format({
                            pathname:"/order-success",
                            query:{
                                order_number: req.body.response_order_id
                            }

                        }));
                });
        });
    } else {
        res.redirect(url.format({
            pathname:"/checkout",
            query:{
                message: "failed"
            }
        }));
    }
});

router.get('/order-success', function(req, res) {
    var order_id = req.query.order_number;

    connection.pool.query(
        `select oi.*, o.* from order_items oi INNER JOIN orders o ON o.id = oi.order_id WHERE o.payment_id = ?`,
        [order_id],
        function(err,orderItems){
            res.render('order_success', {orderItems: orderItems, user: req.user});
        }
    );
});


module.exports = router;