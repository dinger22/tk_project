const bcrypt = require('bcryptjs');
const saltRounds   = 10;

require('./local-signup')(saltRounds);
require('./local-login')(saltRounds);
require('./helper');
