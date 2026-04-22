const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host:     process.env.MYSQLHOST     || 'mysql.railway.internal',
  port:     parseInt(process.env.MYSQLPORT) || 3306,
  database: process.env.MYSQL_DATABASE || 'railway',
  user:     process.env.MYSQLUSER      || 'root',
  password: process.env.MYSQLPASSWORD  || '',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

module.exports = pool;
