const { Client } = require('pg');
const Sequelize = require('sequelize');


let client;

if (process.env.NODE_ENV === 'production') {
  // Verbindung zur Heroku PostgreSQL-Datenbank
  client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false
    }
  });
} else {
  // Lokale Verbindung
  client = new Client({
    host: "localhost",
    user: "postgres",
    port: 5432,
    password: "rootUser",
    database: "postgres"
  });
}

client.connect()
  .then(() => console.log('Connected to the database'))
  .catch(error => console.error('Error connecting to the database', error));

module.exports = client;