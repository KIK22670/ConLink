// api.js
const express = require('express');
const router = express.Router();
const client = require('./connection.js');
const bcrypt = require('bcrypt');
const Sequelize = require('sequelize');


// Middleware, um die Verbindung zu öffnen
//router.use((req, res, next) => {
//    client.connect();
//    next();
//});
router.use((req, res, next) => {
    // Überprüfe, ob ein Benutzer in der Sitzung gespeichert ist
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ message: 'Unauthorized' });
    }
});

router.get('/aerzte', (req, res) => {
    client.query('SELECT * FROM a_aerzte', (err, result) => {
        if (!err) {
            res.send(result.rows);
        } else {
            console.error(err);
            res.status(500).send('Internal Server Error');
        }
    });
});



// Registration route
router.post('/registration', async (req, res) => {
    const { nameregister, emailregister, passwortregister } = req.body;

    try {
        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(passwortregister, 10);

        const query = {
            text: 'INSERT INTO u_userverwaltung(u_id, u_passwort, u_email) VALUES($1, $2, $3)',
            values: [nameregister, emailregister, hashedPassword],
        };

        // Insert user into the database
        await client.query(query);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// Login route
router.post('/login', async (req, res) => {
    const { email, passwort } = req.body;

    try {
        const query = {
            text: 'SELECT * FROM users WHERE email = $1',
            values: [email],
        };

        // Retrieve user from the database based on the provided email
        const result = await client.query(query);

        if (result.rows.length === 0) {
            // User not found
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = result.rows[0];

        // Compare the provided password with the stored hashed password
        const isPasswordValid = await bcrypt.compare(passwort, req.session.user.u_passwort);

        if (!isPasswordValid) {
            // Invalid password
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        res.status(200).json({ message: 'Login successful', user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});


// Middleware, um die Verbindung zu schließen
router.use((req, res, next) => {
    client.end();
    next();
});

module.exports = router;
