const express = require('express');
const path = require('path');
const morgan = require('morgan');
const client = require('./connection.js');
const apiRouter = require('./api');
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');
const crypto = require('crypto');
const { sequelize, DataTypes } = require('sequelize');
const bodyParser = require('body-parser');
const { use } = require('passport');
const sgMail = require('@sendgrid/mail');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

app.use(bodyParser.json({ limit: '2gb' }));

sgMail.setApiKey(process.env.MY_API_KEY);

//kurzer Kommentar
app.use(morgan('combined'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
    secret: '12345', // Geheimer Schlüssel zur Sitzungsverschlüsselung
    resave: false,
    saveUninitialized: true,
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use('/node_modules', express.static(path.join(__dirname, 'node_modules')));
app.use(cors()); // Enable CORS
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Template für die Verifizierungs-E-Mail
const emailVerificationTemplate = (verificationToken) => `
<!DOCTYPE html>
<html lang="de">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>E-Mail-Verifizierung</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
        }

        .container {
            max-width: 600px;
            margin: 20px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }

        .card {
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .card-header {
            background-color: #1b9aaa;
            color: #fff;
            padding: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            text-align: center;
        }

        .card-body {
            padding: 20px;
            text-align: center;
        }

        h1 {
            margin-top: 0;
            font-size: 24px;
        }

        p {
            margin-bottom: 20px;
            color: #555;
            line-height: 1.6;
        }

        .verification-link a {
            display: inline-block;
            padding: 10px 20px;
            background-color: #1b9aaa;
            color: #fff;
            text-decoration: none;
            border-radius: 5px;
            transition: background-color 0.3s ease;
        }

        .verification-link a:hover {
            background-color: #0f7c8a;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <h1>E-Mail-Verifizierung Erforderlich</h1>
            </div>
            <div class="card-body">
                <p>Bitte klicken Sie auf den folgenden Link, um Ihre E-Mail-Adresse zu verifizieren:</p>
                <div class="verification-link">
                    <a href="https://conlink-9cd090f32e8a.herokuapp.com/verify-email/${verificationToken}">Verify Email</a>
                </div>
            </div>
        </div>
    </div>
</body>

</html>


`;

const resetPasswordTemplate = (token) => `
<!DOCTYPE html>
<html lang="de">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passwort zurücksetzen!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
        }

        .container {
            max-width: 600px;
            margin: 20px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }

        .card {
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .card-header {
            background-color: #1b9aaa;
            color: #fff;
            padding: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            text-align: center;
        }

        .card-body {
            padding: 20px;
            text-align: center;
        }

        h1 {
            margin-top: 0;
            font-size: 24px;
        }

        p {
            margin-bottom: 20px;
            color: #555;
            line-height: 1.6;
        }

        .verification-link a {
            display: inline-block;
            padding: 10px 20px;
            background-color: #1b9aaa;
            color: #fff;
            text-decoration: none;
            border-radius: 5px;
            transition: background-color 0.3s ease;
        }

        .verification-link a:hover {
            background-color: #0f7c8a;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <h1>E-Mail-Verifizierung Erforderlich</h1>
            </div>
            <div class="card-body">
                <p>Bitte klicken Sie auf den folgenden Link, um Ihr Passwort zurückzusetzen</p>
                <div class="verification-link">
                    <a href="https://conlink-9cd090f32e8a.herokuapp.com/reset-password/${token}">Verify Email</a>
                </div>
            </div>
        </div>
    </div>
</body>

</html>


`;

app.get('/email-verification', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'emailverification.html'));
});

app.get('/resetpasswordverification', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'resetpasswordverification.html'));
});

app.get('/registration', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'registration.html'));
});

app.post('/registration', async (req, res) => {
    const { emailregister, passwortregister } = req.body;

    try {
        // Check if the email is already registered
        const checkEmailQuery = {
            text: 'SELECT * FROM u_userverwaltung WHERE u_email = $1',
            values: [emailregister],
        };

        const emailCheckResult = await client.query(checkEmailQuery);

        if (emailCheckResult.rows.length > 0) {
            // Email is already registered
            return res.status(400).json({ error: 'Email already exists' });
        }

        // Check if the password meets requirements
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(passwortregister)) {
            // Password does not meet requirements
            return res.status(400).json({ error: 'Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 8 characters long' });
        }

        const verificationToken = crypto.randomBytes(20).toString('hex');

        // If email is not registered and password meets requirements, proceed with registration
        const hashedPassword = await bcrypt.hash(passwortregister, 10);

        const insertUserQuery = {
            text: 'INSERT INTO u_userverwaltung(u_email, u_passwort, verification_token) VALUES($1, $2, $3) RETURNING *',
            values: [emailregister, hashedPassword, verificationToken],
        };

        await client.query(insertUserQuery);

        // Send verification email
        const msg = {
            to: emailregister,
            from: 'kikicaleksandra@gmail.com',
            subject: 'Verify Your Email Address for ConLink',
            html: emailVerificationTemplate(verificationToken)
        };
        await sgMail.send(msg);

        res.redirect('/email-verification');

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});





app.get('/verify-email/:token', async (req, res) => {
    const { token } = req.params;

    try {
        // Find user by verification token
        const findUserQuery = {
            text: 'SELECT * FROM u_userverwaltung WHERE verification_token = $1',
            values: [token],
        };

        const { rows } = await client.query(findUserQuery);

        if (rows.length === 0) {
            // No user found with the provided token
            return res.status(404).send('Invalid verification token.');
        }

        const user = rows[0];

        // Update user as verified
        const updateUserQuery = {
            text: 'UPDATE u_userverwaltung SET verified = true WHERE u_id = $1',
            values: [user.u_id], // Achten Sie darauf, das entsprechende Feld für den Primärschlüssel zu verwenden
        };


        await client.query(updateUserQuery);

        res.redirect('/login'); // Redirect user to login page after successful verification
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal server error');
    }
});


app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
    try {
        const { email, passwort } = req.body;

        // Log Request Body
        console.log('Request Body:', req.body);

        // Check if password is provided
        if (!passwort) {
            console.log('Password is required');
            return res.status(400).json({ error: 'Password is required' });
        }

        // Database Query
        const query = {
            text: 'SELECT * FROM u_userverwaltung WHERE LOWER(u_email) = LOWER($1)',
            values: [email.toLowerCase()],
        };

        const result = await client.query(query);

        // Log Database Query Result
        console.log('Database Query Result:', result.rows);

        if (result.rows.length === 1) {
            console.log('User found in the database');
            const user = result.rows[0];

            if (!user.verified) {
                console.log('User email not verified');
                return res.status(401).json({ error: 'Please verify your email address before logging in' });
            }

            if (user.u_passwort) {
                console.log('User has a hashed password');

                // Check if hashed password is defined
                if (bcrypt.compareSync(passwort, user.u_passwort)) {
                    console.log('Password comparison successful');
                    req.session.user = { id: user.u_id, email: user.u_email };
                    res.redirect('/doctorsearch');
                } else {
                    console.log('Incorrect email or password');
                    res.status(401).json({ error: 'Invalid email or password' });
                }
            } else {
                console.log('User does not have a hashed password');
                res.status(401).json({ error: 'Invalid email or password' });
            }
        } else {
            console.log('No user found with the provided email');
            res.status(401).json({ error: 'Invalid email or password' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: error.message });
    }
});


app.get('/logout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err);
            res.status(500).json({ error: 'Internal Server Error' });
        } else {
            // Redirect to the home page after logout
            res.redirect('/home.html'); // Ändere dies zu der URL deiner Home-Seite
        }
    });
});


app.get('/doctor/:id', async (req, res) => {
    try {
        console.log('Anfrage für Arzt mit ID:', req.params.id);

        const doctorId = req.params.id;
        const query = {
            text: 'SELECT * FROM a_aerzte WHERE a_id = $1',
            values: [doctorId],
        };

        const result = await client.query(query);

        console.log('Ergebnis der Datenbankabfrage:', result.rows);

        if (result.error) {
            console.error('Fehler bei der Datenbankabfrage:', result.error);
            res.status(500).json({ error: 'Internal Server Error' });
            return;
        }

        if (result.rows.length > 0) {
            res.status(200).json(result.rows[0]);
        } else {
            res.status(404).json({ error: 'Arzt nicht gefunden' });
        }
    } catch (error) {
        console.error('Fehler in der Route /doctor/:id:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/doctorsearch', (req, res, next) => {
    console.log("=======================================");
    console.log(req.session.user);
    console.log(req.session.user);
    console.log("=======================================");
    if (req.session.user) {

        // User is logged in, proceed
        console.log("doctorsearch USer erlaubt und vorhanden");
        res.sendFile(path.join(__dirname, 'public', 'doctorsearch.html'));
    } else {
        // User is not logged in, redirect to login page
        console.log("USer nicht erlaubt");
        res.redirect('/login');
    }
});
app.get('/appoitmentoverview', (req, res, next) => {
    console.log("=======================================");
    console.log(req.session.user);
    console.log(req.session.user);
    console.log("=======================================");
    if (req.session.user) {

        // User is logged in, proceed
        res.sendFile(path.join(__dirname, 'public', 'appoitmentoverview.html'));
    } else {
        // User is not logged in, redirect to login page
        res.redirect('/login');
    }
});

app.get('/stammdaten', (req, res, next) => {
    console.log("=======================================");
    console.log(req.session.user);
    console.log(req.session.user);
    console.log("=======================================");
    if (req.session.user) {

        // User is logged in, proceed
        res.sendFile(path.join(__dirname, 'public', 'stammdaten.html'));
    } else {
        // User is not logged in, redirect to login page
        res.redirect('/login');
    }
});

app.use('/api', apiRouter);

// POST-Anfrage zum Speichern oder Aktualisieren der Patientendaten
app.post('/speichereStammdaten', async (req, res) => {
    try {
        const userID = req.session.user.id;
        const { vorname, nachname, email, telefonnummer, svnr, allergien, vorerkrankungen, medikamente, bild } = req.body;

        // Überprüfen, ob bereits Patientendaten für diesen Benutzer vorhanden sind
        const checkExistingDataQuery = {
            text: 'SELECT * FROM p_patienten WHERE p_id = $1',
            values: [userID],
        };
        const existingDataResult = await client.query(checkExistingDataQuery);

        if (existingDataResult.rows.length > 0) {
            // Es gibt bereits Patientendaten für diesen Benutzer, daher aktualisieren Sie sie
            const updateDataQuery = {
                text: `UPDATE p_patienten 
               SET p_vorname = $1, p_nachname = $2, p_email = $3, p_telefonnummer = $4, 
                   p_svnr = $5, p_allergien = $6, p_vorerkrankungen = $7, p_medikamente = $8, p_stammdaten = $9, p_bild = $10
               WHERE p_id = $11`,
                values: [vorname, nachname, email, telefonnummer, svnr, allergien, vorerkrankungen, medikamente, JSON.stringify(req.body), bild, userID],
            };
            await client.query(updateDataQuery);
        } else {
            // Es gibt keine vorhandenen Patientendaten für diesen Benutzer, daher fügen Sie neue Daten hinzu
            const insertDataQuery = {
                text: `INSERT INTO p_patienten 
               (p_id, p_vorname, p_nachname, p_email, p_telefonnummer, p_svnr, p_allergien, p_vorerkrankungen, p_medikamente, p_stammdaten, p_bild) 
               VALUES 
               ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
                values: [userID, vorname, nachname, email, telefonnummer, svnr, allergien, vorerkrankungen, medikamente, JSON.stringify(req.body), bild],
            };
            await client.query(insertDataQuery);
        }

        res.status(201).json({ message: 'Patientendaten wurden gespeichert/aktualisiert' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/ladeStammdaten', async (req, res) => {
    try {
        const userID = req.session.user.id;
        const result = await client.query('SELECT p_stammdaten FROM p_patienten WHERE p_id = $1', [userID]);

        if (result.rows.length > 0 && result.rows[0].p_stammdaten) {
            // Server: Senden Sie die Stammdaten als JSON-Zeichenfolgen
            res.json({ success: true, stammdaten: JSON.stringify(result.rows[0].p_stammdaten) });
        } else {
            res.json({ success: false });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/speichereTermin', async (req, res) => {
    const { doctorId, selectedDate, kategorie, notiz } = req.body;
    console.log("DATUM:", selectedDate, "DoctorID:", doctorId, "Kategorie:", kategorie, "Notiz:", notiz);

    try {
        const userID = req.session.user.id;
        console.log("Die User ID", userID);

        const inserTermin = {
            text: `INSERT INTO t_termine (t_datum, t_a_id, t_p_id, t_termintyp, t_notizen) VALUES ($1, $2, $3, $4, $5)`,
            values: [selectedDate, doctorId, userID, kategorie, notiz],
        };

        const result = await client.query(inserTermin);
        console.log(result);
        res.status(201).json({ message: 'Termin wurde hinzugefügt' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});



app.post('/storniereTermin', async (req, res) => {
    try {
        const appointmentID = req.body.appointmentID;

        // SQL-Abfrage zum Löschen des Termins aus der Datenbank
        const deleteQuery = {
            text: 'DELETE FROM t_termine WHERE t_id = $1',
            values: [appointmentID],
        };

        // Ausführen der SQL-Abfrage
        await client.query(deleteQuery);

        // Erfolgsmeldung senden
        res.status(200).json({ message: 'Termin wurde erfolgreich storniert' });
    } catch (error) {
        console.error('Fehler beim Stornieren des Termins:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/holetermine', async (req, res) => {
    try {
        // Get the user ID from the session
        const userID = req.session.user.id;

        // Construct the SQL query
        const query = {
            text: 'SELECT t_id, t_datum, t_termintyp, t_notizen FROM t_termine WHERE t_p_id = $1 ORDER BY t_datum',
            values: [userID],
        };
        // Execute the SQL query
        const result = await client.query(query);

        // Check if the appointment was successfully retrieved
        if (result.rowCount > 0) {
            const appointments = result.rows.map(appointment => {
                return {
                    appointmentID: appointment.t_id,
                    appointmentDate: appointment.t_datum.toISOString().substring(0, 19),
                    appointmentTyp: appointment.t_termintyp,
                    appointmentNote: appointment.t_notizen
                };
            });
            res.status(200).json(appointments);
        } else {
            res.status(404).json({ error: 'No appointments found' });
        }
    } catch (error) {
        console.error('Error getting appointments:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Forgot Password validation
function validateResetInput(data) {
    let errors = {};

    data.email = data.email.trim();

    if (!data.email) {
        errors.email = 'Email is required';
    } else if (!/^\S+@\S+\.\S+$/.test(data.email)) {
        errors.email = 'Email is invalid';
    }

    return {
        errors,
        isValid: Object.keys(errors).length === 0,
    };
}

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
    const { errors, isValid } = validateResetInput(req.body);

    if (!isValid) {
        return res.status(400).json(errors);
    }

    const token = crypto.randomBytes(48).toString('hex');
    const expirationTime = new Date(Date.now() + 3600000); // 1 hour expiration

    try {
        // Check if user with provided email exists
        const userResult = await client.query('SELECT * FROM u_userverwaltung WHERE u_email = $1', [req.body.email]);
        if (userResult.rows.length === 0) {
            return res.status(400).json({ email: 'Invalid email address' });
        }

        // Save token and expiration date in database
        await client.query(
            'UPDATE u_userverwaltung SET resetpasswordtoken = $1, resetpasswordexpires = $2 WHERE u_email = $3',
            [token, expirationTime, req.body.email]
        );

        // Send email to user
        const mailOptions = {
            to: req.body.email,
            from: 'kikicaleksandra@gmail.com',
            subject: 'Password Reset',
            html: resetPasswordTemplate(token)
        };
        await sgMail.send(mailOptions);

        res.status(200).sendFile(path.join(__dirname, 'public', 'resetpasswordverification.html'));
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json("Internal Server Error");
    }
});

// Reset Password Route
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).json({ confirmPassword: 'Passwords do not match' });
    }

    try {
        // Check if the token is valid and not expired
        const userResult = await client.query(
            'SELECT * FROM u_userverwaltung WHERE resetpasswordtoken = $1 AND resetpasswordexpires > CURRENT_TIMESTAMP',
            [token]
        );

        if (userResult.rows.length === 0) {
            return res.status(400).json({ token: 'Token is invalid or has expired' });
        }

        // Update user password
        const hashedPassword = await bcrypt.hash(password, 10);
        await client.query(
            'UPDATE u_userverwaltung SET u_passwort = $1, resetpasswordtoken = NULL, resetpasswordexpires = NULL WHERE resetpasswordtoken = $2',
            [hashedPassword, token]
        );

        res.status(200).sendFile(path.join(__dirname, 'public', 'resetsuccess.html'));
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json("Internal Server Error");
    }
});

// Reset Password Route
app.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;

    try {
        // Check if the token is valid and not expired
        const userResult = await client.query(
            'SELECT * FROM u_userverwaltung WHERE resetpasswordtoken = $1 AND resetpasswordexpires > CURRENT_TIMESTAMP',
            [token]
        );

        if (userResult.rows.length === 0) {
            return res.status(400).json({ token: 'Token is invalid or has expired' });
        }

        // If the token is valid, render the HTML page for resetting the password
        res.sendFile(path.join(__dirname, 'public', 'newpassword.html'));
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json("Internal Server Error");
    }
});



app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});