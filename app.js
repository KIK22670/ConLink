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
const app = express();
const port = process.env.PORT || 3001;

app.use(bodyParser.json());


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

        // If email is not registered and password meets requirements, proceed with registration
        const hashedPassword = await bcrypt.hash(passwortregister, 10);

        const insertUserQuery = {
            text: 'INSERT INTO u_userverwaltung(u_email, u_passwort) VALUES($1, $2) RETURNING *',
            values: [emailregister, hashedPassword],
        };

        const result = await client.query(insertUserQuery);

        console.log(result);
        res.status(201).json({ message: 'User registered successfully, now try to login' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});



/* app.post('/registration', async (req, res) => {
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

        // If email is not registered, proceed with registration
        const hashedPassword = await bcrypt.hash(passwortregister, 10);

        const insertUserQuery = {
            text: 'INSERT INTO u_userverwaltung(u_email, u_passwort) VALUES($1, $2) RETURNING *',
            values: [emailregister, hashedPassword],
        };

        const result = await client.query(insertUserQuery);
        console.log(result);
        res.status(201).json({ message: 'User registered successfully, now try to login' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});
 */

app.get('/verify/:token', async (req, res) => {
    const token = req.params.token;

    try {
        // Find user by verification token
        const findUserQuery = {
            text: 'SELECT * FROM u_userverwaltung WHERE verification_token = $1',
            values: [token],
        };

        const user = await client.query(findUserQuery);

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'Invalid or expired token' });
        }

        // Update user to mark as verified
        const updateUserQuery = {
            text: 'UPDATE u_userverwaltung SET verified = true WHERE u_id = $1',
            values: [user.rows[0].u_id],
        };

        await client.query(updateUserQuery);

        res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
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
        const { vorname, nachname, email, telefonnummer, svnr, allergien, vorerkrankungen, medikamente } = req.body;

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
                   p_svnr = $5, p_allergien = $6, p_vorerkrankungen = $7, p_medikamente = $8, p_stammdaten = $9
               WHERE p_id = $10`,
                values: [vorname, nachname, email, telefonnummer, svnr, allergien, vorerkrankungen, medikamente, JSON.stringify(req.body), userID],
            };
            await client.query(updateDataQuery);
        } else {
            // Es gibt keine vorhandenen Patientendaten für diesen Benutzer, daher fügen Sie neue Daten hinzu
            const insertDataQuery = {
                text: `INSERT INTO p_patienten 
               (p_id, p_vorname, p_nachname, p_email, p_telefonnummer, p_svnr, p_allergien, p_vorerkrankungen, p_medikamente, p_stammdaten) 
               VALUES 
               ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
                values: [userID, vorname, nachname, email, telefonnummer, svnr, allergien, vorerkrankungen, medikamente, JSON.stringify(req.body)],
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

/* app.post('/aktualisiereNotiz', async (req, res) => {
  try {
    // Get appointment ID and new note from request body
    const appointmentID = req.body.appointmentID;
    const newNote = req.body.newNote;

    // Update the note in the database
    const query = {
      text: 'UPDATE t_termine SET t_notizen = $1 WHERE t_id = $2',
      values: [newNote, appointmentID],
    };
    await client.query(query);

    // Send success response
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Error updating note:', error);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
}); */


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

app.listen(port, () => {
    console.log(`Server läuft auf http://localhost:${port}`);
});

