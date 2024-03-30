const express = require('express');
const path = require('path');
const morgan = require('morgan');
const client = require('./connection.js');
const apiRouter = require('./api');
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');
const { use } = require('passport');


const app = express();
const port = process.env.PORT || 3001;

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
          // sessionStorage.setItem("user-id", user.id);
          //sessionStorage.setItem("usermail", user.email);
          //sessionStorage.getItem() != null
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

// ...

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

// ...


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

app.post('/speichereStammdaten', async (req, res) => {
  const userID = req.session.user.id;
  const { vorname, nachname, email, telefonnummer, svnr, allergien, vorerkrankungen, medikamente } = req.body;

  try {
    const updateData = {
      text: 'UPDATE p_patienten SET p_stammdaten = $1 WHERE p_id = $2',
      values: [{ vorname, nachname, email, telefonnummer, svnr, allergien, vorerkrankungen, medikamente }, userID],
    };

    await client.query(updateData);
    res.status(201).json({ message: 'Stammdaten wurden gespeichert' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
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
  const { doctorId, selectedDate, kategorie } = req.body;//patientID
  console.log("DATUM:", selectedDate, "DoctorID:", doctorId, "Kategorie:", kategorie);//"PatientID:",patientID
  const datetime = Date.parse(selectedDate);
  console.log(datetime);

  try {
    const userID = req.session.user.id;
    console.log("dDie User ID", userID);

    const inserTermin = {
      text: `INSERT INTO t_termine (t_datum, t_a_id,t_p_id,t_termintyp) VALUES ($1, $2, $3, $4)`,
      values: [selectedDate, doctorId, userID, kategorie],
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
    const terminID = req.body.terminID;

    // SQL-Abfrage zum Löschen des Termins aus der Datenbank
    const deleteQuery = {
      text: 'DELETE FROM t_termine WHERE t_id = $1',
      values: [terminID],
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

app.get('/aktualisiereTermin', (req, res) => {
  // Hier können Sie die Logik für die Behandlung der GET-Anfrage implementieren
  res.send('GET-Anfrage an /aktualisiereTermin erfolgreich verarbeitet.');
});

app.get('/holetermine', async (req, res) => {
  try {
    // Get the user ID from the session
    const userID = req.session.user.id;

    // Construct the SQL query
    const query = {
      text: 'SELECT t_id, t_datum, t_termintyp FROM t_termine WHERE t_p_id = $1 Order by t_datum',
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

// Starten Sie den Server und lauschen Sie auf dem angegebenen Port
app.listen(port, () => {
  console.log(`Server läuft auf http://localhost:${port}`);
});
