const express = require('express');
const path = require('path');
const morgan = require('morgan');
const client = require('./connection.js');
const apiRouter = require('./api');
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');
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

/* const User = sequelize.define('User', {
  name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  }
});

sequelize.sync()
  .then(() => {
    console.log('Benutzertabelle synchronisiert');
  })
  .catch(err => {
    console.error('Fehler beim Synchronisieren der Benutzertabelle:', err);
  });

module.exports = User;

// Definieren Sie das Token-Modell
const Token = sequelize.define('Token', {
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Users', // Der Name der Benutzertabelle in der Datenbank
      key: 'id'
    }
  },
  token: {
    type: DataTypes.STRING,
    allowNull: false
  },
  expireAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: Sequelize.literal('CURRENT_TIMESTAMP + interval \'1 day\'') // Ablaufzeit auf einen Tag setzen
  }
});

// Das Modell mit der Datenbank synchronisieren (Tabelle erstellen, wenn sie nicht existiert)
sequelize.sync()
  .then(() => {
    console.log('Token-Tabelle synchronisiert');
  })
  .catch(err => {
    console.error('Fehler beim Synchronisieren der Token-Tabelle:', err);
  });

module.exports = Token;

*/

app.get('/registration', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'registration.html'));
});

/*
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

    // Insert user into database
    const insertUserQuery = {
      text: 'INSERT INTO u_userverwaltung(u_email, u_passwort) VALUES($1, $2) RETURNING *',
      values: [emailregister, hashedPassword],
    };

    const result = await client.query(insertUserQuery);
    console.log(result);

    // Generate verification token
    const token = crypto.randomBytes(16).toString('hex');

    // Save token into database
    const insertTokenQuery = {
      text: 'INSERT INTO verification_tokens(user_id, token) VALUES($1, $2)',
      values: [result.rows[0].u_id, token],
    };

    await client.query(insertTokenQuery);

    // Send verification email
    const transporter = nodemailer.createTransport(
      sendgridTransport({
        auth: {
          api_key: 1606200627072004
        }
      })
    );

    const mailOptions = {
      from: 'KIK22670@example.com',
      to: emailregister,
      subject: 'Account Verification Link',
      text: `Hello,\n\nPlease verify your account by clicking the link below:\n\nhttp://${req.headers.host}/confirmation/${emailregister}/${token}\n\nThank you!`,
    };

    transporter.sendMail(mailOptions, function (err) {
      if (err) {
        console.error('Error sending verification email:', err);
        return res.status(500).json({ error: 'Failed to send verification email' });
      }
      return res.status(201).json({ message: 'User registered successfully. A verification email has been sent to your email address.' });
    });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ error: 'Registration failed. Please try again later.' });
  }
});
 */


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

/* app.post('/login', async (req, res) => {
  try {
    const { email, passwort } = req.body;

    // Log Request Body
    console.log('Request Body:', req.body);

    // Check if email and password are provided
    if (!email || !passwort) {
      console.log('Email and password are required');
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Database Query to find user by email
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

      // Check if hashed password is defined
      if (user.u_passwort) {
        console.log('User has a hashed password');

        // Compare hashed password with provided password
        if (bcrypt.compareSync(passwort, user.u_passwort)) {
          console.log('Password comparison successful');

          // Check if user is verified
          if (user.isVerified) {
            console.log('User is verified');
            req.session.user = { id: user.u_id, email: user.u_email };
            res.redirect('/doctorsearch');
          } else {
            console.log('User is not verified');
            res.status(401).json({ error: 'Your email has not been verified yet' });
          }
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
}); */


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
/* 
app.get('/confirmation/:email/:token', confirmEmail) //fehlt noch

exports.confirmEmail = function (req, res, next) {
  // Suchen des Tokens in der Datenbank
  Token.findOne({ token: req.params.token }, function (err, token) {
    // Wenn der Token nicht gefunden wird (möglicherweise abgelaufen)
    if (!token) {
      return res.status(400).send({ msg: 'Your verification link may have expired. Please click on resend for verify your Email.' });
    }
    // Wenn der Token gefunden wird, überprüfen, ob der Benutzer gültig ist
    else {
      User.findOne({ _id: token._userId, email: req.params.email }, function (err, user) {
        // Wenn der Benutzer nicht gültig ist
        if (!user) {
          return res.status(401).send({ msg: 'We were unable to find a user for this verification. Please SignUp!' });
        }
        // Wenn der Benutzer bereits verifiziert ist
        else if (user.isVerified) {
          return res.status(200).send('User has been already verified. Please Login');
        }
        // Benutzer verifizieren
        else {
          // isVerified auf true setzen
          user.isVerified = true;
          // Benutzer speichern
          user.save(function (err) {
            // Fehler beim Speichern des Benutzers
            if (err) {
              return res.status(500).send({ msg: err.message });
            }
            // Konto erfolgreich verifiziert
            else {
              return res.status(200).send('Your account has been successfully verified');
            }
          });
        }
      });
    }

  });
};

exports.resendLink = function (req, res, next) {

  User.findOne({ email: req.body.email }, function (err, user) {
    // user is not found into database
    if (!user) {
      return res.status(400).send({ msg: 'We were unable to find a user with that email. Make sure your Email is correct!' });
    }
    // user has been already verified
    else if (user.isVerified) {
      return res.status(200).send('This account has been already verified. Please log in.');

    }
    // send verification link
    else {
      // generate token and save
      var token = new Token({ _userId: user._id, token: crypto.randomBytes(16).toString('hex') });
      token.save(function (err) {
        if (err) {
          return res.status(500).send({ msg: err.message });
        }

        // Send email (use verified sender's email address & generated API_KEY on SendGrid)
        const transporter = nodemailer.createTransport(
          sendgridTransport({
            auth: {
              api_key: 1606200627072004,
            }
          })
        )
        var mailOptions = { from: 'no-reply@example.com', to: user.email, subject: 'Account Verification Link', text: 'Hello ' + user.name + ',\n\n' + 'Please verify your account by clicking the link: \nhttp:\/\/' + req.headers.host + '\/confirmation\/' + user.email + '\/' + token.token + '\n\nThank You!\n' };
        transporter.sendMail(mailOptions, function (err) {
          if (err) {
            return res.status(500).send({ msg: 'Technical Issue!, Please click on resend for verify your Email.' });
          }
          return res.status(200).send('A verification email has been sent to ' + user.email + '. It will be expire after one day. If you not get verification Email click on resend token.');
        });
      });
    }
  });
}; */

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


// GET-Anfrage zum Laden der gespeicherten Stammdaten
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



app.get('/aktualisiereTermin', (req, res) => {
  // Hier können Sie die Logik für die Behandlung der GET-Anfrage implementieren
  res.send('GET-Anfrage an /aktualisiereTermin erfolgreich verarbeitet.');
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

/* app.delete('/loeschetermine/:appointmentID', async (req, res) => {
  const appointmentID = req.params.appointmentID;
  try {
    // SQL-Abfrage zum Löschen des Termins aus der Datenbank
    const result = await pool.query('DELETE FROM t_termine WHERE t_id = $1', [appointmentID]);

    // Überprüfen, ob ein Eintrag gelöscht wurde
    if (result.rowCount === 1) {
      res.status(200).json({ message: 'Termin erfolgreich gelöscht' });
    } else {
      // Wenn kein Eintrag gefunden wurde, ist die Termin-ID möglicherweise ungültig
      res.status(404).json({ message: 'Termin nicht gefunden' });
    }
  } catch (error) {
    console.error("Fehler beim Löschen des Termins:", error);
    res.status(500).json({ message: 'Fehler beim Löschen des Termins' });
  }
}); */

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


/* app.get('/holetermine', async (req, res) => {
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
}); */

// Starten Sie den Server und lauschen Sie auf dem angegebenen Port
app.listen(port, () => {
  console.log(`Server läuft auf http://localhost:${port}`);
});
