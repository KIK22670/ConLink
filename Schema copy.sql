DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
 
 
CREATE TABLE IF NOT EXISTS a_aerzte (
  a_id SERIAL PRIMARY KEY,
  a_titel VARCHAR(20),
  a_vorname VARCHAR(45),
  a_nachname VARCHAR(45),
  a_email VARCHAR(100),
  a_telefonnummer VARCHAR(20),
  a_fachrichtung VARCHAR(50),
  a_plz VARCHAR(10),
  a_ort VARCHAR(100),
  a_berufserfahrung INT,
  a_qualifikationen TEXT
);
 
-- Tabelle `p_patienten` erstellen
CREATE TABLE IF NOT EXISTS p_patienten (
  p_id SERIAL PRIMARY KEY,
  p_vorname VARCHAR(45),
  p_nachname VARCHAR(45),
  p_email VARCHAR(100),
  p_passwort VARCHAR(255),
  p_telefonnummer VARCHAR(20),
  p_geburtsdatum DATE,
  p_svnr VARCHAR(45),
  p_allergien TEXT,
  p_vorerkrankungen TEXT,
  p_medikamente TEXT,
  p_a_behandelnderArzt INT REFERENCES a_aerzte(a_id) ON DELETE NO ACTION ON UPDATE NO ACTION
);
 


-- Tabelle `t_termine` erstellen
CREATE TABLE IF NOT EXISTS t_termine (
  t_id SERIAL PRIMARY KEY,
  t_datum DATE,
  t_uhrzeit TIME,
  t_termintyp VARCHAR(45),
  t_p_id INT REFERENCES p_patienten(p_id) ON DELETE NO ACTION ON UPDATE NO ACTION,
  t_a_id INT REFERENCES a_aerzte(a_id) ON DELETE NO ACTION ON UPDATE NO ACTION,
  t_tt_id INT,
  t_z_id INT
); 
 
-- Tabelle `b_bewertungen` erstellen
CREATE TABLE IF NOT EXISTS b_bewertungen (
  b_id SERIAL PRIMARY KEY,
  b_punkte INT,
  b_kommentar TEXT,
  b_p_id INT REFERENCES p_patienten(p_id) ON DELETE NO ACTION ON UPDATE NO ACTION,
  b_a_id INT REFERENCES a_aerzte(a_id) ON DELETE NO ACTION ON UPDATE NO ACTION
);
 
-- Tabelle `tt_termintyp` erstellen
CREATE TABLE IF NOT EXISTS tt_termintyp (
  tt_id SERIAL PRIMARY KEY,
  tt_bezeichnung VARCHAR(45)
);
 
-- Tabelle `m_medikamente` erstellen
CREATE TABLE IF NOT EXISTS m_medikamente (
  m_id SERIAL PRIMARY KEY,
  m_aktuell BOOLEAN NOT NULL,
  m_name VARCHAR(45)
);
 
-- Tabelle `l_logging` erstellen
CREATE TABLE IF NOT EXISTS l_logging (
  l_id SERIAL PRIMARY KEY,
  l_event_typ VARCHAR(255),
  l_p_id INT REFERENCES p_patienten(p_id) ON DELETE NO ACTION ON UPDATE NO ACTION,
  l_a_id INT REFERENCES a_aerzte(a_id) ON DELETE NO ACTION ON UPDATE NO ACTION
);
 
-- Tabelle `z_zeitslots` erstellen
CREATE TABLE IF NOT EXISTS z_zeitslots (
  z_id SERIAL PRIMARY KEY,
  z_startzeit TIME,
  z_endzeit TIME
);
 
-- Tabelle `u_userverwaltung` erstellen
create TABLE IF NOT EXISTS u_userverwaltung (
  u_id SERIAL PRIMARY KEY,
  u_username VARCHAR(45),
  u_passwort VARCHAR(100),
  u_email VARCHAR(45),
  u_telefonnummer VARCHAR(20),
  u_rolle VARCHAR(45),
  u_p_id INT REFERENCES p_patienten(p_id) ON DELETE NO ACTION ON UPDATE NO ACTION,
  u_a_id INT REFERENCES a_aerzte(a_id) ON DELETE NO ACTION ON UPDATE NO ACTION
);
 
-- Tabelle `pm_p_hat_m` erstellen
CREATE TABLE IF NOT EXISTS pm_p_hat_m (
  pm_p_id INT REFERENCES p_patienten(p_id) ON DELETE NO ACTION ON UPDATE NO ACTION,
  pm_m_id INT REFERENCES m_medikamente(m_id) ON DELETE NO ACTION ON UPDATE NO ACTION,
  PRIMARY KEY (pm_p_id, pm_m_id)
);
 
-- Ärzte einfügen
INSERT INTO a_aerzte (a_titel, a_vorname, a_nachname, a_email, a_telefonnummer, a_fachrichtung, a_plz, a_ort, a_berufserfahrung, a_qualifikationen)
VALUES
('Dr', 'Erwald', 'Heberer', 'erwald.heberer@example.com', '123456789', 'Allgemeinarzt', '1050', 'Wien', 10, 'PhD'),
('Dr', 'Marie', 'Effner', 'marie.effnerh@example.com', '987654321', 'Kardiologin', '1100', 'Wien', 15, NULL),
('Dr. med.', 'Michael', 'Jordan', 'michael.jordan@example.com', '555555555', 'Hautarzt', '1120', 'Wien', 12, NULL),
('Dr. med.', 'Julia', 'Schmidt', 'julia.schmidt@example.com', '111111111', 'Kinderärztin', '1010', 'Wien', 8, 'Dr. med.'),
('Dr. med.', 'Michael', 'Müller', 'michael.mueller@example.com', '222222222', 'Onkologe', '1020', 'Wien', 20, 'Dr. med.'),
('Dr. med.', 'Anna', 'Wagner', 'anna.wagner@example.com', '333333333', 'Psychiaterin', '1030', 'Wien', 15, 'Dr. med., Psychiatrie'),
('Dr', 'Christoph', 'Becker', 'christoph.becker@example.com', '444444444', 'Orthopäde', '1040', 'Wien', 18, NULL),
('Dr. med.', 'Laura', 'Hofmann', 'laura.hofmann@example.com', '481910519', 'Neurologin', '1050', 'Wien', 12, 'Dr. med., Neurologie');
 

-- Bewertungen einfügen
INSERT INTO b_bewertungen (b_punkte, b_kommentar, b_p_id, b_a_id)
VALUES
(2, 'Nicht zufrieden mit der Behandlung!', 1, 1),
(5, 'Kompetenter Arzt, empfehle ich weiter.', 3, 3),
(3, 'Etwas längere Wartezeit, aber gute Beratung.', 2, 2),
(4, 'Freundliches Personal und saubere Praxis.', 4, 2),
(5, 'Schnelle Diagnose, bin sehr zufrieden.', 5, 1);
 

-- Termintyp einfügen
INSERT INTO tt_termintyp (tt_bezeichnung)
VALUES
('Erstuntersuchung'),
('Folgeuntersuchung');
 
-- Änderungen an `t_termine`-Tabelle
ALTER TABLE t_termine
ADD CONSTRAINT fk_t_termine_z_zeitslots1
FOREIGN KEY (t_z_id)
REFERENCES z_zeitslots (z_id)
ON DELETE NO ACTION
ON UPDATE NO ACTION;
 
ALTER TABLE t_termine
ADD CONSTRAINT fk_t_termine_tt_termintyp1
FOREIGN KEY (t_tt_id)
REFERENCES tt_termintyp (tt_id)
ON DELETE NO ACTION
ON UPDATE NO ACTION;
 
ALTER TABLE t_termine
ADD CONSTRAINT fk_t_termine_p_patienten1
FOREIGN KEY (t_p_id)
REFERENCES p_patienten (p_id)
ON DELETE NO ACTION
ON UPDATE NO ACTION;
 
ALTER TABLE t_termine
ADD CONSTRAINT fk_t_termine_a_aerzte1
FOREIGN KEY (t_a_id)
REFERENCES a_aerzte (a_id)
ON DELETE NO ACTION
ON UPDATE NO ACTION;
 
-- Weitere Fremdschlüssel für die `b_bewertungen`, `u_userverwaltung` und `l_logging` Tabellen hinzufügen
ALTER TABLE b_bewertungen
ADD CONSTRAINT fk_b_bewertungen_a_aerzte1
FOREIGN KEY (b_a_id)
REFERENCES a_aerzte (a_id)
ON DELETE NO ACTION
ON UPDATE NO ACTION;
 
ALTER TABLE b_bewertungen
ADD CONSTRAINT fk_b_bewertungen_p_patienten1
FOREIGN KEY (b_p_id)
REFERENCES p_patienten (p_id)
ON DELETE NO ACTION
ON UPDATE NO ACTION;
 
ALTER TABLE u_userverwaltung
ADD CONSTRAINT fk_u_userverwaltung_a_aerzte1
FOREIGN KEY (u_a_id)
REFERENCES a_aerzte (a_id)
ON DELETE NO ACTION
ON UPDATE NO ACTION;
 
ALTER TABLE u_userverwaltung
ADD CONSTRAINT fk_u_userverwaltung_p_patienten1
FOREIGN KEY (u_p_id)
REFERENCES p_patienten (p_id)
ON DELETE NO ACTION
ON UPDATE NO ACTION;
 
ALTER TABLE l_logging
ADD CONSTRAINT fk_l_logging_a_aerzte1
FOREIGN KEY (l_a_id)
REFERENCES a_aerzte (a_id)
ON DELETE NO ACTION
ON UPDATE NO ACTION;
 
ALTER TABLE l_logging
ADD CONSTRAINT fk_l_logging_p_patienten1
FOREIGN KEY (l_p_id)
REFERENCES p_patienten (p_id)
ON DELETE NO ACTION
ON UPDATE NO ACTION;
 
 
CREATE TABLE IF NOT EXISTS u_general_users (
  user_id SERIAL PRIMARY KEY,
  password VARCHAR(100),
  email VARCHAR(100)
  /* Add other necessary fields */
);

ALTER TABLE p_patienten
ADD COLUMN IF NOT EXISTS p_stammdaten JSON;

CREATE TABLE IF NOT EXISTS verification_tokens (
  token_id SERIAL PRIMARY KEY,
  user_id INT REFERENCES u_general_users(user_id) ON DELETE CASCADE ON UPDATE NO ACTION,
  token VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


