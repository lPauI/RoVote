# RoVote

## Descriere

RoVote este o aplicație web pentru gestionarea alegerilor prezidențiale. Utilizatorii se pot înregistra, autentifica și vota pentru candidații preferați. Aplicația include funcționalități pentru administratori, cum ar fi încheierea alegerilor și trimiterea rezultatelor prin email.

## Funcționalități

- Înregistrare utilizatori cu validare OTP și extragerea CNP-ului din imaginea CI
- Autentificare utilizatori
- Votare pentru candidați
- Vizualizarea statisticilor voturilor
- Încheierea alegerilor și trimiterea rezultatelor prin email (doar pentru administratori)

## Tehnologii utilizate

- Python
- Flask
- SQLAlchemy
- WTForms
- bcrypt
- cryptography
- OpenCV
- pytesseract
- Matplotlib

## Instalare

1. Clonați repository-ul:
    ```sh
    git clone https://github.com/lPauI/RoVote.git
    cd RoVote
    ```

2. Creați și activați un mediu virtual:
    ```sh
    python3 -m venv venv
    source venv/bin/activate  # Pentru Windows: venv\Scripts\activate
    ```

3. Instalați dependențele:
    ```sh
    pip3 install -r requirements.txt
    ```

4. Configurați variabilele de mediu în fișierul `.env`:
    ```env
    FLASK_SECRET_KEY=your_secret_key
    MYSQL_USER=your_mysql_user
    MYSQL_PASSWORD=your_mysql_password
    MYSQL_HOST=your_mysql_host
    MYSQL_DATABASE=your_mysql_database
    ENCRYPTION_KEY=your_encryption_key
    SMTP_EMAIL=your_smtp_email
    SMTP_PASSWORD=your_smtp_password
    ```

5. Rulați aplicația:
    ```sh
    flask run
    ```

## Utilizare

1. Accesați aplicația la `http://localhost:5000`.
2. Înregistrați-vă sau autentificați-vă pentru a vota.
3. Administratorii pot încheia alegerile și trimite rezultatele prin email.
