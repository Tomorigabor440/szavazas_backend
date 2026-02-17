const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier');

///config
const PORT = 3000;
const HOST = 'localhost'
const JWT_SECRET = 'nagyon_nagyon_titkos_egyedi_jelszo'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth_token'

///cookie beallitas
const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 1000,
}

const db = mysql.createPool({
    host: 'localhost',
    port: '3306',
    user: 'root',
    password: '',
    database: 'szavazas'
})

//app
const app = express();
app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: '*',
    credentials: true
}))

//végpontok
app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body;
    if (!email || !felhasznalonev || !jelszo || !admin) {
        return res.status(400).json({ message: "hianyzo bementi adatok" })
    }

    try {
        const isValid = await emailValidator(email)
        if (!isValid) {
            return res.status(401).json({ message: "nem valos emailt adtal meg" })
        }
        const [exists] = await db.query('SELECT * FROM felhasznalok WHERE email =? OR felhasznalonev =?', [email, felhasznalonev])
        if (exists.length) {
            return res.status(402).json({ message: "email vagy felhszanalonev foglalt" })
        }
        const hash = await bcrypt.hash(jelszo, 10);
        const regisztracioSQL = 'INSERT INTO felhasznalok (email, felhasznalonev, jelszo. admin)VALUES (?,?,?,?)'
        const [result] = await db.query(regisztracioSQL, [email, felhasznalonev, hash, admin])

        return res.status(200).json({
            message: "Sikeres egisztracio",
            id: result.insertId
        })

    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Szerverhiba" })
    }
})

app.post('/belepes', async (req, res) => {
    const { felhasznalonevVagyEmail, jelszo } = req.body;
    if (!felhasznalonevVagyEmail || !jelszo) {
        return res.status(400).json({ message: "hianyos belepesi adatok" });
    }

    try {
        const isValid = await emailValidator(felhasznalonevVagyEmail)
        let hashJelszo = "";
        let user = {}
        if (isValid) {
            const sql = 'SELECT * FROM felhasznalok  WHERE email =?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(401).json({ message: "nincs ilyen fiok  " });
            }
        } else {
            const sql = 'SELECT * FROM felhasznalok  WHERE felhasznaloNev =?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(402).json({ message: "ezzel a felhasznalonevvel meg nem regisztraltak" });
            }
        }

        const ok = bcrypt.compare(jelszo, hashJelszo)
        if(!ok){
            return res.status(403).json({message: "rossz jelszot adtál meg"})
        }     
            const token = jwt.sign(
                { id: user.id, email: user.email, felhasznalonev: user.felhasznalonev, admin: user.admin },
                JWT_SECRET,
                { expiresIn: JWT_EXPIRES_IN }
        )
            
        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({message: "Sikeres belépés"})
        
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "szerverhiba" })
    }
})

app.get('/adataim', auth, async (req, res) => {

})

//szerver elinditas
app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`);
})