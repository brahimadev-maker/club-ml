import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';


const sql = postgres(process.env.DATABASE_URL);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.post('/register', async (req, res) => {
    const { name, whatsapp, email, classe, password } = req.body;

    if (!name || !email || !whatsapp || !classe || !password) {
        return res.status(400).json({ message: 'Tous les champs sont requis.' });
    }

    // Validation du numéro WhatsApp (format ivoirien)
    const whatsappRegex = /^(0[1|5|7])\d{8}$/;
    if (!whatsappRegex.test(whatsapp)) {
        return res.status(400).json({ 
            message: 'Numéro WhatsApp invalide. Format attendu: 07/05/01 XX XX XX XX' 
        });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await sql`
            INSERT INTO inscrit (nom, email, whatsapp, classe, mot_de_passe)
            VALUES (${name}, ${email}, ${whatsapp}, ${classe}, ${hashedPassword})
        `;

        res.status(201).json({
            message: `Inscription réussie pour ${name} ! Bienvenue au Club ML.`,
        });

    } catch (error) {
        console.error('Erreur lors de l\'inscription:', error.message);

        if (error.code === '23505') {
            return res.status(409).json({ message: 'Cet email est déjà utilisé.' });
        }

        res.status(500).json({ message: 'Une erreur interne est survenue.' });
    }
});




app.post('/admin/register', async (req, res) => {
  const { identifiant, mot_de_passe } = req.body;

  if (!identifiant || !mot_de_passe) {
    return res.status(400).json({ message: 'Identifiant et mot de passe requis.' });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(mot_de_passe, salt);

    await sql`
      INSERT INTO admin (identifiant, mot_de_passe)
      VALUES (${identifiant}, ${hashedPassword})
    `;

    res.status(201).json({ message: 'Admin enregistré avec succès.' });
  } catch (error) {
    console.error('Erreur admin register:', error.message);
    if (error.code === '23505') {
      return res.status(409).json({ message: 'Identifiant déjà utilisé.' });
    }
    res.status(500).json({ message: 'Erreur interne.' });
  }
});


app.post('/admin/login', async (req, res) => {
  const { identifiant, mot_de_passe } = req.body;

  if (!identifiant || !mot_de_passe) {
    return res.status(400).json({ message: 'Identifiant et mot de passe requis.' });
  }

  try {
    const admin = await sql`
      SELECT * FROM admin WHERE identifiant = ${identifiant}
    `;

    if (admin.length === 0) {
      return res.status(401).json({ message: 'Identifiant incorrect.' });
    }

    const validPassword = await bcrypt.compare(mot_de_passe, admin[0].mot_de_passe);
    if (!validPassword) {
      return res.status(401).json({ message: 'Mot de passe incorrect.' });
    }

    const token = generateToken({ id: admin[0].id, identifiant: admin[0].identifiant });

    res.json({ message: 'Connexion réussie.', token });
  } catch (error) {
    console.error('Erreur admin login:', error.message);
    res.status(500).json({ message: 'Erreur interne.' });
  }
});
import { generateToken, verifyToken, authMiddleware } from './config/token.js';

// Endpoint pour créer un admin
app.post('/admin/register', async (req, res) => {
    const { identifiant, password } = req.body;

    if (!identifiant || !password) {
        return res.status(400).json({ message: 'Identifiant et mot de passe requis.' });
    }

    // Validation du mot de passe (minimum 8 caractères)
    if (password.length < 8) {
        return res.status(400).json({ 
            message: 'Le mot de passe doit contenir au moins 8 caractères.' 
        });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await sql`
            INSERT INTO admin (identifiant, mot_de_passe)
            VALUES (${identifiant}, ${hashedPassword})
        `;

        res.status(201).json({
            message: 'Admin créé avec succès.',
        });

    } catch (error) {
        console.error('Erreur lors de la création admin:', error.message);

        if (error.code === '23505') {
            return res.status(409).json({ message: 'Cet identifiant existe déjà.' });
        }

        res.status(500).json({ message: 'Une erreur interne est survenue.' });
    }
});


app.post('/admin/login', async (req, res) => {
    const { identifiant, password } = req.body;

    if (!identifiant || !password) {
        return res.status(400).json({ message: 'Identifiant et mot de passe requis.' });
    }

    try {
        const admins = await sql`
            SELECT * FROM admin WHERE identifiant = ${identifiant}
        `;

        if (admins.length === 0) {
            return res.status(401).json({ message: 'Identifiant ou mot de passe incorrect.' });
        }

        const admin = admins[0];
        const isPasswordValid = await bcrypt.compare(password, admin.mot_de_passe);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Identifiant ou mot de passe incorrect.' });
        }

       
        const token = generateToken({
            id: admin.id,
            identifiant: admin.identifiant
        });

        res.json({
            message: 'Connexion réussie.',
            token,
            admin: {
                id: admin.id,
                identifiant: admin.identifiant
            }
        });

    } catch (error) {
        console.error('Erreur lors de la connexion:', error.message);
        res.status(500).json({ message: 'Une erreur interne est survenue.' });
    }
});


app.get('/admin/dashboard', authMiddleware, async (req, res) => {
    try {
        res.json({
            message: 'Bienvenue sur le dashboard admin',
            admin: req.admin
        });
    } catch (error) {
        res.status(500).json({ message: 'Erreur serveur.' });
    }
});
app.listen(PORT, () => {
    console.log(`Serveur démarré sur le port ${PORT}`);
});