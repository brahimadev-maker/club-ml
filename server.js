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

app.get('/admin/stats', authMiddleware, async (req, res) => {
    try {
        // Total des membres
        const totalResult = await sql`SELECT COUNT(*) FROM inscrit`;
        const total = parseInt(totalResult[0].count, 10);

        // Total des classes distinctes
        const classesResult = await sql`SELECT COUNT(DISTINCT classe) FROM inscrit`;
        const classes = parseInt(classesResult[0].count, 10);

        // Inscriptions du jour
        const todayResult = await sql`
            SELECT COUNT(*) FROM inscrit
            WHERE DATE(created_at) = CURRENT_DATE
        `;
        const today = parseInt(todayResult[0].count, 10);

        res.json({ total, classes, today });
    } catch (error) {
        console.error('Erreur stats:', error.message);
        res.status(500).json({ message: 'Erreur serveur.' });
    }
});


app.get('/admin/totalMembers', authMiddleware, async (req, res) => {
    try {
        const result = await sql`SELECT COUNT(*) FROM inscrit`;
        const total = parseInt(result[0].count, 10); // convertir en nombre entier

        res.json({ total });
    } catch (error) {
        console.error('Erreur totalMembers:', error.message);
        res.status(500).json({ message: 'Erreur serveur.' });
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

     
     

    res.json({ message: 'Connexion réussie.', token,admin:{
        id: admin[0].id, identifiant: admin[0].identifiant
    } });
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



// --- Endpoint pour récupérer la liste des inscrits (protégé par token admin) ---
app.get('/admin/liste-inscrits', authMiddleware, async (req, res) => {
    try {
        const inscrits = await sql`
            SELECT id, nom, email, whatsapp, classe, created_at
            FROM inscrit
            ORDER BY created_at DESC
        `;

        res.json({
            message: 'Liste des inscrits récupérée avec succès.',
            inscrits,
        });
    } catch (error) {
        console.error('Erreur lors de la récupération des inscrits:', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur.' });
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