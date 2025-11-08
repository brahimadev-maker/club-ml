import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';

const sql = postgres(process.env.DATABASE_URL);

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

app.post('/register', async (req, res) => {
    const { name, email, classe, password } = req.body;

    if (!name || !email || !classe || !password) {
        return res.status(400).json({ message: 'Tous les champs sont requis.' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await sql`
            INSERT INTO inscrit (nom, email, classe, mot_de_passe)
            VALUES (${name}, ${email}, ${classe}, ${hashedPassword})
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

app.listen(() => {});
