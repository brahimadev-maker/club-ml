import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';

const sql = postgres(process.env.DATABASE_URL);

const app = express();
const PORT = process.env.PORT||3000;

app.use(cors());
app.use(express.json());

app.post('/register', async (req, res) => {
    const { name, email, whatsapp, classe, password } = req.body;

    if (!name || !email || !whatsapp || !classe || !password) {
        return res.status(400).json({ message: 'Tous les champs sont requis.' });
    }


    const whatsappRegex = /^(\+225|225)?(0[1|5|7])\d{8}$/;
    if (!whatsappRegex.test(whatsapp)) {
        return res.status(400).json({ 
            message: 'Numéro WhatsApp invalide. Format attendu: +225 07/05/01 XX XX XX XX' 
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

app.listen(PORT);