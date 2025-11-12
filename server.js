import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';
import nodemailer from 'nodemailer';
import { generateToken, verifyToken, authMiddleware } from './config/token.js';

const sql = postgres(process.env.DATABASE_URL);
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ======================== REGISTER MEMBER ========================
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
        const hashedPassword = await bcrypt.hash(password, 10);
        await sql`
            INSERT INTO inscrit (nom, email, whatsapp, classe, mot_de_passe)
            VALUES (${name}, ${email}, ${whatsapp}, ${classe}, ${hashedPassword})
        `;
        res.status(201).json({ message: `Inscription réussie pour ${name} ! Bienvenue au Club ML.` });
    } catch (error) {
        console.error('Erreur inscription:', error.message);
        if (error.code === '23505') return res.status(409).json({ message: 'Cet email est déjà utilisé.' });
        res.status(500).json({ message: 'Erreur interne.' });
    }
});

// ======================== ADMIN REGISTER ========================
app.post('/admin/register', async (req, res) => {
    const { identifiant, password } = req.body;
    if (!identifiant || !password) return res.status(400).json({ message: 'Identifiant et mot de passe requis.' });
    if (password.length < 8) return res.status(400).json({ message: 'Le mot de passe doit contenir au moins 8 caractères.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await sql`INSERT INTO admin (identifiant, mot_de_passe) VALUES (${identifiant}, ${hashedPassword})`;
        res.status(201).json({ message: 'Admin créé avec succès.' });
    } catch (error) {
        console.error('Erreur admin register:', error.message);
        if (error.code === '23505') return res.status(409).json({ message: 'Cet identifiant existe déjà.' });
        res.status(500).json({ message: 'Erreur interne.' });
    }
});

app.post('/user/login', async (req, res) => {
    const { email, mot_de_passe } = req.body;
    console.log(email)
    if (!email || !mot_de_passe) return res.status(400).json({ message: 'Identifiant et mot de passe requis.' });
    try {
        const admin = await sql`SELECT * FROM inscrit WHERE email = ${email}`;
        if (admin.length === 0) return res.status(401).json({ message: 'Identifiant incorrect.' });

        const valid = await bcrypt.compare(mot_de_passe, admin[0].mot_de_passe);
        if (!valid) return res.status(401).json({ message: 'Mot de passe incorrect.' });

        const token = generateToken({ id: admin[0].id, email: admin[0].email });
        res.json({ message: 'Connexion réussie.', token, admin: { id: admin[0].id, email: admin[0].email } });
    } catch (error) {
        console.error('Erreur admin login:', error.message);
        res.status(500).json({ message: 'Erreur interne.' });
    }
});


// ======================== ADMIN LOGIN ========================
app.post('/admin/login', async (req, res) => {
    const { identifiant, mot_de_passe } = req.body;
    if (!identifiant || !mot_de_passe) return res.status(400).json({ message: 'Identifiant et mot de passe requis.' });

    try {
        const admin = await sql`SELECT * FROM admin WHERE identifiant = ${identifiant}`;
        if (admin.length === 0) return res.status(401).json({ message: 'Identifiant incorrect.' });

        const valid = await bcrypt.compare(mot_de_passe, admin[0].mot_de_passe);
        if (!valid) return res.status(401).json({ message: 'Mot de passe incorrect.' });

        const token = generateToken({ id: admin[0].id, identifiant: admin[0].identifiant });
        res.json({ message: 'Connexion réussie.', token, admin: { id: admin[0].id, identifiant: admin[0].identifiant } });
    } catch (error) {
        console.error('Erreur admin login:', error.message);
        res.status(500).json({ message: 'Erreur interne.' });
    }
});

// ======================== ADMIN DASHBOARD ========================
app.get('/admin/dashboard', authMiddleware, async (req, res) => {
    res.json({ message: 'Bienvenue sur le dashboard admin', admin: req.admin });
});

// ======================== ADMIN STATS ========================
app.get('/admin/stats', authMiddleware, async (req, res) => {
    try {
        const total = parseInt((await sql`SELECT COUNT(*) FROM inscrit`)[0].count, 10);
        const classes = parseInt((await sql`SELECT COUNT(DISTINCT classe) FROM inscrit`)[0].count, 10);
        const today = parseInt((await sql`SELECT COUNT(*) FROM inscrit WHERE DATE(created_at) = CURRENT_DATE`)[0].count, 10);
        res.json({ total, classes, today });
    } catch (error) {
        console.error('Erreur stats:', error.message);
        res.status(500).json({ message: 'Erreur serveur.' });
    }
});

// ======================== LISTE INSCRITS ========================
app.get('/admin/liste-inscrits', authMiddleware, async (req, res) => {
    try {
        const inscrits = await sql`SELECT id, nom, email, whatsapp, classe, created_at FROM inscrit ORDER BY created_at DESC`;
        res.json({ message: 'Liste récupérée.', inscrits });
    } catch (error) {
        console.error('Erreur liste inscrits:', error.message);
        res.status(500).json({ message: 'Erreur interne.' });
    }
});

// ======================== NODEMAILER CONFIG ========================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.AI_MAIL, pass: process.env.APP_PASSWORD },
});
transporter.verify(err => {
  if (err) console.error('Erreur email config:', err);
  else console.log('Serveur email prêt ✅');
});

// ======================== SEND MESSAGE (OPTIMIZED) ========================
app.post('/admin/send-message', authMiddleware, async (req, res) => {
    const { subject, content, theme = '#1c6487', link, linkText } = req.body;
    if (!subject || !content) return res.status(400).json({ message: 'Objet et contenu requis.' });

    try {
        const membres = await sql`SELECT nom, email FROM inscrit`;
        if (membres.length === 0) return res.status(404).json({ message: 'Aucun membre trouvé.' });

        const adjustColor = (color, amount) => {
            const num = parseInt(color.replace('#', ''), 16);
            const r = Math.max(0, Math.min(255, (num >> 16) + amount));
            const g = Math.max(0, Math.min(255, ((num >> 8) & 0x00FF) + amount));
            const b = Math.max(0, Math.min(255, (num & 0x0000FF) + amount));
            return '#' + ((r << 16) | (g << 8) | b).toString(16).padStart(6, '0');
        };

        const generateEmailHTML = (nom) => {
            const darkerTheme = adjustColor(theme, -20);
            const paragraphs = content.split('\n').filter(Boolean)
                .map(p => `<p style="margin-bottom:1rem;color:#333">${p}</p>`).join('');
            const linkButton = link && linkText ? `
                <div style="text-align:center;margin:2rem 0;">
                    <a href="${link}" style="padding:14px 35px;background:${theme};color:#fff;text-decoration:none;border-radius:8px;font-weight:600;">
                        ${linkText}
                    </a>
                </div>` : '';
            return `
                <div style="font-family:'Segoe UI',Arial,sans-serif;background:#f5f5f5;padding:20px">
                    <div style="max-width:600px;margin:auto;background:white;border-radius:10px;overflow:hidden">
                        <div style="background:linear-gradient(135deg,${theme},${darkerTheme});color:white;padding:30px;text-align:center">
                            <h1>🧠 Club ML ESATIC</h1>
                        </div>
                        <div style="padding:30px">
                            <p>Bonjour <strong style="color:${theme}">${nom}</strong>,</p>
                            <h2 style="color:${theme}">${subject}</h2>
                            ${paragraphs}
                            ${linkButton}
                            <hr style="margin-top:2rem">
                            <p>Cordialement,<br><strong style="color:${theme}">L’équipe du Club ML ESATIC</strong></p>
                        </div>
                    </div>
                </div>`;
        };

        const results = [];
        const batchSize = 20; // 20 emails par lot
        for (let i = 0; i < membres.length; i += batchSize) {
            const batch = membres.slice(i, i + batchSize);
            console.log(`Envoi du lot ${i / batchSize + 1}/${Math.ceil(membres.length / batchSize)}...`);

            for (const membre of batch) {
            const mailOptions = {
  from: `"Club ML ESATIC" <${process.env.AI_MAIL}>`,
  to: membre.email,
  subject,
  html: generateEmailHTML(membre.nom),
  headers: {
    "X-Priority": "1",
    "X-MSMail-Priority": "High",
    "Importance": "High"
  }
};

                try {
                    await transporter.sendMail(mailOptions);
                    results.push({ success: true, email: membre.email });
                } catch (error) {
                    results.push({ success: false, email: membre.email, error: error.message });
                }

                await new Promise(r => setTimeout(r, 2000)); // pause 2s entre chaque mail
            }

            await new Promise(r => setTimeout(r, 5000)); // pause 5s entre lots
        }

        const successes = results.filter(r => r.success).length;
        const failures = results.length - successes;
        res.json({ 
            message: `Message envoyé à ${successes} membre(s).`, 
            total: membres.length, 
            successes, 
            failures, 
            errors: results.filter(r => !r.success) 
        });

    } catch (error) {
        console.error('Erreur envoi:', error.message);
        res.status(500).json({ message: 'Erreur lors de l’envoi.', error: error.message });
    }
});

// ======================== SERVER START ========================
app.listen(PORT, () => console.log(`Serveur démarré sur le port ${PORT}`));
