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
import nodemailer from 'nodemailer';

// ==== TRANSPORTEUR NODEMAILER ====
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { 
    user: process.env.AI_MAIL, 
    pass: process.env.APP_PASSWORD 
  },
});

// Vérifier la configuration du transporteur
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Erreur de configuration email:', error);
  } else {
    console.log('✅ Serveur email prêt à envoyer des messages');
  }
});

// ==== ENDPOINT POUR ENVOYER UN MESSAGE À TOUS LES MEMBRES ====
app.post('/admin/send-message', authMiddleware, async (req, res) => {
    const { subject, content, theme, link, linkText } = req.body;


    if (!subject || !content) {
        return res.status(400).json({ 
            message: 'L\'objet et le contenu du message sont requis.' 
        });
    }

    try {
        // Récupérer tous les emails des membres
        const membres = await sql`
            SELECT nom, email FROM inscrit
        `;

        if (membres.length === 0) {
            return res.status(404).json({ 
                message: 'Aucun membre inscrit trouvé.' 
            });
        }

        // Générer le HTML de l'email
        const generateEmailHTML = (nom, subject, content, theme, link, linkText) => {
            const paragraphs = content.split('\n')
                .filter(p => p.trim())
                .map(p => `<p style="margin-bottom: 1rem; line-height: 1.6; color: #333;">${p}</p>`)
                .join('');
            
            const linkButton = link && linkText ? `
                <div style="text-align: center; margin: 2rem 0;">
                    <a href="${link}" style="display: inline-block; padding: 14px 35px; background: ${theme}; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; box-shadow: 0 4px 10px rgba(0,0,0,0.15);">
                        ${linkText}
                    </a>
                </div>
            ` : '';
            
            const darkerTheme = adjustColor(theme, -20);
            
            return `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                </head>
                <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Arial, sans-serif; background-color: #f5f5f5;">
                    <div style="max-width: 600px; margin: 0 auto; background: #ffffff;">
                        <!-- Header -->
                        <div style="background: linear-gradient(135deg, ${theme} 0%, ${darkerTheme} 100%); padding: 40px 20px; text-align: center;">
                            <h1 style="color: white; margin: 0; font-size: 2rem; text-shadow: 0 2px 4px rgba(0,0,0,0.2);">
                                🧠 Club ML ESATIC
                            </h1>
                        </div>
                        
                        <!-- Content -->
                        <div style="padding: 30px 20px; background: #f9f9f9;">
                            <div style="background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                                <p style="color: #666; margin-top: 0; font-size: 1rem;">Bonjour <strong style="color: ${theme};">${nom}</strong>,</p>
                                
                                <h2 style="color: ${theme}; margin-top: 1.5rem; margin-bottom: 1.5rem; font-size: 1.5rem;">
                                    ${subject}
                                </h2>
                                
                                ${paragraphs}
                                ${linkButton}
                                
                                <div style="margin-top: 2rem; padding-top: 1.5rem; border-top: 2px solid #f0f0f0;">
                                    <p style="color: #666; font-size: 0.9rem; margin: 0;">
                                        Cordialement,<br>
                                        <strong style="color: ${theme};">L'équipe du Club ML ESATIC</strong>
                                    </p>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Footer -->
                        <div style="padding: 20px; text-align: center; background: #2c3e50; color: white;">
                            <p style="margin: 0; font-size: 0.9rem;">© 2025 Club ML ESATIC - Machine Learning Club</p>
                            <p style="margin: 5px 0 0 0; font-size: 0.85rem; opacity: 0.8;">École Supérieure Africaine des TIC</p>
                            <div style="margin-top: 15px;">
                                <a href="#" style="color: white; text-decoration: none; margin: 0 10px; font-size: 0.85rem;">📧 Contact</a>
                                <a href="#" style="color: white; text-decoration: none; margin: 0 10px; font-size: 0.85rem;">🌐 Site Web</a>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
            `;
        };

        // Fonction pour ajuster la couleur
        const adjustColor = (color, amount) => {
            const num = parseInt(color.replace('#', ''), 16);
            const r = Math.max(0, Math.min(255, (num >> 16) + amount));
            const g = Math.max(0, Math.min(255, ((num >> 8) & 0x00FF) + amount));
            const b = Math.max(0, Math.min(255, (num & 0x0000FF) + amount));
            return '#' + ((r << 16) | (g << 8) | b).toString(16).padStart(6, '0');
        };

        // Envoyer l'email à chaque membre
        const emailPromises = membres.map(async (membre) => {
            const mailOptions = {
                from: `"Club ML ESATIC" <${process.env.AI_MAIL}>`,
                to: membre.email,
                subject: subject,
                html: generateEmailHTML(
                    membre.nom, 
                    subject, 
                    content, 
                    theme || '#1c6487', 
                    link, 
                    linkText
                )
            };

            try {
                await transporter.sendMail(mailOptions);
                return { success: true, email: membre.email };
            } catch (error) {
                console.error(`Erreur envoi à ${membre.email}:`, error.message);
                return { success: false, email: membre.email, error: error.message };
            }
        });

        // Attendre tous les envois
        const results = await Promise.all(emailPromises);
        
        // Compter les succès et échecs
        const successes = results.filter(r => r.success).length;
        const failures = results.filter(r => !r.success).length;

        res.json({
            message: `Message envoyé avec succès à ${successes} membre(s).`,
            total: membres.length,
            successes,
            failures,
            details: failures > 0 ? results.filter(r => !r.success) : undefined
        });

    } catch (error) {
        console.error('Erreur lors de l\'envoi du message:', error.message);
        res.status(500).json({ 
            message: 'Erreur lors de l\'envoi du message.',
            error: error.message 
        });
    }
});


app.listen(PORT, () => {
    console.log(`Serveur démarré sur le port ${PORT}`);
});