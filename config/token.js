import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'votre_secret_jwt_tres_securise';
const JWT_EXPIRES_IN = '7d';

// Génération du token
export const generateToken = (payload) => {
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    console.log(token); // Affiche le token généré
    return token;
};

export const verifyToken = (token) => {
    console.log(token)
    try {
        return jwt.verify(token, process.env.JWT_SECRET || 'votre_secret_jwt_tres_securise');
    } catch (error) {
        console.error('Erreur JWT verify:', error.message);

        return null;
    }

};


// Middleware d’authentification
export const authMiddleware = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Token manquant ou invalide.' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);

        if (!decoded) {
            return res.status(401).json({ message: 'Token invalide ou expiré.' });
        }

        req.admin = decoded;
        next();
    } catch (error) {
        console.error('Erreur authMiddleware:', error.message);
        res.status(500).json({ message: 'Erreur interne d’authentification.' });
    }
};
