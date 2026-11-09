const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const DB = process.env.DATABASE_URL;
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');

const ADMIN_NAME = (process.env.ADMIN_NAME || 'Kalyan_Kharde_Patil').toLowerCase();
const ADMIN_PW = process.env.ADMIN_PASSWORD;

if (!DB) {
    console.error('Set DATABASE_URL to your PostgreSQL connection string.');
    process.exit(1);
}

const pool = new Pool({
    connectionString: DB,
    ssl: { rejectUnauthorized: false }
});

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(express.json({ limit: '10kb' }));

// IMPORTANT: Folder name is Public with capital P
app.use(express.static(path.join(__dirname, 'Public')));

// Serve homepage
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'index.html'));
});

const bad = (res, err, code = 400) =>
    res.status(code).json({ err });

const hash = password => {
    const salt = crypto.randomBytes(16).toString('hex');
    return salt + ':' + crypto.scryptSync(password, salt, 64).toString('hex');
};

const same = (password, stored) => {
    try {
        const [salt, key] = stored.split(':');
        const a = crypto.scryptSync(password, salt, 64);
        const b = Buffer.from(key, 'hex');

        return a.length === b.length &&
            crypto.timingSafeEqual(a, b);
    } catch {
        return false;
    }
};

const eq = (a, b) => {
    const x = crypto.createHash('sha256').update(a).digest();
    const y = crypto.createHash('sha256').update(b).digest();
    return crypto.timingSafeEqual(x, y);
};

const mac = value =>
    crypto.createHmac('sha256', SECRET).update(value).digest('base64url');

const sign = data => {
    const payload = Buffer.from(JSON.stringify({
        ...data,
        exp: Date.now() + 7 * 864e5
    })).toString('base64url');

    return payload + '.' + mac(payload);
};

const verify = token => {
    try {
        const [payload, signature] = String(token).split('.');
        if (!payload || !signature) return null;

        const a = Buffer.from(mac(payload));
        const b = Buffer.from(signature);

        if (a.length !== b.length ||
            !crypto.timingSafeEqual(a, b)) return null;

        const data = JSON.parse(
            Buffer.from(payload, 'base64url').toString()
        );

        return data.exp > Date.now() ? data : null;
    } catch {
        return null;
    }
};

app.use((req, res, next) => {
    const cookie = (req.headers.cookie || '')
        .split(/;\s*/)
        .find(x => x.startsWith('sid='));

    req.s = cookie ? verify(cookie.slice(4)) : null;
    next();
});

const setSid = (req, res, data) => {
    res.cookie('sid', sign(data), {
        httpOnly: true,
        sameSite: 'lax',
        secure: req.secure,
        maxAge: 7 * 864e5
    });
};

const hits = new Map();

const limit = (req, res, next) => {
    const key = req.ip +
