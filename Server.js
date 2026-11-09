const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const DB = process.env.DATABASE_URL;
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_NAME = (process.env.ADMIN_NAME || 'Kalyan_Kharde_Patil').toLowerCase();
const ADMIN_PW = process.env.ADMIN_PASSWORD;
const MSG91_AUTHKEY = process.env.MSG91_AUTHKEY;
const MSG91_TEMPLATE_ID = process.env.MSG91_TEMPLATE_ID;

if (!DB) {
  console.error('Set DATABASE_URL to your PostgreSQL connection string.');
  process.exit(1);
}
if (!ADMIN_PW) console.warn('ADMIN_PASSWORD is not set: admin login is disabled.');
if (!process.env.SECRET) console.warn('SECRET is not set: sessions reset whenever the server restarts.');
if (!MSG91_AUTHKEY || !MSG91_TEMPLATE_ID) {
  console.warn('MSG91_AUTHKEY / MSG91_TEMPLATE_ID missing: mobile OTP password reset is disabled.');
}

const pool = new Pool({
  connectionString: DB,
  ssl: /localhost|127\.0\.0\.1/.test(DB) ? false : { rejectUnauthorized: false }
});

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin'
  });
  next();
});
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const bad = (res, err, code = 400) => res.status(code).json({ err });
const wrap = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(err => {
    console.error(err);
    bad(res, 'Server error. Please try again.', 500);
  });

const mac = value => crypto.createHmac('sha256', SECRET).update(value).digest('base64url');
const sign = data => {
  const payload = Buffer.from(JSON.stringify({ ...data, exp: Date.now() + 7 * 864e5 })).toString('base64url');
  return payload + '.' + mac(payload);
};
const verify = token => {
  try {
    const [payload, signature] = String(token).split('.');
    const expected = Buffer.from(mac(payload));
    const received = Buffer.from(signature);
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url'));
    return data.exp > Date.now() ? data : null;
  } catch (_) {
    return null;
  }
};

app.use((req, res, next) => {
  const cookie = (req.headers.cookie || '').split(/;\s*/).find(x => x.startsWith('sid='));
  req.session = verify(cookie ? cookie.slice(4) : '');
  next();
});

const setSid = (req, res, data) => res.cookie('sid', sign(data), {
  httpOnly: true,
  sameSite: 'lax',
  secure: req.secure,
  maxAge: 7 * 864e5
});
const hash = password => {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(password, salt, 64).toString('hex');
};
const same = (password, stored) => {
  try {
    const [salt, key] = stored.split(':');
    const a = crypto.scryptSync(password, salt, 64);
    const b = Buffer.from(key, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (_) {
    return false;
  }
};
const equal = (a, b) => {
  const digest = value => crypto.createHash('sha256').update(value).digest();
  return crypto.timingSafeEqual(digest(a), digest(b));
};

const hits = new Map();
const limit = (req, res, next) => {
  const key = req.ip + req.path;
  const now = Date.now();
  const recent = (hits.get(key) || []).filter(time => now - time < 15 * 60 * 1000);
  if (recent.length >= 10) return bad(res, 'Too many attempts. Please wait 15 minutes and try again.', 429);
  recent.push(now);
  hits.set(key, recent);
  next();
};

const needPatient = (req, res, next) =>
  req.session && req.session.role === 'p' ? next() : bad(res, 'Please log in again.', 401);
const passwordMessage = 'Password must be 8+ characters with letters and a symbol such as @ # $ !';
const goodPassword = value =>
  typeof value === 'string' && value.length >= 8 && value.length <= 100 &&
  /[A-Za-z]/.test(value) && /[^A-Za-z0-9\s]/.test(value);
const body = req => req.body || {};
const indiaTime = () => {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Asia/Kolkata', year: 'numeric', month: '2-digit',
      day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
    }).formatToParts(new Date()).map(item => [item.type, item.value])
  );
  return { d: `${parts.year}-${parts.month}-${parts.day}`, t: `${parts.hour}:${parts.minute}` };
};
const slots = [];
for (let hour = 0; hour < 12; hour++) {
  for (const minute of ['00', '30']) slots.push(String(hour).padStart(2, '0') + ':' + minute);
}
slots.push('12:00');

const outputAppointment = row => ({
  id: row.id, uid: row.uid, n: row.name, a: row.age, m: row.mobile,
  e: row.email, d: row.appt_date, t: row.appt_time, s: row.status, by: row.canceled_by
});

/* Short-lived, one-time password-reset tokens held only on the server. */
const resetTokens = new Map();
const sendAttempts = new Map();
const cleanupTokens = () => {
  const now = Date.now();
  for (const [token, item] of resetTokens) if (item.expires < now) resetTokens.delete(token);
};
setInterval(cleanupTokens, 60 * 1000).unref();

app.post('/api/register', limit, wrap(async (req, res) => {
  const b = body(req);
  const name = String(b.n || '').trim();
  const mobile = String(b.m || '').trim();
  const email = String(b.e || '').trim().toLowerCase();
  if (name.length < 2 || name.length > 80) return bad(res, 'Please enter your full name.');
  if (!/^[6-9]\d{9}$/.test(mobile)) return bad(res, 'Enter a valid 10-digit mobile number.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) return bad(res, 'Enter a valid email id.');
  if (!goodPassword(b.p)) return bad(res, passwordMessage);
  try {
    await pool.query('insert into users(name,mobile,email,pw) values($1,$2,$3,$4)', [name, mobile, email, hash(b.p)]);
    res.status(201).json({ ok: 1 });
  } catch (err) {
    if (err.code === '23505') return bad(res, 'This mobile no or email is already registered.', 409);
    throw err;
  }
}));

app.post('/api/login', limit, wrap(async (req, res) => {
  const b = body(req);
  const identity = String(b.i || '').trim().toLowerCase();
  const user = (await pool.query('select * from users where mobile=$1 or email=$1 limit 1', [identity])).rows[0];
  if (!user || !same(String(b.p || ''), user.pw)) return bad(res, 'Wrong mobile no / email id or password.', 401);
  setSid(req, res, { role: 'p', id: user.id });
  res.json({ ok: 1 });
}));

app.post('/api/admin-login', limit, wrap(async (req, res) => {
  const b = body(req);
  if (!ADMIN_PW || String(b.i || '').trim().toLowerCase() !== ADMIN_NAME ||
      !equal(String(b.p || ''), ADMIN_PW)) {
    return bad(res, 'Invalid admin credentials.', 401);
  }
  setSid(req, res, { role: 'a' });
  res.json({ ok: 1 });
}));

/* Step 1: check account and ask MSG91 to send its managed OTP. */
app.post('/api/forgot/send-otp', limit, wrap(async (req, res) => {
  const mobile = String(body(req).m || '').trim();
  if (!/^[6-9]\d{9}$/.test(mobile)) return bad(res, 'Enter a valid 10-digit mobile number.');
  if (!MSG91_AUTHKEY || !MSG91_TEMPLATE_ID) {
    return bad(res, 'OTP service is not configured. Add MSG91_AUTHKEY and MSG91_TEMPLATE_ID in Render environment variables.', 503);
  }
  const now = Date.now();
  const last = sendAttempts.get(mobile) || 0;
  if (now - last < 60 * 1000) return bad(res, 'Please wait 60 seconds before requesting another OTP.', 429);

  const user = (await pool.query('select id from users where mobile=$1', [mobile])).rows[0];
  if (!user) return bad(res, 'No account is registered with this mobile number.', 404);

  const params = new URLSearchParams({
    template_id: MSG91_TEMPLATE_ID,
    mobile: '91' + mobile,
    otp_length: '6',
    otp_expiry: '5',
    realTimeResponse: '1'
  });
  const response = await fetch('https://control.msg91.com/api/v5/otp?' + params.toString(), {
    method: 'POST',
    headers: { authkey: MSG91_AUTHKEY, 'content-type': 'application/json' },
    body: JSON.stringify({})
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || String(result.type || '').toLowerCase() !== 'success') {
    console.error('MSG91 send OTP failed:', result);
    return bad(res, 'Could not send OTP. Check MSG91 Auth Key, OTP Template ID and SMS template setup.', 502);
  }
  sendAttempts.set(mobile, now);
  res.json({ ok: 1, message: 'OTP sent.' });
}));

/* Step 2: MSG91 verifies the OTP. A random one-time reset token is then issued. */
app.post('/api/forgot/verify-otp', limit, wrap(async (req, res) => {
  const mobile = String(body(req).m || '').trim();
  const otp = String(body(req).otp || '').trim();
  if (!/^[6-9]\d{9}$/.test(mobile) || !/^\d{6}$/.test(otp)) {
    return bad(res, 'Enter the registered mobile number and 6-digit OTP.');
  }
  if (!MSG91_AUTHKEY) return bad(res, 'MSG91 is not configured.', 503);
  const user = (await pool.query('select id from users where mobile=$1', [mobile])).rows[0];
  if (!user) return bad(res, 'No account is registered with this mobile number.', 404);

  const params = new URLSearchParams({ mobile: '91' + mobile, otp });
  const response = await fetch('https://control.msg91.com/api/v5/otp/verify?' + params.toString(), {
    method: 'GET',
    headers: { authkey: MSG91_AUTHKEY, accept: 'application/json' }
  });
  const result = await response.json().catch(() => ({}));
  const verificationText = String(result.type || result.message || result.status || '').toLowerCase();
  if (!response.ok || !(verificationText.includes('success') || verificationText.includes('verified'))) {
    console.warn('MSG91 verify OTP response:', result);
    return bad(res, 'Invalid or expired OTP. Please try again.', 400);
  }

  const resetToken = crypto.randomBytes(32).toString('hex');
  resetTokens.set(resetToken, { userId: user.id, mobile, expires: Date.now() + 10 * 60 * 1000 });
  res.json({ ok: 1, resetToken });
}));

/* Step 3: only a verified, unexpired, one-time token can change the password. */
app.post('/api/forgot/reset-password', limit, wrap(async (req, res) => {
  const b = body(req);
  if (!goodPassword(b.p)) return bad(res, passwordMessage);
  if (b.p !== b.q) return bad(res, 'The two passwords do not match.');
  const token = String(b.resetToken || '');
  const record = resetTokens.get(token);
  if (!record || record.expires < Date.now()) {
    resetTokens.delete(token);
    return bad(res, 'Password reset session expired. Please request a new OTP.', 401);
  }
  await pool.query('update users set pw=$1 where id=$2 and mobile=$3', [
    hash(b.p), record.userId, record.mobile
  ]);
  resetTokens.delete(token);
  res.json({ ok: 1 });
}));

app.post('/api/logout', (req, res) => {
  res.clearCookie('sid');
  res.json({ ok: 1 });
});

app.get('/api/me', wrap(async (req, res) => {
  const session = req.session;
  if (!session) return bad(res, 'Not logged in.', 401);
  if (session.role === 'a') {
    const appointments = (await pool.query('select * from appts order by id desc')).rows;
    return res.json({ role: 'admin', appts: appointments.map(outputAppointment) });
  }
  if (session.role !== 'p') return bad(res, 'Not logged in.', 401);
  const user = (await pool.query('select id,name,mobile,email from users where id=$1', [session.id])).rows[0];
  if (!user) return bad(res, 'Please log in again.', 401);
  const appointments = (await pool.query('select * from appts where uid=$1 order by id desc', [user.id])).rows;
  res.json({
    role: 'patient',
    user: { id: user.id, n: user.name, m: user.mobile, e: user.email },
    appts: appointments.map(outputAppointment)
  });
}));

app.post('/api/appointments', needPatient, wrap(async (req, res) => {
  const b = body(req);
  const name = String(b.n || '').trim();
  const date = String(b.d || '');
  const time = String(b.t || '');
  const now = indiaTime();
  const age = String(b.a ?? '').trim() === '' ? NaN : Number(b.a);
  if (name.length < 2 || name.length > 80) return bad(res, 'Enter the patient name.');
  if (!Number.isInteger(age) || age < 0 || age > 120) return bad(res, 'Enter a valid age (0–120).');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || isNaN(new Date(date + 'T00:00:00Z')) || date < now.d) {
    return bad(res, 'Choose today or a future date.');
  }
  if (!slots.includes(time)) return bad(res, 'Choose a time.');
  if (date === now.d && time <= now.t) return bad(res, 'That time has already passed today – choose a later time.');
  const user = (await pool.query('select mobile,email from users where id=$1', [req.session.id])).rows[0];
  if (!user) return bad(res, 'Please log in again.', 401);
  await pool.query(
    'insert into appts(uid,name,age,mobile,email,appt_date,appt_time) values($1,$2,$3,$4,$5,$6,$7)',
    [req.session.id, name, age, user.mobile, user.email, date, time]
  );
  res.status(201).json({ ok: 1 });
}));

app.post('/api/appointments/:id/status', (req, res, next) => {
  if (!req.session || req.session.role !== 'a') return bad(res, 'Admin login required.', 401);
  next();
}, wrap(async (req, res) => {
  const status = body(req).s;
  if (!['Approved', 'Rejected'].includes(status)) return bad(res, 'Invalid status.');
  const result = await pool.query(
    "update appts set status=$1 where id=$2 and status='Pending'",
    [status, Number(req.params.id)]
  );
  result.rowCount ? res.json({ ok: 1 }) : bad(res, 'Only pending requests can be approved or rejected.', 409);
}));

app.post('/api/appointments/:id/cancel', wrap(async (req, res) => {
  const session = req.session;
  if (!session) return bad(res, 'Please log in again.', 401);
  const today = indiaTime().d;
  const id = Number(req.params.id);
  const result = session.role === 'a'
    ? await pool.query(
        "update appts set status='Cancelled',canceled_by='admin' where id=$1 and status='Approved' and appt_date>=$2",
        [id, today]
      )
    : await pool.query(
        "update appts set status='Cancelled',canceled_by='patient' where id=$1 and uid=$2 and status in ('Pending','Approved') and appt_date>=$3",
        [id, session.id, today]
      );
  result.rowCount ? res.json({ ok: 1 }) : bad(res, 'This appointment can no longer be cancelled.', 409);
}));

async function start() {
  await pool.query(`
    create table if not exists users(
      id serial primary key,
      name text not null,
      mobile text unique not null,
      email text unique not null,
      pw text not null
    );
    create table if not exists appts(
      id serial primary key,
      uid int not null references users(id),
      name text not null,
      age int not null,
      mobile text,
      email text,
      appt_date text not null,
      appt_time text not null,
      status text not null default 'Pending',
      canceled_by text,
      created timestamptz default now()
    )
  `);
  app.listen(PORT, () => console.log('Running on port ' + PORT));
}
start().catch(err => {
  console.error(err);
  process.exit(1);
});
