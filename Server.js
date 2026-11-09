const express=require('express'),crypto=require('crypto'),path=require('path'),{Pool}=require('pg');
const DB=process.env.DATABASE_URL,PORT=process.env.PORT||3000,SECRET=process.env.SECRET||crypto.randomBytes(32).toString('hex');
const ADMIN_NAME=(process.env.ADMIN_NAME||'Kalyan_Kharde_Patil').toLowerCase(),ADMIN_PW=process.env.ADMIN_PASSWORD;
if(!DB){console.error('Set DATABASE_URL to your PostgreSQL connection string.');process.exit(1)}
if(!ADMIN_PW)console.warn('ADMIN_PASSWORD is not set: admin login is disabled.');
if(!process.env.SECRET)console.warn('SECRET is not set: logins reset whenever the server restarts.');
const pool=new Pool({connectionString:DB,ssl:/localhost|127\.0\.0\.1/.test(DB)?false:{rejectUnauthorized:false}});
const app=express();app.disable('x-powered-by');app.set('trust proxy',1);
app.use((q,r,n)=>{r.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin'});n()});
app.use(express.json({limit:'10kb'}));app.use(express.static(path.join(__dirname,'public')));

const bad=(r,err,c=400)=>r.status(c).json({err}),h=f=>(q,r,n)=>f(q,r,n).catch(x=>{console.error(x);bad(r,'Server error. Please try again.',500)});
const mac=s=>crypto.createHmac('sha256',SECRET).update(s).digest('base64url');
const sign=o=>{const p=Buffer.from(JSON.stringify({...o,exp:Date.now()+7*864e5})).toString('base64url');return p+'.'+mac(p)};
const verify=t=>{try{const[p,m]=String(t).split('.');if(!crypto.timingSafeEqual(Buffer.from(mac(p)),Buffer.from(m)))return null;const o=JSON.parse(Buffer.from(p,'base64url'));return o.exp>Date.now()?o:null}catch(x){return null}};
app.use((q,r,n)=>{q.s=verify(((q.headers.cookie||'').split(/;\s*/).find(c=>c.startsWith('sid='))||'').slice(4));n()});
const setSid=(q,r,o)=>r.cookie('sid',sign(o),{httpOnly:true,sameSite:'lax',secure:q.secure,maxAge:7*864e5});
const hash=p=>{const s=crypto.randomBytes(16).toString('hex');return s+':'+crypto.scryptSync(p,s,64).toString('hex')};
const same=(p,x)=>{const[s,k]=x.split(':'),a=crypto.scryptSync(p,s,64),b=Buffer.from(k,'hex');return a.length==b.length&&crypto.timingSafeEqual(a,b)};
const eq=(a,b)=>{const f=x=>crypto.createHash('sha256').update(x).digest();return crypto.timingSafeEqual(f(a),f(b))};
const hits=new Map(),limit=(q,r,n)=>{const k=q.ip+q.path,t=Date.now(),a=(hits.get(k)||[]).filter(x=>t-x<9e5);if(a.length>=10)return bad(r,'Too many attempts. Please wait 15 minutes and try again.',429);a.push(t);hits.set(k,a);n()};
const needP=(q,r,n)=>q.s&&q.s.role=='p'?n():bad(r,'Please log in again.',401);
const needA=(q,r,n)=>q.s&&q.s.role=='a'?n():bad(r,'Admin login required.',401);
const PWMSG='Password must be 8+ characters with letters and a symbol such as @ # $ !';
const goodPw=p=>typeof p=='string'&&p.length>=8&&p.length<=100&&/[A-Za-z]/.test(p)&&/[^A-Za-z0-9\s]/.test(p);
const ist=()=>{const p=Object.fromEntries(new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Kolkata',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date()).map(x=>[x.type,x.value]));return{d:`${p.year}-${p.month}-${p.day}`,t:`${p.hour}:${p.minute}`}};
const SLOTS=[];for(let i=0;i<12;i++)for(const m of['00','30'])SLOTS.push(String(i).padStart(2,'0')+':'+m);SLOTS.push('12:00');
const out=r=>({id:r.id,uid:r.uid,n:r.name,a:r.age,m:r.mobile,e:r.email,d:r.appt_date,t:r.appt_time,s:r.status,by:r.canceled_by});
const body=q=>q.body||{};

app.post('/api/register',limit,h(async(q,r)=>{const b=body(q),n=String(b.n||'').trim(),m=String(b.m||'').trim(),e=String(b.e||'').trim().toLowerCase();
 if(n.length<2||n.length>80)return bad(r,'Please enter your full name.');
 if(!/^[6-9]\d{9}$/.test(m))return bad(r,'Enter a valid 10-digit mobile number.');
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)||e.length>120)return bad(r,'Enter a valid email id.');
 if(!goodPw(b.p))return bad(r,PWMSG);
 try{await pool.query('insert into users(name,mobile,email,pw) values($1,$2,$3,$4)',[n,m,e,hash(b.p)]);r.status(201).json({ok:1})}
 catch(x){x.code=='23505'?bad(r,'This mobile no or email is already registered.',409):(()=>{throw x})()}}));
app.post('/api/login',limit,h(async(q,r)=>{const b=body(q),i=String(b.i||'').trim().toLowerCase();
 const u=(await pool.query('select * from users where mobile=$1 or email=$1 limit 1',[i])).rows[0];
 if(!u||!same(String(b.p||''),u.pw))return bad(r,'Wrong mobile no / email id or password.',401);
 setSid(q,r,{role:'p',id:u.id});r.json({ok:1})}));
app.post('/api/admin-login',limit,h(async(q,r)=>{const b=body(q);
 if(!ADMIN_PW||String(b.i||'').trim().toLowerCase()!=ADMIN_NAME||!eq(String(b.p||''),ADMIN_PW))return bad(r,'Invalid admin credentials.',401);
 setSid(q,r,{role:'a'});r.json({ok:1})}));
app.post('/api/forgot',limit,h(async(q,r)=>{const b=body(q);
 if(!goodPw(b.p))return bad(r,PWMSG);if(b.p!==b.q)return bad(r,'The two passwords do not match.');
 const x=await pool.query('update users set pw=$1 where mobile=$2 and email=$3',[hash(b.p),String(b.m||'').trim(),String(b.e||'').trim().toLowerCase()]);
 x.rowCount?r.json({ok:1}):bad(r,'No account matches this mobile no and email id.',404)}));
app.post('/api/logout',(q,r)=>{r.clearCookie('sid');r.json({ok:1})});
app.get('/api/me',h(async(q,r)=>{const s=q.s;if(!s)return bad(r,'Not logged in.',401);
 if(s.role=='a')return r.json({role:'admin',appts:(await pool.query('select * from appts order by id desc')).rows.map(out)});
 const u=(await pool.query('select id,name,mobile,email from users where id=$1',[s.id])).rows[0];if(!u)return bad(r,'Please log in again.',401);
 r.json({role:'patient',user:{id:u.id,n:u.name,m:u.mobile,e:u.email},appts:(await pool.query('select * from appts where uid=$1 order by id desc',[u.id])).rows.map(out)})}));
app.post('/api/appointments',needP,h(async(q,r)=>{const b=body(q),n=String(b.n||'').trim(),d=String(b.d||''),t=String(b.t||''),now=ist(),age=String(b.a??'').trim()===''?NaN:Number(b.a);
 if(n.length<2||n.length>80)return bad(r,'Enter the patient name.');
 if(!Number.isInteger(age)||age<0||age>120)return bad(r,'Enter a valid age (0–120).');
 if(!/^\d{4}-\d{2}-\d{2}$/.test(d)||isNaN(new Date(d+'T00:00:00Z'))||d<now.d)return bad(r,'Choose today or a future date.');
 if(!SLOTS.includes(t))return bad(r,'Choose a time.');
 if(d==now.d&&t<=now.t)return bad(r,'That time has already passed today – choose a later time.');
 const u=(await pool.query('select mobile,email from users where id=$1',[q.s.id])).rows[0];if(!u)return bad(r,'Please log in again.',401);
 await pool.query('insert into appts(uid,name,age,mobile,email,appt_date,appt_time) values($1,$2,$3,$4,$5,$6,$7)',[q.s.id,n,age,u.mobile,u.email,d,t]);r.status(201).json({ok:1})}));
app.post('/api/appointments/:id/status',needA,h(async(q,r)=>{const s=body(q).s;if(!['Approved','Rejected'].includes(s))return bad(r,'Invalid status.');
 const x=await pool.query("update appts set status=$1 where id=$2 and status='Pending'",[s,+q.params.id]);
 x.rowCount?r.json({ok:1}):bad(r,'Only pending requests can be approved or rejected.',409)}));
app.post('/api/appointments/:id/cancel',h(async(q,r)=>{const s=q.s;if(!s)return bad(r,'Please log in again.',401);const today=ist().d,id=+q.params.id;
 const x=s.role=='a'?await pool.query("update appts set status='Cancelled',canceled_by='admin' where id=$1 and status='Approved' and appt_date>=$2",[id,today])
  :await pool.query("update appts set status='Cancelled',canceled_by='patient' where id=$1 and uid=$2 and status in ('Pending','Approved') and appt_date>=$3",[id,s.id,today]);
 x.rowCount?r.json({ok:1}):bad(r,'This appointment can no longer be cancelled.',409)}));

pool.query(`create table if not exists users(id serial primary key,name text not null,mobile text unique not null,email text unique not null,pw text not null);
create table if not exists appts(id serial primary key,uid int not null references users(id),name text not null,age int not null,mobile text,email text,appt_date text not null,appt_time text not null,status text not null default 'Pending',canceled_by text,created timestamptz default now())`)
 .then(()=>app.listen(PORT,()=>console.log('Running on port '+PORT))).catch(x=>{console.error(x);process.exit(1)});
         
