
require('dotenv').config();
const express=require('express');
const path=require('path');
const crypto=require('crypto');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const nodemailer=require('nodemailer');
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

const app=express();
app.use(express.json({limit:'2mb'}));

app.disable('x-powered-by');
app.use((req,res,next)=>{
 res.setHeader('X-Content-Type-Options','nosniff');
 res.setHeader('X-Frame-Options','SAMEORIGIN');
 res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
 next();
});

app.use(express.static(path.join(__dirname,'public')));

const fs=require('fs');
if(dbDir && dbDir!=='.') fs.mkdirSync(dbDir,{recursive:true});
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 first_name TEXT NOT NULL,
 last_name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 email_verified INTEGER NOT NULL DEFAULT 0,
 avatar TEXT DEFAULT '',
 cover TEXT DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verification_codes(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 email TEXT NOT NULL,
 purpose TEXT NOT NULL,
 code_hash TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 used INTEGER NOT NULL DEFAULT 0
);
`);

const JWT_SECRET=process.env.JWT_SECRET;
if(!JWT_SECRET) console.warn('WARNING: Set JWT_SECRET in .env before production use.');

const transporter = process.env.SMTP_HOST ? nodemailer.createTransport({
 host:process.env.SMTP_HOST,
 port:Number(process.env.SMTP_PORT||587),
 secure:String(process.env.SMTP_SECURE||'false')==='true',
 auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}
}) : null;

function hashCode(code){return crypto.createHash('sha256').update(code).digest('hex');}
function makeCode(){return String(crypto.randomInt(100000,1000000));}
async function sendCode(email,code,purpose){
 if(!transporter) {
   console.log(`[DEV] ${purpose} code for ${email}: ${code}`);
   return;
 }
 await transporter.sendMail({
   from:process.env.MAIL_FROM||process.env.SMTP_USER,
   to:email,
   subject: purpose==='verify'?'Trendora email verification code':'Trendora password reset code',
   text:`Your Trendora code is ${code}. It expires in 10 minutes.`
 });
}
function auth(req,res,next){
 try{
   const h=req.headers.authorization||'';
   if(!h.startsWith('Bearer '))return res.status(401).json({error:'Authentication required.'});
   req.user=jwt.verify(h.slice(7),JWT_SECRET);
   next();
 }catch(e){return res.status(401).json({error:'Session expired. Please sign in again.'});}
}
async function issueCode(user,purpose){
 const code=makeCode(),expires=Date.now()+10*60*1000;
 db.prepare(`INSERT INTO verification_codes(user_id,email,purpose,code_hash,expires_at) VALUES(?,?,?,?,?)`)
   .run(user.id,user.email,purpose,hashCode(code),expires);
 await sendCode(user.email,code,purpose);
}
function tokenFor(user){return jwt.sign({id:user.id,email:user.email},JWT_SECRET,{expiresIn:'7d'});}

app.post('/api/auth/register',async(req,res)=>{
 try{
  const {firstName,lastName,email,password}=req.body;
  if(!firstName||!lastName||!email||!password)return res.status(400).json({error:'All fields are required.'});
  if(password.length<8)return res.status(400).json({error:'Password must be at least 8 characters.'});
  const normalized=email.trim().toLowerCase();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized))return res.status(400).json({error:'Invalid email.'});
  if(db.prepare('SELECT id FROM users WHERE email=?').get(normalized))return res.status(409).json({error:'An account with this email already exists.'});
  const info=db.prepare(`INSERT INTO users(first_name,last_name,email,password_hash,created_at) VALUES(?,?,?,?,?)`)
    .run(firstName.trim(),lastName.trim(),normalized,await bcrypt.hash(password,12),new Date().toISOString());
  const user=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  await issueCode(user,'verify');
  res.json({ok:true});
 }catch(e){console.error(e);res.status(500).json({error:'Could not create account.'});}
});
app.post('/api/auth/verify-email',async(req,res)=>{
 try{
  const {email,code}=req.body; const user=db.prepare('SELECT * FROM users WHERE email=?').get(email.trim().toLowerCase());
  if(!user)return res.status(400).json({error:'Account not found.'});
  const row=db.prepare(`SELECT * FROM verification_codes WHERE user_id=? AND purpose='verify' AND used=0 ORDER BY id DESC LIMIT 1`).get(user.id);
  if(!row||Date.now()>row.expires_at||row.code_hash!==hashCode(String(code)))return res.status(400).json({error:'Invalid or expired verification code.'});
  db.prepare('UPDATE verification_codes SET used=1 WHERE id=?').run(row.id);
  db.prepare('UPDATE users SET email_verified=1 WHERE id=?').run(user.id);
  res.json({ok:true,token:tokenFor(user)});
 }catch(e){res.status(500).json({error:'Verification failed.'});}
});
app.post('/api/auth/login',async(req,res)=>{
 const {email,password}=req.body; const user=db.prepare('SELECT * FROM users WHERE email=?').get(String(email||'').trim().toLowerCase());
 if(!user||!(await bcrypt.compare(password||'',user.password_hash)))return res.status(401).json({error:'Incorrect email or password.'});
 if(!user.email_verified)return res.json({requiresVerification:true});
 res.json({token:tokenFor(user)});
});
app.post('/api/auth/resend-verification',async(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase(),user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if(!user)return res.status(400).json({error:'Account not found.'});
 if(user.email_verified)return res.status(400).json({error:'Email is already verified.'});
 await issueCode(user,'verify');
 res.json({ok:true});
});
app.post('/api/auth/request-reset',async(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase(),user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if(user) await issueCode(user,'reset');
 res.json({ok:true});
});
app.post('/api/auth/reset-password',async(req,res)=>{
 const {email,code,newPassword}=req.body;
 if(!newPassword||newPassword.length<8)return res.status(400).json({error:'Password must be at least 8 characters.'});
 const user=db.prepare('SELECT * FROM users WHERE email=?').get(String(email||'').trim().toLowerCase());
 if(!user)return res.status(400).json({error:'Invalid reset request.'});
 const row=db.prepare(`SELECT * FROM verification_codes WHERE user_id=? AND purpose='reset' AND used=0 ORDER BY id DESC LIMIT 1`).get(user.id);
 if(!row||Date.now()>row.expires_at||row.code_hash!==hashCode(String(code)))return res.status(400).json({error:'Invalid or expired reset code.'});
 db.prepare('UPDATE verification_codes SET used=1 WHERE id=?').run(row.id);
 db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await bcrypt.hash(newPassword,12),user.id);
 res.json({ok:true});
});
app.post('/api/auth/change-password',auth,async(req,res)=>{
 const {currentPassword,newPassword}=req.body;
 if(!newPassword||newPassword.length<8)return res.status(400).json({error:'New password must be at least 8 characters.'});
 const user=db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
 if(!user||!(await bcrypt.compare(currentPassword||'',user.password_hash)))return res.status(400).json({error:'Current password is incorrect.'});
 await issueCode(user,'reset');
 res.json({ok:true,requiresCode:true,message:'A verification code was sent to your email.'});
});
app.post('/api/auth/confirm-change-password',auth,async(req,res)=>{
 const {code,newPassword}=req.body;
 if(!newPassword||newPassword.length<8)return res.status(400).json({error:'New password must be at least 8 characters.'});
 const user=db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
 const row=db.prepare(`SELECT * FROM verification_codes WHERE user_id=? AND purpose='reset' AND used=0 ORDER BY id DESC LIMIT 1`).get(user.id);
 if(!row||Date.now()>row.expires_at||row.code_hash!==hashCode(String(code)))return res.status(400).json({error:'Invalid or expired verification code.'});
 db.prepare('UPDATE verification_codes SET used=1 WHERE id=?').run(row.id);
 db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await bcrypt.hash(newPassword,12),user.id);
 res.json({ok:true});
});
app.get('/api/me',auth,(req,res)=>{
 const u=db.prepare('SELECT id,first_name AS firstName,last_name AS lastName,email,email_verified AS emailVerified,avatar,cover FROM users WHERE id=?').get(req.user.id);
 res.json({user:u});
});
app.post('/api/auth/logout',(req,res)=>res.json({ok:true}));

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`Trendora V6 running on http://localhost:${port}`));
