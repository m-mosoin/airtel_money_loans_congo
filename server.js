const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

app.use(express.json({limit:"50kb"}));
app.use(express.urlencoded({extended:false}));
app.use(express.static(path.join(__dirname,"public")));

const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const APP_SECRET = process.env.APP_SECRET || "";
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "";

function requireSecrets(){
  if(!ADMIN_PASSWORD || !APP_SECRET || !/^[0-9a-fA-F]{64}$/.test(ENCRYPTION_KEY))
    throw new Error("Missing ADMIN_PASSWORD, APP_SECRET, or valid 64-hex ENCRYPTION_KEY");
}
function encrypt(value){
  requireSecrets();
  const key=Buffer.from(ENCRYPTION_KEY,"hex"), iv=crypto.randomBytes(12);
  const c=crypto.createCipheriv("aes-256-gcm",key,iv);
  const data=Buffer.concat([c.update(String(value),"utf8"),c.final()]);
  return [iv,c.getAuthTag(),data].map(x=>x.toString("base64url")).join(".");
}
function sign(v){return crypto.createHmac("sha256",APP_SECRET).update(v).digest("base64url")}
function session(){
  const v=`${ADMIN_USER}|${Date.now()}`;
  return `${Buffer.from(v).toString("base64url")}.${sign(v)}`;
}
function isAdmin(req){
  try{
    const c=(req.headers.cookie||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("admin_session="));
    if(!c)return false;
    const [p,s]=c.slice(14).split(".");
    const v=Buffer.from(p,"base64url").toString();
    return v.startsWith(ADMIN_USER+"|") && crypto.timingSafeEqual(Buffer.from(s),Buffer.from(sign(v)));
  }catch{return false}
}
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]))}

async function init(){
  await pool.query(`CREATE TABLE IF NOT EXISTS applications(
    id BIGSERIAL PRIMARY KEY,
    full_name TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    loan_amount NUMERIC(14,2) NOT NULL,
    email TEXT NOT NULL,
    national_id_encrypted TEXT NOT NULL,
    professional_status TEXT NOT NULL,
    loan_purpose TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE applications ADD COLUMN IF NOT EXISTS phone_number TEXT`);
  await pool.query(`ALTER TABLE applications ALTER COLUMN phone_number SET DEFAULT ''`);
  await pool.query(`UPDATE applications SET phone_number='' WHERE phone_number IS NULL`);
  await pool.query(`ALTER TABLE applications ALTER COLUMN phone_number SET NOT NULL`);
}

app.get("/",(req,res)=>res.redirect("/bot/bot7"));
app.get("/bot/bot7",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.post("/api/applications",async(req,res)=>{
  try{
    const {fullName,countryCode,phoneNumber,loanAmount,email,nationalId,professionalStatus,loanPurpose,consent}=req.body;
    if(!consent)return res.status(400).json({error:"Consent is required."});
    if(!fullName||!countryCode||!phoneNumber||!email||!nationalId||!professionalStatus||!loanPurpose)
      return res.status(400).json({error:"Please complete all required fields."});
    const amount=Number(loanAmount);
    if(!Number.isFinite(amount)||amount<50)return res.status(400).json({error:"Loan amount must be at least 50 USD."});
    const phone=`${countryCode} ${phoneNumber.trim()}`;
    const result=await pool.query(
      `INSERT INTO applications(full_name,phone_number,loan_amount,email,national_id_encrypted,professional_status,loan_purpose)
       VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [fullName.trim(),phone,amount,email.trim(),encrypt(nationalId.trim()),professionalStatus,loanPurpose]
    );
    res.json({ok:true,applicationId:result.rows[0].id});
  }catch(e){console.error(e);res.status(500).json({error:"Unable to submit application."})}
});

app.get("/admin/login",(req,res)=>res.sendFile(path.join(__dirname,"public","admin-login.html")));
app.post("/admin/login",(req,res)=>{
  if(req.body.username===ADMIN_USER&&req.body.password===ADMIN_PASSWORD){
    res.setHeader("Set-Cookie",`admin_session=${session()}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`);
    return res.redirect("/admin");
  }
  res.status(401).send("Invalid credentials. <a href='/admin/login'>Try again</a>");
});
app.post("/admin/logout",(req,res)=>{
  res.setHeader("Set-Cookie","admin_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
  res.redirect("/admin/login");
});
app.get("/admin",async(req,res)=>{
  if(!isAdmin(req))return res.redirect("/admin/login");
  const {rows}=await pool.query(`SELECT id,full_name,phone_number,loan_amount,email,professional_status,loan_purpose,created_at FROM applications ORDER BY created_at DESC LIMIT 200`);
  const body=rows.map(r=>`<tr><td>${esc(r.id)}</td><td>${esc(r.full_name)}</td><td>${esc(r.phone_number)}</td><td>$${esc(r.loan_amount)}</td><td>${esc(r.email)}</td><td>${esc(r.professional_status)}</td><td>${esc(r.loan_purpose)}</td><td>${esc(new Date(r.created_at).toLocaleString())}</td></tr>`).join("");
  res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Applications</title>
  <style>body{font-family:Arial;margin:0;background:#f5f5f5}.top{background:#d71920;color:#fff;padding:18px 24px}.wrap{padding:24px;overflow:auto}table{width:100%;border-collapse:collapse;background:#fff}th,td{padding:10px;border-bottom:1px solid #ddd;text-align:left;white-space:nowrap}th{background:#eee}</style></head>
  <body><div class="top"><b>Application Admin</b></div><div class="wrap"><h2>Applications</h2><table><thead><tr><th>ID</th><th>Name</th><th>Phone</th><th>Amount</th><th>Email</th><th>Status</th><th>Purpose</th><th>Date</th></tr></thead><tbody>${body||"<tr><td colspan='8'>No applications yet.</td></tr>"}</tbody></table></div></body></html>`);
});

init().then(()=>app.listen(PORT,"0.0.0.0",()=>console.log("Server running on "+PORT))).catch(e=>{console.error(e);process.exit(1)});
