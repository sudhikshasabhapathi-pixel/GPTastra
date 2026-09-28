require("dotenv").config();
const express=require("express"),cors=require("cors"),jwt=require("jsonwebtoken"),path=require("path"),fs=require("fs"),crypto=require("crypto");
const Database=require("better-sqlite3");
const app=express();
const PORT=process.env.PORT||8000, SECRET=process.env.JWT_SECRET||"dev-only-change-me";
const GOOGLE_CLIENT_ID=process.env.GOOGLE_CLIENT_ID||"";
const GOOGLE_CLIENT_SECRET=process.env.GOOGLE_CLIENT_SECRET||"";
const GOOGLE_REDIRECT_URI=process.env.GOOGLE_REDIRECT_URI||"http://localhost:8000/api/auth/google/callback";
const dbFile=process.env.DB_FILE||"./data/kisan-saathi.db";
fs.mkdirSync(path.dirname(dbFile),{recursive:true});
const db=new Database(dbFile);
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,phone TEXT UNIQUE,email TEXT UNIQUE,location TEXT DEFAULT 'Siddipet, Telangana');
CREATE TABLE IF NOT EXISTS farms(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,name TEXT,area REAL,soil TEXT,irrigation TEXT,location TEXT);
CREATE TABLE IF NOT EXISTS crops(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,name TEXT,area REAL,stage TEXT);
CREATE TABLE IF NOT EXISTS soil_reports(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,ph REAL,organic_carbon REAL,n REAL,p REAL,k REAL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,title TEXT,body TEXT,read INTEGER DEFAULT 0);
`);
const userCols=db.prepare("PRAGMA table_info(users)").all().map(x=>x.name);
if(!userCols.includes("password_hash"))db.exec("ALTER TABLE users ADD COLUMN password_hash TEXT");
if(!userCols.includes("google_sub"))db.exec("ALTER TABLE users ADD COLUMN google_sub TEXT");
function publicUser(u){return {id:u.id,name:u.name,email:u.email||null,phone:u.phone||null,location:u.location}}
function hashPassword(password){const salt=crypto.randomBytes(16).toString("hex");return salt+":"+crypto.scryptSync(password,salt,64).toString("hex")}
function verifyPassword(password,stored){if(!stored||!stored.includes(":"))return false;const [salt,key]=stored.split(":");return crypto.timingSafeEqual(crypto.scryptSync(password,salt,64),Buffer.from(key,"hex"))}
let user=db.prepare("SELECT * FROM users WHERE phone=?").get("9999999999");
if(!user){const r=db.prepare("INSERT INTO users(name,phone,email,location) VALUES(?,?,?,?)").run("Ramesh Kumar","9999999999","ramesh@example.com","Siddipet, Telangana");user=db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid);
db.prepare("INSERT INTO farms(user_id,name,area,soil,irrigation,location) VALUES(?,?,?,?,?,?)").run(user.id,"Main Farm",4.5,"Black soil","Borewell",user.location);
for(const c of [["Cotton",2,"Flowering"],["Maize",1.5,"Vegetative"],["Red gram",1,"Flowering"]]) db.prepare("INSERT INTO crops(user_id,name,area,stage) VALUES(?,?,?,?)").run(user.id,...c);
db.prepare("INSERT INTO soil_reports(user_id,ph,organic_carbon,n,p,k) VALUES(?,?,?,?,?,?)").run(user.id,7.1,.62,71,83,52);
for(const a of [["Rain expected tomorrow","Consider delaying irrigation."],["Cotton scouting","Check your cotton crop for pest symptoms."],["Soil potassium","Potassium is slightly low in your latest report."]]) db.prepare("INSERT INTO alerts(user_id,title,body) VALUES(?,?,?)").run(user.id,...a);}
app.use(cors());app.use(express.json());app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname)));
function token(u){return jwt.sign({id:u.id},SECRET,{expiresIn:"7d"})}
function auth(req,res,next){try{const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))throw 0;req.user=db.prepare("SELECT * FROM users WHERE id=?").get(jwt.verify(h.slice(7),SECRET).id);if(!req.user)throw 0;next()}catch(e){res.status(401).json({error:"Authentication required"})}}
app.get("/api/health",(req,res)=>res.json({ok:true,service:"kisan-saathi"}));
app.post("/api/auth/register",(req,res)=>{const name=String(req.body.name||"").trim(),email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");if(!name||!email||!password)return res.status(400).json({error:"Name, email and password are required"});if(password.length<8)return res.status(400).json({error:"Password must be at least 8 characters"});try{if(db.prepare("SELECT id FROM users WHERE lower(email)=?").get(email))return res.status(409).json({error:"An account with this email already exists"});const r=db.prepare("INSERT INTO users(name,email,location,password_hash) VALUES(?,?,?,?)").run(name,email,"Siddipet, Telangana",hashPassword(password));const u=db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid);res.status(201).json({token:token(u),user:publicUser(u)})}catch(e){res.status(500).json({error:"Could not create account"})}});
app.post("/api/auth/login",(req,res)=>{const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");const u=db.prepare("SELECT * FROM users WHERE lower(email)=?").get(email);if(!u||!verifyPassword(password,u.password_hash))return res.status(401).json({error:"Incorrect email or password"});res.json({token:token(u),user:publicUser(u)})});
app.get("/api/auth/google",(req,res)=>{if(!GOOGLE_CLIENT_ID)return res.status(503).send("Google Sign-In is not configured.");const p=new URLSearchParams({client_id:GOOGLE_CLIENT_ID,redirect_uri:GOOGLE_REDIRECT_URI,response_type:"code",scope:"openid email profile",prompt:"select_account"});res.redirect("https://accounts.google.com/o/oauth2/v2/auth?"+p)});
app.get("/api/auth/google/callback",async(req,res)=>{try{const code=String(req.query.code||"");if(!GOOGLE_CLIENT_ID||!GOOGLE_CLIENT_SECRET||!code)throw new Error("Google auth not configured");const tr=await fetch("https://oauth2.googleapis.com/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({code,client_id:GOOGLE_CLIENT_ID,client_secret:GOOGLE_CLIENT_SECRET,redirect_uri:GOOGLE_REDIRECT_URI,grant_type:"authorization_code"})});const td=await tr.json();if(!tr.ok||!td.id_token)throw new Error("Token exchange failed");const payload=JSON.parse(Buffer.from(td.id_token.split(".")[1],"base64url").toString());if(payload.aud!==GOOGLE_CLIENT_ID||!payload.sub||!payload.email)throw new Error("Invalid Google identity");const email=payload.email.toLowerCase();let u=db.prepare("SELECT * FROM users WHERE google_sub=? OR lower(email)=?").get(payload.sub,email);if(!u){const r=db.prepare("INSERT INTO users(name,email,location,google_sub) VALUES(?,?,?,?)").run(payload.name||email.split("@")[0],email,"Siddipet, Telangana",payload.sub);u=db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid)}else if(!u.google_sub){db.prepare("UPDATE users SET google_sub=? WHERE id=?").run(payload.sub,u.id);u=db.prepare("SELECT * FROM users WHERE id=?").get(u.id)}res.redirect("/?token="+encodeURIComponent(token(u)))}catch(e){res.status(401).send("Google Sign-In failed. Please try again.")}});
app.get("/api/me",auth,(req,res)=>res.json(publicUser(req.user)));
app.patch("/api/me",auth,(req,res)=>{const fields=["name","email","location"].filter(k=>req.body[k]!==undefined);if(fields.length)db.prepare("UPDATE users SET "+fields.map(k=>k+"=?").join(",")+" WHERE id=?").run(...fields.map(k=>req.body[k]),req.user.id);res.json(db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id))});
app.get("/api/farms",auth,(req,res)=>res.json(db.prepare("SELECT * FROM farms WHERE user_id=?").all(req.user.id)));
app.post("/api/farms",auth,(req,res)=>{const r=db.prepare("INSERT INTO farms(user_id,name,area,soil,irrigation,location) VALUES(?,?,?,?,?,?)").run(req.user.id,req.body.name||"Farm",Number(req.body.area)||0,req.body.soil||"",req.body.irrigation||"",req.body.location||req.user.location);res.json(db.prepare("SELECT * FROM farms WHERE id=?").get(r.lastInsertRowid))});
app.get("/api/crops",auth,(req,res)=>res.json(db.prepare("SELECT * FROM crops WHERE user_id=?").all(req.user.id)));
app.post("/api/crops",auth,(req,res)=>{const r=db.prepare("INSERT INTO crops(user_id,name,area,stage) VALUES(?,?,?,?)").run(req.user.id,req.body.name||"Crop",Number(req.body.area)||0,req.body.stage||"Planned");res.json(db.prepare("SELECT * FROM crops WHERE id=?").get(r.lastInsertRowid))});
app.get("/api/soil/reports",auth,(req,res)=>res.json(db.prepare("SELECT * FROM soil_reports WHERE user_id=? ORDER BY id DESC").all(req.user.id)));
app.post("/api/soil/reports",auth,(req,res)=>{const r=db.prepare("INSERT INTO soil_reports(user_id,ph,organic_carbon,n,p,k) VALUES(?,?,?,?,?,?)").run(req.user.id,req.body.ph||null,req.body.organic_carbon||null,req.body.n||null,req.body.p||null,req.body.k||null);res.json(db.prepare("SELECT * FROM soil_reports WHERE id=?").get(r.lastInsertRowid))});
app.get("/api/weather",(req,res)=>res.json({location:"Siddipet, Telangana",current:{temp:29,condition:"Partly cloudy"},forecast:[["Mon",29,26,"🌤️"],["Tue",27,24,"🌧️"],["Wed",28,24,"🌦️"],["Thu",30,25,"☀️"],["Fri",31,25,"☀️"]],rainProbability:65}));
app.get("/api/markets",(req,res)=>res.json([{crop:"Cotton",market:"Siddipet",price:"₹7,250/q",trend:"up"},{crop:"Maize",market:"Siddipet",price:"₹2,180/q",trend:"steady"},{crop:"Red gram",market:"Sangareddy",price:"₹7,950/q",trend:"up"}]));
app.get("/api/schemes",(req,res)=>res.json([{name:"PM-KISAN",type:"Central",description:"Income support for eligible farmer families."},{name:"Telangana Agriculture Services",type:"State",description:"State farmer support and agriculture services."}]));
app.get("/api/inputs",(req,res)=>res.json([{name:"Cotton Seed",price:780,category:"Seed"},{name:"NPK Fertilizer",price:1250,category:"Fertilizer"},{name:"Neem-based Bio Input",price:320,category:"Bio input"}]));
app.get("/api/alerts",auth,(req,res)=>res.json(db.prepare("SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC").all(req.user.id)));
app.patch("/api/alerts/:id/read",auth,(req,res)=>{db.prepare("UPDATE alerts SET read=1 WHERE id=? AND user_id=?").run(req.params.id,req.user.id);res.json({ok:true})});
app.post("/api/ai/ask",auth,(req,res)=>{const q=String(req.body.question||"");res.json({answer:"Based on your farm context, check the latest weather and soil moisture before deciding. For disease or pesticide decisions, confirm the diagnosis with a qualified local agriculture expert.",question:q})});
app.post("/api/crop-health/scan",auth,(req,res)=>res.json({result:"Possible leaf spot",confidence:.86,note:"This is a demonstration workflow. Confirm with an agriculture expert before treatment."}));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.listen(PORT,()=>console.log("Kisan Saathi running on "+PORT));