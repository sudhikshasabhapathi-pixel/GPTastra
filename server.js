require("dotenv").config();
const express=require("express"),cors=require("cors"),jwt=require("jsonwebtoken"),path=require("path"),fs=require("fs");
const Database=require("better-sqlite3");
const app=express();
const PORT=process.env.PORT||8000, SECRET=process.env.JWT_SECRET||"dev-only-change-me";
const dbFile=process.env.DB_FILE||"./data/kisan-saathi.db";
fs.mkdirSync(path.dirname(dbFile),{recursive:true});
const db=new Database(dbFile);
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,phone TEXT UNIQUE,email TEXT,location TEXT DEFAULT 'Siddipet, Telangana');
CREATE TABLE IF NOT EXISTS farms(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,name TEXT,area REAL,soil TEXT,irrigation TEXT,location TEXT);
CREATE TABLE IF NOT EXISTS crops(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,name TEXT,area REAL,stage TEXT);
CREATE TABLE IF NOT EXISTS soil_reports(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,ph REAL,organic_carbon REAL,n REAL,p REAL,k REAL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,title TEXT,body TEXT,read INTEGER DEFAULT 0);
`);
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
app.post("/api/auth/login",(req,res)=>{const phone=String(req.body.phone||"").trim();let u=db.prepare("SELECT * FROM users WHERE phone=?").get(phone);if(!u&&phone){const r=db.prepare("INSERT INTO users(name,phone) VALUES(?,?)").run("Farmer",phone);u=db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid)}if(!u)return res.status(400).json({error:"Phone is required"});res.json({token:token(u),user:u})});
app.post("/api/auth/register",(req,res)=>{const {name,phone,email,location}=req.body;if(!name||!phone)return res.status(400).json({error:"Name and phone are required"});try{const r=db.prepare("INSERT INTO users(name,phone,email,location) VALUES(?,?,?,?)").run(name,phone,email||null,location||"Siddipet, Telangana");const u=db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid);res.json({token:token(u),user:u})}catch(e){res.status(409).json({error:"Phone already registered"})}});
app.get("/api/me",auth,(req,res)=>res.json(req.user));
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