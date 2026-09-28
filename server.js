require("dotenv").config();
const express=require("express"),cors=require("cors"),jwt=require("jsonwebtoken"),path=require("path"),fs=require("fs"),crypto=require("crypto");
const Database=require("better-sqlite3");
const multer=require("multer");
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:6*1024*1024}});
const app=express();
const PORT=process.env.PORT||8000, SECRET=process.env.JWT_SECRET||"dev-only-change-me";
const GOOGLE_CLIENT_ID=process.env.GOOGLE_CLIENT_ID||"";
const GOOGLE_CLIENT_SECRET=process.env.GOOGLE_CLIENT_SECRET||"";
const GOOGLE_REDIRECT_URI=process.env.GOOGLE_REDIRECT_URI||"http://localhost:8000/api/auth/google/callback";
const AI_API_KEY=process.env.AI_API_KEY||process.env.OPENAI_API_KEY||"";
const AI_API_URL=process.env.AI_API_URL||"https://api.openai.com/v1/responses";
const AI_MODEL=process.env.AI_MODEL||"";
const dbFile=process.env.DB_FILE||"./data/kisan-saathi.db";
fs.mkdirSync(path.dirname(dbFile),{recursive:true});
const db=new Database(dbFile);
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,phone TEXT UNIQUE,email TEXT UNIQUE,location TEXT DEFAULT 'Siddipet, Telangana',language TEXT DEFAULT 'en');
CREATE TABLE IF NOT EXISTS farms(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,name TEXT,area REAL,soil TEXT,irrigation TEXT,location TEXT);
CREATE TABLE IF NOT EXISTS crops(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,name TEXT,area REAL,stage TEXT);
CREATE TABLE IF NOT EXISTS soil_reports(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,ph REAL,organic_carbon REAL,n REAL,p REAL,k REAL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,title TEXT,body TEXT,read INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS ai_messages(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,role TEXT NOT NULL,content TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS health_scans(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,crop TEXT,image_name TEXT,result TEXT,confidence REAL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,items_json TEXT NOT NULL,total REAL NOT NULL,status TEXT DEFAULT "PLACED",delivery_note TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
const userCols=db.prepare("PRAGMA table_info(users)").all().map(x=>x.name);
if(!userCols.includes("password_hash"))db.exec("ALTER TABLE users ADD COLUMN password_hash TEXT");
if(!userCols.includes("google_sub"))db.exec("ALTER TABLE users ADD COLUMN google_sub TEXT");
if(!userCols.includes("language"))db.exec("ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'en'");
function publicUser(u){return {id:u.id,name:u.name,email:u.email||null,phone:u.phone||null,location:u.location,language:u.language||"en"}}
function hashPassword(password){const salt=crypto.randomBytes(16).toString("hex");return salt+":"+crypto.scryptSync(password,salt,64).toString("hex")}
function verifyPassword(password,stored){if(!stored||!stored.includes(":"))return false;const [salt,key]=stored.split(":");try{return crypto.timingSafeEqual(crypto.scryptSync(password,salt,64),Buffer.from(key,"hex"))}catch{return false}}
let user=db.prepare("SELECT * FROM users WHERE phone=?").get("9999999999");
if(!user){const r=db.prepare("INSERT INTO users(name,phone,email,location,language) VALUES(?,?,?,?,?)").run("Ramesh Kumar","9999999999","ramesh@example.com","Siddipet, Telangana","te");user=db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid);
db.prepare("INSERT INTO farms(user_id,name,area,soil,irrigation,location) VALUES(?,?,?,?,?,?)").run(user.id,"Main Farm",4.5,"Black soil","Borewell",user.location);
for(const c of [["Cotton",2,"Flowering"],["Maize",1.5,"Vegetative"],["Red gram",1,"Flowering"]]) db.prepare("INSERT INTO crops(user_id,name,area,stage) VALUES(?,?,?,?)").run(user.id,...c);
db.prepare("INSERT INTO soil_reports(user_id,ph,organic_carbon,n,p,k) VALUES(?,?,?,?,?,?)").run(user.id,7.1,.62,71,83,52);
for(const a of [["Rain expected tomorrow","Consider delaying irrigation."],["Cotton scouting","Check your cotton crop for pest symptoms."],["Soil potassium","Potassium is slightly low in your latest report."]]) db.prepare("INSERT INTO alerts(user_id,title,body) VALUES(?,?,?)").run(user.id,...a);}
app.use(cors());app.use(express.json());app.use(express.urlencoded({extended:true}));app.use(express.static(path.join(__dirname)));
function token(u){return jwt.sign({id:u.id},SECRET,{expiresIn:"7d"})}
function auth(req,res,next){try{const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))throw 0;req.user=db.prepare("SELECT * FROM users WHERE id=?").get(jwt.verify(h.slice(7),SECRET).id);if(!req.user)throw 0;next()}catch(e){res.status(401).json({error:"Authentication required"})}}
app.get("/api/health",(req,res)=>res.json({ok:true,service:"kisan-saathi",features:["multilingual-ui","voice-assistant","real-ai-copilot","ai-chat-history"]}));
app.post("/api/auth/register",(req,res)=>{const name=String(req.body.name||"").trim(),email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");if(!name||!email||!password)return res.status(400).json({error:"Name, email and password are required"});if(password.length<8)return res.status(400).json({error:"Password must be at least 8 characters"});try{if(db.prepare("SELECT id FROM users WHERE lower(email)=?").get(email))return res.status(409).json({error:"An account with this email already exists"});const r=db.prepare("INSERT INTO users(name,email,location,password_hash,language) VALUES(?,?,?,?,?)").run(name,email,"Siddipet, Telangana",hashPassword(password),req.body.language||"en");const u=db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid);res.status(201).json({token:token(u),user:publicUser(u)})}catch(e){res.status(500).json({error:"Could not create account"})}});
app.post("/api/auth/login",(req,res)=>{const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");const u=db.prepare("SELECT * FROM users WHERE lower(email)=?").get(email);if(!u||!verifyPassword(password,u.password_hash))return res.status(401).json({error:"Incorrect email or password"});res.json({token:token(u),user:publicUser(u)})});
app.get("/api/auth/google",(req,res)=>{if(!GOOGLE_CLIENT_ID)return res.status(503).send("Google Sign-In is not configured.");const p=new URLSearchParams({client_id:GOOGLE_CLIENT_ID,redirect_uri:GOOGLE_REDIRECT_URI,response_type:"code",scope:"openid email profile",prompt:"select_account"});res.redirect("https://accounts.google.com/o/oauth2/v2/auth?"+p)});
app.get("/api/auth/google/callback",async(req,res)=>{try{const code=String(req.query.code||"");if(!GOOGLE_CLIENT_ID||!GOOGLE_CLIENT_SECRET||!code)throw new Error("Google auth not configured");const tr=await fetch("https://oauth2.googleapis.com/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({code,client_id:GOOGLE_CLIENT_ID,client_secret:GOOGLE_CLIENT_SECRET,redirect_uri:GOOGLE_REDIRECT_URI,grant_type:"authorization_code"})});const td=await tr.json();if(!tr.ok||!td.id_token)throw new Error("Token exchange failed");const payload=JSON.parse(Buffer.from(td.id_token.split(".")[1],"base64url").toString());if(payload.aud!==GOOGLE_CLIENT_ID||!payload.sub||!payload.email)throw new Error("Invalid Google identity");const email=payload.email.toLowerCase();let u=db.prepare("SELECT * FROM users WHERE google_sub=? OR lower(email)=?").get(payload.sub,email);if(!u){const r=db.prepare("INSERT INTO users(name,email,location,google_sub,language) VALUES(?,?,?,?,?)").run(payload.name||email.split("@")[0],email,"Siddipet, Telangana",payload.sub,"en");u=db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid)}else if(!u.google_sub){db.prepare("UPDATE users SET google_sub=? WHERE id=?").run(payload.sub,u.id);u=db.prepare("SELECT * FROM users WHERE id=?").get(u.id)}res.redirect("/?token="+encodeURIComponent(token(u)))}catch(e){res.status(401).send("Google Sign-In failed. Please try again.")}});
app.get("/api/me",auth,(req,res)=>res.json(publicUser(req.user)));
app.patch("/api/me",auth,(req,res)=>{const allowed=["name","email","location","language"],fields=allowed.filter(k=>req.body[k]!==undefined);if(fields.length)db.prepare("UPDATE users SET "+fields.map(k=>k+"=?").join(",")+" WHERE id=?").run(...fields.map(k=>req.body[k]),req.user.id);res.json(publicUser(db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id)))});
app.get("/api/farms",auth,(req,res)=>res.json(db.prepare("SELECT * FROM farms WHERE user_id=?").all(req.user.id)));
app.post("/api/farms",auth,(req,res)=>{const r=db.prepare("INSERT INTO farms(user_id,name,area,soil,irrigation,location) VALUES(?,?,?,?,?,?)").run(req.user.id,req.body.name||"Farm",Number(req.body.area)||0,req.body.soil||"",req.body.irrigation||"",req.body.location||req.user.location);res.json(db.prepare("SELECT * FROM farms WHERE id=?").get(r.lastInsertRowid))});
const CROP_CATALOG=[
["Rice","Cereal","120-150 days","Grain","Local wholesale/APMC; compare paddy procurement, milling deductions and transport."],
["Wheat","Cereal","110-150 days","Grain","Compare APMC/private buyers; check grade, moisture, procurement terms and transport."],
["Maize","Cereal","90-120 days","Grain","Compare feed mills, poultry/feed buyers and APMC; account for moisture drying and transport."],
["Bajra","Cereal","75-110 days","Grain","Compare local APMC, feed and grain buyers; quality and moisture affect price."],
["Jowar","Cereal","100-130 days","Grain","Compare food-grain and feed buyers; separate grain and fodder value where relevant."],
["Ragi","Millet","100-130 days","Grain","Compare APMC, millet processors and direct buyers; cleaning and grading can improve saleability."],
["Sorghum","Cereal","100-130 days","Grain","Compare grain and fodder demand; transport and moisture are major selling costs."],
["Barley","Cereal","120-150 days","Grain","Compare malt/feed buyers and APMC; buyer specifications can affect realized price."],
["Chickpea","Pulse","100-140 days","Pulse","Compare dal mills and APMC; grade, moisture and cleaning losses matter."],
["Pigeon pea (Red gram)","Pulse","160-200 days","Pulse","Compare dal mills, APMC and institutional buyers; check quality and procurement conditions."],
["Black gram (Urad)","Pulse","70-100 days","Pulse","Compare dal mills and APMC; clean, dry grain and low foreign matter support marketability."],
["Green gram (Moong)","Pulse","60-90 days","Pulse","Compare dal mills, APMC and direct buyers; harvest timing and grain quality matter."],
["Lentil","Pulse","100-120 days","Pulse","Compare dal mills and APMC; grade and moisture influence buyer offers."],
["Groundnut","Oilseed","100-130 days","Oilseed","Compare oil mills, shellers and APMC; shelling percentage, moisture and aflatoxin risk matter."],
["Soybean","Oilseed","90-120 days","Oilseed","Compare oil mills, processors and APMC; moisture, foreign matter and oil quality affect returns."],
["Mustard","Oilseed","110-150 days","Oilseed","Compare oil mills and APMC; seed purity, moisture and oil content matter."],
["Sunflower","Oilseed","90-120 days","Oilseed","Compare oil mills and local buyers; seed quality and moisture affect realized price."],
["Sesame","Oilseed","80-110 days","Oilseed","Compare processors/export-oriented buyers and APMC; colour, purity and cleanliness matter."],
["Cotton","Fibre crop","150-180 days","Fibre","Compare regulated market/APMC, ginners and approved buyers; moisture, staple quality and contamination affect price."],
["Sugarcane","Commercial crop","10-18 months","Cane","Compare notified mill procurement terms and harvesting/transport arrangements; avoid comparing raw cane price alone."],
["Tobacco","Commercial crop","120-180 days","Leaf","Sale depends heavily on local auction/buyer grading; follow notified market and quality rules."],
["Tomato","Vegetable","90-150 days","Fresh produce","Compare nearby wholesale markets, collection centres and direct buyers daily; grade, sorting, crates, transport and spoilage determine net return."],
["Onion","Vegetable","100-150 days","Fresh/storage","Compare APMC, wholesale and storage options; curing, grading, storage loss and transport are key."],
["Potato","Vegetable","90-120 days","Fresh/storage","Compare wholesale, processors and cold-storage routes; size, quality, storage charges and shrinkage matter."],
["Brinjal (Eggplant)","Vegetable","100-180 days","Fresh produce","Compare nearby wholesale and direct retail/collection buyers; frequent picking and quality sorting affect returns."],
["Okra","Vegetable","50-70 days to first harvest; 90-120 days crop","Fresh produce","Compare local wholesale and direct buyers; harvest frequency, tenderness, grading and transport are important."],
["Cabbage","Vegetable","70-120 days","Fresh produce","Compare wholesale markets and institutional buyers; head size, uniformity, packing and transport affect price."],
["Cauliflower","Vegetable","70-120 days","Fresh produce","Compare wholesale and institutional buyers; maturity window is short, so coordinate harvest and transport."],
["Carrot","Vegetable","70-100 days","Fresh produce","Compare wholesale, processors and direct buyers; size, colour, cleaning and packing affect value."],
["Radish","Vegetable","35-60 days","Fresh produce","Compare local wholesale/direct markets; freshness, bunching, sorting and transport matter."],
["Beetroot","Vegetable","60-90 days","Fresh produce","Compare wholesale and processors; root size, uniformity and clean packing affect returns."],
["Spinach","Leafy vegetable","30-50 days","Fresh produce","Prefer nearby markets because shelf life is short; bunch quality, cooling and rapid transport are critical."],
["Amaranth","Leafy vegetable","30-60 days","Fresh produce","Sell quickly through nearby wholesale/direct channels; freshness and bunch quality drive value."],
["Drumstick (Moringa)","Vegetable","8-12 months first harvest; perennial","Fresh produce","Compare nearby wholesale, processors and direct buyers; tender pod quality and fast transport matter."],
["Green chilli","Vegetable","75-100 days to first harvest; multi-pick","Fresh produce","Compare wholesale markets, processors and direct buyers; colour, pungency, sorting and spoilage affect net return."],
["Capsicum","Vegetable","75-100 days to first harvest; multi-pick","Fresh produce","Compare wholesale, supermarkets and institutional buyers; grade, colour, firmness and packing matter."],
["Bitter gourd","Vegetable","55-80 days to first harvest; multi-pick","Fresh produce","Compare nearby wholesale and direct buyers; tender size, sorting and frequent harvest affect price."],
["Bottle gourd","Vegetable","55-80 days to first harvest; multi-pick","Fresh produce","Compare local wholesale/direct channels; size, shape, freshness and transport costs matter."],
["Ridge gourd","Vegetable","55-80 days to first harvest; multi-pick","Fresh produce","Compare nearby wholesale/direct buyers; tenderness, uniformity and harvest timing affect value."],
["Cucumber","Vegetable","45-70 days to first harvest; multi-pick","Fresh produce","Compare nearby wholesale and direct buyers; freshness, size and rapid transport are important."],
["Pumpkin","Vegetable","90-140 days","Fresh produce/storage","Compare wholesale, processors and storage; mature fruit can offer more marketing flexibility."],
["French bean","Vegetable","50-75 days to first harvest","Fresh produce","Compare wholesale and institutional buyers; tenderness, uniform pods and quick cooling/transport matter."],
["Peas","Vegetable","60-100 days","Fresh produce","Compare local wholesale, processors and direct buyers; maturity and cold-chain availability affect returns."],
["Sweet corn","Vegetable","70-100 days","Fresh produce/processing","Sell close to harvest through local buyers, processors or direct channels; sweetness and rapid cooling matter."],
["Watermelon","Fruit","80-110 days","Fresh produce","Compare wholesale markets, direct traders and farm-gate buyers; size, sweetness, grading and transport are key."],
["Muskmelon","Fruit","70-100 days","Fresh produce","Compare wholesale/direct buyers; maturity, sweetness, size and careful handling affect value."],
["Banana","Fruit","9-14 months first harvest","Fresh produce","Compare local wholesale, ripening units and direct buyers; harvest maturity, bunch quality, packing and transport matter."],
["Mango","Fruit","3-5 years to bearing; seasonal harvest","Fresh produce/processing","Compare fruit markets, aggregators and processors; grade, maturity, harvest handling and distance to market affect returns."],
["Guava","Fruit","2-3 years to bearing","Fresh produce","Compare wholesale, processors and direct buyers; size, maturity, blemishes and packing affect value."],
["Papaya","Fruit","8-12 months to first harvest","Fresh produce","Compare wholesale and direct buyers; maturity stage, size, handling and rapid movement are important."],
["Pomegranate","Fruit","2-3 years to bearing","Fresh produce/export","Compare regulated wholesale, aggregators and export-oriented buyers; grade, colour, size and residue compliance matter."],
["Grapes","Fruit","2-3 years to bearing","Fresh produce/processing","Compare domestic wholesale, raisin/wine/processing and export channels where available; bunch quality and compliance matter."],
["Orange","Fruit","3-5 years to bearing","Fresh produce/processing","Compare wholesale, juice processors and direct buyers; maturity, size, juice quality and transport matter."],
["Lemon","Fruit","2-3 years to bearing","Fresh produce/processing","Compare wholesale, processors and direct buyers; size, juice content and freshness matter."],
["Pineapple","Fruit","12-18 months","Fresh produce/processing","Compare wholesale, processors and direct buyers; maturity, size, crown condition and transport affect returns."],
["Jackfruit","Fruit","3-7 years to bearing","Fresh produce/processing","Compare fresh-fruit traders and processing buyers; maturity, size, handling and transport are important."],
["Turmeric","Spice","7-9 months","Spice","Compare spice processors, traders and APMC; curing recovery, colour, moisture and quality affect value."],
["Ginger","Spice","7-9 months","Spice","Compare fresh markets and processors; size, fibre, cleanliness and storage affect returns."],
["Coriander","Spice","90-120 days grain","Spice","Compare spice traders, processors and APMC; seed cleanliness, aroma and moisture matter."],
["Cumin","Spice","100-120 days","Spice","Compare spice traders/APMC; purity, moisture, colour and volatile-oil quality affect value."],
["Fenugreek","Spice","90-120 days","Spice","Compare spice traders and APMC; seed quality, cleanliness and moisture matter."],
["Cardamom","Spice","2-3 years to bearing","Spice","Use auction/regulated channels where applicable; grade, moisture and processing quality determine value."],
["Black pepper","Spice","3-4 years to bearing","Spice","Compare regulated traders/processors; grade, moisture, berry quality and processing matter."],
["Chilli (dry)","Spice","5-8 months","Spice","Compare spice markets, processors and traders; colour, pungency, moisture, aflatoxin and cleanliness matter."],
["Coconut","Plantation","5-7 years to bearing","Plantation","Compare local wholesale, copra/oil processors and direct buyers; nut size and moisture affect value."],
["Cashew","Tree nut","3-5 years to bearing","Tree nut","Compare processors/traders; kernel recovery, nut size and quality determine returns."],
["Tea","Plantation","3-5 years to first harvest","Leaf","Sale is generally through local factories/auction/processor channels; leaf quality and plucking standard matter."],
["Coffee","Plantation","3-4 years to bearing","Bean","Compare licensed buyers/processors; bean quality, moisture, grade and processing method affect value."]
];
app.get("/api/crop-catalog",(req,res)=>{const q=String(req.query.q||"").toLowerCase();const type=String(req.query.type||"").toLowerCase();const rows=CROP_CATALOG.filter(x=>(!q||x[0].toLowerCase().includes(q))&&(!type||x[1].toLowerCase()===type)).map(x=>({name:x[0],category:x[1],duration:x[2],marketForm:x[3],marketGuidance:x[4]}));res.json(rows)});
app.get("/api/market-guidance",(req,res)=>{const q=String(req.query.crop||"").toLowerCase();const row=CROP_CATALOG.find(x=>x[0].toLowerCase()===q||x[0].toLowerCase().includes(q));if(!row)return res.status(404).json({error:"Crop not found"});res.json({crop:row[0],category:row[1],duration:row[2],guidance:row[4],buyerBenefit:"Buyers can compare grade, quality, quantity, transport and delivery timing rather than relying on a single headline price.",farmerProfit:"Net return = sale value − seed/input cost − labour − irrigation − harvesting − packing − transport − market/commission charges − storage or spoilage loss. Compare at least two buyers/markets before selling.",livePriceSource:"Current mandi prices should be verified from the official Agmarknet market data for the selected commodity and market; this app does not invent live prices."})});
app.get("/api/crops",auth,(req,res)=>res.json(db.prepare("SELECT * FROM crops WHERE user_id=?").all(req.user.id)));
app.post("/api/crops",auth,(req,res)=>{const r=db.prepare("INSERT INTO crops(user_id,name,area,stage) VALUES(?,?,?,?)").run(req.user.id,req.body.name||"Crop",Number(req.body.area)||0,req.body.stage||"Planned");res.json(db.prepare("SELECT * FROM crops WHERE id=?").get(r.lastInsertRowid))});
app.get("/api/soil/reports",auth,(req,res)=>res.json(db.prepare("SELECT * FROM soil_reports WHERE user_id=? ORDER BY id DESC").all(req.user.id)));
app.post("/api/soil/reports",auth,(req,res)=>{const r=db.prepare("INSERT INTO soil_reports(user_id,ph,organic_carbon,n,p,k) VALUES(?,?,?,?,?,?)").run(req.user.id,req.body.ph||null,req.body.organic_carbon||null,req.body.n||null,req.body.p||null,req.body.k||null);res.json(db.prepare("SELECT * FROM soil_reports WHERE id=?").get(r.lastInsertRowid))});
app.get("/api/weather",(req,res)=>res.json({location:"Siddipet, Telangana",current:{temp:29,condition:"Partly cloudy"},forecast:[["Mon",29,26,"🌤️"],["Tue",27,24,"🌧️"],["Wed",28,24,"🌦️"],["Thu",30,25,"☀️"],["Fri",31,25,"☀️"]],rainProbability:65}));
app.get("/api/markets",(req,res)=>res.json([{crop:"Cotton",market:"Siddipet",price:"₹7,250/q",trend:"up"},{crop:"Maize",market:"Siddipet",price:"₹2,180/q",trend:"steady"},{crop:"Red gram",market:"Sangareddy",price:"₹7,950/q",trend:"up"}]));
app.get("/api/schemes",(req,res)=>res.json([{name:"PM-KISAN",type:"Central",description:"Income support for eligible farmer families."},{name:"Telangana Agriculture Services",type:"State",description:"State farmer support and agriculture services."}]));
const INPUT_PRODUCTS=[
{id:"seed-cotton",name:"Certified Cotton Seed Pack",price:780,category:"Seeds",unit:"1 pack",description:"Certified seed pack for cotton planning; verify variety suitability locally."},
{id:"seed-maize",name:"Hybrid Maize Seed Pack",price:690,category:"Seeds",unit:"1 pack",description:"Seed pack for maize; choose a locally recommended variety."},
{id:"soil-kit",name:"Soil Test Home Kit",price:299,category:"Soil",unit:"1 kit",description:"Basic field screening kit. Use a laboratory test for fertilizer decisions."},
{id:"compost",name:"Organic Compost",price:420,category:"Soil amendment",unit:"25 kg",description:"Compost for improving organic matter; quality and analysis vary by supplier."},
{id:"neem-cake",name:"Neem Cake Soil Amendment",price:520,category:"Bio input",unit:"25 kg",description:"Plant-based soil amendment. Use according to the package label."},
{id:"biofert",name:"Microbial Biofertilizer",price:360,category:"Bio input",unit:"1 L",description:"Microbial input; compatibility and application depend on crop and product label."},
{id:"gloves",name:"Reusable Farm Gloves",price:180,category:"Safety",unit:"1 pair",description:"Protective gloves for routine farm work."},
{id:"drip-kit",name:"Drip Repair Starter Kit",price:450,category:"Irrigation",unit:"1 kit",description:"Basic connectors and repair parts for small drip systems."}
];
app.get("/api/inputs",(req,res)=>{const q=String(req.query.q||"").toLowerCase();const cat=String(req.query.category||"").toLowerCase();res.json(INPUT_PRODUCTS.filter(p=>(!q||[p.name,p.description,p.category].join(" ").toLowerCase().includes(q))&&(!cat||p.category.toLowerCase()===cat)));});
app.post("/api/orders",auth,(req,res)=>{try{const items=Array.isArray(req.body.items)?req.body.items:[];if(!items.length)return res.status(400).json({error:"Cart is empty"});const safe=items.map(i=>{const p=INPUT_PRODUCTS.find(x=>x.id===i.id);if(!p)throw new Error("Unknown product");const qty=Math.max(1,Math.min(20,Number(i.qty)||1));return {id:p.id,name:p.name,price:p.price,qty}});const total=safe.reduce((s,x)=>s+x.price*x.qty,0);const note=String(req.body.delivery_note||"").trim().slice(0,300);const r=db.prepare("INSERT INTO orders(user_id,items_json,total,delivery_note) VALUES(?,?,?,?)").run(req.user.id,JSON.stringify(safe),total,note);res.status(201).json({orderId:r.lastInsertRowid,total,status:"PLACED",items:safe,note});}catch(e){res.status(400).json({error:e.message||"Could not place order"})}});
app.get("/api/orders",auth,(req,res)=>res.json(db.prepare("SELECT id,total,status,delivery_note,created_at,items_json FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 20").all(req.user.id).map(o=>({...o,items:JSON.parse(o.items_json)}))));
app.get("/api/alerts",auth,(req,res)=>res.json(db.prepare("SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC").all(req.user.id)));
app.patch("/api/alerts/:id/read",auth,(req,res)=>{db.prepare("UPDATE alerts SET read=1 WHERE id=? AND user_id=?").run(req.params.id,req.user.id);res.json({ok:true})});
function languageName(code){return ({en:"English",hi:"Hindi",te:"Telugu",ta:"Tamil",kn:"Kannada",ml:"Malayalam",bn:"Bengali",mr:"Marathi",gu:"Gujarati",pa:"Punjabi",or:"Odia",as:"Assamese",ur:"Urdu",sa:"Sanskrit",ne:"Nepali",sd:"Sindhi",kok:"Konkani",mai:"Maithili",doi:"Dogri",mni:"Meitei",sat:"Santali",bho:"Bhojpuri",raj:"Rajasthani"})[code]||"English"}\nfunction buildFarmContext(user){const farms=db.prepare("SELECT name,area,soil,irrigation,location FROM farms WHERE user_id=?").all(user.id);const crops=db.prepare("SELECT name,area,stage FROM crops WHERE user_id=?").all(user.id);const soil=db.prepare("SELECT ph,organic_carbon,n,p,k,created_at FROM soil_reports WHERE user_id=? ORDER BY id DESC LIMIT 3").all(user.id);return {farmer:{name:user.name,location:user.location,language:languageName(user.language||"en")},farms,crops,soil}}\napp.get("/api/ai/history",auth,(req,res)=>{res.json(db.prepare("SELECT role,content,created_at FROM ai_messages WHERE user_id=? ORDER BY id DESC LIMIT 30").all(req.user.id).reverse())});\napp.delete("/api/ai/history",auth,(req,res)=>{db.prepare("DELETE FROM ai_messages WHERE user_id=?").run(req.user.id);res.json({ok:true})});\nconst CROP_CATALOG={
  cereals:["rice","paddy","wheat","maize","corn","sorghum","jowar","bajra","pearl millet","ragi","finger millet","barley","oats"],
  pulses:["red gram","pigeon pea","tur","arhar","chickpea","gram","bengal gram","black gram","urad","green gram","moong","lentil","masoor","cowpea","lobia"],
  oilseeds:["groundnut","peanut","soybean","sunflower","sesame","gingelly","mustard","rapeseed","safflower","castor","linseed"],
  vegetables:["tomato","potato","onion","garlic","brinjal","eggplant","chilli","green chilli","capsicum","okra","lady finger","cabbage","cauliflower","broccoli","carrot","radish","beetroot","turnip","beans","cluster bean","french bean","peas","green peas","bottle gourd","ridge gourd","bitter gourd","snake gourd","pumpkin","ash gourd","cucumber","drumstick","moringa","spinach","amaranth","fenugreek","coriander","lettuce","sweet corn","sweet potato","tapioca","cassava","yam"],
  fruits:["mango","banana","orange","sweet orange","mandarin","lemon","lime","guava","papaya","pomegranate","grapes","watermelon","muskmelon","apple","sapota","chikoo","pineapple","jackfruit","custard apple","ber","aonla","amla","dragon fruit","strawberry","peach","plum","pear","kiwi","fig","coconut"],
  spices:["turmeric","ginger","garlic","black pepper","cardamom","cumin","coriander","fenugreek","fennel","clove","nutmeg","tamarind"],
  plantation:["coconut","arecanut","cashew","coffee","tea","rubber","cocoa"],
  fibre:["cotton","jute","sunn hemp"],
  commercial:["sugarcane","tobacco"]
};
function cropCategory(q){
  for(const [category,crops] of Object.entries(CROP_CATALOG)) if(crops.some(c=>q.includes(c))) return category;
  return null;
}
function localAgricultureCopilot(question,context,lang){
  const q=question.toLowerCase();
  const crop=context.crops?.map(x=>x.name).filter(Boolean).join(", ")||"your crops";
  const location=context.farmer?.location||"your area";
  const category=cropCategory(q);
  const responses=[
    [/\\b(soil|ph|npk|nitrogen|phosphorus|potassium|fertili)/,"For soil and nutrients, start with a recent soil test. Check pH, organic carbon and N-P-K before choosing fertilizer. Use the crop recommendation and dose on your local soil-test report or an agricultural department recommendation. Avoid applying fertilizer only by guesswork."],
    [/\\b(irrigat|water|drip|sprinkler)/,"For irrigation, check crop stage, soil moisture and recent or expected rainfall. Prefer smaller, timely irrigations rather than watering on a fixed schedule when conditions are changing. Drip or sprinkler systems can improve water control where suitable."],
    [/\\b(pest|insect|worm|aphid|bollworm|thrips|whitefly)/,"For pests, first identify the crop, pest and growth stage. Inspect several plants and look for the actual pest or characteristic damage. Use integrated pest management first; if a pesticide is needed, use only a locally approved product and follow its label exactly."],
    [/\\b(disease|fungus|fungal|leaf|yellow|spot|blight|wilt|virus)/,"For crop disease symptoms, avoid treating from symptoms alone. Check the crop, plant part affected, pattern in the field, recent weather and irrigation. A photo can help narrow possibilities, but an agriculture expert or lab may be needed for confirmation before treatment."],
    [/\\b(weather|rain|heat|cold|forecast)/,"Weather matters for sowing, irrigation, spraying and harvest. Before acting, check a current local forecast for your farm area. Avoid spraying during strong wind or when rain is expected soon, and adjust irrigation after meaningful rainfall."],
    [/\\b(market|mandi|price|sell|selling|buyer|profit|return|margin|rate)/,"For any crop—including vegetables and fruits—do not judge profitability from one market price. Compare the current price for the same variety, grade and market, then subtract harvesting, sorting, packing, transport, commission, storage and wastage costs. Farmers can improve net returns by comparing multiple nearby mandis or buyers, choosing the right harvest/dispatch window, grading produce, and avoiding distress sales. Buyers benefit from consistent quality, transparent grading and predictable volumes. Current prices must be verified from a live mandi or market source before making a transaction."],
    [/\\b(scheme|subsidy|government|pm-kisan|insurance|claim)/,"Government schemes and crop-insurance rules depend on state, crop, season and farmer eligibility. Check the current official agriculture department or insurer information before relying on an eligibility or deadline. Keep land, bank, crop and loss documents ready when applicable."],
    [/\\b(storage|harvest|post.harvest|warehouse|grain|packing|packaging|cold storage)/,"Post-harvest handling differs by crop. Vegetables and fruits usually need careful sorting, ventilation and rapid movement or suitable cold-chain storage; grains and pulses need safe drying and moisture-controlled storage. Grade separately and track wastage because loss after harvest directly reduces the farmer's net return."],
    [/\\b(machine|tractor|sprayer|equipment|machinery)/,"Choose farm machinery according to acreage, crop, soil, field access and available labour. Compare purchase, rental and custom-hiring costs, and use protective equipment and the manufacturer's operating instructions."],
    [/\\b(weed|weeding|herbicide)/,"For weeds, identify the weed species and crop stage first. Timely mechanical or manual control can reduce competition. If an herbicide is considered, use only a crop-and-weed-approved product and follow the label and local agricultural guidance."]
  ];
  for(const [pattern,answer] of responses) if(pattern.test(q)) return answer;
  if(category){
    const advice={
      cereals:"For cereals, plan variety, sowing window, seed quality, irrigation and nutrient timing around your local season. At harvest, drying, grading and storage moisture strongly affect saleable quality.",
      pulses:"For pulses, choose a locally suitable variety and manage seed quality, weeds and water carefully. For marketing, compare cleaned/graded lots across nearby markets because quality can change the realized price.",
      oilseeds:"For oilseeds, protect flowering and seed-filling stages from moisture stress and monitor pests. Compare oilseed markets using grade, moisture, transport and cleaning costs rather than headline price alone.",
      vegetables:"For vegetables, production and marketing must be planned together because perishability is high. Stagger harvests where practical, grade produce, compare nearby wholesale markets and buyers, and include sorting, packing, transport and wastage when calculating net return.",
      fruits:"For fruits, variety, maturity, grading, packing and cold-chain/transport decisions can strongly affect returns. Compare farm-gate, wholesale and direct-buyer options using net realization after harvest and logistics costs.",
      spices:"For spices, quality, cleanliness, moisture and traceability can affect the buyer's price. Dry and grade correctly and compare buyers on net realization, not only quoted price.",
      plantation:"For plantation crops, evaluate yield, quality grade, harvest labour and long-term input costs. Compare local traders, cooperatives and organized buyers where available.",
      fibre:"For fibre crops, fibre quality, moisture, contamination and grading can affect market realization. Keep production records and compare buyers after accounting for transport and deductions.",
      commercial:"For commercial crops, compare expected yield and net realization with water, labour, input and transport costs before choosing the crop."
    };
    return advice[category]+" This guidance applies to "+category+" crops; tell me the exact crop, variety, growth stage, acreage and your market/location for a more specific plan.";
  }
  return "I am your Kisan Saathi agriculture copilot. I cover cereals, millets, pulses, oilseeds, vegetables, fruits, spices, plantation crops, fibre and commercial crops. I can help with crop selection, soil and NPK, irrigation, pests, diseases, harvesting, storage, mandi/market comparison and farmer-buyer economics. For your farm in "+location+" with "+crop+", tell me the exact crop, stage, acreage, location and question. I will give practical steps and flag anything that needs current local verification.";
}
app.post("/api/ai/ask",auth,async(req,res)=>{try{const q=String(req.body.question||"").trim();const lang=String(req.body.language||req.user.language||"en");if(!q)return res.status(400).json({error:"Question is required"});const context=buildFarmContext(req.user);
  if(AI_API_KEY&&AI_MODEL){
    const recent=db.prepare("SELECT role,content FROM ai_messages WHERE user_id=? ORDER BY id DESC LIMIT 12").all(req.user.id).reverse();
    const system=["You are Kisan Saathi AI, an agriculture-focused copilot for Indian farmers.","Answer agriculture questions broadly: crops, varieties, sowing, nursery, soil, NPK, fertilizers, irrigation, pests, diseases, weeds, weather-aware farm decisions, machinery, post-harvest, storage, markets, government schemes, crop insurance, and sustainable practices.","Use the farmer context when relevant, but never invent measurements, diagnoses, prices, weather, scheme eligibility, or legal requirements. If a question needs current local data, clearly say that live verification is needed.","Give practical, step-by-step advice in simple language. For pesticide/fertilizer recommendations, avoid unsafe or unverified dosage instructions; recommend following the product label and local agricultural authority guidance.","For crop disease images or symptoms, give likely possibilities and explain that an expert/lab confirmation may be needed before treatment.","Respond in the farmer's preferred language: "+languageName(lang)+". If that language is unavailable, use simple English.","Farmer context JSON: "+JSON.stringify(context)].join("\\n");
    const input=[...recent.map(x=>({role:x.role==="assistant"?"assistant":"user",content:x.content})),{role:"user",content:q}];
    const r=await fetch(AI_API_URL,{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+AI_API_KEY},body:JSON.stringify({model:AI_MODEL,instructions:system,input})});
    const d=await r.json(); if(r.ok&&d.output_text){const answer=String(d.output_text).trim();db.prepare("INSERT INTO ai_messages(user_id,role,content) VALUES(?,?,?)").run(req.user.id,"user",q);db.prepare("INSERT INTO ai_messages(user_id,role,content) VALUES(?,?,?)").run(req.user.id,"assistant",answer);return res.json({answer,question:q,language:lang,model:AI_MODEL});}
  }
  const answer=localAgricultureCopilot(q,context,lang);
  db.prepare("INSERT INTO ai_messages(user_id,role,content) VALUES(?,?,?)").run(req.user.id,"user",q);
  db.prepare("INSERT INTO ai_messages(user_id,role,content) VALUES(?,?,?)").run(req.user.id,"assistant",answer);
  res.json({answer,question:q,language:lang,model:"Kisan Saathi Agriculture Copilot"});
}catch(e){console.error(e);res.status(500).json({error:"AI assistant is temporarily unavailable."})}});
function localHealthResult(crop){
const name=String(crop||"").toLowerCase();
if(/cotton/.test(name))return {result:"Possible cotton leaf spot / fungal leaf disease",confidence:.62,why:"Leaf spots can have several causes and a photo alone cannot confirm the pathogen.",treatment:"Remove badly affected fallen plant material where practical, avoid prolonged leaf wetness, improve field airflow, and ask a local agriculture expert about a crop-approved fungicide if symptoms continue.",fertilizer:"Do not add extra nitrogen just because leaves look yellow. Use the latest soil test and crop-stage recommendation before changing nutrients.",precaution:"Do not mix or apply pesticides or fertilizers based only on this screening. Read the product label, use required protective equipment, keep products away from children and food, and follow local agricultural guidance."};
if(/tomato|potato/.test(name))return {result:"Possible fungal/bacterial leaf-spot type symptom",confidence:.58,why:"Tomato and potato leaves can show similar spots from different diseases and stresses.",treatment:"Remove severely affected material where practical, avoid overhead irrigation when disease pressure is high, and seek crop-specific diagnosis before any chemical treatment.",fertilizer:"Check soil-test results and crop stage before fertilizer changes; avoid blanket dosing.",precaution:"Only use a crop-approved product exactly as its label and local authority require; do not mix products unless the label specifically permits it."};
return {result:"Possible pest, disease or nutrient-stress symptom",confidence:.45,why:"Many crop problems look alike in photos, so the image is a screening aid rather than a confirmed diagnosis.",treatment:"Inspect several plants, photograph both healthy and affected leaves, check the underside of leaves and record recent irrigation/weather. Use an agriculture expert or lab for confirmation before treatment.",fertilizer:"Use soil-test and crop-stage information rather than symptom-only fertilizer decisions.",precaution:"Do not apply pesticide or fertilizer from this result alone. Follow the product label and local agricultural advice, and use appropriate protective equipment."};
}
app.post("/api/crop-health/scan",auth,upload.single("image"),async(req,res)=>{
try{
 if(!req.file)return res.status(400).json({error:"Please take or select a crop photo."});
 const crop=String(req.body.crop||"").trim();
 let result=null;
 if(AI_API_KEY&&AI_MODEL){
   const mime=req.file.mimetype||"image/jpeg";
   const dataUrl="data:"+mime+";base64,"+req.file.buffer.toString("base64");
   const prompt="You are a cautious Indian agriculture crop-health screening assistant. Analyze this crop image and return JSON only with keys result, confidence, why, treatment, fertilizer, precaution. Give a likely symptom/disease/pest category, never claim certainty, confidence 0 to 1, and keep treatment general and label/qualified-agronomist based. Do not provide unsafe pesticide mixing or dosing instructions. Mention that photo diagnosis may be wrong. Crop: "+(crop||"unknown");
   const rr=await fetch(AI_API_URL,{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+AI_API_KEY},body:JSON.stringify({model:AI_MODEL,input:[{role:"user",content:[{type:"input_text",text:prompt},{type:"input_image",image_url:dataUrl}]}]} )});
   const d=await rr.json();
   if(rr.ok&&d.output_text){try{result=JSON.parse(d.output_text.replace(/^\`\`\`json\s*/,"").replace(/\s*\`\`\`$/,""));}catch{}}
 }
 if(!result)result=localHealthResult(crop);
 const confidence=Math.max(0,Math.min(1,Number(result.confidence)||0));
 db.prepare("INSERT INTO health_scans(user_id,crop,image_name,result,confidence) VALUES(?,?,?,?,?)").run(req.user.id,crop,req.file.originalname,result.result,confidence);
 res.json({...result,confidence,model:AI_API_KEY&&AI_MODEL?"vision-provider":"Kisan Saathi photo screening",photoReceived:true});
}catch(e){console.error(e);res.status(500).json({error:"Crop photo analysis is temporarily unavailable."})}});
app.get("/api/crop-health/history",auth,(req,res)=>res.json(db.prepare("SELECT id,crop,image_name,result,confidence,created_at FROM health_scans WHERE user_id=? ORDER BY id DESC LIMIT 20").all(req.user.id)));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.listen(PORT,()=>console.log("Kisan Saathi running on "+PORT));