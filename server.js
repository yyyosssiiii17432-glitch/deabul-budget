
const express=require("express");
const path=require("path");
const crypto=require("crypto");
const Database=require("better-sqlite3");
const cookieParser=require("cookie-parser");
const app=express();
const db=new Database(path.join(__dirname,"data.db"));
app.use(express.json({limit:"1mb"})); app.use(cookieParser()); app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,date TEXT NOT NULL,amount REAL NOT NULL,category TEXT NOT NULL,subcategory TEXT,payment TEXT,type TEXT,note TEXT,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS incomes(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,date TEXT NOT NULL,amount REAL NOT NULL,source TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS budgets(user_id INTEGER NOT NULL,category TEXT NOT NULL,amount REAL NOT NULL,PRIMARY KEY(user_id,category),FOREIGN KEY(user_id) REFERENCES users(id));
`);
const sessions=new Map();
const makeHash=p=>new Promise((resolve,reject)=>crypto.scrypt(p,"deabul-salt",64,(e,k)=>e?reject(e):resolve(k.toString("hex"))));
const auth=(req,res,next)=>{let uid=sessions.get(req.cookies.session);if(!uid)return res.status(401).json({error:"לא מחובר"});req.uid=uid;next()};

app.post("/api/register",async(req,res)=>{let {username,password}=req.body||{};username=(username||"").trim();if(username.length<3||!password||password.length<6)return res.status(400).json({error:"שם משתמש צריך 3 תווים לפחות וסיסמה 6 תווים לפחות"});try{let h=await makeHash(password);let x=db.prepare("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,datetime('now'))").run(username,h);let t=crypto.randomBytes(32).toString("hex");sessions.set(t,x.lastInsertRowid);res.cookie("session",t,{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production"});res.json({username})}catch(e){res.status(409).json({error:"שם המשתמש כבר קיים"})}});
app.post("/api/login",async(req,res)=>{let {username,password}=req.body||{};let u=db.prepare("SELECT * FROM users WHERE username=?").get((username||"").trim());if(!u)return res.status(401).json({error:"שם משתמש או סיסמה שגויים"});let h=await makeHash(password||"");if(h!==u.password_hash)return res.status(401).json({error:"שם משתמש או סיסמה שגויים"});let t=crypto.randomBytes(32).toString("hex");sessions.set(t,u.id);res.cookie("session",t,{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production"});res.json({username:u.username})});
app.post("/api/logout",(req,res)=>{sessions.delete(req.cookies.session);res.clearCookie("session");res.json({ok:true})});
app.get("/api/me",auth,(req,res)=>res.json(db.prepare("SELECT username,created_at FROM users WHERE id=?").get(req.uid)));
app.get("/api/data",auth,(req,res)=>{let e=db.prepare("SELECT * FROM expenses WHERE user_id=? ORDER BY date DESC,id DESC").all(req.uid),i=db.prepare("SELECT * FROM incomes WHERE user_id=? ORDER BY date DESC,id DESC").all(req.uid),b=db.prepare("SELECT category,amount FROM budgets WHERE user_id=?").all(req.uid);res.json({expenses:e,incomes:i,budgets:Object.fromEntries(b.map(x=>[x.category,x.amount]))})});
app.post("/api/expenses",auth,(req,res)=>{let x=req.body;if(!x.date||!x.amount||!x.category)return res.status(400).json({error:"חסרים נתונים"});let r=db.prepare("INSERT INTO expenses(user_id,date,amount,category,subcategory,payment,type,note,created_at) VALUES(?,?,?,?,?,?,?,?,datetime('now'))").run(req.uid,x.date,+x.amount,x.category,x.subcategory||"",x.payment||"",x.type||"משתנה",x.note||"");res.json({id:r.lastInsertRowid})});
app.delete("/api/expenses/:id",auth,(req,res)=>{db.prepare("DELETE FROM expenses WHERE id=? AND user_id=?").run(req.params.id,req.uid);res.json({ok:true})});
app.post("/api/incomes",auth,(req,res)=>{let x=req.body;if(!x.date||!x.amount||!x.source)return res.status(400).json({error:"חסרים נתונים"});db.prepare("INSERT INTO incomes(user_id,date,amount,source,created_at) VALUES(?,?,?,?,datetime('now'))").run(req.uid,x.date,+x.amount,x.source);res.json({ok:true})});
app.put("/api/budgets",auth,(req,res)=>{let {category,amount}=req.body;db.prepare("INSERT INTO budgets(user_id,category,amount) VALUES(?,?,?) ON CONFLICT(user_id,category) DO UPDATE SET amount=excluded.amount").run(req.uid,category,+amount||0);res.json({ok:true})});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(process.env.PORT||3000,()=>console.log("Deabul Budget Pro running"));
