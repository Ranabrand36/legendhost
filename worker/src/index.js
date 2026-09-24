const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const COOKIE = "lh_session";
const MAX_PROJECTS = 5;
const MAX_ZIP_BYTES = 20 * 1024 * 1024;
const MAX_FILES = 1000;
const MAX_FILE_BYTES = 25 * 1024 * 1024;
const SESSION_DAYS = 30;

// The schema is intentionally idempotent so a fresh D1 database can start working
// without requiring a separate first-time SQL command. It also matches schema.sql.
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
 expires_at TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS projects (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
 source_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', url TEXT, created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS deployments (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL, provider_deployment_id TEXT,
 status TEXT NOT NULL DEFAULT 'pending', url TEXT, created_at TEXT NOT NULL,
 FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS oauth_states (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider TEXT NOT NULL,
 expires_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS github_tokens (
 user_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id);
CREATE INDEX IF NOT EXISTS idx_deployments_project ON deployments(project_id);
CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions(token_hash);
`;
let schemaPromise;
async function ensureSchema(env) {
  if (!env.DB) throw new Error("D1 database binding DB is missing.");
  if (!schemaPromise) schemaPromise = env.DB.exec(SCHEMA_SQL).catch(e => { schemaPromise = null; throw e; });
  await schemaPromise;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try { return await api(request, env, ctx, url); }
      catch (e) {
        console.error("Legend Host API error:", e);
        return json({ error: safeError(e) }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  }
};

function safeError(e) {
  const message = String(e?.message || e || "Internal server error");
  if (/no such table|D1_ERROR|D1 database|binding/i.test(message)) return "Database is not ready yet. Please try again in a moment.";
  if (/api token|authentication|permission|forbidden/i.test(message)) return "Cloudflare deployment access is not configured yet.";
  return message.length > 180 ? "Internal server error." : message;
}

async function api(request, env, ctx, url) {
  const method = request.method;
  if (method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request, env) });
  if (url.pathname === "/api/health" && method === "GET") {
    try { await ensureSchema(env); return json({ ok: true, service: "Legend Host API", database: "ready" }); }
    catch (e) { return json({ ok: false, error: safeError(e) }, 503); }
  }
  if (url.pathname === "/api/auth/signup" && method === "POST") return signup(request, env);
  if (url.pathname === "/api/auth/login" && method === "POST") return login(request, env);
  if (url.pathname === "/api/auth/logout" && method === "POST") return logout(request, env);
  if (url.pathname === "/api/auth/me" && method === "GET") return me(request, env);

  const user = await requireUser(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401);

  if (url.pathname === "/api/config/status" && method === "GET") return configStatus(env);
  if (url.pathname === "/api/projects" && method === "GET") return listProjects(user, env);
  if (url.pathname === "/api/projects" && method === "POST") return createProject(request, user, env);
  if (url.pathname === "/api/deployments" && method === "POST") return deployUpload(request, user, env);
  if (url.pathname.startsWith("/api/projects/") && method === "DELETE") return deleteProject(request, user, env, url);
  if (url.pathname.startsWith("/api/projects/") && url.pathname.endsWith("/deployments") && method === "GET") return listDeployments(user, env, url);
  if (url.pathname.startsWith("/api/deployments/") && method === "GET") return deploymentInfo(user, env, url);

  if (url.pathname === "/api/github/start" && method === "GET") return githubStart(request, env, user);
  if (url.pathname === "/api/github/callback" && method === "GET") return githubCallback(request, env, url);
  if (url.pathname === "/api/github/repos" && method === "GET") return githubRepos(request, env, user);
  if (url.pathname === "/api/github/deploy" && method === "POST") return githubDeploy(request, env, user);

  return json({ error: "Not found" }, 404);
}

function json(data, status=200, extra={}) {
  const h = new Headers(JSON_HEADERS);
  for (const [k,v] of Object.entries(extra)) h.set(k,v);
  return new Response(JSON.stringify(data), { status, headers: h });
}
function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = env.APP_ORIGIN || origin || "null";
  return { "access-control-allow-origin": allowed, "access-control-allow-credentials": "true", "access-control-allow-headers": "content-type", "access-control-allow-methods": "GET,POST,DELETE,OPTIONS", "vary": "Origin" };
}
function cleanName(s) { return String(s||"").trim().replace(/[^a-zA-Z0-9 _.-]/g, "").slice(0,50); }
function slugify(s) { const x=String(s||"").toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-+|-+$/g,"").slice(0,40); return x || `site-${crypto.randomUUID().slice(0,8)}`; }
function now(){return new Date().toISOString();}
function bytesToHex(b){return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");}
function b64url(bytes){let s="";for(const b of new Uint8Array(bytes))s+=String.fromCharCode(b);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");}
function hexToBytes(hex){const a=new Uint8Array(hex.length/2);for(let i=0;i<a.length;i++)a[i]=parseInt(hex.slice(i*2,i*2+2),16);return a;}
async function pbkdf2(password, saltHex, iterations=210000) {
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:hexToBytes(saltHex),iterations,hash:"SHA-256"},key,256);
  return bytesToHex(bits);
}
async function passwordHash(password){const salt=bytesToHex(crypto.getRandomValues(new Uint8Array(16)));return `pbkdf2$210000$${salt}$${await pbkdf2(password,salt)}`;}
async function passwordVerify(password,stored){const [,it,salt,hash]=String(stored).split("$");if(!it||!salt||!hash)return false;return timingEqual(await pbkdf2(password,salt,Number(it)),hash);}
function timingEqual(a,b){if(a.length!==b.length)return false;let x=0;for(let i=0;i<a.length;i++)x|=a.charCodeAt(i)^b.charCodeAt(i);return x===0;}
async function tokenHash(token){return bytesToHex(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(token)));}
function cookie(name,value,maxAge){return `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`}
function getCookie(req,name){const m=(req.headers.get("Cookie")||"").match(new RegExp(`(?:^|; )${name}=([^;]+)`));return m?.[1]||null;}

async function signup(req,env){
  await ensureSchema(env);
  const body=await req.json().catch(()=>null); if(!body)return json({error:"Invalid JSON"},400);
  const name=cleanName(body.name), email=String(body.email||"").trim().toLowerCase(), password=String(body.password||"");
  if(name.length<2||name.length>50)return json({error:"Name must be 2-50 characters."},400);
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return json({error:"Enter a valid email."},400);
  if(password.length<8||password.length>128)return json({error:"Password must be 8-128 characters."},400);
  const exists=await env.DB.prepare("SELECT id FROM users WHERE email=?1").bind(email).first(); if(exists)return json({error:"Email is already registered."},409);
  const id=crypto.randomUUID(), hash=await passwordHash(password);
  await env.DB.prepare("INSERT INTO users(id,name,email,password_hash,created_at) VALUES(?,?,?,?,?)").bind(id,name,email,hash,now()).run();
  return issueSession(req,env,{id,name,email});
}
async function login(req,env){
  await ensureSchema(env);
  const body=await req.json().catch(()=>null); if(!body)return json({error:"Invalid JSON"},400);
  const email=String(body.email||"").trim().toLowerCase(), password=String(body.password||"");
  const user=await env.DB.prepare("SELECT id,name,email,password_hash FROM users WHERE email=?1").bind(email).first();
  if(!user || !(await passwordVerify(password,user.password_hash)))return json({error:"Invalid email or password."},401);
  return issueSession(req,env,user);
}
async function issueSession(req,env,user){
  await ensureSchema(env);
  const raw=b64url(crypto.getRandomValues(new Uint8Array(32))), hash=await tokenHash(raw), id=crypto.randomUUID(), exp=new Date(Date.now()+SESSION_DAYS*86400000).toISOString();
  await env.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)").bind(id,user.id,hash,exp,now()).run();
  const r=json({user:{id:user.id,name:user.name,email:user.email}}); const h=new Headers(r.headers); h.append("Set-Cookie",cookie(COOKIE,raw,SESSION_DAYS*86400)); return new Response(r.body,{status:r.status,headers:h});
}
async function logout(req,env){await ensureSchema(env);const t=getCookie(req,COOKIE);if(t)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(await tokenHash(t)).run();return new Response(null,{status:204,headers:{"Set-Cookie":cookie(COOKIE,"",0)}});}
async function requireUser(req,env){await ensureSchema(env);const t=getCookie(req,COOKIE);if(!t)return null;const h=await tokenHash(t);const row=await env.DB.prepare("SELECT u.id,u.name,u.email,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?1").bind(h).first();if(!row)return null;if(row.expires_at<now()){await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(h).run();return null;}return row;}
async function me(req,env){const u=await requireUser(req,env);return u?json({user:{id:u.id,name:u.name,email:u.email}}):json({user:null},200);}
async function configStatus(env){return json({cloudflare:!!(env.CLOUDFLARE_API_TOKEN&&env.CLOUDFLARE_ACCOUNT_ID),github:!!(env.GITHUB_CLIENT_ID&&env.GITHUB_CLIENT_SECRET&&env.GITHUB_REDIRECT_URI),appOrigin:!!env.APP_ORIGIN});}

async function listProjects(user,env){const rows=await env.DB.prepare("SELECT id,name,slug,source_type,status,url,created_at FROM projects WHERE user_id=?1 ORDER BY created_at DESC").bind(user.id).all();return json({projects:rows.results||[]});}
async function createProject(req,user,env){const body=await req.json().catch(()=>null);const name=cleanName(body?.name);if(name.length<2)return json({error:"Project name is required."},400);const c=await env.DB.prepare("SELECT COUNT(*) AS n FROM projects WHERE user_id=?1").bind(user.id).first();if(Number(c.n)>=MAX_PROJECTS)return json({error:`Free limit: ${MAX_PROJECTS} projects per account.`},429);let slug=slugify(name);for(let i=0;i<5;i++){const x=await env.DB.prepare("SELECT id FROM projects WHERE slug=?1").bind(slug).first();if(!x)break;slug=`${slugify(name)}-${Math.random().toString(36).slice(2,6)}`;}const id=crypto.randomUUID();await env.DB.prepare("INSERT INTO projects(id,user_id,name,slug,source_type,status,created_at) VALUES(?,?,?,?,?,?,?)").bind(id,user.id,name,slug,body?.source_type||"upload","pending",now()).run();return json({project:{id,name,slug,status:"pending"}},201);}

async function cfFetch(path,env,init={}){
  if(!env.CLOUDFLARE_API_TOKEN||!env.CLOUDFLARE_ACCOUNT_ID)throw new Error("Cloudflare deployment access is not configured yet.");
  const h=new Headers(init.headers||{});h.set("Authorization",`Bearer ${env.CLOUDFLARE_API_TOKEN}`);h.set("Content-Type",h.get("Content-Type")||"application/json");
  const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}${path}`,{...init,headers:h});const data=await r.json().catch(()=>({}));if(!r.ok||data.success===false)throw new Error(data?.errors?.[0]?.message||`Cloudflare API ${r.status}`);return data;
}
async function ensurePagesProject(project,env){
  const path=`/pages/projects/${encodeURIComponent(project.slug)}`;
  try{return await cfFetch(path,env)}catch(e){
    if(!/not found|404/i.test(e.message))throw e;
    return await cfFetch("/pages/projects",env,{method:"POST",body:JSON.stringify({name:project.slug,production_branch:"main",build_config:{build_command:"",destination_dir:""}})});
  }
}
async function deployUpload(req,user,env){
  if(!env.CLOUDFLARE_API_TOKEN||!env.CLOUDFLARE_ACCOUNT_ID)return json({error:"Cloudflare deployment access is not configured yet."},503);
  const form=await req.formData();const projectId=String(form.get("project_id")||"");const manifestRaw=String(form.get("manifest")||"");
  const project=await env.DB.prepare("SELECT * FROM projects WHERE id=?1 AND user_id=?2").bind(projectId,user.id).first();if(!project)return json({error:"Project not found."},404);
  let manifest;try{manifest=JSON.parse(manifestRaw)}catch{return json({error:"Invalid deployment manifest."},400)}
  if(!Array.isArray(manifest.files)||manifest.files.length===0||manifest.files.length>MAX_FILES)return json({error:"Invalid file list."},400);
  const files=[];for(let i=0;i<manifest.files.length;i++){const f=form.get(`file_${i}`);if(!(f instanceof File))return json({error:`Missing file ${i}.`},400);if(f.size>MAX_FILE_BYTES)return json({error:`File too large: ${f.name}`},413);files.push(f);}
  const result=await deployFilesToPages(project,manifest.files,files,env);const status=result.status||"deploying";
  await env.DB.prepare("UPDATE projects SET status=?1,url=?2 WHERE id=?3 AND user_id=?4").bind(status === "success" ? "live" : "deploying",result.url,project.id,user.id).run();
  await env.DB.prepare("INSERT INTO deployments(id,project_id,provider_deployment_id,status,url,created_at) VALUES(?,?,?,?,?,?)").bind(crypto.randomUUID(),project.id,result.id,status,result.url,now()).run();
  return json({ok:true,url:result.url,deployment_id:result.id,status});
}
async function deployFilesToPages(project,metaFiles,files,env){
  const projectData=await ensurePagesProject(project,env);const uploadToken=await cfFetch(`/pages/projects/${encodeURIComponent(project.slug)}/upload-token`,env);const jwt=uploadToken.result.jwt;
  const manifest={};const byHash=new Map();
  for(let i=0;i<files.length;i++){const path="/"+String(metaFiles[i].path).replace(/^\/+/,"");if(path.includes("..")||path.includes("\\")||path.startsWith("//"))throw new Error("Invalid file path");const buf=await files[i].arrayBuffer();const full=new Uint8Array(await crypto.subtle.digest("SHA-256",buf));const hash=bytesToHex(full).slice(0,32);manifest[path]={hash,size:buf.byteLength};byHash.set(hash,{buf,contentType:files[i].type||mime(path)});}
  if(!manifest["/index.html"])throw new Error("index.html is required at the website root.");
  const missing=await cfAssetJson("/pages/assets/check-missing",jwt,{hashes:Object.values(manifest).map(x=>x.hash)},env);const missingSet=new Set(missing.result||[]);let batch=[];let batchBytes=0;
  for(const [hash,item] of byHash){if(!missingSet.has(hash))continue;const encoded=await toBase64(item.buf);batch.push({base64:true,key:hash,metadata:{contentType:item.contentType},value:encoded});batchBytes+=encoded.length;if(batch.length>=10||batchBytes>=8*1024*1024){await uploadAssetBatch(batch,jwt,env);batch=[];batchBytes=0;}}
  if(batch.length)await uploadAssetBatch(batch,jwt,env);
  const fd=new FormData();fd.append("manifest",JSON.stringify(manifest));const dep=await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/pages/projects/${encodeURIComponent(project.slug)}/deployments`,{method:"POST",headers:{Authorization:`Bearer ${env.CLOUDFLARE_API_TOKEN}`},body:fd});const d=await dep.json().catch(()=>({}));if(!dep.ok||d.success===false)throw new Error(d?.errors?.[0]?.message||"Deployment failed");
  return {id:d.result.id,url:d.result.url||d.result.aliases?.[0]||projectData.result?.subdomain||null,status:d.result.latest_stage?.status||"deploying"};
}
async function uploadAssetBatch(batch,jwt,env){const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/pages/assets/upload`,{method:"POST",headers:{Authorization:`Bearer ${jwt}`,"Content-Type":"application/json"},body:JSON.stringify(batch)});const d=await r.json().catch(()=>({}));if(!r.ok||d.success===false)throw new Error(d?.errors?.[0]?.message||"Asset upload failed");}
async function cfAssetJson(path,jwt,body,env){const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}${path}`,{method:"POST",headers:{Authorization:`Bearer ${jwt}`,"Content-Type":"application/json"},body:JSON.stringify(body)});const d=await r.json().catch(()=>({}));if(!r.ok||d.success===false)throw new Error(d?.errors?.[0]?.message||"Cloudflare asset request failed");return d;}
async function toBase64(buf){let s="";const b=new Uint8Array(buf);const chunk=0x8000;for(let i=0;i<b.length;i+=chunk)s+=String.fromCharCode(...b.subarray(i,i+chunk));return btoa(s);}
function mime(path){const x=path.toLowerCase().split(".").pop();return ({html:"text/html",css:"text/css",js:"application/javascript",json:"application/json",svg:"image/svg+xml",png:"image/png",jpg:"image/jpeg",jpeg:"image/jpeg",gif:"image/gif",webp:"image/webp",ico:"image/x-icon",txt:"text/plain",xml:"application/xml",woff:"font/woff",woff2:"font/woff2"})[x]||"application/octet-stream";}

async function deleteProject(req,user,env,url){const id=url.pathname.split("/")[3];const p=await env.DB.prepare("SELECT * FROM projects WHERE id=?1 AND user_id=?2").bind(id,user.id).first();if(!p)return json({error:"Project not found."},404);if(env.CLOUDFLARE_API_TOKEN&&env.CLOUDFLARE_ACCOUNT_ID){try{await cfFetch(`/pages/projects/${encodeURIComponent(p.slug)}`,env,{method:"DELETE"});}catch(e){console.warn(e.message)}}await env.DB.prepare("DELETE FROM deployments WHERE project_id=?1").bind(id).run();await env.DB.prepare("DELETE FROM projects WHERE id=?1 AND user_id=?2").bind(id,user.id).run();return new Response(null,{status:204});}
async function listDeployments(user,env,url){const id=url.pathname.split("/")[3];const p=await env.DB.prepare("SELECT id,slug FROM projects WHERE id=?1 AND user_id=?2").bind(id,user.id).first();if(!p)return json({error:"Project not found."},404);const rows=await env.DB.prepare("SELECT id,provider_deployment_id,status,url,created_at FROM deployments WHERE project_id=?1 ORDER BY created_at DESC").bind(id).all();return json({deployments:rows.results||[]});}
async function deploymentInfo(user,env,url){const did=url.pathname.split("/")[3];const d=await env.DB.prepare("SELECT d.*,p.slug FROM deployments d JOIN projects p ON p.id=d.project_id WHERE d.id=?1 AND p.user_id=?2").bind(did,user.id).first();if(!d)return json({error:"Deployment not found."},404);if(!d.provider_deployment_id)return json({deployment:d});const data=await cfFetch(`/pages/projects/${encodeURIComponent(d.slug)}/deployments/${encodeURIComponent(d.provider_deployment_id)}`,env);return json({deployment:d,provider:data.result});}

function githubSecret(env){return env.APP_ENCRYPTION_KEY||env.GITHUB_CLIENT_SECRET||null;}
async function deriveGithubKey(env){const secret=githubSecret(env);if(!secret)throw new Error("GitHub encryption secret is not configured yet.");const raw=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(secret));return crypto.subtle.importKey("raw",raw,{name:"AES-GCM"},false,["encrypt","decrypt"]);}
async function encryptToken(token,env){const key=await deriveGithubKey(env);const iv=crypto.getRandomValues(new Uint8Array(12));const data=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,new TextEncoder().encode(token));const out=new Uint8Array(iv.byteLength+data.byteLength);out.set(iv);out.set(new Uint8Array(data),iv.byteLength);return b64url(out);}
function b64decode(s){s=s.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";const bin=atob(s);return Uint8Array.from(bin,c=>c.charCodeAt(0));}
async function decryptToken(cipher,env){const key=await deriveGithubKey(env);const raw=b64decode(cipher);const iv=raw.slice(0,12),data=raw.slice(12);const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,data);return new TextDecoder().decode(plain);}
async function githubStart(req,env,user){if(!env.GITHUB_CLIENT_ID||!env.GITHUB_CLIENT_SECRET||!env.GITHUB_REDIRECT_URI)return json({error:"GitHub integration is not configured yet."},503);await ensureSchema(env);const state=b64url(crypto.getRandomValues(new Uint8Array(24)));await env.DB.prepare("INSERT INTO oauth_states(id,user_id,provider,expires_at) VALUES(?,?,?,?)").bind(state,user.id,"github",new Date(Date.now()+10*60*1000).toISOString()).run();const u=new URL("https://github.com/login/oauth/authorize");u.searchParams.set("client_id",env.GITHUB_CLIENT_ID);u.searchParams.set("redirect_uri",env.GITHUB_REDIRECT_URI);u.searchParams.set("scope","read:user repo");u.searchParams.set("state",state);return Response.redirect(u.toString(),302);}
async function githubCallback(req,env,url){if(!env.GITHUB_CLIENT_ID||!env.GITHUB_CLIENT_SECRET||!env.GITHUB_REDIRECT_URI)return new Response("GitHub integration is not configured yet",{status:503});const state=url.searchParams.get("state"),code=url.searchParams.get("code");if(!state||!code)return new Response("Invalid OAuth callback",{status:400});const s=await env.DB.prepare("SELECT * FROM oauth_states WHERE id=?1 AND provider='github'").bind(state).first();if(!s||s.expires_at<now())return new Response("Expired OAuth state",{status:400});const tokenRes=await fetch("https://github.com/login/oauth/access_token",{method:"POST",headers:{Accept:"application/json","Content-Type":"application/json"},body:JSON.stringify({client_id:env.GITHUB_CLIENT_ID,client_secret:env.GITHUB_CLIENT_SECRET,code,redirect_uri:env.GITHUB_REDIRECT_URI})});const token=await tokenRes.json();if(!token.access_token)return new Response("GitHub authorization failed",{status:400});const encrypted=await encryptToken(token.access_token,env);await env.DB.prepare("INSERT INTO github_tokens(user_id,token_hash,created_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,created_at=excluded.created_at").bind(s.user_id,encrypted,now()).run();await env.DB.prepare("DELETE FROM oauth_states WHERE id=?1").bind(state).run();return Response.redirect(`${env.APP_ORIGIN||new URL(req.url).origin}/?github=connected`,302);}
async function githubToken(user,env){const row=await env.DB.prepare("SELECT token_hash FROM github_tokens WHERE user_id=?1").bind(user.id).first();return row?.token_hash?decryptToken(row.token_hash,env):null;}
async function githubRepos(req,env,user){const t=await githubToken(user,env);if(!t)return json({error:"Connect GitHub first."},401);const r=await fetch("https://api.github.com/user/repos?per_page=100&sort=updated",{headers:{Authorization:`Bearer ${t}`,Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"Legend-Host"}});const d=await r.json();if(!r.ok)return json({error:"GitHub request failed."},502);return json({repositories:(d||[]).map(x=>({id:x.id,name:x.full_name,default_branch:x.default_branch,private:x.private,html_url:x.html_url}))});}
async function githubDeploy(req,env,user){const t=await githubToken(user,env);if(!t)return json({error:"Connect GitHub first."},401);if(!env.CLOUDFLARE_API_TOKEN||!env.CLOUDFLARE_ACCOUNT_ID)return json({error:"Cloudflare deployment access is not configured yet."},503);const b=await req.json().catch(()=>null);if(!b?.name||!b?.repo_id||!b?.repo_name||!b?.branch)return json({error:"name, repo_id, repo_name and branch are required."},400);const c=await env.DB.prepare("SELECT COUNT(*) AS n FROM projects WHERE user_id=?1").bind(user.id).first();if(Number(c.n)>=MAX_PROJECTS)return json({error:`Free limit: ${MAX_PROJECTS} projects per account.`},429);const slug=slugify(b.name)+"-gh";const exists=await env.DB.prepare("SELECT id FROM projects WHERE slug=?1").bind(slug).first();if(exists)return json({error:"A GitHub project with this name already exists."},409);const data=await cfFetch("/pages/projects",env,{method:"POST",body:JSON.stringify({name:slug,production_branch:b.branch,source:{type:"github",config:{owner:b.repo_name.split("/")[0],repo_name:b.repo_name,repo_id:String(b.repo_id),production_branch:b.branch,production_deployments_enabled:true,preview_deployment_setting:"all"}}})});const r=data.result;const id=crypto.randomUUID();const live=r.subdomain?`https://${r.subdomain}`:null;await env.DB.prepare("INSERT INTO projects(id,user_id,name,slug,source_type,status,url,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(id,user.id,b.name,slug,"github","deploying",live,now()).run();return json({ok:true,project:{id,name:b.name,slug,source_type:"github",status:"deploying",url:live}});}
