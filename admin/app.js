'use strict';
/* ============================================================
   লাইসেন্স মেশিন — মাদরাসা ম্যানেজার
   GitHub Pages-এ চলা স্ট্যাটিক অ্যাডমিন প্যানেল।
   ডেটা: এই রিপোর data/*.json ফাইল (GitHub API দিয়ে পড়া/লেখা)
   স্বাক্ষর: Ed25519 (tweetnacl) — ডেস্কটপ অ্যাপের ed25519-dalek-এর সাথে সামঞ্জস্যপূর্ণ
   ============================================================ */

/* ---------- utils ---------- */
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const te = new TextEncoder(), td = new TextDecoder();
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const nowSec = () => Math.floor(Date.now() / 1000);
function hexOf(bytes){ return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join(''); }
function b64urlEncode(bytes){
  let s=''; const b=new Uint8Array(bytes);
  for(let i=0;i<b.length;i+=0x8000){ s += String.fromCharCode.apply(null, b.subarray(i,i+0x8000)); }
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlDecode(s){
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while(s.length%4) s+='=';
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
  return out;
}
function b64stdEncode(bytes){
  let s=''; const b=new Uint8Array(bytes);
  for(let i=0;i<b.length;i+=0x8000){ s += String.fromCharCode.apply(null, b.subarray(i,i+0x8000)); }
  return btoa(s);
}
function b64stdDecode(s){ // GitHub contents API -> standard base64
  const bin = atob(s.replace(/\n/g,''));
  const out = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
  return out;
}
async function sha256hex(str){
  const d = await crypto.subtle.digest('SHA-256', te.encode(str));
  return hexOf(new Uint8Array(d));
}
function randHex(nBytes){
  const b = new Uint8Array(nBytes); crypto.getRandomValues(b); return hexOf(b);
}
function fmtDate(ts){
  if(!ts) return '—';
  return new Date(ts*1000).toLocaleDateString('bn-BD',{year:'numeric',month:'long',day:'numeric'});
}
function fmtDateTime(ts){
  if(!ts) return '—';
  return new Date(ts*1000).toLocaleString('bn-BD',{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
}
function daysLeft(exp){
  if(!exp) return null;
  return Math.ceil((exp - nowSec())/86400);
}

/* ---------- config / session ---------- */
const CFG_KEY='lmg_cfg_v1';
const store = {
  cfg(){ try{ return JSON.parse(localStorage.getItem(CFG_KEY)); }catch(e){ return null; } },
  saveCfg(c){ localStorage.setItem(CFG_KEY, JSON.stringify(c)); },
  clearCfg(){ localStorage.removeItem(CFG_KEY); },
  user(){ try{ return JSON.parse(sessionStorage.getItem('lmg_user')); }catch(e){ return null; } },
  saveUser(u){ sessionStorage.setItem('lmg_user', JSON.stringify(u)); },
  clearUser(){ sessionStorage.removeItem('lmg_user'); }
};
const EXPECTED_PUBKEY = 'kJ7HQm8AiQUSdJTWU-4PXrodLm6DFEHI7ukN7Gv8wc4'; // licensing-client.json

/* ---------- GitHub API ---------- */
const GH = {
  base:'https://api.github.com',
  async api(path, method, body, token){
    const r = await fetch(this.base+path, {
      method: method||'GET',
      headers:{ 'Authorization':'Bearer '+token, 'Accept':'application/vnd.github+json', 'Content-Type':'application/json' },
      body: body ? JSON.stringify(body) : null
    });
    let data=null; try{ data=await r.json(); }catch(e){}
    if(!r.ok){ const e=new Error((data&&data.message)||('GitHub ত্রুটি (HTTP '+r.status+')')); e.status=r.status; throw e; }
    return data;
  },
  async me(token){ return this.api('/user','GET',null,token); },
  async getFile(owner, repo, path, token){
    try{
      const d = await this.api('/repos/'+owner+'/'+repo+'/contents/'+path,'GET',null,token);
      if(d.type!=='file'||!d.content) return null;
      return { sha:d.sha, content: td.decode(b64stdDecode(d.content)) };
    }catch(e){ if(e.status===404) return null; throw e; }
  },
  async putFile(owner, repo, path, content, token, message){
    let sha=null;
    const cur = await this.getFile(owner,repo,path,token);
    if(cur) sha=cur.sha;
    for(let i=0;i<3;i++){
      try{
        const body={ message:message, content: b64stdEncode(te.encode(content)) };
        if(sha) body.sha=sha;
        return await this.api('/repos/'+owner+'/'+repo+'/contents/'+path,'PUT',body,token);
      }catch(e){
        if((e.status===422||e.status===409)&&i<2){
          const fresh=await this.getFile(owner,repo,path,token);
          sha=fresh?fresh.sha:null; continue;
        }
        throw e;
      }
    }
  }
};

/* ---------- crypto (Ed25519) ---------- */
function keypairFromSeedB64(seedB64){
  const seed=b64urlDecode((seedB64||'').trim());
  if(seed.length!==32) throw new Error('গোপন বীজ ৩২ বাইটের হতে হবে।');
  return nacl.sign.keyPair.fromSeed(seed);
}
function pubkeyOfSeedB64(seedB64){ return b64urlEncode(keypairFromSeedB64(seedB64).publicKey); }
function parseOwnerKey(text){
  const t=(text||'').trim();
  if(!t) throw new Error('Owner-Key.json-এর পুরো লেখা পেস্ট করুন।');
  let obj;
  try{ obj=JSON.parse(t); }catch(e){ throw new Error('JSON ঠিকমতো পেস্ট হয়নি। Owner-Key.json ফাইলটা নোটপ্যাডে খুলে পুরো লেখা কপি করে পেস্ট করুন।'); }
  const seedB64 = obj.secret_seed || obj.secretSeed || obj.seed;
  if(!seedB64) throw new Error('ফাইলে secret_seed পাওয়া যায়নি।');
  const pub = pubkeyOfSeedB64(seedB64);
  if(pub!==EXPECTED_PUBKEY) throw new Error('এই চাবি বর্তমান মাদরাসা ম্যানেজারের সাথে মেলে না। সঠিক Owner-Key.json দিন।');
  return seedB64;
}

/* ডেস্কটপ অ্যাপের (Rust serde) সাথে হুবহু মিল রেখে লাইসেন্স তৈরি */
function normalizeDeviceCode(code){
  let c=String(code||'').trim().toUpperCase();
  if(c.startsWith('MM-PC-')) c=c.slice(6);
  c=c.toLowerCase();
  if(!/^[0-9a-f]{64}$/.test(c)) throw new Error('ডিভাইস কোড সঠিক নয়। MM-PC- দিয়ে শুরু ৬৪ অক্ষরের কোড দিন।');
  return c;
}
function buildLicense(o){
  const customer=String(o.customer||'').trim();
  if(!customer) throw new Error('গ্রাহকের নাম দিন।');
  if(customer.length>512) throw new Error('নাম ৫১২ অক্ষরের বেশি হবে না।');
  const deviceId=normalizeDeviceCode(o.deviceCode);
  const days=(o.days==null?'lifetime':o.days);
  if(days!=='lifetime'&&(days<1||days>3650)) throw new Error('মেয়াদ ১–৩৬৫০ দিনের মধ্যে দিন অথবা আজীবন।');
  const licenseId=randHex(16);
  const now=o.nowSecOverride||nowSec();
  const expiresAt=days==='lifetime'?null:now+days*86400;
  // Rust struct field order: v, product, license_id, customer_name, device_id, issued_at, expires_at
  const claim={v:1,product:'madrasa-manager',license_id:licenseId,customer_name:customer,device_id:deviceId,issued_at:now,expires_at:expiresAt};
  const payload=te.encode(JSON.stringify(claim));
  const kp=keypairFromSeedB64(o.seedB64);
  const sig=nacl.sign.detached(payload,kp.secretKey);
  const key='MM1.'+b64urlEncode(payload)+'.'+b64urlEncode(sig);
  return { key:key, license_id:licenseId, customer_name:customer, device_code:'MM-PC-'+deviceId,
           days:days, issued_at:now, expires_at:expiresAt };
}
/* বাতিল তালিকার স্বাক্ষর — ফরম্যাট data/SPEC.md-তে নথিভুক্ত */
function buildRevocations(revokedIds, seedB64, issuedAt){
  const sorted=Array.from(new Set(revokedIds)).sort();
  const payload=te.encode(JSON.stringify({v:1,issued_at:issuedAt,revoked:sorted}));
  const kp=keypairFromSeedB64(seedB64);
  const sig=b64urlEncode(nacl.sign.detached(payload,kp.secretKey));
  return JSON.stringify({v:1,issued_at:issuedAt,revoked:sorted,signature:sig});
}

/* ---------- data layer ---------- */
const DB = {
  cfg:null,
  usersCache:null,
  licCache:null,
  init(){ this.cfg=store.cfg(); },
  gh(){ const c=this.cfg; return {owner:c.owner, repo:c.repo, token:c.token}; },
  async loadUsers(force){
    if(this.usersCache&&!force) return this.usersCache;
    const g=this.gh();
    const f=await GH.getFile(g.owner,g.repo,'data/users.json',g.token);
    this.usersCache=f?JSON.parse(f.content):null;
    return this.usersCache;
  },
  async saveUsers(users){
    const g=this.gh();
    await GH.putFile(g.owner,g.repo,'data/users.json',JSON.stringify(users,null,2),g.token,'Update users.json');
    this.usersCache=users;
  },
  async loadLicenses(force){
    if(this.licCache&&!force) return this.licCache;
    const g=this.gh();
    const f=await GH.getFile(g.owner,g.repo,'data/licenses.json',g.token);
    this.licCache=f?JSON.parse(f.content):[];
    return this.licCache;
  },
  async saveLicenses(list){
    const g=this.gh();
    await GH.putFile(g.owner,g.repo,'data/licenses.json',JSON.stringify(list,null,2),g.token,'Update licenses.json');
    this.licCache=list;
  },
  async publishRevocations(){
    const g=this.gh();
    const list=await this.loadLicenses();
    const revoked=list.filter(l=>l.status==='revoked').map(l=>l.license_id);
    if(!this.cfg.seedB64) throw new Error('স্বাক্ষরের জন্য গোপন চাবি যোগ করুন (সেটিংস থেকে)।');
    const body=buildRevocations(revoked,this.cfg.seedB64,nowSec());
    await GH.putFile(g.owner,g.repo,'revocations.json',body,g.token,'Publish signed revocation list');
  }
};

/* ---------- rendering helpers ---------- */
const app=$('#app');
function showErr(msg){ const e=$('#form-err'); if(e){ e.textContent=msg; e.style.display='block'; } }
function hideErr(){ const e=$('#form-err'); if(e){ e.style.display='none'; } }
function btnBusy(btn,busy,label){
  if(busy){ btn.dataset.label=btn.textContent; btn.textContent=(label||'কাজ চলছে…'); btn.disabled=true; }
  else{ btn.textContent=btn.dataset.label||btn.textContent; btn.disabled=false; }
}
function statusBadge(l){
  if(l.status==='revoked') return '<span class="badge off">বাতিল</span>';
  const dl=daysLeft(l.expires_at);
  if(dl!==null&&dl<0) return '<span class="badge off">মেয়াদোত্তীর্ণ</span>';
  return '<span class="badge on">সক্রিয়</span>';
}
function validityText(l){
  if(l.days==='lifetime'||l.expires_at==null) return 'আজীবন';
  return l.days+' দিন ('+fmtDate(l.expires_at)+' পর্যন্ত)';
}

/* ---------- view: first-run token setup ---------- */
function vSetupToken(){
  app.innerHTML=
  '<div class="auth-wrap"><div class="auth-card">'+
  '<img class="logo" src="logo.webp" alt="logo">'+
  '<h1>লাইসেন্স মেশিন</h1><p class="sub">মাদরাসা ম্যানেজার — লাইসেন্স ব্যবস্থাপনা</p>'+
  '<span class="step-badge">সেটআপ ধাপ ১/২</span><h2>GitHub সংযোগ</h2>'+
  '<p class="hint">ডেটা GitHub রিপোতে সংরক্ষিত হবে। একবার টোকেন দিলেই হবে।</p>'+
  '<div id="form-err" class="err" style="display:none"></div>'+
  '<label class="f">GitHub Personal Access Token (classic, repo scope)</label>'+
  '<input type="password" id="in-token" placeholder="ghp_xxxxxxxxxxxx" autocomplete="off">'+
  '<div class="hint">github.com → Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new → <b>repo</b> টিক দিন → Generate → কপি করে এখানে পেস্ট করুন।</div>'+
  '<label class="f">Repo Owner (username)</label><input type="text" id="in-owner" placeholder="heraralo24bd-cmyk">'+
  '<label class="f">Repo নাম</label><input type="text" id="in-repo" value="madrasa-licenses">'+
  '<div class="row-btns"><button class="btn btn-primary" id="btn-go">সংযোগ করুন</button></div>'+
  '</div></div>';
  $('#btn-go').onclick=async (ev)=>{
    hideErr(); const btn=ev.target; btnBusy(btn,true);
    try{
      const token=$('#in-token').value.trim(), owner=$('#in-owner').value.trim(), repo=$('#in-repo').value.trim();
      if(!token||!owner||!repo) throw new Error('তিনটি ঘরই পূরণ করুন।');
      const me=await GH.me(token);
      const cfg={token:token,owner:owner,repo:repo,ghLogin:me.login,seedB64:null};
      store.saveCfg(cfg); DB.init();
      const users=await DB.loadUsers();
      if(users) vLogin(); else vSetupAdmin();
    }catch(e){ showErr(e.message||'সংযোগ হয়নি।'); }
    btnBusy(btn,false);
  };
}

/* ---------- view: create main admin ---------- */
function vSetupAdmin(){
  app.innerHTML=
  '<div class="auth-wrap"><div class="auth-card">'+
  '<img class="logo" src="logo.webp" alt="logo">'+
  '<h1>লাইসেন্স মেশিন</h1><p class="sub">মাদরাসা ম্যানেজার — লাইসেন্স ব্যবস্থাপনা</p>'+
  '<span class="step-badge">সেটআপ ধাপ ২/২</span><h2>মেইন অ্যাডমিন তৈরি</h2>'+
  '<div id="form-err" class="err" style="display:none"></div>'+
  '<label class="f">ইউজারনেম</label><input type="text" id="in-user" placeholder="admin" autocomplete="off">'+
  '<label class="f">পাসওয়ার্ড</label><input type="password" id="in-pass" autocomplete="new-password">'+
  '<label class="f">পাসওয়ার্ড আবার দিন</label><input type="password" id="in-pass2" autocomplete="new-password">'+
  '<label class="f">মালিকের গোপন চাবি (Owner-Key.json)</label>'+
  '<textarea id="in-key" placeholder=\'{"version":1,"secret_seed":"...","public_key":"..."}\'></textarea>'+
  '<div class="hint">License-Generator-এর ফোল্ডারে থাকা <b>Owner-Key.json</b> ফাইলটা নোটপ্যাডে খুলে পুরো লেখা কপি করে এখানে পেস্ট করুন। এই চাবি দিয়েই লাইসেন্সে স্বাক্ষর হবে।</div>'+
  '<div class="row-btns"><button class="btn btn-primary" id="btn-go">মেশিন চালু করুন</button></div>'+
  '</div></div>';
  $('#btn-go').onclick=async (ev)=>{
    hideErr(); const btn=ev.target; btnBusy(btn,true);
    try{
      const u=$('#in-user').value.trim(), p1=$('#in-pass').value, p2=$('#in-pass2').value;
      if(!u) throw new Error('ইউজারনেম দিন।');
      if(p1.length<6) throw new Error('পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের দিন।');
      if(p1!==p2) throw new Error('দুটি পাসওয়ার্ড মিলছে না।');
      const seedB64=parseOwnerKey($('#in-key').value);
      const salt=randHex(8);
      const users=[{username:u, salt:salt, pass_hash:await sha256hex(salt+':'+p1), role:'main', created_by:'system', created_at:nowSec()}];
      await DB.saveUsers(users);
      await DB.saveLicenses([]);
      DB.cfg.seedB64=seedB64; store.saveCfg(DB.cfg);
      vLogin('মেশিন প্রস্তুত! এখন লগইন করুন।');
    }catch(e){ showErr(e.message||'সেটআপ হয়নি।'); }
    btnBusy(btn,false);
  };
}

/* ---------- view: login ---------- */
function vLogin(notice){
  app.innerHTML=
  '<div class="auth-wrap"><div class="auth-card">'+
  '<img class="logo" src="logo.webp" alt="logo">'+
  '<h1>লাইসেন্স মেশিন</h1><p class="sub">মাদরাসা ম্যানেজার — লাইসেন্স ব্যবস্থাপনা</p>'+
  (notice?'<div class="ok">'+esc(notice)+'</div>':'')+
  '<div id="form-err" class="err" style="display:none"></div>'+
  '<label class="f">ইউজারনেম</label><input type="text" id="in-user" autocomplete="username">'+
  '<label class="f">পাসওয়ার্ড</label><input type="password" id="in-pass" autocomplete="current-password">'+
  '<div class="row-btns"><button class="btn btn-primary" id="btn-go">প্রবেশ করুন</button></div>'+
  '<p class="hint" style="text-align:center;margin-top:14px">ইউজারনেম-পাসওয়ার্ড মেইন অ্যাডমিনের কাছ থেকে নিন।</p>'+
  '</div></div>';
  const go=async ()=>{
    hideErr(); const btn=$('#btn-go'); btnBusy(btn,true);
    try{
      const u=$('#in-user').value.trim(), p=$('#in-pass').value;
      const users=await DB.loadUsers(true);
      const found=(users||[]).find(x=>x.username===u);
      if(!found) throw new Error('ইউজারনেম বা পাসওয়ার্ড ভুল।');
      const h=await sha256hex(found.salt+':'+p);
      if(h!==found.pass_hash) throw new Error('ইউজারনেম বা পাসওয়ার্ড ভুল।');
      store.saveUser({username:found.username, role:found.role});
      vShell('dashboard');
    }catch(e){ showErr(e.message||'লগইন হয়নি।'); }
    btnBusy(btn,false);
  };
  $('#btn-go').onclick=go;
  $('#in-pass').addEventListener('keydown',(e)=>{ if(e.key==='Enter') go(); });
}

/* ---------- shell ---------- */
let currentView='dashboard';
function vShell(view){
  currentView=view||'dashboard';
  const u=store.user();
  if(!u){ vLogin(); return; }
  const isMain=u.role==='main';
  const nav=[
    ['dashboard','ড্যাশবোর্ড'], ['licenses','লাইসেন্স তালিকা'], ['new','নতুন লাইসেন্স']
  ];
  if(isMain) nav.push(['users','ব্যবহারকারী']);
  nav.push(['settings','সেটিংস']);
  app.innerHTML=
  '<div class="shell">'+
  '<div class="topbar"><img class="logo" src="logo.webp" alt=""><div class="title">লাইসেন্স মেশিন<small>মাদরাসা ম্যানেজার</small></div>'+
  '<div class="spacer"></div><div class="who">স্বাগতম, <b>'+esc(u.username)+'</b> '+(isMain?'<span class="badge gold">মেইন অ্যাডমিন</span>':'<span class="badge on">সাব অ্যাডমিন</span>')+'</div></div>'+
  '<div class="nav">'+nav.map(n=>'<button data-v="'+n[0]+'" class="'+(currentView===n[0]?'active':'')+'">'+n[1]+'</button>').join('')+'</div>'+
  '<div class="main" id="view"></div>'+
  '<div class="footer-note">অফলাইন-ফার্স্ট লাইসেন্স ব্যবস্থাপনা • GitHub-এ নিরাপদে সংরক্ষিত</div>'+
  '</div>';
  $$('.nav button').forEach(b=>{ b.onclick=()=>vShell(b.dataset.v); });
  ({dashboard:vDashboard,licenses:vLicenses,'new':vNewLicense,users:vUsers,settings:vSettings}[currentView]||vDashboard)();
}
function needKeyBanner(){
  if(DB.cfg.seedB64) return '';
  return '<div class="warnbox">⚠️ <b>গোপন চাবি যোগ করা হয়নি।</b> লাইসেন্স তৈরি বা বাতিল করতে সেটিংস থেকে Owner-Key.json-এর লেখা পেস্ট করুন।</div>';
}

/* ---------- dashboard ---------- */
async function vDashboard(){
  const v=$('#view'); v.innerHTML='<div class="boot">লোড হচ্ছে…</div>';
  try{
    const list=await DB.loadLicenses();
    const active=list.filter(l=>l.status!=='revoked').length;
    const revoked=list.filter(l=>l.status==='revoked').length;
    const expSoon=list.filter(l=>{const d=daysLeft(l.expires_at);return d!==null&&d>=0&&d<=30;}).length;
    const recent=list.slice().sort((a,b)=>b.issued_at-a.issued_at).slice(0,5);
    v.innerHTML=needKeyBanner()+
    '<div class="page-head"><h2>ড্যাশবোর্ড</h2></div>'+
    '<div class="stats">'+
    '<div class="stat"><div class="n">'+list.length+'</div><div class="l">মোট লাইসেন্স</div></div>'+
    '<div class="stat"><div class="n">'+active+'</div><div class="l">সক্রিয়</div></div>'+
    '<div class="stat red"><div class="n">'+revoked+'</div><div class="l">বাতিল</div></div>'+
    '<div class="stat gold"><div class="n">'+expSoon+'</div><div class="l">৩০ দিনে মেয়াদ শেষ</div></div>'+
    '</div>'+
    '<div class="card"><h3>সাম্প্রতিক লাইসেন্স</h3>'+licTable(recent,true)+'</div>';
    wireLicRows(v);
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}
function licRow(l){
  return '<tr class="clickable" data-id="'+esc(l.license_id)+'">'+
  '<td><b>'+esc(l.customer_name)+'</b></td>'+
  '<td class="mono">'+esc(l.license_id.slice(0,12))+'…</td>'+
  '<td class="mono">'+esc((l.device_code||'').slice(0,18))+'…</td>'+
  '<td>'+esc(validityText(l))+'</td>'+
  '<td>'+statusBadge(l)+'</td>'+
  '<td>'+esc(l.issued_by||'—')+'</td>'+
  '<td>'+esc(fmtDate(l.issued_at))+'</td></tr>';
}
function licTable(list,skipEmpty){
  if(!list.length) return '<p class="hint">কোনো লাইসেন্স নেই।</p>';
  return '<div class="tbl-wrap"><table><thead><tr><th>গ্রাহক</th><th>লাইসেন্স ID</th><th>ডিভাইস</th><th>মেয়াদ</th><th>অবস্থা</th><th>ইস্যুকারী</th><th>তারিখ</th></tr></thead><tbody>'+
    list.map(licRow).join('')+'</tbody></table></div>';
}
function wireLicRows(root){
  $$('tr.clickable',root).forEach(tr=>{ tr.onclick=()=>vLicDetail(tr.dataset.id); });
}

/* ---------- license list ---------- */
async function vLicenses(){
  const v=$('#view'); v.innerHTML='<div class="boot">লোড হচ্ছে…</div>';
  try{
    const list=await DB.loadLicenses(true);
    v.innerHTML=
    '<div class="page-head"><h2>লাইসেন্স তালিকা</h2>'+
    '<button class="btn btn-primary btn-sm" id="btn-new">+ নতুন লাইসেন্স</button></div>'+
    '<div class="toolbar"><input type="text" id="q" placeholder="গ্রাহক / লাইসেন্স ID দিয়ে খুঁজুন…">'+
    '<select id="f"><option value="all">সবগুলো</option><option value="active">সক্রিয়</option><option value="revoked">বাতিল</option><option value="exp">মেয়াদোত্তীর্ণ</option></select></div>'+
    '<div class="card" id="tbl"></div>';
    $('#btn-new').onclick=()=>vShell('new');
    const render=()=>{
      const q=$('#q').value.trim().toLowerCase(), f=$('#f').value;
      let rows=list.slice().sort((a,b)=>b.issued_at-a.issued_at);
      if(q) rows=rows.filter(l=>(l.customer_name+' '+l.license_id).toLowerCase().includes(q));
      if(f==='active') rows=rows.filter(l=>l.status!=='revoked'&&(daysLeft(l.expires_at)===null||daysLeft(l.expires_at)>=0));
      if(f==='revoked') rows=rows.filter(l=>l.status==='revoked');
      if(f==='exp') rows=rows.filter(l=>{const d=daysLeft(l.expires_at);return d!==null&&d<0;});
      $('#tbl').innerHTML='<p class="hint">'+rows.length+'টি পাওয়া গেছে</p>'+licTable(rows);
      wireLicRows($('#tbl'));
    };
    $('#q').oninput=render; $('#f').onchange=render; render();
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}

/* ---------- license detail modal ---------- */
async function vLicDetail(id){
  const list=await DB.loadLicenses();
  const l=list.find(x=>x.license_id===id);
  if(!l) return;
  const u=store.user(); const isMain=u.role==='main';
  const dl=daysLeft(l.expires_at);
  const m=document.createElement('div'); m.className='modal-bg';
  m.innerHTML='<div class="modal"><h3>লাইসেন্স বিবরণ</h3>'+
  '<dl class="kv">'+
  '<dt>গ্রাহক</dt><dd><b>'+esc(l.customer_name)+'</b></dd>'+
  '<dt>লাইসেন্স ID</dt><dd class="mono">'+esc(l.license_id)+'</dd>'+
  '<dt>ডিভাইস কোড</dt><dd class="mono">'+esc(l.device_code)+'</dd>'+
  '<dt>মেয়াদ</dt><dd>'+esc(validityText(l))+(dl!==null&&l.status!=='revoked'?' ('+(dl>=0?dl+' দিন বাকি':'মেয়াদ শেষ')+')':'')+'</dd>'+
  '<dt>অবস্থা</dt><dd>'+statusBadge(l)+'</dd>'+
  '<dt>ইস্যুকারী</dt><dd>'+esc(l.issued_by||'—')+' • '+esc(fmtDateTime(l.issued_at))+'</dd>'+
  (l.status==='revoked'?'<dt>বাতিলকারী</dt><dd>'+esc(l.revoked_by||'—')+' • '+esc(fmtDateTime(l.revoked_at))+'</dd>':'')+
  '</dl>'+
  '<label class="f">লাইসেন্স কী</label><div class="keybox">'+esc(l.key||'(সংরক্ষিত নেই)')+'</div>'+
  '<div class="row-btns">'+
  (l.key?'<button class="btn btn-ghost btn-sm" id="m-copy">কী কপি করুন</button>':'')+
  (isMain&&l.status!=='revoked'?'<button class="btn btn-danger btn-sm" id="m-revoke">লাইসেন্স বাতিল করুন</button>':'')+
  '<button class="btn btn-ghost btn-sm" id="m-close">বন্ধ করুন</button>'+
  '</div><div id="m-msg"></div></div>';
  document.body.appendChild(m);
  $('#m-close',m).onclick=()=>m.remove();
  m.onclick=(e)=>{ if(e.target===m) m.remove(); };
  const cp=$('#m-copy',m); if(cp) cp.onclick=()=>{ navigator.clipboard.writeText(l.key); cp.textContent='কপি হয়েছে ✓'; };
  const rv=$('#m-revoke',m);
  if(rv) rv.onclick=async ()=>{
    if(!confirm('“'+l.customer_name+'”-এর লাইসেন্স বাতিল করবেন? গ্রাহকের পিসি ইন্টারনেটে এলে লাইসেন্স বন্ধ হয়ে যাবে।')) return;
    rv.disabled=true; rv.textContent='বাতিল হচ্ছে…';
    try{
      l.status='revoked'; l.revoked_at=nowSec(); l.revoked_by=u.username;
      await DB.saveLicenses(list);
      await DB.publishRevocations();
      $('#m-msg',m).innerHTML='<div class="ok">লাইসেন্স বাতিল হয়েছে এবং GitHub-এ প্রকাশিত হয়েছে। গ্রাহকের পিসি অনলাইনে এলে কার্যকর হবে (Pages আপডেটে ১-২ মিনিট লাগতে পারে)।</div>';
      rv.remove();
    }catch(e){ $('#m-msg',m).innerHTML='<div class="err">'+esc(e.message)+'</div>'; rv.disabled=false; rv.textContent='লাইসেন্স বাতিল করুন'; }
  };
}

/* ---------- new license ---------- */
function vNewLicense(){
  const v=$('#view');
  v.innerHTML=needKeyBanner()+
  '<div class="page-head"><h2>নতুন লাইসেন্স তৈরি</h2></div>'+
  '<div class="card" style="max-width:640px">'+
  '<div id="form-err" class="err" style="display:none"></div><div id="form-ok"></div>'+
  '<label class="f">প্রতিষ্ঠান / গ্রাহকের নাম</label><input type="text" id="in-cust" placeholder="যেমন: আল ইসলামিয়া দারুন্নাজাত কওমি মাদ্রাসা">'+
  '<label class="f">ডিভাইস কোড</label><input type="text" id="in-dev" placeholder="MM-PC-…" class="mono" autocomplete="off">'+
  '<div class="hint">গ্রাহকের সফটওয়্যারে দেখানো <b>MM-PC-</b> দিয়ে শুরু কোডটি হুবহু বসান।</div>'+
  '<label class="f">মেয়াদ</label><div class="dur-pick" id="dur">'+
  [['lifetime','আজীবন'],['7','৭ দিন'],['30','৩০ দিন'],['365','১ বছর'],['custom','কাস্টম…']].map((d,i)=>'<label class="'+(i===0?'sel':'')+'"><input type="radio" name="dur" value="'+d[0]+'">'+d[1]+'</label>').join('')+
  '</div><div id="custom-days" style="display:none"><label class="f">কত দিন?</label><input type="number" id="in-days" min="1" max="3650" value="30"></div>'+
  '<div class="row-btns"><button class="btn btn-primary" id="btn-make">লাইসেন্স তৈরি করুন</button></div>'+
  '</div><div id="result"></div>';
  $$('#dur label').forEach(lb=>{ lb.onclick=()=>{
    $$('#dur label').forEach(x=>x.classList.remove('sel')); lb.classList.add('sel');
    $('#custom-days').style.display=$('input',lb).value==='custom'?'block':'none';
  };});
  $('#btn-make').onclick=async (ev)=>{
    hideErr(); $('#form-ok').innerHTML=''; $('#result').innerHTML='';
    const btn=ev.target; btnBusy(btn,true,'তৈরি হচ্ছে…');
    try{
      if(!DB.cfg.seedB64) throw new Error('আগে সেটিংস থেকে গোপন চাবি যোগ করুন।');
      const durVal=$('input[name=dur]:checked').value;
      const days=durVal==='lifetime'?null:(durVal==='custom'?parseInt($('#in-days').value,10):parseInt(durVal,10));
      const lic=buildLicense({customer:$('#in-cust').value, deviceCode:$('#in-dev').value, days:days, seedB64:DB.cfg.seedB64});
      const u=store.user();
      const list=await DB.loadLicenses();
      list.push({license_id:lic.license_id, customer_name:lic.customer_name, device_code:lic.device_code,
        days:lic.days, issued_at:lic.issued_at, expires_at:lic.expires_at, issued_by:u.username,
        status:'active', key:lic.key});
      await DB.saveLicenses(list);
      $('#form-ok').innerHTML='<div class="ok">লাইসেন্স তৈরি ও সংরক্ষিত হয়েছে।</div>';
      $('#result').innerHTML='<div class="card"><h3>লাইসেন্স কী — '+esc(lic.customer_name)+'</h3>'+
        '<div class="keybox">'+esc(lic.key)+'</div>'+
        '<div class="row-btns"><button class="btn btn-gold" id="btn-copy">কী কপি করুন</button>'+
        '<button class="btn btn-ghost" id="btn-again">আরেকটি তৈরি করুন</button></div>'+
        '<p class="hint">এই কী গ্রাহককে দিন। মেয়াদ: '+esc(validityText(lic))+'।</p></div>';
      $('#btn-copy').onclick=(e)=>{ navigator.clipboard.writeText(lic.key); e.target.textContent='কপি হয়েছে ✓'; };
      $('#btn-again').onclick=()=>vShell('new');
      $('#in-cust').value=''; $('#in-dev').value='';
    }catch(e){ showErr(e.message); }
    btnBusy(btn,false);
  };
}

/* ---------- users (main admin only) ---------- */
async function vUsers(){
  const u=store.user();
  if(u.role!=='main'){ $('#view').innerHTML='<div class="err">এই পেজ শুধু মেইন অ্যাডমিনের জন্য।</div>'; return; }
  const v=$('#view'); v.innerHTML='<div class="boot">লোড হচ্ছে…</div>';
  try{
    const users=await DB.loadUsers(true);
    v.innerHTML=
    '<div class="page-head"><h2>ব্যবহারকারী</h2></div>'+
    '<div class="card"><h3>সব ব্যবহারকারী</h3><div class="tbl-wrap"><table><thead><tr><th>ইউজারনেম</th><th>ভূমিকা</th><th>তৈরিকারী</th><th>তারিখ</th><th></th></tr></thead><tbody>'+
    users.map(x=>'<tr><td><b>'+esc(x.username)+'</b></td><td>'+(x.role==='main'?'<span class="badge gold">মেইন অ্যাডমিন</span>':'<span class="badge on">সাব অ্যাডমিন</span>')+'</td><td>'+esc(x.created_by||'—')+'</td><td>'+esc(fmtDate(x.created_at))+'</td>'+
      '<td>'+(x.role!=='main'?'<button class="btn btn-danger btn-sm" data-del="'+esc(x.username)+'">মুছুন</button>':'')+'</td></tr>').join('')+
    '</tbody></table></div></div>'+
    '<div class="card" style="max-width:560px"><h3>নতুন সাব-অ্যাডমিন তৈরি</h3>'+
    '<div id="form-err" class="err" style="display:none"></div><div id="form-ok"></div>'+
    '<label class="f">ইউজারনেম</label><input type="text" id="nu-user" autocomplete="off">'+
    '<label class="f">পাসওয়ার্ড</label><input type="password" id="nu-pass" autocomplete="new-password">'+
    '<div class="hint">সাব-অ্যাডমিন লাইসেন্স তৈরি ও তালিকা দেখতে পারবে; বাতিল বা ব্যবহারকারী ব্যবস্থাপনা পারবে না।</div>'+
    '<div class="row-btns"><button class="btn btn-primary" id="nu-go">তৈরি করুন</button></div></div>'+
    '<div class="card"><h3>সাব-অ্যাডমিনকে যা যা দিতে হবে</h3><div class="warnbox">'+
    '১) এই পেজের লিংক: <b>'+esc(location.href.split('#')[0])+'</b><br>'+
    '২) তার ইউজারনেম ও পাসওয়ার্ড<br>'+
    '৩) GitHub টোকেন (সেটিংস পেজ থেকে কপি করে নিরাপদে পাঠান)<br>'+
    '৪) গোপন চাবি (Owner-Key.json-এর লেখা) — সেটিংসে পেস্ট করতে বলুন'+
    '</div></div>';
    $$('[data-del]').forEach(b=>{ b.onclick=async ()=>{
      if(!confirm('“'+b.dataset.del+'” মুছে ফেলবেন?')) return;
      const nu=users.filter(x=>x.username!==b.dataset.del);
      await DB.saveUsers(nu); vUsers();
    };});
    $('#nu-go').onclick=async (ev)=>{
      hideErr(); $('#form-ok').innerHTML=''; const btn=ev.target; btnBusy(btn,true);
      try{
        const un=$('#nu-user').value.trim(), pw=$('#nu-pass').value;
        if(!un) throw new Error('ইউজারনেম দিন।');
        if(pw.length<6) throw new Error('পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের দিন।');
        if(users.some(x=>x.username===un)) throw new Error('এই ইউজারনেম আগেই আছে।');
        const salt=randHex(8);
        users.push({username:un, salt:salt, pass_hash:await sha256hex(salt+':'+pw), role:'sub', created_by:u.username, created_at:nowSec()});
        await DB.saveUsers(users);
        $('#form-ok').innerHTML='<div class="ok">সাব-অ্যাডমিন “'+esc(un)+'” তৈরি হয়েছে।</div>';
        $('#nu-user').value=''; $('#nu-pass').value='';
        setTimeout(vUsers,900);
      }catch(e){ showErr(e.message); }
      btnBusy(btn,false);
    };
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}

/* ---------- settings ---------- */
function vSettings(){
  const v=$('#view'); const u=store.user(); const isMain=u.role==='main';
  const c=DB.cfg;
  v.innerHTML=
  '<div class="page-head"><h2>সেটিংস</h2></div>'+
  '<div class="card"><h3>সংযোগ</h3><dl class="kv">'+
  '<dt>GitHub</dt><dd class="mono">'+esc(c.ghLogin||'—')+'</dd>'+
  '<dt>রিপো</dt><dd class="mono">'+esc(c.owner+'/'+c.repo)+'</dd>'+
  '<dt>ডেটা ফাইল</dt><dd class="mono">data/users.json, data/licenses.json</dd>'+
  '<dt>বাতিল তালিকা</dt><dd class="mono">revocations.json (স্বাক্ষরিত)</dd></dl>'+
  (isMain?'<label class="f">GitHub টোকেন (সাব-অ্যাডমিনকে দেওয়ার জন্য)</label>'+
    '<div class="row-btns"><button class="btn btn-ghost btn-sm" id="btn-tok">টোকেন কপি করুন</button></div>'+
    '<div class="hint">টোকেনটি শুধু বিশ্বস্ত সাব-অ্যাডমিনকে নিরাপদে পাঠান।</div>':'')+
  '</div>'+
  '<div class="card"><h3>গোপন চাবি (স্বাক্ষরের জন্য)</h3>'+
  (c.seedB64?'<div class="ok">গোপন চাবি যোগ করা আছে ✓ (পাবলিক কী যাচাইকৃত)</div>':'<div class="warnbox">গোপন চাবি যোগ করা হয়নি। লাইসেন্স তৈরি/বাতিল করতে লাগবে।</div>')+
  '<div id="form-err" class="err" style="display:none"></div>'+
  '<label class="f">Owner-Key.json-এর লেখা পেস্ট করুন</label>'+
  '<textarea id="set-key" placeholder=\'{"version":1,"secret_seed":"...","public_key":"..."}\'></textarea>'+
  '<div class="row-btns"><button class="btn btn-primary btn-sm" id="btn-key">চাবি সংরক্ষণ করুন</button>'+
  (c.seedB64?'<button class="btn btn-ghost btn-sm" id="btn-keyrm">চাবি মুছুন</button>':'')+'</div></div>'+
  '<div class="card"><h3>অ্যাকাউন্ট</h3><div class="row-btns">'+
  '<button class="btn btn-ghost" id="btn-logout">লগআউট</button>'+
  '<button class="btn btn-danger" id="btn-reset">এই ব্রাউজারের সেটআপ মুছুন</button></div>'+
  '<p class="hint">সেটআপ মুছলে টোকেন ও চাবি এই ব্রাউজার থেকে মুছে যাবে; GitHub-এর ডেটা মুছবে না।</p></div>';
  const tk=$('#btn-tok'); if(tk) tk.onclick=()=>{ navigator.clipboard.writeText(c.token); tk.textContent='কপি হয়েছে ✓'; };
  $('#btn-key').onclick=(ev)=>{ hideErr(); try{
    const s=parseOwnerKey($('#set-key').value);
    DB.cfg.seedB64=s; store.saveCfg(DB.cfg);
    ev.target.textContent='সংরক্ষিত ✓'; setTimeout(vSettings,800);
  }catch(e){ showErr(e.message); } };
  const kr=$('#btn-keyrm'); if(kr) kr.onclick=()=>{ if(confirm('এই ব্রাউজার থেকে গোপন চাবি মুছবেন?')){ DB.cfg.seedB64=null; store.saveCfg(DB.cfg); vSettings(); } };
  $('#btn-logout').onclick=()=>{ store.clearUser(); vLogin(); };
  $('#btn-reset').onclick=()=>{ if(confirm('এই ব্রাউজারের সব সেটআপ (টোকেন+চাবি) মুছে ফেলবেন?')){ store.clearCfg(); store.clearUser(); location.reload(); } };
}

/* ---------- init ---------- */
(async function init(){
  DB.init();
  if(!window.nacl){ app.innerHTML='<div class="err" style="margin:40px">ক্রিপ্টো লাইব্রেরি লোড হয়নি। ইন্টারনেট চেক করে রিলোড করুন।</div>'; return; }
  if(!DB.cfg){ vSetupToken(); return; }
  try{
    const users=await DB.loadUsers();
    if(!users){ vSetupAdmin(); return; }
  }catch(e){
    app.innerHTML='<div class="auth-wrap"><div class="auth-card"><h1>সংযোগ ত্রুটি</h1><div class="err">'+esc(e.message)+'</div><div class="row-btns"><button class="btn btn-primary" onclick="location.reload()">আবার চেষ্টা</button><button class="btn btn-ghost" id="btn-wipe">সেটআপ মুছে নতুন করে শুরু</button></div><p class="hint">টোকেন ভুল হলে সেটআপ মুছে আবার সঠিক টোকেন দিন।</p></div></div>';
    $('#btn-wipe').onclick=()=>{ store.clearCfg(); store.clearUser(); location.reload(); };
    return;
  }
  const u=store.user();
  if(u) vShell('dashboard'); else vLogin();
})();
