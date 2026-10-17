'use strict';
/* ============================================================
   লাইসেন্স মেশিন v2 — মাদরাসা ম্যানেজার
   সহজ লগইন • প্রি-কনফিগার্ড • সাব-অ্যাডমিন শুধু নিজেরটা দেখে
   ============================================================ */
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const te = new TextEncoder(), td = new TextDecoder();
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const nowSec = () => Math.floor(Date.now() / 1000);
const REPO_OWNER = 'heraralo24bd-cmyk', REPO_NAME = 'madrasa-licenses';
const EXPECTED_PUBKEY = 'kJ7HQm8AiQUSdJTWU-4PXrodLm6DFEHI7ukN7Gv8wc4';

function hexOf(b){ return Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join(''); }
function hexToBytes(h){ const o=new Uint8Array(h.length/2); for(let i=0;i<o.length;i++) o[i]=parseInt(h.slice(i*2,i*2+2),16); return o; }
function b64urlEncode(bytes){
  let s=''; const b=new Uint8Array(bytes);
  for(let i=0;i<b.length;i+=0x8000) s+=String.fromCharCode.apply(null,b.subarray(i,i+0x8000));
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlDecode(s){
  s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='=';
  const bin=atob(s), o=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) o[i]=bin.charCodeAt(i);
  return o;
}
function b64stdEncode(bytes){
  let s=''; const b=new Uint8Array(bytes);
  for(let i=0;i<b.length;i+=0x8000) s+=String.fromCharCode.apply(null,b.subarray(i,i+0x8000));
  return btoa(s);
}
function b64stdDecode(s){
  const bin=atob(s.replace(/\n/g,'')), o=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) o[i]=bin.charCodeAt(i);
  return o;
}
async function sha256hex(str){ return hexOf(await crypto.subtle.digest('SHA-256', te.encode(str))); }
function randHex(n){ const b=new Uint8Array(n); crypto.getRandomValues(b); return hexOf(b); }
function fmtDate(ts){ return ts?new Date(ts*1000).toLocaleDateString('bn-BD',{year:'numeric',month:'long',day:'numeric'}):'—'; }
function fmtDT(ts){ return ts?new Date(ts*1000).toLocaleString('bn-BD',{day:'numeric',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'}):'—'; }
function daysLeft(e){ return e?Math.ceil((e-nowSec())/86400):null; }

/* ---------- session: শুধু মেমরিতে ---------- */
const SESS = { user:null, secrets:null, pw:null };

/* ---------- crypto: পাসওয়ার্ড দিয়ে গোপন তথ্য এনক্রিপ্ট ---------- */
async function deriveKey(password, saltHex){
  const km = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt:hexToBytes(saltHex), iterations:100000, hash:'SHA-256'},
    km, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function encSecrets(password, saltHex, obj){
  const key = await deriveKey(password, saltHex);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, te.encode(JSON.stringify(obj)));
  return {iv:hexOf(iv), ct:b64urlEncode(ct)};
}
async function decSecrets(password, saltHex, enc){
  const key = await deriveKey(password, saltHex);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:hexToBytes(enc.iv)}, key, b64urlDecode(enc.ct));
  return JSON.parse(td.decode(pt));
}

/* ---------- GitHub ---------- */
const GH = {
  base:'https://api.github.com',
  async api(path, method, body, token){
    const h={'Accept':'application/vnd.github+json','Content-Type':'application/json'};
    if(token) h['Authorization']='Bearer '+token;
    const r = await fetch(this.base+path,{method:method||'GET',headers:h,body:body?JSON.stringify(body):null});
    let d=null; try{ d=await r.json(); }catch(e){}
    if(!r.ok){ const e=new Error((d&&d.message)||'নেটওয়ার্ক সমস্যা'); e.status=r.status; throw e; }
    return d;
  },
  async getFile(path, token){
    try{
      const d=await this.api('/repos/'+REPO_OWNER+'/'+REPO_NAME+'/contents/'+path,'GET',null,token);
      if(!d||d.type!=='file'||!d.content) return null;
      return {sha:d.sha, content:td.decode(b64stdDecode(d.content))};
    }catch(e){ if(e.status===404) return null; throw e; }
  },
  async putFile(path, content, token, message){
    const cur=await this.getFile(path,token);
    for(let i=0;i<3;i++){
      try{
        const body={message:message, content:b64stdEncode(te.encode(content))};
        if(cur&&cur.sha) body.sha=cur.sha;
        return await this.api('/repos/'+REPO_OWNER+'/'+REPO_NAME+'/contents/'+path,'PUT',body,token);
      }catch(e){
        if((e.status===422||e.status===409)&&i<2){ const f=await this.getFile(path,token); if(f) cur.sha=f.sha; continue; }
        throw e;
      }
    }
  }
};

/* ---------- লাইসেন্স ক্রিপ্টো (ডেস্কটপ অ্যাপের সাথে হুবহু) ---------- */
function keypairFromSeedB64(s){
  const seed=b64urlDecode((s||'').trim());
  if(seed.length!==32) throw new Error('চাবি সঠিক নয়।');
  return nacl.sign.keyPair.fromSeed(seed);
}
function parseOwnerKey(text){
  const t=(text||'').trim();
  if(!t) throw new Error('Owner-Key.json-এর লেখা পেস্ট করুন।');
  let o; try{ o=JSON.parse(t); }catch(e){ throw new Error('লেখাটি ঠিকমতো পেস্ট হয়নি।'); }
  const s=o.secret_seed||o.secretSeed||o.seed;
  if(!s) throw new Error('ফাইলে secret_seed পাওয়া যায়নি।');
  if(b64urlEncode(keypairFromSeedB64(s).publicKey)!==EXPECTED_PUBKEY)
    throw new Error('এই চাবি তোমার সফটওয়্যারের সাথে মিলছে না। সঠিক Owner-Key.json দাও।');
  return s;
}
function normDevice(c){
  c=String(c||'').trim().toUpperCase();
  if(c.startsWith('MM-PC-')) c=c.slice(6);
  c=c.toLowerCase();
  if(!/^[0-9a-f]{64}$/.test(c)) throw new Error('ডিভাইস কোড ভুল। MM-PC- দিয়ে শুরু কোডটি হুবহু বসাও।');
  return c;
}
function buildLicense(o){
  const customer=String(o.customer||'').trim();
  if(!customer) throw new Error('গ্রাহকের নাম লেখো।');
  if(customer.length>512) throw new Error('নাম বেশি বড়।');
  const deviceId=normDevice(o.deviceCode);
  const days=o.days==null?'lifetime':o.days;
  if(days!=='lifetime'&&(days<1||days>3650)) throw new Error('মেয়াদ ১–৩৬৫০ দিন।');
  const id=randHex(16), now=nowSec();
  const claim={v:1,product:'madrasa-manager',license_id:id,customer_name:customer,device_id:deviceId,issued_at:now,expires_at:days==='lifetime'?null:now+days*86400};
  const payload=te.encode(JSON.stringify(claim));
  const sig=nacl.sign.detached(payload,keypairFromSeedB64(o.seedB64).secretKey);
  return {key:'MM1.'+b64urlEncode(payload)+'.'+b64urlEncode(sig), license_id:id, customer_name:customer,
    device_code:'MM-PC-'+deviceId, days:days, issued_at:now, expires_at:claim.expires_at};
}
function buildRevocations(ids, seedB64, at){
  const sorted=Array.from(new Set(ids)).sort();
  const p=te.encode(JSON.stringify({v:1,issued_at:at,revoked:sorted}));
  const sig=b64urlEncode(nacl.sign.detached(p,keypairFromSeedB64(seedB64).secretKey));
  return JSON.stringify({v:1,issued_at:at,revoked:sorted,signature:sig});
}

/* ---------- data ---------- */
const DB = {
  users:null, licenses:null,
  async loadUsers(force){
    if(this.users&&!force) return this.users;
    const f=await GH.getFile('data/users.json', SESS.secrets&&SESS.secrets.pat);
    if(!f) throw new Error('মেশিন এখনো তৈরি হয়নি।');
    this.users=JSON.parse(f.content); return this.users;
  },
  async saveUsers(u){
    await GH.putFile('data/users.json', JSON.stringify(u,null,2), SESS.secrets.pat, 'Update users');
    this.users=u;
  },
  async loadLicenses(force){
    if(this.licenses&&!force) return this.licenses;
    const f=await GH.getFile('data/licenses.json', SESS.secrets&&SESS.secrets.pat);
    this.licenses=f?JSON.parse(f.content):[]; return this.licenses;
  },
  async saveLicenses(l){
    await GH.putFile('data/licenses.json', JSON.stringify(l,null,2), SESS.secrets.pat, 'Update licenses');
    this.licenses=l;
  },
  async publishRevocations(){
    const list=await this.loadLicenses();
    const grave=await this.loadGrave();
    const revoked=list.filter(l=>l.status==='revoked').map(l=>l.license_id)
      .concat(grave.filter(id=>!list.some(l=>l.license_id===id)));
    const body=buildRevocations(revoked, SESS.secrets.seed, nowSec());
    await GH.putFile('revocations.json', body, SESS.secrets.pat, 'Publish revocations');
  },
  async loadGrave(){ try{ const r=await gh('GET','data/deleted_revoked.json'); return Array.isArray(r)?r:[]; }catch(e){ return []; } },
  async saveGrave(a){ await GH.putFile('data/deleted_revoked.json', JSON.stringify(a,null,2), SESS.secrets.pat, 'Update deleted revocations'); }
};

/* ---------- helpers ---------- */
const app=$('#app');
const showErr=m=>{ const e=$('#ferr'); if(e){ e.textContent=m; e.style.display='block'; } };
const hideErr=()=>{ const e=$('#ferr'); if(e) e.style.display='none'; };
const busy=(b,on,t)=>{ if(on){ b.dataset.t=b.textContent; b.textContent=t||'অপেক্ষা করো…'; b.disabled=true; } else { b.textContent=b.dataset.t||b.textContent; b.disabled=false; } };
const isMain=()=>SESS.user&&SESS.user.role==='main';
function badge(l){
  if(l.status==='revoked') return '<span class="badge off">বাতিল</span>';
  const d=daysLeft(l.expires_at);
  if(d!==null&&d<0) return '<span class="badge off">মেয়াদ শেষ</span>';
  return '<span class="badge on">চালু</span>';
}
function validity(l){
  if(l.expires_at==null) return 'আজীবন';
  return l.days+' দিন';
}
function visibleLicenses(list){
  const me=SESS.user.username;
  const rows=list.filter(l=>isMain()||l.issued_by===me);
  return rows.sort((a,b)=>b.issued_at-a.issued_at);
}

/* ---------- login ---------- */
function vLogin(msg){
  app.innerHTML=
  '<div class="auth-wrap"><div class="auth-card">'+
  '<img class="logo" src="logo.webp" alt="">'+
  '<h1>লাইসেন্স মেশিন</h1><p class="sub">মাদরাসা ম্যানেজার</p>'+
  (msg?'<div class="ok">'+esc(msg)+'</div>':'')+
  '<div id="ferr" class="err" style="display:none"></div>'+
  '<label class="f">ইউজারনেম</label><input type="text" id="u" autocomplete="username">'+
  '<label class="f">পাসওয়ার্ড</label><input type="password" id="p" autocomplete="current-password">'+
  '<div class="row-btns"><button class="btn btn-primary" id="go">প্রবেশ করো</button></div>'+
  '</div></div>';
  const go=async()=>{
    hideErr(); const b=$('#go'); busy(b,true);
    try{
      const users=await DB.loadUsers(true);
      const u=users.find(x=>x.username===$('#u').value.trim());
      if(!u) throw new Error('ইউজারনেম বা পাসওয়ার্ড ভুল।');
      const pw=$('#p').value;
      if(await sha256hex(u.salt+':'+pw)!==u.pass_hash) throw new Error('ইউজারনেম বা পাসওয়ার্ড ভুল।');
      let sec; try{ sec=await decSecrets(pw,u.salt,u.secrets_enc); }catch(e){ throw new Error('ডেটা খোলা যায়নি।'); }
      SESS.user={username:u.username,role:u.role}; SESS.secrets=sec; SESS.pw=pw;
      if(!sec.seed) vKeySetup(); else { SESS.pw=null; vShell('dashboard'); }
    }catch(e){ showErr(e.message||'ঢোকা যায়নি।'); }
    busy(b,false);
  };
  $('#go').onclick=go;
  $('#p').addEventListener('keydown',e=>{ if(e.key==='Enter') go(); });
}

/* ---------- একবার গোপন চাবি ---------- */
function vKeySetup(){
  app.innerHTML=
  '<div class="auth-wrap"><div class="auth-card">'+
  '<img class="logo" src="logo.webp" alt="">'+
  '<h1>স্বাগতম, '+esc(SESS.user.username)+'!</h1><p class="sub">লাইসেন্স বানাতে একবার গোপন চাবি দাও</p>'+
  '<div id="ferr" class="err" style="display:none"></div>'+
  '<label class="f">Owner-Key.json-এর লেখা</label>'+
  '<textarea id="k" placeholder=\'{"version":1,"secret_seed":"..."}\'></textarea>'+
  '<p class="hint">কম্পিউটারে License-Generator ফোল্ডারের Owner-Key.json নোটপ্যাডে খুলে পুরোটা কপি করে এখানে বসাও। একবারই লাগবে।</p>'+
  '<div class="row-btns"><button class="btn btn-primary" id="go">সংরক্ষণ করো</button></div>'+
  '</div></div>';
  $('#go').onclick=async ev=>{
    hideErr(); const b=ev.target; busy(b,true);
    try{
      const seed=parseOwnerKey($('#k').value);
      const users=await DB.loadUsers(true);
      const u=users.find(x=>x.username===SESS.user.username);
      SESS.secrets.seed=seed;
      u.secrets_enc=await encSecrets(SESS.pw,u.salt,SESS.secrets);
      await DB.saveUsers(users);
      SESS.pw=null; vShell('dashboard');
    }catch(e){ showErr(e.message); }
    busy(b,false);
  };
}

/* ---------- shell: বাম সাইডবার ---------- */
let CV='dashboard';
const I={
dash:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
list:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9h10M7 13h6"/></svg>',
plus:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>',
users:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="8" r="3.5"/><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6"/><circle cx="17" cy="9" r="2.5"/><path d="M16 14.5c2.8.4 5 2.6 5 5.5"/></svg>',
gear:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.3 1a7 7 0 0 0-2-1.2L14.2 3h-4l-.4 2.7a7 7 0 0 0-2 1.2l-2.3-1-2 3.4 2 1.5a7 7 0 0 0 0 2.4l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 2 1.2l.4 2.7h4l.4-2.7a7 7 0 0 0 2-1.2l2.3 1 2-3.4-2-1.5c.06-.4.1-.8.1-1.2z"/></svg>'};
const SI={
box:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 8l-9-5-9 5v8l9 5 9-5V8z"/><path d="M3 8l9 5 9-5M12 13v8"/></svg>',
check:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 4.5-5.5"/></svg>',
x:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/></svg>',
clock:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></svg>'};
const stat=(c,ic,n,l)=>'<div class="stat '+c+'"><div class="s-icon">'+ic+'</div><div><div class="n">'+n+'</div><div class="l">'+l+'</div></div></div>';
function vShell(view){
  CV=view||'dashboard';
  if(!SESS.user){ vLogin(); return; }
  const nav=[['dashboard','ড্যাশবোর্ড',I.dash],['licenses','লাইসেন্স',I.list],['new','নতুন লাইসেন্স',I.plus]];
  if(isMain()) nav.push(['users','সাব-অ্যাডমিন',I.users]);
  nav.push(['settings','সেটিংস',I.gear]);
  app.innerHTML=
  '<div class="shell"><aside class="sidebar">'+
  '<div class="brand"><img class="logo" src="logo.webp" alt=""><div class="bt">লাইসেন্স মেশিন<small>মাদরাসা ম্যানেজার</small></div></div>'+
  '<nav class="snav">'+nav.map(n=>'<button data-v="'+n[0]+'" class="'+(CV===n[0]?'active':'')+'">'+n[2]+'<span>'+n[1]+'</span></button>').join('')+'</nav>'+
  '<div class="side-foot"><div class="who"><b>'+esc(SESS.user.username)+'</b>'+(isMain()?'<span class="badge gold">মেইন</span>':'<span class="badge on">সাব</span>')+'</div>'+
  '<button class="btn btn-ghost btn-sm" id="slo">লগআউট</button></div>'+
  '</aside><div class="content"><div class="main" id="view"></div>'+
  '<div class="footer-note">মাদরাসা ম্যানেজার • লাইসেন্স মেশিন</div></div></div>';
  $$('.snav button').forEach(b=>b.onclick=()=>vShell(b.dataset.v));
  $('#slo').onclick=()=>{ SESS.user=null; SESS.secrets=null; SESS.pw=null; vLogin('লগআউট হয়েছে।'); };
  ({dashboard:vDash,licenses:vLicenses,'new':vNew,users:vUsers,settings:vSettings}[CV]||vDash)();
}

/* ---------- dashboard ---------- */
async function vDash(){
  const v=$('#view'); v.innerHTML='<div class="boot">আসছে…</div>';
  try{
    const rows=visibleLicenses(await DB.loadLicenses(true));
    const act=rows.filter(l=>l.status!=='revoked').length;
    const rev=rows.filter(l=>l.status==='revoked').length;
    const exp=rows.filter(l=>{const d=daysLeft(l.expires_at);return d!==null&&d>=0&&d<=30;}).length;
    v.innerHTML='<div class="page-head"><h2>ড্যাশবোর্ড</h2></div>'+
    '<div class="stats">'+
    stat('s1',SI.box,rows.length,'মোট লাইসেন্স')+
    stat('s2',SI.check,act,'চালু')+
    stat('s3',SI.x,rev,'বাতিল')+
    stat('s4',SI.clock,exp,'৩০ দিনে শেষ')+'</div>'+
    '<div class="card"><h3>সাম্প্রতিক</h3>'+licTable(rows.slice(0,6))+'</div>';
    wireRows(v);
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}
function licRow(l){
  return '<tr class="clickable" data-id="'+esc(l.license_id)+'"><td><b>'+esc(l.customer_name)+'</b></td>'+
  '<td class="mono">'+esc(l.license_id.slice(0,10))+'…</td><td>'+esc(validity(l))+'</td><td>'+badge(l)+'</td>'+
  (isMain()?'<td>'+esc(l.issued_by||'—')+'</td>':'')+'<td>'+esc(fmtDate(l.issued_at))+'</td></tr>';
}
function licTable(rows){
  if(!rows.length) return '<p class="hint">এখনো কোনো লাইসেন্স নেই।</p>';
  return '<div class="tbl-wrap"><table><thead><tr><th>গ্রাহক</th><th>লাইসেন্স</th><th>মেয়াদ</th><th>অবস্থা</th>'+
  (isMain()?'<th>বানিয়েছে</th>':'')+'<th>তারিখ</th></tr></thead><tbody>'+rows.map(licRow).join('')+'</tbody></table></div>';
}
const wireRows=r=>$$('tr.clickable',r).forEach(t=>t.onclick=()=>vDetail(t.dataset.id));

/* ---------- licenses ---------- */
async function vLicenses(){
  const v=$('#view'); v.innerHTML='<div class="boot">আসছে…</div>';
  try{
    const all=visibleLicenses(await DB.loadLicenses(true));
    v.innerHTML='<div class="page-head"><h2>লাইসেন্স</h2><button class="btn btn-primary btn-sm" id="nw">+ নতুন</button></div>'+
    '<div class="toolbar"><input type="text" id="q" placeholder="খুঁজুন…">'+
    '<select id="f"><option value="all">সব</option><option value="on">চালু</option><option value="off">বাতিল</option></select></div>'+
    '<div class="card" id="tbl"></div>';
    $('#nw').onclick=()=>vShell('new');
    const render=()=>{
      const q=$('#q').value.trim().toLowerCase(), f=$('#f').value;
      let rows=all;
      if(q) rows=rows.filter(l=>(l.customer_name+' '+l.license_id).toLowerCase().includes(q));
      if(f==='on') rows=rows.filter(l=>l.status!=='revoked');
      if(f==='off') rows=rows.filter(l=>l.status==='revoked');
      $('#tbl').innerHTML='<p class="hint">'+rows.length+'টি</p>'+licTable(rows);
      wireRows($('#tbl'));
    };
    $('#q').oninput=render; $('#f').onchange=render; render();
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}

/* ---------- detail ---------- */
async function vDetail(id){
  const rows=visibleLicenses(await DB.loadLicenses());
  const l=rows.find(x=>x.license_id===id); if(!l) return;
  const d=daysLeft(l.expires_at);
  const m=document.createElement('div'); m.className='modal-bg';
  m.innerHTML='<div class="modal"><h3>'+esc(l.customer_name)+'</h3>'+
  '<dl class="kv"><dt>লাইসেন্স ID</dt><dd class="mono">'+esc(l.license_id)+'</dd>'+
  '<dt>ডিভাইস</dt><dd class="mono">'+esc(l.device_code)+'</dd>'+
  '<dt>মেয়াদ</dt><dd>'+esc(validity(l))+(l.expires_at?' — '+esc(fmtDate(l.expires_at))+' পর্যন্ত':'')+(d!==null&&l.status!=='revoked'?' ('+d+' দিন বাকি)':'')+'</dd>'+
  '<dt>অবস্থা</dt><dd>'+badge(l)+'</dd>'+
  (isMain()?'<dt>বানিয়েছে</dt><dd>'+esc(l.issued_by||'—')+' • '+esc(fmtDT(l.issued_at))+'</dd>':'<dt>তারিখ</dt><dd>'+esc(fmtDT(l.issued_at))+'</dd>')+
  (l.status==='revoked'?'<dt>বাতিল</dt><dd>'+esc(fmtDT(l.revoked_at))+'</dd>':'')+'</dl>'+
  '<label class="f">লাইসেন্স কী</label><div class="keybox">'+esc(l.key||'—')+'</div>'+
  '<div class="row-btns">'+(l.key?'<button class="btn btn-ghost btn-sm" id="cp">কপি</button>':'')+
  (isMain()&&l.status!=='revoked'?'<button class="btn btn-danger btn-sm" id="rv">বাতিল করো</button>':'')+
  (isMain()&&l.status==='revoked'?'<button class="btn btn-primary btn-sm" id="ac">সচল করো</button>':'')+
  (isMain()?'<button class="btn btn-ghost btn-sm" id="dl">ডিলিট</button>':'')+
  '<button class="btn btn-ghost btn-sm" id="x">বন্ধ</button></div><div id="mm"></div></div>';
  document.body.appendChild(m);
  $('#x',m).onclick=()=>m.remove(); m.onclick=e=>{ if(e.target===m) m.remove(); };
  const cp=$('#cp',m); if(cp) cp.onclick=()=>{ navigator.clipboard.writeText(l.key); cp.textContent='কপি হয়েছে ✓'; };
  const rv=$('#rv',m);
  if(rv) rv.onclick=async()=>{
    if(!confirm('“'+l.customer_name+'”-এর লাইসেন্স বাতিল করবে?')) return;
    rv.disabled=true; rv.textContent='হচ্ছে…';
    try{
      const all=await DB.loadLicenses();
      const t=all.find(x=>x.license_id===id);
      t.status='revoked'; t.revoked_at=nowSec(); t.revoked_by=SESS.user.username;
      await DB.saveLicenses(all); await DB.publishRevocations();
      $('#mm',m).innerHTML='<div class="ok">বাতিল হয়েছে। গ্রাহকের পিসি অনলাইনে এলে বন্ধ হয়ে যাবে।</div>'; rv.remove();
    }catch(e){ $('#mm',m).innerHTML='<div class="err">'+esc(e.message)+'</div>'; rv.disabled=false; rv.textContent='বাতিল করো'; }
  };
  const ac=$('#ac',m);
  if(ac) ac.onclick=async()=>{
    if(!confirm('"'+l.customer_name+'"-এর লাইসেন্স আবার সচল করবে?')) return;
    ac.disabled=true; ac.textContent='হচ্ছে…';
    try{
      const all=await DB.loadLicenses();
      const t=all.find(x=>x.license_id===id);
      t.status='active'; delete t.revoked_at; delete t.revoked_by;
      await DB.saveLicenses(all); await DB.publishRevocations();
      $('#mm',m).innerHTML='<div class="ok">লাইসেন্স সচল হয়েছে। গ্রাহকের পিসি অনলাইনে এলে খুলে যাবে।</div>'; ac.remove();
    }catch(e){ $('#mm',m).innerHTML='<div class="err">'+esc(e.message)+'</div>'; ac.disabled=false; ac.textContent='সচল করো'; }
  };
  const dl=$('#dl',m);
  if(dl) dl.onclick=async()=>{
    const msg=l.status==='revoked'
      ? '"'+l.customer_name+'"-এর বাতিল লাইসেন্স সম্পূর্ণ ডিলিট করবে? (তার সফটওয়্যার বন্ধই থাকবে)'
      : '"'+l.customer_name+'"-এর লাইসেন্স ডিলিট করবে?';
    if(!confirm(msg)) return;
    dl.disabled=true; dl.textContent='হচ্ছে…';
    try{
      const wasRevoked=l.status==='revoked';
      const all=(await DB.loadLicenses()).filter(x=>x.license_id!==id);
      await DB.saveLicenses(all);
      if(wasRevoked){
        const g=await DB.loadGrave();
        if(!g.includes(id)){ g.push(id); await DB.saveGrave(g); }
      }
      await DB.publishRevocations();
      m.remove(); vShell('licenses');
    }catch(e){ $('#mm',m).innerHTML='<div class="err">'+esc(e.message)+'</div>'; dl.disabled=false; dl.textContent='ডিলিট'; }
  };
}

/* ---------- new license ---------- */
function vNew(){
  const v=$('#view');
  v.innerHTML='<div class="page-head"><h2>নতুন লাইসেন্স</h2></div>'+
  '<div class="card" style="max-width:620px"><div id="ferr" class="err" style="display:none"></div><div id="fok"></div>'+
  '<label class="f">গ্রাহকের নাম</label><input type="text" id="c" placeholder="মাদরাসার নাম">'+
  '<label class="f">ডিভাইস কোড</label><input type="text" id="d" class="mono" placeholder="MM-PC-…" autocomplete="off">'+
  '<p class="hint">গ্রাহকের সফটওয়্যারে যে কোড দেখায়, সেটা হুবহু বসাও।</p>'+
  '<label class="f">মেয়াদ</label><div class="dur-pick" id="dur">'+
  [['lifetime','আজীবন'],['30','৩০ দিন'],['365','১ বছর'],['custom','অন্য…']].map((x,i)=>'<label class="'+(i===0?'sel':'')+'"><input type="radio" name="dur" value="'+x[0]+'">'+x[1]+'</label>').join('')+
  '</div><div id="cd" style="display:none"><label class="f">কত দিন?</label><input type="number" id="nd" min="1" max="3650" value="90"></div>'+
  '<div class="row-btns"><button class="btn btn-primary" id="mk">তৈরি করো</button></div></div><div id="res"></div>';
  $$('#dur label').forEach(lb=>lb.onclick=()=>{
    $$('#dur label').forEach(x=>x.classList.remove('sel')); lb.classList.add('sel');
    $('#cd').style.display=$('input',lb).value==='custom'?'block':'none';
  });
  $('#mk').onclick=async ev=>{
    hideErr(); $('#fok').innerHTML=''; $('#res').innerHTML='';
    const b=ev.target; busy(b,true,'বানাচ্ছি…');
    try{
      const dv=$('input[name=dur]:checked').value;
      const days=dv==='lifetime'?null:(dv==='custom'?parseInt($('#nd').value,10):parseInt(dv,10));
      const lic=buildLicense({customer:$('#c').value,deviceCode:$('#d').value,days:days,seedB64:SESS.secrets.seed});
      const all=await DB.loadLicenses();
      all.push({license_id:lic.license_id,customer_name:lic.customer_name,device_code:lic.device_code,
        days:lic.days,issued_at:lic.issued_at,expires_at:lic.expires_at,issued_by:SESS.user.username,status:'active',key:lic.key});
      await DB.saveLicenses(all);
      $('#fok').innerHTML='<div class="ok">লাইসেন্স তৈরি হয়েছে ✓</div>';
      $('#res').innerHTML='<div class="card"><h3>'+esc(lic.customer_name)+'</h3><div class="keybox">'+esc(lic.key)+'</div>'+
      '<div class="row-btns"><button class="btn btn-gold" id="cp2">কপি করো</button><button class="btn btn-ghost" id="ag">আরেকটি</button></div>'+
      '<p class="hint">মেয়াদ: '+esc(validity(lic))+'</p></div>';
      $('#cp2').onclick=e=>{ navigator.clipboard.writeText(lic.key); e.target.textContent='কপি হয়েছে ✓'; };
      $('#ag').onclick=()=>vShell('new');
      $('#c').value=''; $('#d').value='';
    }catch(e){ showErr(e.message); }
    busy(b,false);
  };
}

/* ---------- sub-admins (main only) ---------- */
async function vUsers(){
  if(!isMain()){ $('#view').innerHTML='<div class="err">শুধু মেইন অ্যাডমিন।</div>'; return; }
  const v=$('#view'); v.innerHTML='<div class="boot">আসছে…</div>';
  try{
    const users=await DB.loadUsers(true);
    const subs=users.filter(u=>u.role!=='main');
    v.innerHTML='<div class="page-head"><h2>সাব-অ্যাডমিন</h2></div>'+
    '<div class="card"><h3>তালিকা</h3>'+
    (subs.length?'<div class="tbl-wrap"><table><thead><tr><th>নাম</th><th>যোগ করেছে</th><th>তারিখ</th><th></th></tr></thead><tbody>'+
      subs.map(u=>'<tr><td><b>'+esc(u.username)+'</b></td><td>'+esc(u.created_by||'—')+'</td><td>'+esc(fmtDate(u.created_at))+'</td>'+
      '<td><button class="btn btn-danger btn-sm" data-del="'+esc(u.username)+'">মুছো</button></td></tr>').join('')+'</tbody></table></div>'
      :'<p class="hint">এখনো কেউ নেই।</p>')+'</div>'+
    '<div class="card" style="max-width:560px"><h3>নতুন যোগ করো</h3>'+
    '<div id="ferr" class="err" style="display:none"></div><div id="share"></div>'+
    '<label class="f">ইউজারনেম</label><input type="text" id="nu" autocomplete="off">'+
    '<label class="f">পাসওয়ার্ড</label><input type="password" id="np" autocomplete="new-password">'+
    '<p class="hint">সে শুধু নিজের বানানো লাইসেন্স দেখতে পাবে। বাতিল করতে পারবে না।</p>'+
    '<div class="row-btns"><button class="btn btn-primary" id="ngo">যোগ করো</button></div></div>';
    $$('[data-del]').forEach(x=>x.onclick=async()=>{
      if(!confirm('“'+x.dataset.del+'” মুছে ফেলবে?')) return;
      await DB.saveUsers(users.filter(u=>u.username!==x.dataset.del)); vUsers();
    });
    $('#ngo').onclick=async ev=>{
      hideErr(); $('#share').innerHTML=''; const b=ev.target; busy(b,true);
      try{
        const un=$('#nu').value.trim(), pw=$('#np').value;
        if(!un) throw new Error('ইউজারনেম লেখো।');
        if(pw.length<6) throw new Error('পাসওয়ার্ড ৬ অক্ষরের বেশি দাও।');
        if(users.some(u=>u.username===un)) throw new Error('এই নামে আগেই আছে।');
        const salt=randHex(8);
        users.push({username:un,salt:salt,pass_hash:await sha256hex(salt+':'+pw),role:'sub',
          created_by:SESS.user.username,created_at:nowSec(),
          secrets_enc:await encSecrets(pw,salt,{pat:SESS.secrets.pat,seed:SESS.secrets.seed})});
        await DB.saveUsers(users);
        $('#share').innerHTML='<div class="ok"><b>'+esc(un)+'</b> যোগ হয়েছে ✓<br><br>তাকে পাঠাও:<br>লিংক: <span class="mono">'+esc(location.href.split('#')[0])+'</span><br>ইউজারনেম: <b>'+esc(un)+'</b><br>পাসওয়ার্ড: <b>'+esc(pw)+'</b></div>';
        $('#nu').value=''; $('#np').value='';
      }catch(e){ showErr(e.message); }
      busy(b,false);
    };
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}

/* ---------- settings ---------- */
function vSettings(){
  const v=$('#view');
  v.innerHTML='<div class="page-head"><h2>সেটিংস</h2></div>'+
  '<div class="card" style="max-width:560px"><h3>পাসওয়ার্ড বদলাও</h3>'+
  '<div id="ferr" class="err" style="display:none"></div><div id="fok2"></div>'+
  '<label class="f">বর্তমান পাসওয়ার্ড</label><input type="password" id="op" autocomplete="current-password">'+
  '<label class="f">নতুন পাসওয়ার্ড</label><input type="password" id="np1" autocomplete="new-password">'+
  '<label class="f">নতুন পাসওয়ার্ড আবার</label><input type="password" id="np2" autocomplete="new-password">'+
  '<div class="row-btns"><button class="btn btn-primary" id="chg">বদলাও</button></div></div>'+
  '<div class="card" style="max-width:560px"><h3>বের হও</h3>'+
  '<div class="row-btns"><button class="btn btn-ghost" id="lo">লগআউট</button></div></div>';
  $('#chg').onclick=async ev=>{
    hideErr(); $('#fok2').innerHTML=''; const b=ev.target; busy(b,true);
    try{
      const op=$('#op').value, n1=$('#np1').value, n2=$('#np2').value;
      const users=await DB.loadUsers(true);
      const u=users.find(x=>x.username===SESS.user.username);
      if(await sha256hex(u.salt+':'+op)!==u.pass_hash) throw new Error('বর্তমান পাসওয়ার্ড ভুল।');
      if(n1.length<6) throw new Error('নতুন পাসওয়ার্ড ৬ অক্ষরের বেশি দাও।');
      if(n1!==n2) throw new Error('দুটি নতুন পাসওয়ার্ড মিলছে না।');
      const nsalt=randHex(8);
      u.salt=nsalt; u.pass_hash=await sha256hex(nsalt+':'+n1);
      u.secrets_enc=await encSecrets(n1,nsalt,SESS.secrets);
      await DB.saveUsers(users);
      $('#fok2').innerHTML='<div class="ok">পাসওয়ার্ড বদলে গেছে ✓</div>';
      $('#op').value=$('#np1').value=$('#np2').value='';
    }catch(e){ showErr(e.message); }
    busy(b,false);
  };
  $('#lo').onclick=()=>{ SESS.user=null; SESS.secrets=null; SESS.pw=null; vLogin('লগআউট হয়েছে।'); };
}

/* ---------- init ---------- */
(function init(){
  if(!window.nacl){ app.innerHTML='<div class="err" style="margin:40px">লাইব্রেরি আসেনি। নেট চেক করে রিলোড দাও।</div>'; return; }
  vLogin();
})();
