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
async function encWithKey(key, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, te.encode(JSON.stringify(obj)));
  return {iv:hexOf(iv), ct:b64urlEncode(ct)};
}
async function decWithKey(key, enc){
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:hexToBytes(enc.iv)}, key, b64urlDecode(enc.ct));
  return JSON.parse(td.decode(pt));
}
/* ---------- চ্যাট ---------- */
function chatThread(chat, username){
  chat.threads=chat.threads||{};
  return chat.threads[username]=chat.threads[username]||[];
}
async function chatSend(toUser, text){
  text=String(text||'').trim().slice(0,1000);
  if(!text) return;
  const chat=await DB.loadChat(true);
  const th=chatThread(chat,toUser);
  th.push({from:SESS.user.username,text:text,at:nowSec(),seen:false});
  if(th.length>200) th.splice(0,th.length-200);
  await DB.saveChat(chat);
}
function chatUnreadSub(chat, username){
  return chatThread(chat,username).filter(m=>m.from!==username&&!m.seen).length;
}
function chatUnreadMain(chat, mainUser){
  let n=0;
  for(const k in (chat.threads||{})) n+=chatThread(chat,k).filter(m=>m.from!==mainUser&&!m.seen).length;
  return n;
}
async function chatMarkSeen(username){
  const chat=await DB.loadChat(true);
  const th=chatThread(chat,username);
  let ch=false;
  th.forEach(m=>{ if(m.from!==SESS.user.username&&!m.seen){ m.seen=true; ch=true; } });
  if(ch) await DB.saveChat(chat);
  return chat;
}
function chatTime(at){
  try{ return new Date(at*1000).toLocaleString('bn-BD',{hour:'2-digit',minute:'2-digit',day:'numeric',month:'short'}); }
  catch(e){ return ''; }
}

/* প্যাকেজ থেকে কার্যকর লিমিট */
function pkgLimit(u){
  if(u.packages&&u.packages.length)
    return u.packages.filter(p=>p.status==='active').reduce((s,p)=>s+Number(p.qty||0),0);
  return Number(u.license_limit)>0?Number(u.license_limit):null;
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
  chat:null,
  async loadChat(force){
    if(this.chat&&!force) return this.chat;
    const f=await GH.getFile('data/chat.json', SESS.secrets&&SESS.secrets.pat);
    this.chat=f?JSON.parse(f.content):{threads:{}}; return this.chat;
  },
  async saveChat(c){
    await GH.putFile('data/chat.json', JSON.stringify(c), SESS.secrets.pat, 'Update chat');
    this.chat=c;
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

/* ---------- customer profile + validity dashboard ---------- */
function custOf(l){ return (l&&l.customer)||{}; }
function custKey(l){ if(!l) return ''; if(l.customer_id) return 'id:'+l.customer_id; const c=custOf(l); return 'nm:'+String(l.customer_name||'').trim().toLowerCase()+'|'+String(c.mobile||'').trim(); }
function fmtTk(n){ return Number(n||0).toLocaleString('en-US'); }
let NEW_PREFILL=null;
function validityInfo(l){
  const t=nowSec();
  if(l.expires_at==null)
    return {life:true, totalTxt:'আজীবন', elapsed:Math.max(0,Math.floor((t-l.issued_at)/86400)), leftTxt:'∞', pct:0};
  const total=Math.max(1,Math.round((l.expires_at-l.issued_at)/86400));
  const elapsed=Math.max(0,Math.floor((t-l.issued_at)/86400));
  const left=Math.ceil((l.expires_at-t)/86400);
  return {life:false, total:total, elapsed:elapsed, left:left,
    totalTxt:String(total), elapsedTxt:String(elapsed),
    leftTxt:left<0?'শেষ':String(left),
    pct:Math.min(100,Math.max(0,Math.round(Math.min(elapsed,total)/total*100)))};
}
function photoHTML(c,cls){
  cls=cls||'p-photo';
  if(c&&c.photo) return '<img class="'+cls+'" src="'+c.photo+'" alt="ছবি">';
  return '<div class="'+cls+' p-empty">👤</div>';
}
function readPhoto(file){
  return new Promise((res,rej)=>{
    if(!file) return res('');
    if(!/^image\//.test(file.type||'')) return rej(new Error('ছবির ফাইল দাও।'));
    if(file.size>8*1024*1024) return rej(new Error('ছবি ৮ MB-এর কম দাও।'));
    const img=new Image();
    img.onload=()=>{
      try{
        const k=200/Math.max(img.width,img.height);
        const cv=document.createElement('canvas');
        cv.width=Math.max(1,Math.round(img.width*k)); cv.height=Math.max(1,Math.round(img.height*k));
        cv.getContext('2d').drawImage(img,0,0,cv.width,cv.height);
        res(cv.toDataURL('image/jpeg',0.72));
      }catch(e){ rej(new Error('ছবি পড়া যায়নি।')); }
    };
    img.onerror=()=>rej(new Error('ছবি পড়া যায়নি।'));
    const r=new FileReader();
    r.onload=e=>{ img.src=e.target.result; };
    r.onerror=()=>rej(new Error('ছবি পড়া যায়নি।'));
    r.readAsDataURL(file);
  });
}
const canEditL=l=>isMain()||(l.issued_by===SESS.user.username);

/* ---------- সাব-অ্যাডমিন: লিমিট ও প্রোফাইল ---------- */
async function quotaOf(username){
  const users=await DB.loadUsers(true);
  const u=users.find(x=>x.username===username);
  const limit=u?pkgLimit(u):null;
  if(!limit) return {limit:null,used:0,left:null};
  const all=await DB.loadLicenses();
  const used=all.filter(l=>l.issued_by===username).length;
  return {limit:limit,used:used,left:Math.max(0,limit-used)};
}
const dispName=u=>(u&&(u.display_name||u.username))||'';

/* গোল মিটার: লাইসেন্স কোটা (তিন রঙের ডোনাট) — শুধু SVG */
function quotaDonut(q, actN, revN){
  const total=q.limit, r=70, c=2*Math.PI*r;
  const a=actN/total*c, rv=revN/total*c, rm=Math.max(0,(total-q.used))/total*c;
  const seg=(len,off,color)=>'<circle cx="90" cy="90" r="'+r+'" fill="none" stroke="'+color+
    '" stroke-width="24" stroke-dasharray="'+len.toFixed(1)+' '+c.toFixed(1)+
    '" stroke-dashoffset="'+(-off).toFixed(1)+'" transform="rotate(-90 90 90)"/>';
  return '<svg viewBox="0 0 180 180" class="dq">'+
    '<circle cx="90" cy="90" r="'+r+'" fill="none" stroke="#e6ecf4" stroke-width="24"/>'+
    seg(a,0,'#147958')+seg(rv,a,'#c0392b')+seg(rm,a+rv,'#c9a227')+
    '<text x="90" y="84" text-anchor="middle" class="dq-num">'+q.left+'</text>'+
    '<text x="90" y="108" text-anchor="middle" class="dq-lab">বাকি আছে</text></svg>';
}
function quotaBar(q){
  if(!q.limit) return '<span class="hint">সীমা নেই</span>';
  const pct=Math.min(100,Math.round(q.used/q.limit*100));
  return '<div style="min-width:130px"><div style="display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:4px"><b>'+q.used+'/'+q.limit+'</b><span class="'+(q.left===0?'badge off':'badge on')+'">'+(q.left===0?'শেষ':'বাকি '+q.left)+'</span></div>'+
  '<div class="pbar" style="height:8px"><div class="pfill" style="width:'+pct+'%"></div></div></div>';
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
      if(u.role==='main'){ try{ SESS.viewKey=await deriveKey(pw,u.salt); }catch(e){ SESS.viewKey=null; } }
      if(u.role==='main'&&SESS.viewKey&&!u.pw_enc){ try{ u.pw_enc=await encWithKey(SESS.viewKey,{pw:pw}); await DB.saveUsers(users); }catch(e){} }
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
user:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a8 8 0 0 1 16 0v1"/></svg>',
chat:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11.5a8.5 8.5 0 0 1-8.5 8.5c-1.5 0-3-.4-4.2-1L3 20l1.2-4.1A8.5 8.5 0 1 1 21 11.5z"/><path d="M8.5 11.5h.01M12 11.5h.01M15.5 11.5h.01"/></svg>',
gear:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.3 1a7 7 0 0 0-2-1.2L14.2 3h-4l-.4 2.7a7 7 0 0 0-2 1.2l-2.3-1-2 3.4 2 1.5a7 7 0 0 0 0 2.4l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 2 1.2l.4 2.7h4l.4-2.7a7 7 0 0 0 2-1.2l2.3 1 2-3.4-2-1.5c.06-.4.1-.8.1-1.2z"/></svg>'};
const SI={
box:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 8l-9-5-9 5v8l9 5 9-5V8z"/><path d="M3 8l9 5 9-5M12 13v8"/></svg>',
check:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 4.5-5.5"/></svg>',
x:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/></svg>',
clock:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></svg>'};
const stat=(c,ic,n,l)=>'<div class="stat '+c+'"><div class="s-icon">'+ic+'</div><div><div class="n">'+n+'</div><div class="l">'+l+'</div></div></div>';
/* সংখ্যা গণনা অ্যানিমেশন */
function countUp(root){
  try{
    root.querySelectorAll('.stat .n, .vstat .n').forEach(el=>{
      const target=parseInt((el.textContent||'').replace(/[^0-9]/g,''),10);
      if(isNaN(target)||target<=0) return;
      const t0=performance.now(), dur=900;
      const step=t=>{
        const p=Math.min(1,(t-t0)/dur), e=1-Math.pow(1-p,3);
        el.textContent=Math.round(target*e);
        if(p<1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    });
  }catch(_){}
}
/* ---------- চ্যাট UI ---------- */
let CHAT_TIMER=null, CHAT_OPEN=null, CHAT_USERS=[];
function chatPollStop(){ if(CHAT_TIMER){ clearInterval(CHAT_TIMER); CHAT_TIMER=null; } }
function chatPollStart(){ chatPollStop(); CHAT_TIMER=setInterval(chatPollTick,15000); chatPollTick(); }
async function chatPollTick(){
  try{
    if(!SESS.user) return;
    const chat=await DB.loadChat(true);
    if(isMain()){
      const n=chatUnreadMain(chat,SESS.user.username);
      const b=document.querySelector('#navChatB');
      if(b){ b.style.display=n?'inline-flex':'none'; b.textContent=n>99?'99+':n; }
      if(CV==='chat') vChatRender(chat);
    }else{
      const me=SESS.user.username;
      const n=chatUnreadSub(chat,me);
      const b=document.querySelector('#chatBadge');
      if(b){ b.style.display=n?'flex':'none'; b.textContent=n>99?'99+':n; }
      const p=document.querySelector('#chatPanel');
      if(p&&p.style.display!=='none'){
        chatWidgetRender(chat);
        const th=chatThread(chat,me);
        if(th.some(m=>m.from!==me&&!m.seen)) await chatMarkSeen(me);
      }
    }
  }catch(e){}
}
function chatBubble(m,mine){
  return '<div class="msg '+(mine?'me':'them')+'"><div class="bub">'+esc(m.text)+'<span class="mt">'+chatTime(m.at)+'</span></div></div>';
}
function chatWidgetInit(){
  if(isMain()) return;
  if(!document.querySelector('#chatFab')){
    const w=document.createElement('div');
    w.innerHTML='<button id="chatFab" class="chat-fab" title="চ্যাট"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11.5a8.5 8.5 0 0 1-8.5 8.5c-1.5 0-3-.4-4.2-1L3 20l1.2-4.1A8.5 8.5 0 1 1 21 11.5z"/></svg><span id="chatBadge" class="chat-badge" style="display:none">0</span></button>'+
    '<div id="chatPanel" class="chat-panel" style="display:none">'+
    '<div class="chat-head"><div><b>সাপোর্ট চ্যাট</b><small>মেইন অ্যাডমিনের সাথে কথা বলো</small></div><button id="chatX">✕</button></div>'+
    '<div id="chatMsgs" class="chat-msgs"></div>'+
    '<div class="chat-in"><input type="text" id="chatTxt" placeholder="লেখো…" maxlength="1000" autocomplete="off"><button id="chatGo" class="btn btn-primary">➤</button></div></div>';
    document.body.appendChild(w);
    document.querySelector('#chatFab').onclick=()=>{
      const p=document.querySelector('#chatPanel'), open=p.style.display!=='none';
      p.style.display=open?'none':'flex';
      if(!open){ chatWidgetLoad(); }
    };
    document.querySelector('#chatX').onclick=()=>{ document.querySelector('#chatPanel').style.display='none'; };
    document.querySelector('#chatGo').onclick=chatWidgetSend;
    document.querySelector('#chatTxt').addEventListener('keydown',e=>{ if(e.key==='Enter') chatWidgetSend(); });
  }
  chatPollStart();
}
async function chatWidgetLoad(){
  const chat=await chatMarkSeen(SESS.user.username);
  chatWidgetRender(chat);
  const ms=document.querySelector('#chatMsgs'); if(ms) ms.scrollTop=ms.scrollHeight;
}
function chatWidgetRender(chat){
  const ms=document.querySelector('#chatMsgs'); if(!ms) return;
  const me=SESS.user.username, th=chatThread(chat,me);
  const nearBottom=ms.scrollHeight-ms.scrollTop-ms.clientHeight<80;
  ms.innerHTML=th.length?th.map(m=>chatBubble(m,m.from===me)).join(''):'<p class="hint" style="text-align:center;padding:20px">কোনো সমস্যা হলে এখানে লেখো।<br>মেইন অ্যাডমিন দেখে জবাব দেবে।</p>';
  if(nearBottom) ms.scrollTop=ms.scrollHeight;
}
async function chatWidgetSend(){
  const inp=document.querySelector('#chatTxt'); if(!inp) return;
  const t=inp.value.trim(); if(!t) return;
  inp.value='';
  try{
    await chatSend(SESS.user.username,t);
    const chat=await DB.loadChat(true);
    chatWidgetRender(chat);
    const ms=document.querySelector('#chatMsgs'); if(ms) ms.scrollTop=ms.scrollHeight;
  }catch(e){}
}
function chatWidgetKill(){
  chatPollStop();
  const f=document.querySelector('#chatFab'); if(f) f.parentNode.remove();
}

/* সুন্দর কনফার্ম ডায়ালগ (সব জায়গায় একই) */
function confirmDlg(title,msg,okText,danger){
  return new Promise(res=>{
    const bg=document.createElement('div');
    bg.className='modal-bg';
    bg.innerHTML='<div class="modal cdlg">'+
      '<div class="cdlg-ic">'+(danger?'⚠️':'💬')+'</div>'+
      '<h3>'+esc(title)+'</h3><p>'+esc(msg)+'</p>'+
      '<div class="row-btns" style="justify-content:center;margin-top:20px">'+
      '<button class="btn '+(danger?'btn-danger':'btn-primary')+'" id="cfOk">'+esc(okText||'হ্যাঁ, করো')+'</button>'+
      '<button class="btn btn-ghost" id="cfNo">না, থাক</button></div></div>';
    document.body.appendChild(bg);
    const done=v=>{ bg.remove(); res(v); };
    bg.querySelector('#cfOk').onclick=()=>done(true);
    bg.querySelector('#cfNo').onclick=()=>done(false);
    bg.onclick=e=>{ if(e.target===bg) done(false); };
    const esc2=e=>{ if(e.key==='Escape') done(false); };
    document.addEventListener('keydown',esc2,{once:true});
  });
}

function vShell(view){
  CV=view||'dashboard';
  if(!SESS.user){ vLogin(); return; }
  const nav=[['dashboard','ড্যাশবোর্ড',I.dash],['licenses','লাইসেন্স',I.list],['new','নতুন লাইসেন্স',I.plus]];
  if(isMain()) nav.push(['users','সাব-অ্যাডমিন',I.users]);
  if(isMain()) nav.push(['chat','চ্যাট',I.chat]);
  nav.push(['profile','প্রোফাইল',I.user]);
  nav.push(['settings','সেটিংস',I.gear]);
  app.innerHTML=
  '<div class="shell"><aside class="sidebar">'+
  '<div class="brand"><img class="logo" src="logo.webp" alt=""><div class="bt">লাইসেন্স মেশিন<small>মাদরাসা ম্যানেজার</small></div></div>'+
  '<nav class="snav">'+nav.map(n=>'<button data-v="'+n[0]+'" class="'+(CV===n[0]?'active':'')+'">'+n[2]+'<span>'+n[1]+'</span>'+(n[0]==='chat'?'<span class="nav-badge" id="navChatB" style="display:none">0</span>':'')+'</button>').join('')+'</nav>'+
  '<div class="side-foot"><div class="who"><b>'+esc(SESS.user.username)+'</b>'+(isMain()?'<span class="badge gold">মেইন</span>':'<span class="badge on">সাব</span>')+'</div>'+
  '<button class="btn btn-ghost btn-sm" id="slo">লগআউট</button></div>'+
  '</aside><div class="content"><div class="main" id="view"></div>'+
  '<div class="footer-note">মাদরাসা ম্যানেজার • লাইসেন্স মেশিন</div></div></div>';
  $$('.snav button').forEach(b=>b.onclick=()=>vShell(b.dataset.v));
  $('#slo').onclick=()=>{ chatWidgetKill(); SESS.user=null; SESS.secrets=null; SESS.pw=null; SESS.viewKey=null; vLogin('লগআউট হয়েছে।'); };
  ({dashboard:vDash,licenses:vLicenses,'new':vNew,users:vUsers,chat:vChat,profile:()=>vProfile(),settings:vSettings}[CV]||vDash)();
  if(!isMain()) chatWidgetInit(); else chatPollStart();
}

/* ---------- পাসওয়ার্ড দেখো / বদলাও (মেইন) ---------- */
async function viewPw(username){
  const box=$('#pwbox'); if(!box) return;
  try{
    if(!SESS.viewKey) throw new Error('আবার লগইন করো।');
    const users=await DB.loadUsers(true);
    const u=users.find(x=>x.username===username);
    if(!u||!u.pw_enc) throw new Error('পাসওয়ার্ড সংরক্ষিত নেই। "বদলাও" চেপে নতুন দাও।');
    const d=await decWithKey(SESS.viewKey,u.pw_enc);
    box.innerHTML='<div class="ok"><b>'+esc(dispName(u))+'</b> (@'+esc(username)+') এর পাসওয়ার্ড:<br><span class="mono" style="font-size:18px"><b>'+esc(d.pw)+'</b></span></div>';
  }catch(e){ box.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}
async function resetPw(username){
  const box=$('#pwbox'); if(!box) return;
  const np=prompt('“'+username+'” এর নতুন পাসওয়ার্ড দাও (কমপক্ষে ৬ অক্ষর):');
  if(np===null) return;
  if(np.length<6){ box.innerHTML='<div class="err">পাসওয়ার্ড ৬ অক্ষরের বেশি দাও।</div>'; return; }
  try{
    const users=await DB.loadUsers(true);
    const u=users.find(x=>x.username===username);
    if(!u) throw new Error('পাওয়া যায়নি।');
    const nsalt=randHex(8);
    u.salt=nsalt; u.pass_hash=await sha256hex(nsalt+':'+np);
    u.secrets_enc=await encSecrets(np,nsalt,{pat:SESS.secrets.pat,seed:SESS.secrets.seed});
    if(SESS.viewKey){ try{ u.pw_enc=await encWithKey(SESS.viewKey,{pw:np}); }catch(e){} }
    await DB.saveUsers(users);
    box.innerHTML='<div class="ok"><b>'+esc(dispName(u))+'</b> এর নতুন পাসওয়ার্ড সেট হয়েছে ✓<br><br>তাকে পাঠাও:<br>ইউজারনেম: <b>'+esc(username)+'</b><br>পাসওয়ার্ড: <b>'+esc(np)+'</b></div>';
  }catch(e){ box.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}

/* ---------- ইউজারনেম বদলাও (মেইন) ---------- */
async function renameUser(oldU, newU){
  newU=(newU||'').trim();
  if(!/^[a-zA-Z0-9_-]{3,30}$/.test(newU)) throw new Error('ইউজারনেম ৩-৩০ অক্ষরের হতে হবে (শুধু A-Z, ০-৯, _, -)।');
  if(newU===oldU) throw new Error('এটাই বর্তমান ইউজারনেম।');
  const users=await DB.loadUsers(true);
  if(users.some(x=>x.username===newU)) throw new Error('এই ইউজারনেমে অন্য কেউ আছে।');
  const u=users.find(x=>x.username===oldU);
  if(!u) throw new Error('ব্যবহারকারী পাওয়া যায়নি।');
  u.username=newU;
  if(u.created_by===oldU) u.created_by=newU;
  users.forEach(x=>{ if(x.created_by===oldU) x.created_by=newU; (x.packages||[]).forEach(p=>{ if(p.given_by===oldU) p.given_by=newU; }); });
  const licenses=await DB.loadLicenses(true);
  licenses.forEach(l=>{ if(l.issued_by===oldU) l.issued_by=newU; });
  const chat=await DB.loadChat(true);
  chat.threads=chat.threads||{};
  if(chat.threads[oldU]){ chat.threads[newU]=chat.threads[oldU]; delete chat.threads[oldU]; }
  for(const k in chat.threads){ (chat.threads[k]||[]).forEach(m=>{ if(m.from===oldU) m.from=newU; }); }
  await DB.saveUsers(users);
  await DB.saveLicenses(licenses);
  await DB.saveChat(chat);
  SESS.user.username=newU;
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
    wireRows(v); countUp(v);
    if(!isMain()){
      const users0=await DB.loadUsers(true);
      const me=users0.find(x=>x.username===SESS.user.username)||{};
      const hero=document.createElement('div');
      hero.className='card dh-hero';
      hero.innerHTML='<div class="dh-cover"></div><div class="dh-main">'+
        '<div class="dh-ava" id="dhAva" title="ছবি বদলাও">'+(me.photo?'<img src="'+me.photo+'" alt="">':'<div class="p-empty">👤</div>')+'<span class="dh-cam">📷</span></div>'+
        '<div class="dh-txt"><p class="dh-salam">আসসালামু আলাইকুম</p>'+
        '<h3 class="dh-name">'+esc(dispName(me))+'</h3>'+
        '<p class="dh-addr"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 21s-7-5.5-7-11a7 7 0 0 1 14 0c0 5.5-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>'+
        esc(me.address||'ঠিকানা দেওয়া হয়নি')+'</p></div>'+
        '<button class="btn btn-ghost btn-sm dh-edit" id="dhEdit">বদলাও</button></div>'+
        '<input type="file" id="dhPhoto" accept="image/*" style="display:none">';
      v.insertBefore(hero, v.children[1]||null);
      $('#dhEdit').onclick=()=>vEditProfile();
      $('#dhAva').onclick=()=>$('#dhPhoto').click();
      $('#dhPhoto').onchange=async e=>{
        try{
          const ph=await readPhoto(e.target.files[0]);
          const users2=await DB.loadUsers(true);
          const uu=users2.find(x=>x.username===SESS.user.username);
          uu.photo=ph; await DB.saveUsers(users2);
          vDash();
        }catch(err){ alert(err.message); }
      };
    }
    if(isMain()){
      const users=await DB.loadUsers(true);
      const subs=users.filter(x=>x.role!=='main');
      if(subs.length){
        const cc=document.createElement('div');
        cc.className='card';
        cc.innerHTML='<h3>সবার লগইন তথ্য</h3><div class="tbl-wrap"><table><thead><tr><th>নাম</th><th>ইউজারনেম</th><th>পাসওয়ার্ড</th><th></th></tr></thead><tbody>'+
          subs.map(x=>'<tr><td><b>'+esc(dispName(x))+'</b></td><td class="mono">'+esc(x.username)+'</td>'+
          '<td>'+(x.pw_enc?'<span class="mono">••••••</span>':'<span class="hint">সেট করা নেই</span>')+'</td>'+
          '<td style="white-space:nowrap"><button class="btn btn-ghost btn-sm" data-vpw="'+esc(x.username)+'">দেখো</button> '+
          '<button class="btn btn-gold btn-sm" data-rpw="'+esc(x.username)+'">বদলাও</button></td></tr>').join('')+
          '</tbody></table></div><div id="pwbox"></div>';
        v.appendChild(cc);
        cc.querySelectorAll('[data-vpw]').forEach(b=>b.onclick=()=>viewPw(b.dataset.vpw));
        cc.querySelectorAll('[data-rpw]').forEach(b=>b.onclick=()=>resetPw(b.dataset.rpw));
      }
    }
    if(!isMain()){
      const q=await quotaOf(SESS.user.username);
      if(q.limit){
        const act=rows.filter(l=>l.status!=='revoked').length, rev=rows.length-act;
        const box=document.createElement('div');
        box.className='card';
        const users0b=await DB.loadUsers(true);
        const me2=users0b.find(x=>x.username===SESS.user.username)||{};
        const vmn=me2.valid_min>0?me2.valid_min:null, vmx=me2.valid_max>0?me2.valid_max:null;
        const vrline=(vmn||vmx)?'<p style="margin:12px 0 0;font-size:14.5px">মেয়াদের সীমা: <b>'+(vmn||'—')+' – '+(vmx||'∞')+' দিন</b></p>':'';
        box.innerHTML='<h3>তোমার লাইসেন্স কোটা</h3><div class="qgrid">'+
        '<div class="qbox qb-used"><div class="qn">'+q.used+'</div><div class="ql">বানিয়েছে</div></div>'+
        '<div class="qbox qb-donut">'+quotaDonut(q,act,rev)+'</div>'+
        '<div class="qbox qb-rev"><div class="qn">'+rev+'</div><div class="ql">বাতিল</div></div>'+
        '<div class="qbox qb-total"><div class="qn">'+q.limit+'</div><div class="ql">মোট লিমিট</div></div>'+
        '</div>'+vrline;
        const st=v.querySelector('.stats');
        if(st) st.parentNode.insertBefore(box, st.nextSibling); else v.appendChild(box);
        const pkgs2=(me2.packages||[]).slice().reverse();
        if(pkgs2.length){
          const pc=document.createElement('div');
          pc.className='card';
          const totGot=pkgs2.reduce((sm,p)=>sm+Number(p.qty||0),0);
          const totOn=pkgs2.filter(p=>p.status==='active').reduce((sm,p)=>sm+Number(p.qty||0),0);
          pc.innerHTML='<h3>তোমার প্যাকেজ</h3>'+
          '<p style="font-size:14.5px">মোট পেয়েছ: <b>'+totGot+'টি</b> &nbsp;•&nbsp; চালু আছে: <b style="color:var(--teal-dark)">'+totOn+'টি</b></p>'+
          '<div class="tbl-wrap"><table><thead><tr><th>প্যাকেজ</th><th>তারিখ</th><th>অবস্থা</th></tr></thead><tbody>'+
          pkgs2.map(p=>'<tr><td><b>'+p.qty+'টি</b></td><td>'+esc(fmtDate(p.given_at))+'</td>'+
          '<td>'+(p.status==='active'?'<span class="badge on">চালু</span>':'<span class="badge off">বাতিল করা হয়েছে</span>')+'</td></tr>').join('')+
          '</tbody></table></div>';
          box.parentNode.insertBefore(pc, box.nextSibling);
        }
      }
    }
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}
function licRow(l){
  const c=custOf(l);
  return '<tr class="clickable" data-id="'+esc(l.license_id)+'"><td><div class="c-cell">'+photoHTML(c,'p-thumb')+'<b>'+esc(l.customer_name)+'</b></div></td>'+
  '<td class="mono">'+esc(l.license_id.slice(0,10))+'…</td><td>'+esc(validity(l))+'</td><td>'+(l.price>0?'৳'+fmtTk(l.price):'<span class="hint">—</span>')+'</td><td>'+badge(l)+'</td>'+
  (isMain()?'<td>'+esc(l.issued_by||'—')+'</td>':'')+'<td>'+esc(fmtDate(l.issued_at))+'</td></tr>';
}
function licTable(rows){
  if(!rows.length) return '<p class="hint">এখনো কোনো লাইসেন্স নেই।</p>';
  return '<div class="tbl-wrap"><table><thead><tr><th>গ্রাহক</th><th>লাইসেন্স</th><th>মেয়াদ</th><th>দাম</th><th>অবস্থা</th>'+
  (isMain()?'<th>বানিয়েছে</th>':'')+'<th>তারিখ</th></tr></thead><tbody>'+rows.map(licRow).join('')+'</tbody></table></div>';
}
const wireRows=r=>$$('tr.clickable',r).forEach(t=>t.onclick=()=>vCustomer(t.dataset.id));

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
      if(q) rows=rows.filter(l=>{ const c=custOf(l); return (l.customer_name+' '+(c.mobile||'')+' '+(c.madrasa||'')+' '+l.license_id).toLowerCase().includes(q); });
      if(f==='on') rows=rows.filter(l=>l.status!=='revoked');
      if(f==='off') rows=rows.filter(l=>l.status==='revoked');
      $('#tbl').innerHTML='<p class="hint">'+rows.length+'টি</p>'+licTable(rows);
      wireRows($('#tbl'));
    };
    $('#q').oninput=render; $('#f').onchange=render; render();
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}

/* ---------- customer dashboard ---------- */
async function vCustomer(id){
  const v=$('#view'); v.innerHTML='<div class="boot">আসছে…</div>';
  const rows=visibleLicenses(await DB.loadLicenses());
  const l=rows.find(x=>x.license_id===id);
  if(!l){ v.innerHTML='<div class="err">লাইসেন্স পাওয়া যায়নি।</div>'; return; }
  const c=custOf(l), vi=validityInfo(l), d=daysLeft(l.expires_at);
  const ck=custKey(l);
  const hist=rows.filter(x=>custKey(x)===ck).sort((a,b)=>(b.issued_at||0)-(a.issued_at||0));
  const totSell=hist.reduce((sm,x)=>sm+(Number(x.price)||0),0);
  const histHTML='<div class="card"><h3>লাইসেন্সের ইতিহাস ('+hist.length+'টি)</h3><div class="tbl-wrap"><table><thead><tr><th>তারিখ</th><th>মেয়াদ</th><th>দাম</th><th>অবস্থা</th><th></th></tr></thead><tbody>'+
    hist.map(h=>'<tr><td>'+esc(fmtDate(h.issued_at))+'</td><td>'+esc(validity(h))+'</td><td>'+(h.price>0?'৳'+fmtTk(h.price):'—')+'</td><td>'+badge(h)+'</td><td>'+(h.license_id===id?'':'<button class="btn btn-ghost btn-sm" data-h="'+esc(h.license_id)+'">দেখো</button>')+'</td></tr>').join('')+
    '</tbody></table></div><p style="font-size:15px;margin:10px 0 0">মোট বিক্রি: <b>৳'+fmtTk(totSell)+'</b></p></div>';
  const prof=[['মোবাইল',c.mobile],['ইমেইল',c.email],['ঠিকানা',c.address],['মাদরাসার ঠিকানা',c.madrasa_address]]
    .filter(x=>x[1]).map(x=>'<dt>'+x[0]+'</dt><dd>'+esc(x[1])+'</dd>').join('');
  v.innerHTML=
  '<div class="page-head"><h2><button class="btn btn-ghost btn-sm" id="bk">‹ পেছনে</button> গ্রাহক ড্যাশবোর্ড</h2>'+
  (canEditL(l)?'<button class="btn btn-ghost btn-sm" id="ed">তথ্য বদলাও</button>':'')+'</div>'+
  '<div class="card p-card"><div class="p-top">'+photoHTML(c)+
  '<div class="p-id"><h3>'+esc(l.customer_name)+'</h3>'+
  (c.madrasa?'<p class="p-mad">🕌 '+esc(c.madrasa)+'</p>':'')+
  '<div>'+badge(l)+'</div></div></div>'+
  (prof?'<dl class="kv">'+prof+'</dl>':'<p class="hint">বাড়তি তথ্য দেওয়া হয়নি। “তথ্য বদলাও” চেপে যোগ করো।</p>')+'</div>'+
  '<div class="card"><h3>মেয়াদের হিসাব</h3><div class="vstats">'+
  '<div class="vstat v1"><div class="n">'+esc(vi.totalTxt)+'</div><div class="l">মোট মেয়াদ (দিন)</div></div>'+
  '<div class="vstat v2"><div class="n">'+esc(String(vi.elapsed))+'</div><div class="l">পার হয়েছে (দিন)</div></div>'+
  '<div class="vstat v3"><div class="n">'+esc(vi.leftTxt)+'</div><div class="l">বাকি আছে (দিন)</div></div></div>'+
  (vi.life?'':'<div class="pbar"><div class="pfill" style="width:'+vi.pct+'%"></div></div><p class="hint">'+vi.pct+'% সময় পার হয়েছে</p>')+'</div>'+
  '<div class="card"><h3>লাইসেন্স</h3>'+
  '<dl class="kv"><dt>লাইসেন্স ID</dt><dd class="mono">'+esc(l.license_id)+'</dd>'+
  '<dt>ডিভাইস</dt><dd class="mono">'+esc(l.device_code)+'</dd>'+
  '<dt>মেয়াদ</dt><dd>'+esc(validity(l))+(l.expires_at?' — '+esc(fmtDate(l.expires_at))+' পর্যন্ত':'')+(d!==null&&l.status!=='revoked'?' ('+d+' দিন বাকি)':'')+'</dd>'+
  (isMain()?'<dt>বানিয়েছে</dt><dd>'+esc(l.issued_by||'—')+' • '+esc(fmtDT(l.issued_at))+'</dd>':'<dt>তারিখ</dt><dd>'+esc(fmtDT(l.issued_at))+'</dd>')+
  (l.status==='revoked'?'<dt>বাতিল</dt><dd>'+esc(fmtDT(l.revoked_at))+'</dd>':'')+'</dl>'+
  '<label class="f">লাইসেন্স কী</label><div class="keybox">'+esc(l.key||'—')+'</div>'+
  '<div class="row-btns">'+(l.key?'<button class="btn btn-ghost btn-sm" id="cp">কপি</button>':'')+
  (isMain()&&l.status!=='revoked'?'<button class="btn btn-danger btn-sm" id="rv">বাতিল করো</button>':'')+
  (isMain()&&l.status==='revoked'?'<button class="btn btn-primary btn-sm" id="ac">সচল করো</button>':'')+
  (isMain()?'<button class="btn btn-ghost btn-sm" id="dl">ডিলিট</button>':'')+
  (canEditL(l)?'<button class="btn btn-primary btn-sm" id="nw2">নতুন লাইসেন্স দাও</button>':'')+'</div><div id="mm"></div></div>'+histHTML;
  $('#bk').onclick=()=>vShell('licenses');
  const nw2=$('#nw2'); if(nw2) nw2.onclick=()=>{ NEW_PREFILL={ckey:ck}; vShell('new'); };
  $$('#view [data-h]').forEach(b=>b.onclick=()=>vCustomer(b.dataset.h));
  const ed=$('#ed'); if(ed) ed.onclick=()=>vEditCustomer(id);
  const cp=$('#cp'); if(cp) cp.onclick=()=>{ navigator.clipboard.writeText(l.key); cp.textContent='কপি হয়েছে ✓'; };
  const rv=$('#rv');
  if(rv) rv.onclick=async()=>{
    if(!await confirmDlg('লাইসেন্স বাতিল','“'+l.customer_name+'”-এর লাইসেন্স বাতিল করবে? বাতিল করলে তার সফটওয়্যার বন্ধ হয়ে যাবে।','বাতিল করো',true)) return;
    rv.disabled=true; rv.textContent='হচ্ছে…';
    try{
      const all=await DB.loadLicenses();
      const t=all.find(x=>x.license_id===id);
      t.status='revoked'; t.revoked_at=nowSec(); t.revoked_by=SESS.user.username;
      await DB.saveLicenses(all); await DB.publishRevocations();
      $('#mm').innerHTML='<div class="ok">বাতিল হয়েছে। গ্রাহকের পিসি অনলাইনে এলে বন্ধ হয়ে যাবে।</div>';
      vCustomer(id);
    }catch(e){ $('#mm').innerHTML='<div class="err">'+esc(e.message)+'</div>'; rv.disabled=false; rv.textContent='বাতিল করো'; }
  };
  const ac=$('#ac');
  if(ac) ac.onclick=async()=>{
    if(!await confirmDlg('লাইসেন্স সচল','"'+l.customer_name+'"-এর লাইসেন্স আবার সচল করবে?','সচল করো',false)) return;
    ac.disabled=true; ac.textContent='হচ্ছে…';
    try{
      const all=await DB.loadLicenses();
      const t=all.find(x=>x.license_id===id);
      t.status='active'; delete t.revoked_at; delete t.revoked_by;
      await DB.saveLicenses(all); await DB.publishRevocations();
      $('#mm').innerHTML='<div class="ok">লাইসেন্স সচল হয়েছে। গ্রাহকের পিসি অনলাইনে এলে খুলে যাবে।</div>';
      vCustomer(id);
    }catch(e){ $('#mm').innerHTML='<div class="err">'+esc(e.message)+'</div>'; ac.disabled=false; ac.textContent='সচল করো'; }
  };
  const dl=$('#dl');
  if(dl) dl.onclick=async()=>{
    const msg=l.status==='revoked'
      ? '"'+l.customer_name+'"-এর বাতিল লাইসেন্স সম্পূর্ণ ডিলিট করবে? (তার সফটওয়্যার বন্ধই থাকবে)'
      : '"'+l.customer_name+'"-এর লাইসেন্স ডিলিট করবে?';
    if(!await confirmDlg('লাইসেন্স ডিলিট',msg,'ডিলিট করো',true)) return;
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
      vShell('licenses');
    }catch(e){ $('#mm').innerHTML='<div class="err">'+esc(e.message)+'</div>'; dl.disabled=false; dl.textContent='ডিলিট'; }
  };
}

/* ---------- customer info edit ---------- */
async function vEditCustomer(id){
  const rows=visibleLicenses(await DB.loadLicenses());
  const l=rows.find(x=>x.license_id===id);
  if(!l||!canEditL(l)){ vShell('licenses'); return; }
  const c=custOf(l);
  const v=$('#view');
  v.innerHTML='<div class="page-head"><h2><button class="btn btn-ghost btn-sm" id="bk">‹ পেছনে</button> তথ্য বদলাও</h2></div>'+
  '<div class="card" style="max-width:620px"><div id="ferr" class="err" style="display:none"></div>'+
  '<div class="p-top">'+photoHTML(c)+'<div><label class="f" style="margin-top:0">ছবি</label>'+
  '<input type="file" id="ph" accept="image/*"><p class="hint">নতুন ছবি দিলে আগেরটা বদলে যাবে।</p>'+
  '<button class="btn btn-ghost btn-sm" id="rmph"'+(c.photo?'':' style="display:none"')+'>ছবি মুছো</button></div></div>'+
  '<label class="f">নাম</label><input type="text" id="nm" value="'+esc(c.name||l.customer_name||'')+'">'+
  '<label class="f">মোবাইল নম্বর</label><input type="text" id="mb" value="'+esc(c.mobile||'')+'">'+
  '<label class="f">ইমেইল</label><input type="text" id="em" value="'+esc(c.email||'')+'">'+
  '<label class="f">ঠিকানা</label><textarea id="ad">'+esc(c.address||'')+'</textarea>'+
  '<label class="f">মাদরাসার নাম</label><input type="text" id="mn" value="'+esc(c.madrasa||'')+'">'+
  '<label class="f">মাদরাসার ঠিকানা</label><textarea id="ma">'+esc(c.madrasa_address||'')+'</textarea>'+
  '<div class="row-btns"><button class="btn btn-primary" id="sv">সংরক্ষণ করো</button></div></div>';
  $('#bk').onclick=()=>vCustomer(id);
  let photo=c.photo||'', photoRemoved=false;
  $('#ph').onchange=async e=>{
    hideErr();
    try{ photo=await readPhoto(e.target.files[0]); photoRemoved=false;
      const p=$('.p-top .p-photo, .p-top img',v); if(p) p.outerHTML=photoHTML({photo:photo});
      $('#rmph').style.display='';
    }catch(err){ showErr(err.message); e.target.value=''; }
  };
  $('#rmph').onclick=()=>{ photo=''; photoRemoved=true; const p=$('.p-top .p-photo, .p-top img',v); if(p) p.outerHTML=photoHTML({}); $('#rmph').style.display='none'; $('#ph').value=''; };
  $('#sv').onclick=async ev=>{
    hideErr(); const b=ev.target; busy(b,true);
    try{
      const nm=$('#nm').value.trim();
      if(!nm) throw new Error('নাম লেখো।');
      const all=await DB.loadLicenses();
      const t0=all.find(x=>x.license_id===id);
      const ck2=custKey(t0);
      const nc={name:nm, mobile:$('#mb').value.trim(), email:$('#em').value.trim(),
        address:$('#ad').value.trim(), madrasa:$('#mn').value.trim(), madrasa_address:$('#ma').value.trim(), photo:photo};
      all.forEach(x=>{ if(custKey(x)===ck2){ x.customer_name=nm; x.customer=Object.assign({},nc); } });
      await DB.saveLicenses(all);
      vCustomer(id);
    }catch(e){ showErr(e.message); }
    busy(b,false);
  };
}

/* ---------- new license ---------- */
async function vNew(){
  const v=$('#view');
  const me0=(await DB.loadUsers(true)).find(x=>x.username===SESS.user.username)||{};
  const VR={vmin:me0.valid_min>0?me0.valid_min:null, vmax:me0.valid_max>0?me0.valid_max:null};
  const vrange=(VR.vmin||VR.vmax)?'<p class="hint" style="font-weight:700;color:var(--navy)">তোমার অনুমোদিত মেয়াদ: '+(VR.vmin||1)+' – '+(VR.vmax||'∞')+' দিন</p>':'';
  const all0=visibleLicenses(await DB.loadLicenses());
  const groups={};
  all0.forEach(l=>{ const k=custKey(l); if(!groups[k]) groups[k]={cid:l.customer_id||null,lic:l,count:0}; groups[k].count++; if((l.issued_at||0)>(groups[k].lic.issued_at||0)) groups[k].lic=l; });
  const gkeys=Object.keys(groups).sort((a,b)=>(groups[b].lic.issued_at||0)-(groups[a].lic.issued_at||0));
  const custOpts=gkeys.map(k=>{ const g=groups[k],cc=custOf(g.lic); return '<option value="'+esc(k)+'">'+esc(g.lic.customer_name||'—')+(cc.madrasa?' — '+esc(cc.madrasa):'')+' ('+g.count+'টি)</option>'; }).join('');
  let qnote='';
  if(!isMain()){
    const q=await quotaOf(SESS.user.username);
    if(q.limit){
      qnote='<div class="card" style="border-right:4px solid '+(q.left===0?'var(--red)':'var(--gold)')+'">'+
        '<div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap"><b>তোমার লাইসেন্স লিমিট:</b>'+quotaBar(q)+'</div>'+
        (q.left===0?'<p class="hint" style="color:var(--red);font-weight:700">লিমিট শেষ — নতুন লাইসেন্স বানাতে মেইন অ্যাডমিনের সাথে যোগাযোগ করো।</p>':'')+'</div>';
    }
  }
  v.innerHTML='<div class="page-head"><h2>নতুন লাইসেন্স</h2></div>'+qnote+
  '<div class="card" style="max-width:620px"><div id="ferr" class="err" style="display:none"></div><div id="fok"></div>'+
  '<h3>গ্রাহকের তথ্য</h3>'+
  '<label class="f">আগের গ্রাহক (ঐচ্ছিক)</label><select id="pc"><option value="">➕ নতুন গ্রাহক</option>'+custOpts+'</select>'+
  '<p class="hint">আগের গ্রাহক বাছলে তার তথ্য বসে যাবে — একই গ্রাহকের নামে বারবার নতুন লাইসেন্স দেওয়া যাবে।</p>'+
  '<div class="p-top">'+photoHTML({})+'<div style="flex:1"><label class="f" style="margin-top:0">ছবি (ইচ্ছা)</label>'+
  '<input type="file" id="ph" accept="image/*"></div></div>'+
  '<label class="f">গ্রাহকের নাম *</label><input type="text" id="c" placeholder="যেমন: মুহতামিম সাহেবের নাম">'+
  '<label class="f">মোবাইল নম্বর</label><input type="text" id="m" placeholder="01XXXXXXXXX">'+
  '<label class="f">ইমেইল</label><input type="text" id="e" placeholder="ইমেইল (ইচ্ছা)">'+
  '<label class="f">ঠিকানা</label><textarea id="a" placeholder="গ্রাম/এলাকা, থানা, জেলা"></textarea>'+
  '<label class="f">মাদরাসার নাম</label><input type="text" id="mn" placeholder="মাদরাসার নাম">'+
  '<label class="f">মাদরাসার ঠিকানা</label><textarea id="ma" placeholder="মাদরাসার ঠিকানা"></textarea>'+
  '<label class="f">দাম (টাকা)</label><input type="number" id="pr" min="0" placeholder="যেমন: 1500">'+
  '<h3 style="margin-top:18px">লাইসেন্সের তথ্য</h3>'+vrange+
  '<label class="f">ডিভাইস কোড *</label><input type="text" id="d" class="mono" placeholder="MM-PC-…" autocomplete="off">'+
  '<p class="hint">গ্রাহকের সফটওয়্যারে যে কোড দেখায়, সেটা হুবহু বসাও।</p>'+
  '<label class="f">মেয়াদ</label><div class="dur-pick" id="dur">'+
  [['lifetime','আজীবন'],['30','৩০ দিন'],['365','১ বছর'],['custom','অন্য…']].map((x,i)=>'<label class="'+(i===0?'sel':'')+'"><input type="radio" name="dur" value="'+x[0]+'">'+x[1]+'</label>').join('')+
  '</div><div id="cd" style="display:none"><label class="f">কত দিন?</label><input type="number" id="nd" min="1" max="3650" value="90"></div>'+
  '<div class="row-btns"><button class="btn btn-primary" id="mk">তৈরি করো</button></div></div><div id="res"></div>';
  $$('#dur label').forEach(lb=>lb.onclick=()=>{
    $$('#dur label').forEach(x=>x.classList.remove('sel')); lb.classList.add('sel');
    $('#cd').style.display=$('input',lb).value==='custom'?'block':'none';
  });
  let newPhoto='';
  $('#pc').onchange=()=>{
    hideErr();
    const k=$('#pc').value;
    const p0=$('.p-top .p-photo',v);
    if(!k){ ['c','m','e','a','mn','ma','pr'].forEach(i=>{ $('#'+i).value=''; }); newPhoto=''; if(p0) p0.outerHTML=photoHTML({}); return; }
    const g=groups[k]; if(!g) return; const cc=custOf(g.lic);
    $('#c').value=g.lic.customer_name||''; $('#m').value=cc.mobile||''; $('#e').value=cc.email||'';
    $('#a').value=cc.address||''; $('#mn').value=cc.madrasa||''; $('#ma').value=cc.madrasa_address||''; $('#pr').value='';
    newPhoto=cc.photo||''; if(p0) p0.outerHTML=photoHTML({photo:newPhoto});
  };
  if(NEW_PREFILL&&NEW_PREFILL.ckey&&groups[NEW_PREFILL.ckey]){ $('#pc').value=NEW_PREFILL.ckey; $('#pc').onchange(); }
  NEW_PREFILL=null;
  $('#ph').onchange=async e=>{
    hideErr();
    try{ newPhoto=await readPhoto(e.target.files[0]);
      const p=$('.p-top .p-photo',v); if(p) p.outerHTML=photoHTML({photo:newPhoto});
    }catch(err){ showErr(err.message); e.target.value=''; }
  };
  $('#mk').onclick=async ev=>{
    hideErr(); $('#fok').innerHTML=''; $('#res').innerHTML='';
    const b=ev.target; busy(b,true,'বানাচ্ছি…');
    try{
      if(!isMain()){
        const q=await quotaOf(SESS.user.username);
        if(q.limit&&q.left<=0) throw new Error('তোমার লাইসেন্স লিমিট শেষ। মেইন অ্যাডমিনের সাথে যোগাযোগ করো।');
      }
      const dv=$('input[name=dur]:checked').value;
      const days=dv==='lifetime'?null:(dv==='custom'?parseInt($('#nd').value,10):parseInt(dv,10));
      if(VR.vmax&&days===null) throw new Error('আজীবন মেয়াদের লাইসেন্স বানানোর অনুমতি তোমার নেই (সর্বোচ্চ '+VR.vmax+' দিন)।');
      if(days!==null){ if(VR.vmin&&days<VR.vmin) throw new Error('মেয়াদ কমপক্ষে '+VR.vmin+' দিন হতে হবে।'); if(VR.vmax&&days>VR.vmax) throw new Error('মেয়াদ সর্বোচ্চ '+VR.vmax+' দিন হতে পারবে।'); }
      const price=Math.max(0,parseInt($('#pr').value,10)||0);
      const lic=buildLicense({customer:$('#c').value,deviceCode:$('#d').value,days:days,seedB64:SESS.secrets.seed});
      const all=await DB.loadLicenses();
      let cid=null; const sk=$('#pc').value;
      if(sk&&groups[sk]){ const gg=groups[sk]; cid=gg.cid||('cus_'+randHex(6)); if(!gg.cid) all.forEach(x=>{ if(custKey(x)===sk) x.customer_id=cid; }); }
      all.push({license_id:lic.license_id,customer_id:cid,price:price,customer_name:lic.customer_name,device_code:lic.device_code,
        days:lic.days,issued_at:lic.issued_at,expires_at:lic.expires_at,issued_by:SESS.user.username,status:'active',key:lic.key,
        customer:{name:lic.customer_name,mobile:$('#m').value.trim(),email:$('#e').value.trim(),address:$('#a').value.trim(),
          madrasa:$('#mn').value.trim(),madrasa_address:$('#ma').value.trim(),photo:newPhoto}});
      await DB.saveLicenses(all);
      $('#fok').innerHTML='<div class="ok">লাইসেন্স তৈরি হয়েছে ✓</div>';
      $('#res').innerHTML='<div class="card"><h3>'+esc(lic.customer_name)+'</h3><div class="keybox">'+esc(lic.key)+'</div>'+
      '<div class="row-btns"><button class="btn btn-gold" id="cp2">কপি করো</button><button class="btn btn-ghost" id="ag">আরেকটি</button></div>'+
      '<p class="hint">মেয়াদ: '+esc(validity(lic))+'</p></div>';
      $('#cp2').onclick=e=>{ navigator.clipboard.writeText(lic.key); e.target.textContent='কপি হয়েছে ✓'; };
      $('#ag').onclick=()=>vShell('new');
      $('#c').value=''; $('#d').value=''; $('#m').value=''; $('#e').value=''; $('#a').value=''; $('#mn').value=''; $('#ma').value=''; $('#pr').value=''; $('#pc').value=''; newPhoto='';
    }catch(e){ showErr(e.message); }
    busy(b,false);
  };
}

/* ---------- প্রোফাইল ---------- */
async function vProfile(username){
  const v=$('#view'); v.innerHTML='<div class="boot">আসছে…</div>';
  try{
    const target=username||SESS.user.username;
    if(!isMain()&&target!==SESS.user.username){ v.innerHTML='<div class="err">অনুমতি নেই।</div>'; return; }
    const users=await DB.loadUsers(true);
    const u=users.find(x=>x.username===target);
    if(!u){ v.innerHTML='<div class="err">ব্যবহারকারী পাওয়া যায়নি।</div>'; return; }
    const all=await DB.loadLicenses();
    const mine=all.filter(l=>l.issued_by===target);
    const act=mine.filter(l=>l.status!=='revoked').length, rev=mine.length-act;
    const q=await quotaOf(target);
    const canEdit=isMain()||target===SESS.user.username;
    const icPhone='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="7" y="2" width="10" height="20" rx="2.5"/><path d="M11 18.5h2"/></svg>';
    const icCal='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="16" rx="2.5"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>';
    const icUser='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a8 8 0 0 1 16 0v1"/></svg>';
    const pfAva=u.photo?'<div class="pf-ava"><img src="'+u.photo+'" alt=""></div>':'<div class="pf-ava"><div class="p-empty">\uD83D\uDC64</div></div>';
    v.innerHTML='<div class="page-head"><h2>প্রোফাইল</h2>'+
      (canEdit?'<button class="btn btn-ghost btn-sm" id="pe">বদলাও</button>':'')+'</div>'+
    '<div class="card pf-card"><div class="pf-cover"></div><div class="pf-main">'+pfAva+
      '<h3 class="pf-name">'+esc(dispName(u))+'</h3>'+
      '<p class="pf-un">@'+esc(u.username)+'</p>'+
      '<div>'+(u.role==='main'?'<span class="badge gold">মেইন অ্যাডমিন</span>':'<span class="badge on">সাব-অ্যাডমিন</span>')+'</div>'+
      '<div class="pf-info">'+
      (u.phone?'<div class="pf-row"><span class="k">'+icPhone+'মোবাইল</span><span class="v">'+esc(u.phone)+'</span></div>':'')+
      '<div class="pf-row"><span class="k">'+icCal+'যোগ দিয়েছে</span><span class="v">'+esc(fmtDate(u.created_at))+'</span></div>'+
      (u.created_by?'<div class="pf-row"><span class="k">'+icUser+'যোগ করেছে</span><span class="v">'+esc(u.created_by)+'</span></div>':'')+
      '</div></div></div>'+
    '<div class="card"><h3>লাইসেন্সের হিসাব</h3><div class="vstats">'+
      '<div class="vstat v1"><div class="n">'+mine.length+'</div><div class="l">মোট বানিয়েছে</div></div>'+
      '<div class="vstat v3"><div class="n">'+act+'</div><div class="l">চালু</div></div>'+
      '<div class="vstat v2"><div class="n">'+rev+'</div><div class="l">বাতিল</div></div></div>'+
      (q.limit?'<h3 style="margin-top:6px">লাইসেন্স লিমিট</h3>'+quotaBar(q):'<p class="hint">লাইসেন্স লিমিট: সীমা নেই (আনলিমিটেড)</p>')+'</div>';
    countUp(v);
    const pe=$('#pe'); if(pe) pe.onclick=()=>vEditProfile(target);
    if(isMain()&&u.role==='main'&&target===SESS.user.username){
      const lc=document.createElement('div');
      lc.className='card'; lc.style.borderRight='4px solid var(--navy)';
      lc.innerHTML='<h3>লগইন তথ্য</h3><div id="pwbox"></div>'+
        '<div class="pf-info">'+
        '<div class="pf-row"><span class="k">ইউজারনেম</span><span class="v mono">@'+esc(u.username)+'</span></div>'+
        '<div class="pf-row"><span class="k">পাসওয়ার্ড</span><span class="v"><span class="mono">••••••</span> '+
        '<button class="btn btn-ghost btn-sm" id="pwv">দেখো</button></span></div></div>'+
        '<div class="row-btns"><button class="btn btn-ghost" id="unm">ইউজারনেম বদলাও</button></div>'+
        '<p class="hint">ইউজারনেম বদলালে তোমার বানানো লাইসেন্স, চ্যাট ও প্যাকেজের হিসাব নতুন নামে চলে যাবে।</p>';
      v.appendChild(lc);
      $('#pwv').onclick=()=>viewPw(target);
      $('#unm').onclick=async()=>{
        const nn=prompt('নতুন ইউজারনেম দাও (৩-৩০ অক্ষর, A-Z ০-৯ _ -):', u.username);
        if(nn===null) return;
        try{ await renameUser(target, nn);
          const who=document.querySelector('.side-foot .who b'); if(who) who.textContent=nn;
          vProfile(nn); }
        catch(e){ const pb=$('#pwbox'); if(pb) pb.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
      };
    }
    if(isMain()&&u.role!=='main'){
      const pkgs=(u.packages||[]).slice().reverse();
      const eff=pkgLimit(u);
      const qc=document.createElement('div');
      qc.className='card'; qc.style.borderRight='4px solid var(--gold)';
      let ph='<h3>লাইসেন্স প্যাকেজ</h3><div id="qerr" class="err" style="display:none"></div>';
      ph+='<p style="font-size:15px">মোট কার্যকর: <b style="font-family:\'Baloo Da 2\';font-size:20px;color:var(--navy)">'+(eff===null?'আনলিমিটেড':eff+'টি')+'</b></p>';
      if(pkgs.length){
        ph+='<div class="tbl-wrap"><table><thead><tr><th>প্যাকেজ</th><th>দিয়েছে</th><th>অবস্থা</th><th></th></tr></thead><tbody>'+
          pkgs.map(p=>'<tr><td><b>'+p.qty+'টি</b></td><td>'+esc(fmtDate(p.given_at))+'<br><small class="hint">'+esc(p.given_by||'')+'</small></td>'+
          '<td>'+(p.status==='active'?'<span class="badge on">চালু</span>':'<span class="badge off">বাতিল</span>')+'</td>'+
          '<td>'+(p.status==='active'?'<button class="btn btn-danger btn-sm" data-cpkg="'+p.id+'">ক্যানসেল</button>':'')+'</td></tr>').join('')+
          '</tbody></table></div>';
      }else ph+='<p class="hint">এখনো কোনো প্যাকেজ দেওয়া হয়নি।</p>';
      ph+='<div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin-top:14px">'+
        '<div style="flex:1;min-width:160px"><label class="f" style="margin-top:0">নতুন প্যাকেজ (টি)</label>'+
        '<input type="number" id="qpkg" min="1" placeholder="যেমন: ২০"></div>'+
        '<button class="btn btn-gold" id="qadd">প্যাকেজ দাও</button></div>'+
        '<p class="hint">দেওয়ার সাথে সাথে তার ড্যাশবোর্ডের মিটারে যোগ হবে। ক্যানসেল করলে ওই প্যাকেজের সংখ্যা বাদ যাবে।</p>';
      qc.innerHTML=ph;
      v.insertBefore(qc, v.children[2]||null);
      const vc=document.createElement('div');
      vc.className='card'; vc.style.borderRight='4px solid var(--teal-dark)';
      const curR=(u.valid_min>0||u.valid_max>0)?('বর্তমান: '+(u.valid_min>0?u.valid_min+' দিন':'—')+' থেকে '+(u.valid_max>0?u.valid_max+' দিন':'সীমা নেই')):'বর্তমান: সীমা নেই';
      vc.innerHTML='<h3>লাইসেন্স মেয়াদ সীমা</h3><div id="verr" class="err" style="display:none"></div>'+
        '<p class="hint">এই সাব-অ্যাডমিন কত দিন থেকে কত দিন মেয়াদের লাইসেন্স বানাতে পারবে। খালি রাখলে সীমা নেই।</p>'+
        '<p style="font-size:14.5px">'+curR+'</p>'+
        '<div style="display:flex;gap:10px;flex-wrap:wrap">'+
        '<div style="flex:1;min-width:140px"><label class="f" style="margin-top:0">সর্বনিম্ন (দিন)</label><input type="number" id="vmin" min="1" max="3650" value="'+(u.valid_min>0?u.valid_min:'')+'" placeholder="যেমন: 30"></div>'+
        '<div style="flex:1;min-width:140px"><label class="f" style="margin-top:0">সর্বোচ্চ (দিন)</label><input type="number" id="vmax" min="1" max="3650" value="'+(u.valid_max>0?u.valid_max:'')+'" placeholder="যেমন: 365"></div></div>'+
        '<div class="row-btns"><button class="btn btn-gold" id="vsv">সংরক্ষণ</button>'+((u.valid_min>0||u.valid_max>0)?'<button class="btn btn-ghost" id="vclr">সীমা তুলে দাও</button>':'')+'</div>';
      v.insertBefore(vc, v.children[3]||null);
      $('#vsv').onclick=async ev=>{ const b=ev.target; busy(b,true);
        try{
          const mn=parseInt($('#vmin').value,10)||null, mx=parseInt($('#vmax').value,10)||null;
          if(mn&&mx&&mn>mx) throw new Error('সর্বনিম্ন সর্বোচ্চের চেয়ে বেশি হতে পারবে না।');
          if((mn&&mn>3650)||(mx&&mx>3650)) throw new Error('মেয়াদ ৩৬৫০ দিনের বেশি নয়।');
          const users2=await DB.loadUsers(true); const uu=users2.find(x=>x.username===target);
          if(mn) uu.valid_min=mn; else delete uu.valid_min;
          if(mx) uu.valid_max=mx; else delete uu.valid_max;
          await DB.saveUsers(users2); vProfile(target);
        }catch(e){ const ve=$('#verr'); if(ve){ ve.textContent=e.message; ve.style.display='block'; } }
        busy(b,false); };
      const vclr=$('#vclr'); if(vclr) vclr.onclick=async()=>{ const users2=await DB.loadUsers(true); const uu=users2.find(x=>x.username===target); delete uu.valid_min; delete uu.valid_max; await DB.saveUsers(users2); vProfile(target); };
      qc.querySelectorAll('[data-cpkg]').forEach(b=>b.onclick=async ev=>{
        if(!await confirmDlg('প্যাকেজ ক্যানসেল','এই প্যাকেজটি ক্যানসেল করবে? ক্যানসেল করলে এই প্যাকেজের লাইসেন্স সংখ্যা তার কোটা থেকে বাদ যাবে।','ক্যানসেল করো',true)) return;
        const btn=ev.target; busy(btn,true);
        try{
          const users2=await DB.loadUsers(true);
          const uu=users2.find(x=>x.username===target);
          const p=(uu.packages||[]).find(x=>x.id===b.dataset.cpkg);
          if(p){ p.status='cancelled'; p.cancelled_at=nowSec(); }
          await DB.saveUsers(users2);
          vProfile(target);
        }catch(e){ const qe=$('#qerr'); if(qe){ qe.textContent=e.message; qe.style.display='block'; } }
        busy(btn,false);
      });
      $('#qadd').onclick=async ev=>{
        const b=ev.target; busy(b,true);
        try{
          const n=parseInt($('#qpkg').value,10);
          if(!(n>0)) throw new Error('কতটি দেবে লেখো।');
          const users2=await DB.loadUsers(true);
          const uu=users2.find(x=>x.username===target);
          uu.packages=uu.packages||[];
          uu.packages.push({id:'pkg_'+randHex(4),qty:n,given_at:nowSec(),given_by:SESS.user.username,status:'active'});
          await DB.saveUsers(users2);
          vProfile(target);
        }catch(e){ const qe=$('#qerr'); if(qe){ qe.textContent=e.message; qe.style.display='block'; } }
        busy(b,false);
      };
    }
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}
async function vEditProfile(username){
  const v=$('#view'); v.innerHTML='<div class="boot">আসছে…</div>';
  try{
    const target=username||SESS.user.username;
    if(!isMain()&&target!==SESS.user.username){ v.innerHTML='<div class="err">অনুমতি নেই।</div>'; return; }
    const users=await DB.loadUsers(true);
    const u=users.find(x=>x.username===target);
    if(!u){ v.innerHTML='<div class="err">ব্যবহারকারী পাওয়া যায়নি।</div>'; return; }
    let newPhoto=u.photo||'';
    v.innerHTML='<div class="page-head"><h2><button class="btn btn-ghost btn-sm" id="bk">‹ পেছনে</button> প্রোফাইল বদলাও</h2></div>'+
    '<div class="card" style="max-width:560px"><div id="ferr" class="err" style="display:none"></div>'+
    '<div class="p-top">'+photoHTML({photo:newPhoto})+'<div style="flex:1"><label class="f" style="margin-top:0">ছবি</label>'+
    '<input type="file" id="ph" accept="image/*"></div></div>'+
    '<label class="f">নাম</label><input type="text" id="dn" value="'+esc(u.display_name||'')+'" placeholder="যেমন: মোঃ রহিম">'+
    '<label class="f">মোবাইল</label><input type="text" id="ph2" value="'+esc(u.phone||'')+'" placeholder="01XXXXXXXXX">'+
    '<label class="f">ঠিকানা</label><textarea id="ad" placeholder="গ্রাম/এলাকা, থানা, জেলা">'+esc(u.address||'')+'</textarea>'+

    '<div class="row-btns"><button class="btn btn-primary" id="sv">সংরক্ষণ</button></div></div>';
    $('#bk').onclick=()=>vProfile(target);
    $('#ph').onchange=async e=>{
      try{ newPhoto=await readPhoto(e.target.files[0]);
        const p=$('.p-top .p-photo',v); if(p) p.outerHTML=photoHTML({photo:newPhoto});
      }catch(err){ showErr(err.message); e.target.value=''; }
    };
    $('#sv').onclick=async ev=>{
      hideErr(); const b=ev.target; busy(b,true);
      try{
        u.display_name=$('#dn').value.trim(); u.phone=$('#ph2').value.trim(); u.address=$('#ad').value.trim(); u.photo=newPhoto;
        await DB.saveUsers(users);
        vProfile(target);
      }catch(e){ showErr(e.message); }
      busy(b,false);
    };
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}

/* ---------- sub-admins (main only) ---------- */
async function vUsers(){
  if(!isMain()){ $('#view').innerHTML='<div class="err">শুধু মেইন অ্যাডমিন।</div>'; return; }
  const v=$('#view'); v.innerHTML='<div class="boot">আসছে…</div>';
  try{
    const users=await DB.loadUsers(true);
    const subs=users.filter(u=>u.role!=='main');
    const all=await DB.loadLicenses();
    const qmap={};
    for(const u of subs){
      const lim=pkgLimit(u);
      const used=all.filter(l=>l.issued_by===u.username).length;
      qmap[u.username]={limit:lim,used:used,left:lim===null?null:Math.max(0,lim-used)};
    }
    v.innerHTML='<div class="page-head"><h2>সাব-অ্যাডমিন</h2></div>'+
    '<div class="card"><h3>তালিকা</h3>'+
    (subs.length?'<div class="tbl-wrap"><table><thead><tr><th>সাব-অ্যাডমিন</th><th>লাইসেন্স লিমিট</th><th>যোগ করেছে</th><th></th></tr></thead><tbody>'+
      subs.map(u=>'<tr><td><div class="c-cell">'+photoHTML({photo:u.photo},'p-thumb')+'<div><b>'+esc(dispName(u))+'</b><br><small class="hint">@'+esc(u.username)+'</small></div></div></td>'+
      '<td>'+quotaBar(qmap[u.username])+'</td><td>'+esc(u.created_by||'—')+'<br><small class="hint">'+esc(fmtDate(u.created_at))+'</small></td>'+
      '<td style="white-space:nowrap"><button class="btn btn-ghost btn-sm" data-prof="'+esc(u.username)+'">প্রোফাইল</button> '+
      '<button class="btn btn-danger btn-sm" data-del="'+esc(u.username)+'">মুছো</button></td></tr>').join('')+'</tbody></table></div>'
      :'<p class="hint">এখনো কেউ নেই।</p>')+'</div>'+
    '<div class="card" style="max-width:560px"><h3>নতুন যোগ করো</h3>'+
    '<div id="ferr" class="err" style="display:none"></div><div id="share"></div>'+
    '<label class="f">নাম</label><input type="text" id="nd" placeholder="যেমন: মোঃ রহিম">'+
    '<label class="f">ইউজারনেম *</label><input type="text" id="nu" autocomplete="off">'+
    '<label class="f">মোবাইল</label><input type="text" id="nph" placeholder="01XXXXXXXXX">'+
    '<label class="f">পাসওয়ার্ড *</label><input type="password" id="np" autocomplete="new-password">'+
    '<label class="f">প্রথম প্যাকেজ (টি)</label><input type="number" id="nl" min="0" placeholder="যেমন: ৫০ (খালি = প্যাকেজ ছাড়া)">'+
    '<p class="hint">সে শুধু নিজের বানানো লাইসেন্স দেখতে পাবে। বাতিল করতে পারবে না। প্যাকেজ শেষ হলে নতুন লাইসেন্স বানাতে পারবে না।</p>'+
    '<div class="row-btns"><button class="btn btn-primary" id="ngo">যোগ করো</button></div></div>';
    $$('[data-prof]').forEach(x=>x.onclick=()=>vProfile(x.dataset.prof));
    $$('[data-del]').forEach(x=>x.onclick=async()=>{
      if(!await confirmDlg('সাব-অ্যাডমিন মুছো','“'+x.dataset.del+'” কে মুছে ফেলবে?','মুছে ফেলো',true)) return;
      await DB.saveUsers(users.filter(u=>u.username!==x.dataset.del)); vUsers();
    });
    $('#ngo').onclick=async ev=>{
      hideErr(); $('#share').innerHTML=''; const b=ev.target; busy(b,true);
      try{
        const un=$('#nu').value.trim(), pw=$('#np').value;
        if(!un) throw new Error('ইউজারনেম লেখো।');
        if(pw.length<6) throw new Error('পাসওয়ার্ড ৬ অক্ষরের বেশি দাও।');
        if(users.some(u=>u.username===un)) throw new Error('এই নামে আগেই আছে।');
        const salt=randHex(8), limN=parseInt((document.querySelector('#nl')||{value:''}).value,10);
        const pkgs=limN>0?[{id:'pkg_'+randHex(4),qty:limN,given_at:nowSec(),given_by:SESS.user.username,status:'active'}]:[];
        const nu={username:un,salt:salt,pass_hash:await sha256hex(salt+':'+pw),role:'sub',
          display_name:document.querySelector('#nd').value.trim(),phone:document.querySelector('#nph').value.trim(),
          packages:pkgs,
          created_by:SESS.user.username,created_at:nowSec(),
          secrets_enc:await encSecrets(pw,salt,{pat:SESS.secrets.pat,seed:SESS.secrets.seed})};
        if(SESS.viewKey){ try{ nu.pw_enc=await encWithKey(SESS.viewKey,{pw:pw}); }catch(e){} }
        users.push(nu);
        await DB.saveUsers(users);
        $('#share').innerHTML='<div class="ok"><b>'+esc(un)+'</b> যোগ হয়েছে ✓<br><br>তাকে পাঠাও:<br>লিংক: <span class="mono">'+esc(location.href.split('#')[0])+'</span><br>ইউজারনেম: <b>'+esc(un)+'</b><br>পাসওয়ার্ড: <b>'+esc(pw)+'</b></div>';
        $('#nu').value=''; $('#np').value='';
      }catch(e){ showErr(e.message); }
      busy(b,false);
    };
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}

/* ---------- মেইন অ্যাডমিন চ্যাট ---------- */
async function vChat(){
  if(!isMain()){ document.querySelector('#view').innerHTML='<div class="err">শুধু মেইন অ্যাডমিন।</div>'; return; }
  CHAT_OPEN=null;
  const v=document.querySelector('#view');
  v.innerHTML='<div class="page-head"><h2>চ্যাট</h2></div>'+
  '<div class="card chat-card"><div class="chat-layout">'+
  '<div class="chat-threads" id="chTh"><div class="boot">আসছে…</div></div>'+
  '<div class="chat-conv" id="chCv"><p class="hint" style="padding:30px;text-align:center">বাম থেকে একজন সাব-অ্যাডমিন বাছো।</p></div>'+
  '</div></div>';
  try{
    CHAT_USERS=await DB.loadUsers(true);
    const chat=await DB.loadChat(true);
    vChatRender(chat);
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}
function vChatRender(chat){
  const thEl=document.querySelector('#chTh'); if(!thEl) return;
  const me=SESS.user.username;
  const names={}; CHAT_USERS.forEach(u=>names[u.username]=dispName(u));
  const keys=Object.keys(chat.threads||{}).sort((a,b)=>{
    const ta=(chat.threads[a]||[]), tb=(chat.threads[b]||[]);
    return ((tb[tb.length-1]||{}).at||0)-((ta[ta.length-1]||{}).at||0);
  });
  thEl.innerHTML=keys.length?keys.map(k=>{
    const th=chat.threads[k], last=th[th.length-1]||{};
    const un=th.filter(m=>m.from!==me&&!m.seen).length;
    return '<button class="th-item'+(CHAT_OPEN===k?' active':'')+'" data-th="'+esc(k)+'">'+
    '<div class="th-ava">👤</div><div class="th-mid"><b>'+esc(names[k]||k)+'</b>'+
    '<small>'+esc(String(last.text||'').slice(0,40))+'</small></div>'+
    (un?'<span class="th-badge">'+un+'</span>':'')+
    '<small class="th-time">'+chatTime(last.at)+'</small></button>';
  }).join(''):'<p class="hint" style="padding:20px">এখনো কেউ মেসেজ পাঠায়নি।</p>';
  thEl.querySelectorAll('[data-th]').forEach(b=>b.onclick=()=>{ CHAT_OPEN=b.dataset.th; vChatOpen(); });
  if(CHAT_OPEN){
    const k=CHAT_OPEN, me=SESS.user.username, th=chatThread(chat,k);
    const ms=document.querySelector('#cvMsgs');
    if(ms){
      const cur=ms.querySelectorAll('.msg').length;
      if(cur!==th.length){
        const nearBottom=ms.scrollHeight-ms.scrollTop-ms.clientHeight<100;
        ms.innerHTML=th.length?th.map(m=>chatBubble(m,m.from===me)).join(''):'<p class="hint" style="text-align:center">এখনো কথা হয়নি।</p>';
        if(nearBottom||th.length>cur) ms.scrollTop=ms.scrollHeight;
        if(th.some(m=>m.from!==me&&!m.seen)) chatMarkSeen(k);
      }
    }
  }
}
async function vChatOpen(soft){
  const cv=document.querySelector('#chCv'); if(!cv||!CHAT_OPEN) return;
  const me=SESS.user.username, k=CHAT_OPEN;
  const names={}; CHAT_USERS.forEach(u=>names[u.username]=dispName(u));
  let chat=await DB.loadChat(true);
  let th=chatThread(chat,k);
  if(th.some(m=>m.from!==me&&!m.seen)) chat=await chatMarkSeen(k), th=chatThread(chat,k);
  const msId='cvMsgs';
  cv.innerHTML='<div class="cv-head"><div class="th-ava">👤</div><div><b>'+esc(names[k]||k)+'</b><small>@'+esc(k)+'</small></div></div>'+
  '<div class="cv-msgs" id="'+msId+'">'+(th.length?th.map(m=>chatBubble(m,m.from===me)).join(''):'<p class="hint" style="text-align:center">এখনো কথা হয়নি।</p>')+'</div>'+
  '<div class="cv-in"><input type="text" id="cvTxt" placeholder="জবাব লেখো…" maxlength="1000" autocomplete="off"><button id="cvGo" class="btn btn-primary">পাঠাও</button></div>';
  document.querySelectorAll('.th-item').forEach(b=>b.classList.toggle('active',b.dataset.th===k));
  const ms=document.querySelector('#'+msId); if(ms) ms.scrollTop=ms.scrollHeight;
  const go=async()=>{
    const inp=document.querySelector('#cvTxt'); const t=inp.value.trim(); if(!t) return;
    inp.value='';
    try{ await chatSend(k,t); vChatOpen(true); }catch(e){}
  };
  document.querySelector('#cvGo').onclick=go;
  document.querySelector('#cvTxt').addEventListener('keydown',e=>{ if(e.key==='Enter') go(); });
  if(!soft) document.querySelector('#cvTxt').focus();
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
      const oldKey=await deriveKey(op,u.salt), newKey=await deriveKey(n1,nsalt);
      u.salt=nsalt; u.pass_hash=await sha256hex(nsalt+':'+n1);
      u.secrets_enc=await encSecrets(n1,nsalt,SESS.secrets);
      try{ u.pw_enc=await encWithKey(newKey,{pw:n1}); }catch(e){}
      for(const su of users){ if(su.pw_enc){ try{ su.pw_enc=await encWithKey(newKey,await decWithKey(oldKey,su.pw_enc)); }catch(e){} } }
      SESS.viewKey=newKey;
      await DB.saveUsers(users);
      $('#fok2').innerHTML='<div class="ok">পাসওয়ার্ড বদলে গেছে ✓</div>';
      $('#op').value=$('#np1').value=$('#np2').value='';
    }catch(e){ showErr(e.message); }
    busy(b,false);
  };
  $('#lo').onclick=()=>{ chatWidgetKill(); SESS.user=null; SESS.secrets=null; SESS.pw=null; SESS.viewKey=null; vLogin('লগআউট হয়েছে।'); };
}

/* ---------- init ---------- */
(function init(){
  if(!window.nacl){ app.innerHTML='<div class="err" style="margin:40px">লাইব্রেরি আসেনি। নেট চেক করে রিলোড দাও।</div>'; return; }
  vLogin();
})();
