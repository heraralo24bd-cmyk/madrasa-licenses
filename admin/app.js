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

/* ---------- customer profile + validity dashboard ---------- */
function custOf(l){ return (l&&l.customer)||{}; }
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
  const limit=(u&&Number(u.license_limit)>0)?Number(u.license_limit):null;
  if(!limit) return {limit:null,used:0,left:null};
  const all=await DB.loadLicenses();
  const used=all.filter(l=>l.issued_by===username).length;
  return {limit:limit,used:used,left:Math.max(0,limit-used)};
}
const dispName=u=>(u&&(u.display_name||u.username))||'';

/* গোল মিটার: লাইসেন্স কোটা (তিন রঙের ডোনাট) */
function quotaDonut(q, actN, revN){
  const total=q.limit, r=70, c=2*Math.PI*r;
  const a=actN/total*c, rv=revN/total*c, rm=Math.max(0,(total-q.used))/total*c;
  const seg=(len,off,color)=>'<circle cx="90" cy="90" r="'+r+'" fill="none" stroke="'+color+
    '" stroke-width="24" stroke-dasharray="'+len.toFixed(1)+' '+c.toFixed(1)+
    '" stroke-dashoffset="'+(-off).toFixed(1)+'" transform="rotate(-90 90 90)" class="dq-seg"/>';
  return '<div class="dq-wrap"><svg viewBox="0 0 180 180" class="dq">'+
    '<circle cx="90" cy="90" r="'+r+'" fill="none" stroke="#e6ecf4" stroke-width="24"/>'+
    seg(a,0,'#147958')+seg(rv,a,'#c0392b')+seg(rm,a+rv,'#c9a227')+
    '<text x="90" y="84" text-anchor="middle" class="dq-num">'+q.left+'</text>'+
    '<text x="90" y="108" text-anchor="middle" class="dq-lab">বাকি আছে</text></svg>'+
    '<div class="dq-legend">'+
    '<div class="dq-li"><span class="dot" style="background:#147958"></span>বানিয়েছে <b>'+q.used+'</b></div>'+
    '<div class="dq-li"><span class="dot" style="background:#c0392b"></span>বাতিল <b>'+revN+'</b></div>'+
    '<div class="dq-li"><span class="dot" style="background:#c9a227"></span>মোট লিমিট <b>'+total+'</b></div>'+
    '</div></div>';
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
function vShell(view){
  CV=view||'dashboard';
  if(!SESS.user){ vLogin(); return; }
  const nav=[['dashboard','ড্যাশবোর্ড',I.dash],['licenses','লাইসেন্স',I.list],['new','নতুন লাইসেন্স',I.plus]];
  if(isMain()) nav.push(['users','সাব-অ্যাডমিন',I.users]);
  nav.push(['profile','প্রোফাইল',I.user]);
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
  ({dashboard:vDash,licenses:vLicenses,'new':vNew,users:vUsers,profile:()=>vProfile(),settings:vSettings}[CV]||vDash)();
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
      const q=await quotaOf(SESS.user.username);
      if(q.limit){
        const act=rows.filter(l=>l.status!=='revoked').length, rev=rows.length-act;
        const box=document.createElement('div');
        box.className='card dq-card';
        box.innerHTML='<h3>তোমার লাইসেন্স কোটা</h3>'+quotaDonut(q,act,rev);
        v.insertBefore(box, v.children[2]||null);
      }
    }
  }catch(e){ v.innerHTML='<div class="err">'+esc(e.message)+'</div>'; }
}
function licRow(l){
  const c=custOf(l);
  return '<tr class="clickable" data-id="'+esc(l.license_id)+'"><td><div class="c-cell">'+photoHTML(c,'p-thumb')+'<b>'+esc(l.customer_name)+'</b></div></td>'+
  '<td class="mono">'+esc(l.license_id.slice(0,10))+'…</td><td>'+esc(validity(l))+'</td><td>'+badge(l)+'</td>'+
  (isMain()?'<td>'+esc(l.issued_by||'—')+'</td>':'')+'<td>'+esc(fmtDate(l.issued_at))+'</td></tr>';
}
function licTable(rows){
  if(!rows.length) return '<p class="hint">এখনো কোনো লাইসেন্স নেই।</p>';
  return '<div class="tbl-wrap"><table><thead><tr><th>গ্রাহক</th><th>লাইসেন্স</th><th>মেয়াদ</th><th>অবস্থা</th>'+
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
  (isMain()?'<button class="btn btn-ghost btn-sm" id="dl">ডিলিট</button>':'')+'</div><div id="mm"></div></div>';
  $('#bk').onclick=()=>vShell('licenses');
  const ed=$('#ed'); if(ed) ed.onclick=()=>vEditCustomer(id);
  const cp=$('#cp'); if(cp) cp.onclick=()=>{ navigator.clipboard.writeText(l.key); cp.textContent='কপি হয়েছে ✓'; };
  const rv=$('#rv');
  if(rv) rv.onclick=async()=>{
    if(!confirm('“'+l.customer_name+'”-এর লাইসেন্স বাতিল করবে?')) return;
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
    if(!confirm('"'+l.customer_name+'"-এর লাইসেন্স আবার সচল করবে?')) return;
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
      const t=all.find(x=>x.license_id===id);
      t.customer_name=nm;
      t.customer={name:nm, mobile:$('#mb').value.trim(), email:$('#em').value.trim(),
        address:$('#ad').value.trim(), madrasa:$('#mn').value.trim(), madrasa_address:$('#ma').value.trim(), photo:photo};
      await DB.saveLicenses(all);
      vCustomer(id);
    }catch(e){ showErr(e.message); }
    busy(b,false);
  };
}

/* ---------- new license ---------- */
async function vNew(){
  const v=$('#view');
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
  '<div class="p-top">'+photoHTML({})+'<div style="flex:1"><label class="f" style="margin-top:0">ছবি (ইচ্ছা)</label>'+
  '<input type="file" id="ph" accept="image/*"></div></div>'+
  '<label class="f">গ্রাহকের নাম *</label><input type="text" id="c" placeholder="যেমন: মুহতামিম সাহেবের নাম">'+
  '<label class="f">মোবাইল নম্বর</label><input type="text" id="m" placeholder="01XXXXXXXXX">'+
  '<label class="f">ইমেইল</label><input type="text" id="e" placeholder="ইমেইল (ইচ্ছা)">'+
  '<label class="f">ঠিকানা</label><textarea id="a" placeholder="গ্রাম/এলাকা, থানা, জেলা"></textarea>'+
  '<label class="f">মাদরাসার নাম</label><input type="text" id="mn" placeholder="মাদরাসার নাম">'+
  '<label class="f">মাদরাসার ঠিকানা</label><textarea id="ma" placeholder="মাদরাসার ঠিকানা"></textarea>'+
  '<h3 style="margin-top:18px">লাইসেন্সের তথ্য</h3>'+
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
      const lic=buildLicense({customer:$('#c').value,deviceCode:$('#d').value,days:days,seedB64:SESS.secrets.seed});
      const all=await DB.loadLicenses();
      all.push({license_id:lic.license_id,customer_name:lic.customer_name,device_code:lic.device_code,
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
      $('#c').value=''; $('#d').value=''; $('#m').value=''; $('#e').value=''; $('#a').value=''; $('#mn').value=''; $('#ma').value=''; newPhoto='';
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
    if(isMain()&&u.role!=='main'){
      const qc=document.createElement('div');
      qc.className='card'; qc.style.borderRight='4px solid var(--gold)';
      qc.innerHTML='<h3>লাইসেন্সের সংখ্যা নির্ধারণ করো</h3><div id="qerr" class="err" style="display:none"></div>'+
        '<div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">'+
        '<div style="flex:1;min-width:160px"><label class="f" style="margin-top:0">কতটি লাইসেন্স বানাতে পারবে</label>'+
        '<input type="number" id="qlm" min="0" value="'+(u.license_limit||'')+'" placeholder="যেমন: ২০"></div>'+
        '<button class="btn btn-gold" id="qsv">সেভ করো</button></div>'+
        '<p class="hint">খালি বা ০ রাখলে সীমা থাকবে না। সেভ করার সাথে সাথে তার ড্যাশবোর্ডের মিটারে দেখা যাবে।</p>';
      v.insertBefore(qc, v.children[2]||null);
      $('#qsv').onclick=async ev=>{
        const b=ev.target; busy(b,true);
        try{
          const n=parseInt($('#qlm').value,10);
          const users2=await DB.loadUsers(true);
          const uu=users2.find(x=>x.username===target);
          uu.license_limit=n>0?n:null;
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
    (isMain()&&u.role!=='main'?'<label class="f">লাইসেন্স লিমিট (টি)</label><input type="number" id="lm" min="0" value="'+(u.license_limit||'')+'" placeholder="খালি = আনলিমিটেড"><p class="hint">০ বা খালি রাখলে সীমা থাকবে না।</p>':'')+
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
        u.display_name=$('#dn').value.trim(); u.phone=$('#ph2').value.trim(); u.photo=newPhoto;
        const lm=$('#lm'); if(lm) u.license_limit=parseInt(lm.value,10)>0?parseInt(lm.value,10):null;
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
      const lim=Number(u.license_limit)>0?Number(u.license_limit):null;
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
    '<label class="f">লাইসেন্স লিমিট (টি)</label><input type="number" id="nl" min="0" placeholder="খালি = আনলিমিটেড">'+
    '<p class="hint">সে শুধু নিজের বানানো লাইসেন্স দেখতে পাবে। বাতিল করতে পারবে না। লিমিট শেষ হলে নতুন লাইসেন্স বানাতে পারবে না।</p>'+
    '<div class="row-btns"><button class="btn btn-primary" id="ngo">যোগ করো</button></div></div>';
    $$('[data-prof]').forEach(x=>x.onclick=()=>vProfile(x.dataset.prof));
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
        const salt=randHex(8), limN=parseInt((document.querySelector('#nl')||{value:''}).value,10);
        users.push({username:un,salt:salt,pass_hash:await sha256hex(salt+':'+pw),role:'sub',
          display_name:document.querySelector('#nd').value.trim(),phone:document.querySelector('#nph').value.trim(),
          license_limit:limN>0?limN:null,
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
