const J=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'content-type':'application/json'}});
const hx=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const H=async(p,s)=>hx(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s+p)));
const rnd=()=>hx(crypto.getRandomValues(new Uint8Array(16)));
const ck=(x,y)=>x<0||y<0?[Math.min(x,y),Math.min(x,y)]:[Math.min(x,y),Math.max(x,y)];
const PUB='id,username,avatar,bio,status';
export default{async fetch(req,env,ctx){const u=new URL(req.url);
if(!u.pathname.startsWith('/api/'))return env.ASSETS.fetch(req);
try{return await api(req,env,u,ctx)}catch(e){return J({error:'സെർവർ പിശക്: D1 binding (DB) പരിശോധിക്കുക'},500)}}};
async function api(req,env,u,ctx){const db=env.DB,path=u.pathname.slice(5),now=Date.now();let b={};
if(req.method=='POST')try{b=await req.json()}catch{}
if(path=='signup'||path=='login'){const n=String(b.username||'').toLowerCase(),p=String(b.password||'');
if(!/^[a-z0-9_]{3,20}$/.test(n))return J({error:'Username: 3-20 അക്ഷരം (a-z, 0-9, _)'},400);
if(p.length<6)return J({error:'Password കുറഞ്ഞത് 6 അക്ഷരം വേണം'},400);
if(path=='signup'){const em=String(b.email||'').trim().toLowerCase();if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em))return J({error:'ശരിയായ ഇമെയിൽ നൽകുക'},400);if(await db.prepare('SELECT 1 x FROM users WHERE email=?').bind(em).first())return J({error:'ഈ ഇമെയിൽ ഉപയോഗത്തിലുണ്ട്'},409);const s=rnd();try{await db.prepare('INSERT INTO users(username,salt,pw,created,email)VALUES(?,?,?,?,?)').bind(n,s,await H(p,s),now,em).run()}catch{return J({error:'ഈ username എടുത്തിട്ടുണ്ട്'},409)}}
const us=await db.prepare('SELECT * FROM users WHERE username=?').bind(n).first();
const fr=await db.prepare('SELECT n,ts FROM fails WHERE k=?').bind(n).first();
if(fr&&fr.n>=5&&now-fr.ts<900000)return J({error:'വളരെയധികം ശ്രമങ്ങൾ. 15 മിനിറ്റ് കഴിഞ്ഞ് ശ്രമിക്കുക'},429);
if(!us||us.pw!=await H(p,us.salt)){await db.prepare('INSERT OR REPLACE INTO fails(k,n,ts)VALUES(?,?,?)').bind(n,(fr&&now-fr.ts<900000?fr.n:0)+1,now).run();return J({error:'തെറ്റായ username / password'},401)}
await db.prepare('DELETE FROM fails WHERE k=?').bind(n).run();
const t=rnd()+rnd();await db.prepare('INSERT INTO sessions(token,uid,ts)VALUES(?,?,?)').bind(t,us.id,now).run();
return J({token:t,user:{id:us.id,username:us.username,avatar:us.avatar,bio:us.bio,status:us.status}})}
if(path=='vapid')return J({key:env.VAPID_PUB||''});
if(path=='forgot'){if(!env.RESEND_KEY)return J({error:'ഇമെയിൽ സേവനം സജ്ജമാക്കിയിട്ടില്ല (RESEND_KEY)'},503);
const em=String(b.email||'').trim().toLowerCase();const u2=await db.prepare('SELECT id FROM users WHERE email=?').bind(em).first();
if(u2){const rr=await db.prepare('SELECT exp FROM resets WHERE uid=?').bind(u2.id).first();
if(!rr||rr.exp<now+540000){const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%900000+100000);
await db.prepare('INSERT OR REPLACE INTO resets(uid,code,exp,tries)VALUES(?,?,?,0)').bind(u2.id,await H(code,'rs'+u2.id),now+600000).run();
try{await fetch('https://api.resend.com/emails',{method:'POST',headers:{authorization:'Bearer '+env.RESEND_KEY,'content-type':'application/json'},body:JSON.stringify({from:env.MAIL_FROM||'CHOLLU <onboarding@resend.dev>',to:[em],subject:'CHOLLU password reset code',text:'Your CHOLLU reset code: '+code+'\nValid for 10 minutes. Ignore this email if it was not you.'})})}catch{}}}
return J({ok:1})}
if(path=='reset'){const em=String(b.email||'').trim().toLowerCase(),pw=String(b.password||'');if(pw.length<6)return J({error:'Password കുറഞ്ഞത് 6 അക്ഷരം വേണം'},400);
const u2=await db.prepare('SELECT id,username FROM users WHERE email=?').bind(em).first();const rr=u2&&await db.prepare('SELECT code,exp,tries FROM resets WHERE uid=?').bind(u2.id).first();
if(!rr||rr.exp<now||rr.tries>=5)return J({error:'കോഡ് അസാധുവാണ് അല്ലെങ്കിൽ കാലാവധി കഴിഞ്ഞു'},400);
await db.prepare('UPDATE resets SET tries=tries+1 WHERE uid=?').bind(u2.id).run();
if(rr.code!=await H(String(b.code||'').trim(),'rs'+u2.id))return J({error:'തെറ്റായ കോഡ്'},400);
const s2=rnd();await db.prepare('UPDATE users SET pw=?,salt=? WHERE id=?').bind(await H(pw,s2),s2,u2.id).run();
await db.prepare('DELETE FROM resets WHERE uid=?').bind(u2.id).run();await db.prepare('DELETE FROM sessions WHERE uid=?').bind(u2.id).run();await db.prepare('DELETE FROM fails WHERE k=?').bind(u2.username).run();return J({ok:1})}
const tk=(req.headers.get('authorization')||'').slice(7);
const s=await db.prepare('SELECT uid FROM sessions WHERE token=? AND ts>?').bind(tk,now-2592000000).first();if(!s)return J({error:'auth'},401);
const me=s.uid;const AID=await aiUser(db);await db.prepare('UPDATE users SET seen=? WHERE id=?').bind(now,me).run();
if(path=='users'){const q=(u.searchParams.get('q')||'').replace(/[%_\\]/g,'\\$&');
return J({users:(await db.prepare(`SELECT ${PUB} FROM users WHERE username LIKE ? ESCAPE '\\' AND id!=? LIMIT 20`).bind('%'+q.toLowerCase()+'%',me).all()).results})}
if(path=='chats'){const r=await db.prepare(`SELECT u.id,u.username,u.avatar,u.bio,u.status,u.seen,m.kind,m.ts,CASE WHEN m.kind='text' AND m.deleted=0 THEN m.body ELSE '' END body,(SELECT COUNT(*) FROM messages WHERE from_id=u.id AND to_id=?1 AND rd=0 AND deleted=0 AND (exp=0 OR exp>${now})) unread FROM users u JOIN messages m ON m.id=(SELECT MAX(id) FROM messages WHERE ((from_id=u.id AND to_id=?1) OR (from_id=?1 AND to_id=u.id)) AND (exp=0 OR exp>${now})) WHERE u.id!=?1 ORDER BY m.id DESC`).bind(me).all();const cs=r.results;cs.push(...(await db.prepare(`SELECT -g.id id,g.name username,'👥' avatar,'' bio,'' status,0 seen,1 grp,m.kind,COALESCE(m.ts,0) ts,CASE WHEN m.kind='text' AND m.deleted=0 THEN m.body ELSE '' END body,(SELECT COUNT(*) FROM messages WHERE to_id=-g.id AND id>gm.lr AND from_id!=?1 AND deleted=0 AND (exp=0 OR exp>${now})) unread FROM grps g JOIN gmembers gm ON gm.gid=g.id AND gm.uid=?1 LEFT JOIN messages m ON m.id=(SELECT MAX(id) FROM messages WHERE to_id=-g.id AND (exp=0 OR exp>${now}))`).bind(me).all()).results);if(me!=AID&&!cs.find(c=>c.id==AID))cs.push({id:AID,username:'chollu_ai',avatar:'🤖',bio:'',status:'ചോദിക്കൂ, ഞാൻ ഉത്തരം തരാം',seen:0,kind:'text',ts:0,body:'',unread:0});return J({chats:cs.sort((a,b)=>(b.ts||0)-(a.ts||0))})}
if(path=='messages'){const w=+u.searchParams.get('with'),a=+u.searchParams.get('after')||0;
const q=w<0?'(to_id=?2 AND ?1>0)':'((from_id=?1 AND to_id=?2) OR (from_id=?2 AND to_id=?1))';
if(w<0&&!await db.prepare('SELECT 1 x FROM gmembers WHERE gid=? AND uid=?').bind(-w,me).first())return J({error:'x'},403);
if(w<0)await db.prepare('UPDATE gmembers SET lr=(SELECT COALESCE(MAX(id),0) FROM messages WHERE to_id=?1) WHERE gid=?2 AND uid=?3').bind(w,-w,me).run();
await db.prepare('UPDATE messages SET rd=1 WHERE from_id=? AND to_id=? AND rd=0').bind(w,me).run();
await db.prepare('DELETE FROM messages WHERE exp>0 AND exp<?').bind(now).run();
const m=(await db.prepare(`SELECT * FROM (SELECT id,from_id,kind,body,reply_to,ts,deleted,exp FROM messages WHERE ${q} AND id>?3 AND (exp=0 OR exp>?4) ORDER BY id DESC LIMIT 60) ORDER BY id`).bind(me,w,a,now).all()).results;
const del=(await db.prepare(`SELECT id FROM messages WHERE ${q} AND deleted=1 ORDER BY id DESC LIMIT 200`).bind(me,w).all()).results.map(x=>x.id);
const re=(await db.prepare(`SELECT r.msg_id,r.emoji FROM reactions r JOIN messages m ON m.id=r.msg_id WHERE ${q} LIMIT 500`).bind(me,w).all()).results;
const sn=await db.prepare('SELECT MAX(id) x FROM messages WHERE from_id=? AND to_id=? AND rd=1').bind(me,w).first();
const p=await db.prepare('SELECT seen,typ_to,typ_at FROM users WHERE id=?').bind(w).first()||{};
return J({names:w<0?Object.fromEntries((await db.prepare('SELECT u.id,u.username FROM users u JOIN gmembers g ON g.uid=u.id WHERE g.gid=?').bind(-w).all()).results.map(x=>[x.id,x.username])):{},m,del,re,ed:(await db.prepare(`SELECT id,body FROM messages WHERE ${q} AND edited=1 AND deleted=0 ORDER BY id DESC LIMIT 100`).bind(me,w).all()).results,ttl:(await db.prepare('SELECT ttl FROM chat_cfg WHERE a=? AND b=?').bind(...ck(me,w)).first())?.ttl||0,seen:sn?.x||0,peer:{online:now-p.seen<30000,typing:p.typ_to==me&&now-p.typ_at<4000}})}
if(path=='send'){const to=+b.to,kind=b.kind,body=String(b.body||'');
if(!['text','sticker','image','video','audio','file'].includes(kind)||!body||body.length>1000000)return J({error:'അസാധുവായ സന്ദേശം'},400);
if(to<0?!await db.prepare('SELECT 1 x FROM gmembers WHERE gid=? AND uid=?').bind(-to,me).first():!await db.prepare('SELECT id FROM users WHERE id=?').bind(to).first())return J({error:'user ഇല്ല'},404);
if(to>0&&await db.prepare('SELECT 1 x FROM blocks WHERE (a=? AND b=?) OR (a=? AND b=?)').bind(to,me,me,to).first())return J({error:'ഈ chat-ൽ സന്ദേശം അയയ്ക്കാൻ കഴിയില്ല (Block)'},403);
const tl=(await db.prepare('SELECT ttl FROM chat_cfg WHERE a=? AND b=?').bind(...ck(me,to)).first())?.ttl||0;
const r=await db.prepare('INSERT INTO messages(from_id,to_id,kind,body,reply_to,ts,exp)VALUES(?,?,?,?,?,?,?)').bind(me,to,kind,body,+b.reply_to||0,now,tl?now+tl*1000:0).run();
const mid=r.meta.last_row_id;if(to!=AID)ctx?.waitUntil(pushTo(env,db,to>0?[to]:(await db.prepare('SELECT uid FROM gmembers WHERE gid=? AND uid!=?').bind(-to,me).all()).results.map(x=>x.uid)));
if(to==AID&&kind=='text'){let rep;try{const h=(await db.prepare("SELECT from_id,body FROM messages WHERE kind='text' AND deleted=0 AND body!='' AND ((from_id=?1 AND to_id=?2) OR (from_id=?2 AND to_id=?1)) ORDER BY id DESC LIMIT 10").bind(me,AID).all()).results.reverse();
const o=await env.AI.run('@cf/meta/llama-3.1-8b-instruct',{max_tokens:400,messages:[{role:'system',content:'You are CHOLLU AI, a friendly assistant inside the CHOLLU chat app. Always reply in the same language the user writes (Malayalam or English). Keep answers short and helpful.'},...h.map(x=>({role:x.from_id==me?'user':'assistant',content:x.body}))]});rep=o.response}catch{rep='AI ഇപ്പോൾ ലഭ്യമല്ല. Pages → Settings → Bindings → Workers AI (variable name: AI) ചേർത്ത് Redeploy ചെയ്യുക.'}
const n2=Date.now();await db.prepare('INSERT INTO messages(from_id,to_id,kind,body,ts,exp)VALUES(?,?,?,?,?,?)').bind(AID,me,'text',String(rep||'…').slice(0,4000),n2,tl?n2+tl*1000:0).run()}
return J({id:mid})}
if(path=='typing'){await db.prepare('UPDATE users SET typ_to=?,typ_at=? WHERE id=?').bind(+b.to,now,me).run();return J({ok:1})}
if(path=='react'){const id=+b.id,e=String(b.emoji).slice(0,8);
if(!await db.prepare('SELECT id FROM messages WHERE id=? AND (from_id=? OR to_id=? OR to_id IN (SELECT -gid FROM gmembers WHERE uid=?))').bind(id,me,me,me).first())return J({error:'x'},404);
const ex=await db.prepare('SELECT emoji FROM reactions WHERE msg_id=? AND uid=?').bind(id,me).first();
if(ex&&ex.emoji==e)await db.prepare('DELETE FROM reactions WHERE msg_id=? AND uid=?').bind(id,me).run();
else await db.prepare('INSERT OR REPLACE INTO reactions(msg_id,uid,emoji)VALUES(?,?,?)').bind(id,me,e).run();return J({ok:1})}
if(path=='edit'){const t=String(b.body||'').trim();if(!t||t.length>5000)return J({error:'x'},400);await db.prepare("UPDATE messages SET body=?,edited=1 WHERE id=? AND from_id=? AND kind='text' AND deleted=0").bind(t,+b.id,me).run();return J({ok:1})}
if(path=='delete'){await db.prepare("UPDATE messages SET deleted=1,body='' WHERE id=? AND from_id=?").bind(+b.id,me).run();return J({ok:1})}
if(path=='disappear'){const w=+b.with,t=+b.ttl;if(![0,60,3600,86400,604800].includes(t))return J({error:'x'},400);
await db.prepare('INSERT OR REPLACE INTO chat_cfg(a,b,ttl)VALUES(?,?,?)').bind(...ck(me,w),t).run();return J({ok:1})}
if(path=='block'){if(b.all)await db.prepare('DELETE FROM blocks WHERE a=?').bind(me).run();else if(b.on)await db.prepare('INSERT OR IGNORE INTO blocks(a,b)VALUES(?,?)').bind(me,+b.id).run();else await db.prepare('DELETE FROM blocks WHERE a=? AND b=?').bind(me,+b.id).run();return J({ok:1})}
if(path=='report'){await db.prepare('INSERT INTO reports(by_id,target,reason,ts)VALUES(?,?,?,?)').bind(me,+b.id,String(b.reason||'').slice(0,300),now).run();return J({ok:1})}
if(path=='gcreate'){const nm=String(b.name||'').trim().slice(0,40);if(!nm)return J({error:'ഗ്രൂപ്പിന് പേര് വേണം'},400);
const r=await db.prepare('INSERT INTO grps(name,owner,created)VALUES(?,?,?)').bind(nm,me,now).run();const g=r.meta.last_row_id;const ids=new Set([me]);
for(const n of(b.members||[]).slice(0,49)){const x=await db.prepare('SELECT id FROM users WHERE username=?').bind(String(n).trim().toLowerCase()).first();if(x&&x.id!=AID)ids.add(x.id)}
for(const i of ids)await db.prepare('INSERT OR IGNORE INTO gmembers(gid,uid,lr)VALUES(?,?,0)').bind(g,i).run();return J({id:-g,count:ids.size})}
if(path=='pushsub'){const ep=String(b.endpoint||'');if(!/^https:\/\//.test(ep)||ep.length>1000)return J({error:'x'},400);await db.prepare('INSERT OR REPLACE INTO push_subs(uid,endpoint,ts)VALUES(?,?,?)').bind(me,ep,now).run();return J({ok:1})}
if(path=='ice'){const ic=[{urls:'stun:stun.l.google.com:19302'}];if(env.TURN_URL)ic.push({urls:env.TURN_URL.split(','),username:env.TURN_USER,credential:env.TURN_CRED});return J({iceServers:ic})}
if(path=='sig'){const to=+b.to,k=String(b.kind);if(!['invite','accept','offer','answer','ice','end'].includes(k))return J({error:'x'},400);
if(to==AID||!await db.prepare('SELECT id FROM users WHERE id=?').bind(to).first())return J({error:'x'},404);
if(await db.prepare('SELECT 1 x FROM blocks WHERE (a=? AND b=?) OR (a=? AND b=?)').bind(to,me,me,to).first())return J({error:'x'},403);
await db.prepare('INSERT INTO sigs(from_id,to_id,kind,data,ts)VALUES(?,?,?,?,?)').bind(me,to,k,String(b.data||'{}').slice(0,20000),now).run();
if(k=='invite')ctx?.waitUntil(pushTo(env,db,[to]));return J({ok:1})}
if(path=='sigpoll'){const a=+u.searchParams.get('after')||0;await db.prepare('DELETE FROM sigs WHERE ts<?').bind(now-120000).run();
return J({s:(await db.prepare('SELECT s.id,s.from_id,s.kind,s.data,s.ts,u.username FROM sigs s JOIN users u ON u.id=s.from_id WHERE s.to_id=? AND s.id>? AND s.ts>? ORDER BY s.id').bind(me,a,now-30000).all()).results})}
if(path=='gadd'){const g=-(+b.id);if(!await db.prepare('SELECT 1 x FROM gmembers WHERE gid=? AND uid=?').bind(g,me).first())return J({error:'x'},403);let n=0;
for(const nm of(b.members||[]).slice(0,49)){const x=await db.prepare('SELECT id FROM users WHERE username=?').bind(String(nm).trim().toLowerCase()).first();if(x&&x.id!=AID){await db.prepare('INSERT OR IGNORE INTO gmembers(gid,uid,lr)VALUES(?,?,(SELECT COALESCE(MAX(id),0) FROM messages WHERE to_id=?))').bind(g,x.id,-g).run();n++}}return J({added:n})}
if(path=='gleave'){await db.prepare('DELETE FROM gmembers WHERE gid=? AND uid=?').bind(-(+b.id),me).run();return J({ok:1})}
if(path=='profile'){await db.prepare('UPDATE users SET avatar=?,bio=?,status=? WHERE id=?').bind(String(b.avatar||'').slice(0,8),String(b.bio||'').slice(0,150),String(b.status||'').slice(0,60),me).run();
{const em=String(b.email||'').trim().toLowerCase();if(/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)&&!await db.prepare('SELECT 1 x FROM users WHERE email=? AND id!=?').bind(em,me).first())await db.prepare('UPDATE users SET email=? WHERE id=?').bind(em,me).run()}
return J({user:await db.prepare(`SELECT ${PUB} FROM users WHERE id=?`).bind(me).first()})}
return J({error:'not found'},404)}

async function aiUser(db){const q="SELECT id FROM users WHERE username='chollu_ai'";let u=await db.prepare(q).bind().first();
if(!u){await db.prepare("INSERT OR IGNORE INTO users(username,salt,pw,avatar,bio,status,created)VALUES('chollu_ai','-','-','🤖','CHOLLU AI അസിസ്റ്റന്റ്','ചോദിക്കൂ, ഞാൻ ഉത്തരം തരാം',?)").bind(Date.now()).run();u=await db.prepare(q).bind().first()}return u.id}

async function pushTo(env,db,uids){if(!env.VAPID_JWK||!env.VAPID_PUB)return;let key;
try{key=await crypto.subtle.importKey('jwk',JSON.parse(env.VAPID_JWK),{name:'ECDSA',namedCurve:'P-256'},false,['sign'])}catch{return}
const b64=x=>btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''),te=new TextEncoder();
for(const uid of uids){const subs=(await db.prepare('SELECT endpoint FROM push_subs WHERE uid=? LIMIT 5').bind(uid).all()).results;
for(const s of subs){try{const h=b64(te.encode(JSON.stringify({typ:'JWT',alg:'ES256'}))),p=b64(te.encode(JSON.stringify({aud:new URL(s.endpoint).origin,exp:Math.floor(Date.now()/1000)+43200,sub:env.VAPID_SUB||'mailto:admin@example.com'})));
const sg=b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,te.encode(h+'.'+p)));
const r=await fetch(s.endpoint,{method:'POST',headers:{TTL:'60',Urgency:'high',Authorization:'vapid t='+h+'.'+p+'.'+sg+', k='+env.VAPID_PUB}});
if(r.status==404||r.status==410)await db.prepare('DELETE FROM push_subs WHERE endpoint=?').bind(s.endpoint).run()}catch{}}}}
