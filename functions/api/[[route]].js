const J=(d,s=200,h={})=>new Response(JSON.stringify(d),{status:s,headers:{'content-type':'application/json',...h}});
const E=(m,s=400)=>J({error:m},s);
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
const now=()=>Date.now();
async function hash(pw,salt){
  const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);
  return hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:new TextEncoder().encode(salt),iterations:100000},k,256));
}
const isAdmin=(env,email)=>(env.ADMIN_EMAILS||'').toLowerCase().split(',').map(s=>s.trim()).includes(email.toLowerCase());
async function mail(env,to,subject,text){
  if(!env.RESEND_API_KEY)return;
  await fetch('https://api.resend.com/emails',{method:'POST',headers:{authorization:'Bearer '+env.RESEND_API_KEY,'content-type':'application/json'},
    body:JSON.stringify({from:env.MAIL_FROM,to,subject,text})});
}
async function startSession(env,uid){
  const t=rnd(32);
  await env.DB.prepare('INSERT INTO sessions VALUES(?,?,?)').bind(t,uid,now()+30*864e5).run();
  return {'set-cookie':`s=${t}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`};
}
async function getUser(env,req){
  const t=(req.headers.get('cookie')||'').match(/(?:^|; )s=([a-f0-9]+)/)?.[1];
  if(!t)return null;
  const u=await env.DB.prepare('SELECT u.id,u.email,u.name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?').bind(t,now()).first();
  return u?{...u,admin:isAdmin(env,u.email)}:null;
}
async function unzip(buf,max=26214400){
  const v=new DataView(buf),u8=new Uint8Array(buf);let e=buf.byteLength-22;
  while(e>=0&&v.getUint32(e,true)!==0x06054b50)e--;
  if(e<0)throw new Error('This is not a valid zip file.');
  const n=v.getUint16(e+10,true),out=[];let p=v.getUint32(e+16,true);
  for(let i=0;i<n&&v.getUint32(p,true)===0x02014b50;i++){
    const fl=v.getUint16(p+8,true),method=v.getUint16(p+10,true),cs=v.getUint32(p+20,true),us=v.getUint32(p+24,true),nl=v.getUint16(p+28,true),xl=v.getUint16(p+30,true),cl=v.getUint16(p+32,true),off=v.getUint32(p+42,true);
    const name=new TextDecoder().decode(u8.subarray(p+46,p+46+nl));p+=46+nl+xl+cl;
    if(name.endsWith('/')||name.startsWith('__MACOSX')||name.split('/').pop().startsWith('.')||(fl&1)||us>max||(method!==0&&method!==8))continue;
    const s=off+30+v.getUint16(off+26,true)+v.getUint16(off+28,true),raw=u8.subarray(s,s+cs);
    out.push({name,read:async()=>method===0?raw:new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).arrayBuffer())});
  }
  return out;
}
export async function onRequest({request:req,env,waitUntil}){
  const url=new URL(req.url),p=url.pathname.replace(/^\/api\/?/,'').split('/').filter(Boolean);
  const body=req.method==='POST'&&(req.headers.get('content-type')||'').includes('json')?await req.json().catch(()=>({})):{};
  const [a,b,c]=p;

  if(a==='config')return J({google:env.GOOGLE_CLIENT_ID||''});

  if(a==='stats')return J(await env.DB.prepare("SELECT (SELECT COUNT(*) FROM orders) o,(SELECT COUNT(*) FROM orders WHERE kind='design') d,(SELECT COUNT(*) FROM orders WHERE status IN ('shipped','done')) c,(SELECT COUNT(*) FROM users) u").first());

  if(a==='auth'){
    if(b==='register'||b==='login'){
      const email=String(body.email||'').trim().toLowerCase(),pw=String(body.password||'');
      if(!/^\S+@\S+\.\S+$/.test(email))return E('Enter a valid email address.');
      if(b==='register'){
        if(pw.length<8)return E('Password must be at least 8 characters.');
        if(await env.DB.prepare('SELECT 1 FROM users WHERE email=?').bind(email).first())return E('An account with this email already exists.');
        const salt=rnd(16),r=await env.DB.prepare('INSERT INTO users(email,name,pw,created) VALUES(?,?,?,?)').bind(email,String(body.name||'').slice(0,80),salt+':'+await hash(pw,salt),now()).run();
        return J({ok:1},200,await startSession(env,r.meta.last_row_id));
      }
      const u=await env.DB.prepare('SELECT id,pw FROM users WHERE email=?').bind(email).first();
      const [salt,h]=(u?.pw||':').split(':');
      if(!u||!u.pw||await hash(pw,salt)!==h)return E('Wrong email or password.',401);
      return J({ok:1},200,await startSession(env,u.id));
    }
    if(b==='google'){
      const r=await fetch('https://oauth2.googleapis.com/tokeninfo?id_token='+encodeURIComponent(body.credential||''));
      const g=await r.json();
      if(!r.ok||g.aud!==env.GOOGLE_CLIENT_ID||g.email_verified!=='true')return E('Google sign-in failed.',401);
      const email=g.email.toLowerCase();
      let u=await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
      if(!u){const x=await env.DB.prepare('INSERT INTO users(email,name,created) VALUES(?,?,?)').bind(email,g.name||'',now()).run();u={id:x.meta.last_row_id};}
      return J({ok:1},200,await startSession(env,u.id));
    }
    if(b==='logout')return J({ok:1},200,{'set-cookie':'s=; Path=/; Max-Age=0'});
  }

  const me=await getUser(env,req);
  if(a==='me')return J({user:me});
  if(a==='mfile'){
    const key='models/'+p.slice(1).join('/');
    const obj=await env.FILES?.get(key);if(!obj)return E('Not found.',404);
    const ext=key.split('.').pop().toLowerCase();
    return new Response(obj.body,{headers:{'content-type':{webp:'image/webp',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg'}[ext]||'application/octet-stream','cache-control':'public, max-age=86400','x-content-type-options':'nosniff'}});
  }
  if(a==='models'){
    const Q=`SELECT m.*,(SELECT COUNT(*) FROM model_likes l WHERE l.model_id=m.id) likes,(SELECT COUNT(*) FROM orders o WHERE o.model_id=m.id AND o.status IN ('shipped','done')) prints,(SELECT COUNT(*) FROM orders o2 WHERE o2.model_id=m.id) ordered FROM models m`;
    if(!b&&req.method==='GET')return J({models:(await env.DB.prepare(Q+' ORDER BY m.id DESC').all()).results});
    if(!b&&req.method==='POST'){
      if(!me?.admin)return E('Not allowed.',403);
      const t=String(body.title||'').trim();if(!t)return E('Give the model a title.');
      const s=(v,n)=>String(v??'').slice(0,n);
      const r=await env.DB.prepare('INSERT INTO models(title,cat,mat,hours,who,descr,lay,inf,walls,sup,tags,col,imgs,stls,views,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
        .bind(s(t,120),s(body.cat||'Other',40),s(body.mat,40),+body.hours||0,s(body.who||'ProLab',60),s(body.descr,4000),s(body.lay,30),s(body.inf,30),+body.walls||0,s(body.sup,60),s(body.tags,200),/^#[0-9a-f]{6}$/i.test(body.col)?body.col:'#00ae42','[]','[]',0,now()).run();
      return J({id:r.meta.last_row_id});
    }
    if(b==='import'&&req.method==='POST'){
      if(!me?.admin)return E('Not allowed.',403);
      if(!env.FILES)return E('File storage is not set up yet.',503);
      if(+req.headers.get('content-length')>52428800)return E('The zip is over 50 MB.');
      const buf=await req.arrayBuffer();if(buf.byteLength>52428800)return E('The zip is over 50 MB.');
      let ents;try{ents=await unzip(buf);}catch(x){return E(x.message);}
      const hd=k=>decodeURIComponent(req.headers.get(k)||''),cat=hd('x-cat')||'Figurines',mat=hd('x-mat')||'PLA',who=hd('x-who')||'ProLab',col=/^#[0-9a-f]{6}$/i.test(hd('x-col'))?hd('x-col'):'#00ae42';
      const files=ents.map(e=>{const parts=e.name.split('/').filter(Boolean);return{...e,parts,ext:(parts[parts.length-1].match(/\.([a-z0-9]+)$/i)||[])[1]?.toLowerCase()};}).filter(f=>['stl','png','jpg','jpeg','webp'].includes(f.ext));
      if(new Set(files.map(f=>f.parts[0])).size===1&&files.every(f=>f.parts.length>1)&&files.some(f=>f.parts.length>2))files.forEach(f=>f.parts.shift());
      const groups={};
      for(const f of files){const last=f.parts[f.parts.length-1],g=f.parts.length>1?f.parts[0]:last.replace(/\.[^.]+$/,'');(groups[g]??=[]).push(f);}
      const created=[];
      for(const [g,fs] of Object.entries(groups)){
        if(!fs.some(f=>f.ext==='stl'))continue;
        fs.sort((x,y)=>x.parts.join('/').localeCompare(y.parts.join('/'),undefined,{numeric:true}));
        const title=g.replace(/_+/g,' ').trim().slice(0,120)||'Untitled';
        const r=await env.DB.prepare('INSERT INTO models(title,cat,mat,hours,who,descr,lay,inf,walls,sup,tags,col,imgs,stls,views,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(title,cat.slice(0,40),mat.slice(0,40),0,who.slice(0,60),'','0.2 mm','15%',3,'None','',col,'[]','[]',0,now()).run();
        const id=r.meta.last_row_id,imgs=[],stls=[];
        for(const f of fs){const name=f.parts[f.parts.length-1].replace(/[^A-Za-z0-9._-]/g,'_').slice(-80),path=`${id}/${rnd(6)}-${name}`;
          await env.FILES.put('models/'+path,await f.read());(f.ext==='stl'?stls:imgs).push('/api/mfile/'+path);}
        await env.DB.prepare('UPDATE models SET imgs=?,stls=? WHERE id=?').bind(JSON.stringify(imgs),JSON.stringify(stls),id).run();
        created.push({id,title,stls:stls.length,imgs:imgs.length});
      }
      if(!created.length)return E('No STL files were found in the zip.');
      return J({created});
    }
    const m=await env.DB.prepare(Q+' WHERE m.id=?').bind(+b).first();
    if(!m)return E('Not found.',404);
    if(!c&&req.method==='GET'){m.liked=me?!!(await env.DB.prepare('SELECT 1 FROM model_likes WHERE model_id=? AND user_id=?').bind(m.id,me.id).first()):false;return J({model:m});}
    if(c==='view'){await env.DB.prepare('UPDATE models SET views=views+1 WHERE id=?').bind(m.id).run();return J({ok:1});}
    if(!me)return E('Sign in first.',401);
    if(c==='like'){
      const had=await env.DB.prepare('SELECT 1 FROM model_likes WHERE model_id=? AND user_id=?').bind(m.id,me.id).first();
      await env.DB.prepare(had?'DELETE FROM model_likes WHERE model_id=? AND user_id=?':'INSERT INTO model_likes VALUES(?,?)').bind(m.id,me.id).run();
      return J({liked:!had,likes:m.likes+(had?-1:1)});
    }
    if(!me.admin)return E('Not allowed.',403);
    if(c==='update'&&req.method==='POST'){
      const s=(v,n)=>String(v??'').slice(0,n),t=s(body.title,120).trim();if(!t)return E('Give the model a title.');
      await env.DB.prepare('UPDATE models SET title=?,cat=?,mat=?,hours=?,who=?,descr=?,lay=?,inf=?,walls=?,sup=?,tags=?,col=? WHERE id=?').bind(t,s(body.cat||'Other',40),s(body.mat,40),+body.hours||0,s(body.who||'ProLab',60),s(body.descr,4000),s(body.lay,30),s(body.inf,30),+body.walls||0,s(body.sup,60),s(body.tags,200),/^#[0-9a-f]{6}$/i.test(body.col)?body.col:'#00ae42',m.id).run();
      return J({ok:1});
    }
    if(c==='files'&&req.method==='POST'){
      if(!env.FILES)return E('File storage is not set up yet.',503);
      const kind=req.headers.get('x-kind')==='stl'?'stl':'img';
      const name=decodeURIComponent(req.headers.get('x-filename')||'file').replace(/[^A-Za-z0-9._-]/g,'_').slice(-80);
      const zip=kind==='stl'&&/\.zip$/i.test(name),lim=zip?52428800:26214400;
      if(!zip&&!(kind==='stl'?/\.stl$/i:/\.(png|jpe?g|webp)$/i).test(name))return E('This file type is not allowed.');
      if(+req.headers.get('content-length')>lim)return E(`Max file size is ${lim>>20} MB.`);
      const buf=await req.arrayBuffer();if(buf.byteLength>lim)return E(`Max file size is ${lim>>20} MB.`);
      const imgs=JSON.parse(m.imgs||'[]'),stls=JSON.parse(m.stls||'[]');
      const put=async(nm,data,k)=>{const path=`${m.id}/${rnd(6)}-${nm}`;await env.FILES.put('models/'+path,data);(k==='stl'?stls:imgs).push('/api/mfile/'+path);};
      if(zip){
        let ents;try{ents=await unzip(buf);}catch(x){return E(x.message);}
        ents.sort((x,y)=>x.name.localeCompare(y.name,undefined,{numeric:true}));let n=0;
        for(const e of ents){const base=e.name.split('/').pop(),ext=(base.match(/\.([a-z0-9]+)$/i)||[])[1]?.toLowerCase();
          if(ext==='stl'||['png','jpg','jpeg','webp'].includes(ext)){await put(base.replace(/[^A-Za-z0-9._-]/g,'_').slice(-80),await e.read(),ext==='stl'?'stl':'img');n++;}}
        if(!n)return E('No STL files were found in the zip.');
      }else await put(name,buf,kind);
      await env.DB.prepare('UPDATE models SET imgs=?,stls=? WHERE id=?').bind(JSON.stringify(imgs),JSON.stringify(stls),m.id).run();
      return J({ok:1});
    }
    if(c==='delete'&&req.method==='POST'){
      if(env.FILES){const l=await env.FILES.list({prefix:`models/${m.id}/`});if(l.objects.length)await env.FILES.delete(l.objects.map(o=>o.key));}
      await env.DB.batch([env.DB.prepare('DELETE FROM model_likes WHERE model_id=?').bind(m.id),env.DB.prepare('DELETE FROM models WHERE id=?').bind(m.id)]);
      return J({ok:1});
    }
    return E('Not found.',404);
  }

  if(!me)return E('Sign in first.',401);

  if(a==='files'&&b){
    const f=await env.DB.prepare('SELECT a.*,o.user_id ou FROM attachments a JOIN orders o ON o.id=a.order_id WHERE a.id=?').bind(+b).first();
    if(!f||(!me.admin&&f.ou!==me.id))return E('Not found.',404);
    const obj=await env.FILES?.get(f.key);if(!obj)return E('File missing.',404);
    return new Response(obj.body,{headers:{'content-type':'application/octet-stream','content-disposition':`attachment; filename*=UTF-8''${encodeURIComponent(f.name)}`,'x-content-type-options':'nosniff'}});
  }

  if(a==='orders'&&!b){
    if(req.method==='POST'){
      const t=String(body.title||'').trim();
      if(!t)return E('Give your request a title.');
      const r=await env.DB.prepare('INSERT INTO orders(user_id,title,kind,details,material,qty,link,created,model_id) VALUES(?,?,?,?,?,?,?,?,?)')
        .bind(me.id,t.slice(0,120),body.kind==='design'?'design':'print',String(body.details||'').slice(0,4000),String(body.material||'PLA').slice(0,30),Math.max(1,Math.min(500,+body.qty||1)),String(body.link||'').slice(0,500),now(),+body.model||null).run();
      return J({id:r.meta.last_row_id});
    }
    const q=me.admin?'SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200'
      :'SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.user_id=? ORDER BY o.id DESC';
    const s=env.DB.prepare(q);
    return J({orders:(await (me.admin?s:s.bind(me.id)).all()).results});
  }

  if(a==='orders'&&b){
    const o=await env.DB.prepare('SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?').bind(+b).first();
    if(!o||(!me.admin&&o.user_id!==me.id))return E('Not found.',404);
    if(c==='messages'&&req.method==='POST'){
      const text=String(body.body||'').trim().slice(0,2000);
      if(!text)return E('Message is empty.');
      await env.DB.prepare('INSERT INTO messages(order_id,sender_id,is_admin,body,created) VALUES(?,?,?,?,?)').bind(o.id,me.id,me.admin?1:0,text,now()).run();
      const link=`${url.origin}/#/order/${o.id}`;
      if(me.admin)waitUntil(mail(env,o.email,`New message about "${o.title}"`,`${text}\n\nReply here: ${link}`));
      else if(env.NOTIFY_EMAIL)waitUntil(mail(env,env.NOTIFY_EMAIL,`Customer message on #${o.id}`,`${me.email}: ${text}\n\n${link}`));
      return J({ok:1});
    }
    if(c==='files'&&req.method==='POST'){
      if(!env.FILES)return E('File storage is not set up yet.',503);
      const name=decodeURIComponent(req.headers.get('x-filename')||'file').replace(/[\\/]/g,'_').slice(0,120);
      if(!/\.(stl|3mf|obj|step|stp|png|jpe?g|webp|pdf|zip|gcode)$/i.test(name))return E('This file type is not allowed.');
      if(+req.headers.get('content-length')>26214400)return E('Max file size is 25 MB.');
      if((await env.DB.prepare('SELECT COUNT(*) n FROM attachments WHERE order_id=?').bind(o.id).first()).n>=10)return E('Max 10 files per request.');
      const buf=await req.arrayBuffer();if(buf.byteLength>26214400)return E('Max file size is 25 MB.');
      const key=`${o.id}/${rnd(8)}-${name}`;await env.FILES.put(key,buf);
      await env.DB.prepare('INSERT INTO attachments(order_id,user_id,name,size,key,created) VALUES(?,?,?,?,?,?)').bind(o.id,me.id,name,buf.byteLength,key,now()).run();
      return J({ok:1});
    }
    if(c==='delete'&&req.method==='POST'){
      if(!me.admin)return E('Not allowed.',403);
      const ks=(await env.DB.prepare('SELECT key FROM attachments WHERE order_id=?').bind(o.id).all()).results;
      if(env.FILES&&ks.length)await env.FILES.delete(ks.map(k=>k.key));
      await env.DB.batch([env.DB.prepare('DELETE FROM attachments WHERE order_id=?').bind(o.id),env.DB.prepare('DELETE FROM messages WHERE order_id=?').bind(o.id),env.DB.prepare('DELETE FROM orders WHERE id=?').bind(o.id)]);
      return J({ok:1});
    }
    if(c==='status'&&req.method==='POST'){
      if(!me.admin)return E('Not allowed.',403);
      if(!['new','quoted','designing','printing','shipped','done'].includes(body.status))return E('Bad status.');
      await env.DB.prepare('UPDATE orders SET status=? WHERE id=?').bind(body.status,o.id).run();
      if(env.RESEND_API_KEY)waitUntil(mail(env,o.email,`"${o.title}" is now ${body.status}`,`Status changed to: ${body.status}\n${url.origin}/#/order/${o.id}`));
      return J({ok:1});
    }
    const m=await env.DB.prepare('SELECT id,is_admin,body,created FROM messages WHERE order_id=? ORDER BY id').bind(o.id).all();
    let fl={results:[]};try{fl=await env.DB.prepare('SELECT id,name,size FROM attachments WHERE order_id=? ORDER BY id').bind(o.id).all();}catch{}
    return J({order:o,messages:m.results,files:fl.results,user:me});
  }
  return E('Not found.',404);
}
