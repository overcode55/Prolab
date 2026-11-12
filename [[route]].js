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
export async function onRequest({request:req,env,waitUntil}){
  const url=new URL(req.url),p=url.pathname.replace(/^\/api\/?/,'').split('/').filter(Boolean);
  const body=req.method==='POST'?await req.json().catch(()=>({})):{};
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
  if(!me)return E('Sign in first.',401);

  if(a==='orders'&&!b){
    if(req.method==='POST'){
      const t=String(body.title||'').trim();
      if(!t)return E('Give your request a title.');
      const r=await env.DB.prepare('INSERT INTO orders(user_id,title,kind,details,material,qty,link,created) VALUES(?,?,?,?,?,?,?,?)')
        .bind(me.id,t.slice(0,120),body.kind==='design'?'design':'print',String(body.details||'').slice(0,4000),String(body.material||'PLA').slice(0,30),Math.max(1,Math.min(500,+body.qty||1)),String(body.link||'').slice(0,500),now()).run();
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
    if(c==='status'&&req.method==='POST'){
      if(!me.admin)return E('Not allowed.',403);
      if(!['new','quoted','designing','printing','shipped','done'].includes(body.status))return E('Bad status.');
      await env.DB.prepare('UPDATE orders SET status=? WHERE id=?').bind(body.status,o.id).run();
      if(env.RESEND_API_KEY)waitUntil(mail(env,o.email,`"${o.title}" is now ${body.status}`,`Status changed to: ${body.status}\n${url.origin}/#/order/${o.id}`));
      return J({ok:1});
    }
    const m=await env.DB.prepare('SELECT id,is_admin,body,created FROM messages WHERE order_id=? ORDER BY id').bind(o.id).all();
    return J({order:o,messages:m.results,user:me});
  }
  return E('Not found.',404);
}
