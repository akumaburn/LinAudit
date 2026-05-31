package web

// The first-run setup page and the login page. These are self-contained HTML
// documents (CSS + JS inline, no external assets) served before a session
// exists. They are a direct port of server.py's _auth_page(): the setup page
// adds a confirm field with a min-8 / match check and posts to /api/setup; the
// login page posts to /api/login. On a successful response the page reloads,
// which then renders the dashboard.

// setupPage is served on first run (no auth.json yet). It is _auth_page(...,
// "/api/setup", "set password") with the confirm field included.
const setupPage = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>LinAudit</title>
<style>
  body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
    background:#0e1116;color:#dbe3ee;font:14px/1.5 ui-monospace,Menlo,Consolas,monospace}
  .box{background:#161b22;border:1px solid #2a3340;border-radius:12px;padding:28px 30px;width:340px}
  h1{font-size:17px;margin:0 0 4px} p{color:#8b97a7;font-size:12px;margin:0 0 18px}
  input{width:100%;background:#1c2230;color:#dbe3ee;border:1px solid #2a3340;border-radius:8px;
    padding:10px;font:inherit;margin-bottom:10px}
  button{width:100%;background:#1f6feb;color:#fff;border:0;border-radius:8px;padding:10px;
    font:inherit;cursor:pointer}
  button:hover{background:#388bfd}
  .err{color:#f85149;font-size:12px;min-height:16px;margin-top:8px}
  .dot{color:#3fb950}
</style></head><body>
<div class="box">
  <h1><span class="dot">&#9679;</span> LinAudit</h1>
  <p>First-time setup &mdash; choose a dashboard password.</p>
  <input id="pw" type="password" placeholder="password" autofocus>
  <input id="pw2" type="password" placeholder="confirm password">
  <button id="go">set password</button>
  <div class="err" id="err"></div>
</div>
<script>
const go=document.getElementById('go'),pw=document.getElementById('pw'),
      pw2=document.getElementById('pw2'),err=document.getElementById('err');
async function submit(){
  err.textContent='';
  const p=pw.value;
  if(pw2){ if(p.length<8){err.textContent='min 8 characters';return;}
            if(p!==pw2.value){err.textContent='passwords do not match';return;} }
  try{
    const r=await fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:p})});
    if(r.ok){location.reload();} else {err.textContent=await r.text();}
  }catch(e){err.textContent=String(e);}
}
go.onclick=submit;
[pw,pw2].forEach(el=>el&&el.addEventListener('keydown',e=>{if(e.key==='Enter')submit();}));
</script></body></html>`

// loginPage is served once auth.json exists but no valid session is present. It
// is _auth_page(..., "/api/login", "unlock") with no confirm field.
const loginPage = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>LinAudit</title>
<style>
  body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
    background:#0e1116;color:#dbe3ee;font:14px/1.5 ui-monospace,Menlo,Consolas,monospace}
  .box{background:#161b22;border:1px solid #2a3340;border-radius:12px;padding:28px 30px;width:340px}
  h1{font-size:17px;margin:0 0 4px} p{color:#8b97a7;font-size:12px;margin:0 0 18px}
  input{width:100%;background:#1c2230;color:#dbe3ee;border:1px solid #2a3340;border-radius:8px;
    padding:10px;font:inherit;margin-bottom:10px}
  button{width:100%;background:#1f6feb;color:#fff;border:0;border-radius:8px;padding:10px;
    font:inherit;cursor:pointer}
  button:hover{background:#388bfd}
  .err{color:#f85149;font-size:12px;min-height:16px;margin-top:8px}
  .dot{color:#3fb950}
</style></head><body>
<div class="box">
  <h1><span class="dot">&#9679;</span> LinAudit</h1>
  <p>Enter your dashboard password.</p>
  <input id="pw" type="password" placeholder="password" autofocus>
  
  <button id="go">unlock</button>
  <div class="err" id="err"></div>
</div>
<script>
const go=document.getElementById('go'),pw=document.getElementById('pw'),
      pw2=document.getElementById('pw2'),err=document.getElementById('err');
async function submit(){
  err.textContent='';
  const p=pw.value;
  if(pw2){ if(p.length<8){err.textContent='min 8 characters';return;}
            if(p!==pw2.value){err.textContent='passwords do not match';return;} }
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:p})});
    if(r.ok){location.reload();} else {err.textContent=await r.text();}
  }catch(e){err.textContent=String(e);}
}
go.onclick=submit;
[pw,pw2].forEach(el=>el&&el.addEventListener('keydown',e=>{if(e.key==='Enter')submit();}));
</script></body></html>`
