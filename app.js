const els = {
  form: document.querySelector('#lookup-form'),
  input: document.querySelector('#ip-input'),
  msg: document.querySelector('#validation-message'),
  results: document.querySelector('#results-container'),
  chips: document.querySelectorAll('[data-example]'),
  how: document.querySelector('#how-it-works'),
  themeBtn: document.querySelector('#theme-toggle')
};
let lastReport = null;
const RIR_MAP = [{k:'arin.net',code:'ARIN',name:'ARIN',region:'North America',website:'https://www.arin.net',color:'#4a9fff'},{k:'ripe.net',code:'RIPE NCC',name:'RIPE NCC',region:'Europe, Middle East, Central Asia',website:'https://www.ripe.net',color:'#ff6577'},{k:'apnic.net',code:'APNIC',name:'APNIC',region:'Asia Pacific',website:'https://www.apnic.net',color:'#2bd4a3'},{k:'lacnic.net',code:'LACNIC',name:'LACNIC',region:'Latin America & Caribbean',website:'https://www.lacnic.net',color:'#ffa451'},{k:'afrinic.net',code:'AFRINIC',name:'AFRINIC',region:'Africa',website:'https://afrinic.net',color:'#b88dff'}];
function detectIPVersion(raw){
  let s=raw.trim();if(!s)return null;
  if(s.startsWith('[')&&s.endsWith(']')) s=s.slice(1,-1);
  const zone=s.indexOf('%'); if(zone>-1) s=s.slice(0,zone);
  if(/^\d+\.\d+\.\d+\.\d+:\d+$/.test(s)) s=s.replace(/:\d+$/,'');
  if(s.includes(':')&&/^\[?[0-9a-fA-F:.]+\]?::?[0-9a-fA-F:.]*:\d+$/.test(s)&&s.split(':').length<8&&!s.includes('::ffff')){}
  if(validIPv4(s)) return {version:'v4',addr:s};
  if(s.includes(':')) { if(s.includes('.') && s.includes('::ffff:')) { const v4=s.split(':').at(-1); if(!validIPv4(v4)) return null; }
    if(validIPv6(s)) return {version:'v6',addr:s.toLowerCase()}; }
  return null;
}
const validIPv4=s=>{const p=s.split('.');return p.length===4&&p.every(x=>/^\d+$/.test(x)&&+x>=0&&+x<=255)};
function isValidHostname(raw){
  const s=raw.trim().toLowerCase().replace(/\.$/,'');
  if(!s||s.length>253) return false;
  const labels=s.split('.');
  if(labels.length<2) return false;
  const labelRe=/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  if(!labels.every(l=>labelRe.test(l))) return false;
  return /^[a-z]{2,}$/.test(labels.at(-1));
}
async function resolveHostname(name){
  const providers=['https://cloudflare-dns.com/dns-query','https://dns.google/resolve'];
  for(const type of ['A','AAAA']){
    for(const base of providers){
      try{
        const resp=await fetch(`${base}?name=${encodeURIComponent(name)}&type=${type}`,{headers:{accept:'application/dns-json'}});
        if(!resp.ok) continue;
        const j=await resp.json();
        if(j.Status===0&&Array.isArray(j.Answer)){
          const rec=j.Answer.find(r=>r.type===(type==='A'?1:28));
          if(rec) return {version:type==='A'?'v4':'v6',addr:type==='A'?rec.data:rec.data.toLowerCase()};
        }
      }catch{}
    }
  }
  return null;
}
const validIPv6=s=>{ if((s.match(/::/g)||[]).length>1)return false; const has=s.includes('::'); const parts=s.split(':'); if(!has&&parts.length!==8 && !s.includes('.')) return false; let cnt=0; for(const part of parts){ if(!part)continue; if(part.includes('.')){if(!validIPv4(part)) return false; cnt+=2; continue;} if(!/^[0-9a-fA-F]{1,4}$/.test(part)) return false; cnt++; } return has?cnt<8:cnt===8; };
function isReserved(version, ip){ if(version==='v4'){const n=ip.split('.').map(Number); const x=(n[0]<<24)|(n[1]<<16)|(n[2]<<8)|n[3]; const inC=(b,m)=> (x& m[1])===m[0]; const ranges=[['0.0.0.0',0xff000000],['10.0.0.0',0xff000000],['127.0.0.0',0xff000000],['169.254.0.0',0xffff0000],['172.16.0.0',0xfff00000],['192.0.0.0',0xffffff00],['192.0.2.0',0xffffff00],['192.168.0.0',0xffff0000],['198.18.0.0',0xfffe0000],['198.51.100.0',0xffffff00],['203.0.113.0',0xffffff00],['224.0.0.0',0xf0000000],['240.0.0.0',0xf0000000]].map(([a,m])=>[a.split('.').map(Number).reduce((t,v)=> (t<<8)|v,0),m]); return ranges.some(r=>inC(ip,r)); }
  const l=ip.toLowerCase(); return ['::','::1'].includes(l)||l.startsWith('fc')||l.startsWith('fd')||l.startsWith('fe8')||l.startsWith('fe9')||l.startsWith('fea')||l.startsWith('feb')||l.startsWith('2001:db8')||l.startsWith('ff'); }
async function lookup(ip,version,hostname){
 const rdapResp=await fetch(`https://rdap-bootstrap.arin.net/bootstrap/ip/${ip}`);
 if(!rdapResp.ok) throw new Error(`RDAP failed (${rdapResp.status})`);
 const rdap=await rdapResp.json(); const final=rdapResp.url;
 const rir=RIR_MAP.find(r=>final.includes(r.k)||JSON.stringify(rdap.links||[]).includes(r.k)||String(rdap.port43||'').includes(r.k.split('.')[0]))||{code:'UNKNOWN',name:'Unknown',region:'Unknown',website:'#',color:'#2bd4a3'};
 let geo=null; for(const u of [`https://ipinfo.io/${ip}/json`,`https://ipwho.is/${ip}`,`https://ipapi.co/${ip}/json/`]){try{const g=await fetch(u);if(!g.ok) continue; const j=await g.json();
  const failed = !j || j.success===false || !!j.error || !!j.message;
  if(!failed){geo=j;break;}}
  catch{}}
 return {rdap,final,rir,geo,ip,version,hostname};
}
const fmtDate=d=>d?new Date(d).toISOString().slice(0,16).replace('T',' ')+' UTC':'';
function parseContacts(rdap){ return (rdap.entities||[]).map(e=>{const v=(e.vcardArray&&e.vcardArray[1])||[]; const get=t=>v.filter(x=>x[0]===t).map(x=>x[3]); const phones=v.filter(x=>x[0]==='tel').map(x=>({number:x[3],types:(x[1]&&x[1].type)||[]})); return {roles:e.roles||[],name:get('fn')[0]||'',handle:e.handle||'',org:get('org')[0]||'',kind:get('kind')[0]||'',emails:get('email'),phones,urls:get('url'),addresses:get('adr').map(a=>Array.isArray(a)?a.join(' '):a),notes:(e.remarks||[]).flatMap(r=>r.description||[])}; }); }
function buildReport(data){const {rdap,rir,final,geo,ip,version,hostname}=data;const contacts=parseContacts(rdap);
 const registrant=(contacts.find(c=>c.roles.includes('registrant'))||contacts[0]||{}).name||rdap.name||'Unknown';
 const asnFrom=(geo&&geo.org)||((rdap.remarks||[]).flatMap(r=>r.description||[]).join(' ')); const m=asnFrom&&asnFrom.match(/AS(\d+)\s*(.*)?/i);
 return {query:{ip,version,hostname:hostname||null,fetched_at:new Date().toISOString()},summary:{registrant,rir_code:rir.code},rir:{code:rir.code,name:rir.name,region:rir.region,website:rir.website,rdap_source:final},network:{name:rdap.name||'',handle:rdap.handle||'',type:rdap.type||'',ip_version:version,country:rdap.country||'',parent_handle:rdap.parentHandle||'',status:(rdap.status||[]).join(', '),start_address:rdap.startAddress||'',end_address:rdap.endAddress||'',cidr:(rdap.cidr0_cidrs||[]).map(c=>`${c.v4prefix||c.v6prefix}/${c.length}`).join(', ')},asn:m?{number:m[1],organization:(m[2]||'').trim()}:null,location:geo?{city:geo.city||'',region:geo.region||'',country:geo.country_name||geo.country||'',country_code:geo.country||geo.country_code||'',postal:geo.postal||'',timezone:geo.timezone||'',latitude:geo.latitude||geo.loc?.split(',')[0]||'',longitude:geo.longitude||geo.loc?.split(',')[1]||''}:null,contacts:{registrant:contacts.filter(c=>c.roles.includes('registrant')),administrative:contacts.filter(c=>c.roles.includes('administrative')),technical:contacts.filter(c=>c.roles.includes('technical')),abuse:contacts.filter(c=>c.roles.includes('abuse'))},events:(rdap.events||[]).map(e=>({action:e.eventAction,date:fmtDate(e.eventDate)})),remarks:(rdap.remarks||[]).map(r=>({title:r.title||'',description:(r.description||[]).join(' ')}))}; }
function reportToJSON(r){return JSON.stringify(r,null,2)}
function reportToText(r){const sep='='.repeat(60);return [sep,'IP WHOIS REPORT',sep,...(r.query.hostname?[`Hostname: ${r.query.hostname}`]:[]),`IP: ${r.query.ip}`,`Version: ${r.query.version}`,`Registered to: ${r.summary.registrant}`,`RIR: ${r.rir.code}`,'', 'NETWORK',`  Network name:  ${r.network.name}`,`  Handle:        ${r.network.handle}`,`  Range:         ${r.network.start_address} - ${r.network.end_address}`, '', 'EVENTS',...r.events.map(e=>`  ${e.action}: ${e.date}`), '', 'REMARKS',...r.remarks.map(x=>`  ${x.title}: ${x.description}`)].join('\n');}
function reportToMarkdown(r){return `# IP WHOIS report — \`${r.query.hostname||r.query.ip}\`\n\n${r.query.hostname?`**Resolved to:** \`${r.query.ip}\` · `:''}**Version:** ${r.query.version} · **Registered to:** ${r.summary.registrant} · **RIR:** ${r.rir.code} · **Generated:** ${r.query.fetched_at}\n\n## Network\n| Field | Value |\n|---|---|\n| Name | ${r.network.name} |\n| Handle | \`${r.network.handle}\` |\n| Range | \`${r.network.start_address}\` — \`${r.network.end_address}\` |\n\n## Source\n- Website: <${r.rir.website}>\n- RDAP source: <${r.rir.rdap_source}>`;}
async function copyToClipboard(text){try{await navigator.clipboard.writeText(text);return true;}catch{const ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();const ok=document.execCommand('copy');ta.remove();return ok;}}
function flashButton(btn,msg,err=false){const s=btn.querySelector('span')||btn; const old=s.textContent; s.textContent=msg; btn.classList.toggle('is-copied',!err); btn.classList.toggle('is-error',err); setTimeout(()=>{s.textContent=old;btn.classList.remove('is-copied','is-error');},1500);}
function renderResult(data){els.how.hidden=true; const r=buildReport(data); lastReport=r;
 const copyIcon='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
 els.results.innerHTML=`<article class="result-summary" style="--rir-color:${data.rir.color}"><div class="summary-main"><div class="k">${r.query.hostname?'DNS HOSTNAME':(r.query.version==='v4'?'IPV4 ADDRESS':'IPV6 ADDRESS')}</div><div class="v mono" style="font-size:1.35rem">${r.query.hostname?`${r.query.hostname} → `:''}${r.query.ip} <button class="export-btn" data-copy="${r.query.ip}">${copyIcon}<span>copy</span></button></div><p>Registered to <strong>${r.summary.registrant}</strong></p></div><div class="summary-side"><span class="badge" style="color:${data.rir.color}">${r.rir.code}</span><div class="export-bar"><span class="export-label">COPY REPORT</span><button class="export-btn" data-export="markdown">${copyIcon}<span>Markdown</span></button><button class="export-btn" data-export="text">${copyIcon}<span>Text</span></button><button class="export-btn" data-export="json">${copyIcon}<span>JSON</span></button></div></div></article>
 <div class="result-grid"><article class="card"><h4>Network allocation</h4><div class="kv"><div class="k">name</div><div class="v">${r.network.name}</div><div class="k">handle</div><div class="v mono">${r.network.handle}</div><div class="k">type</div><div class="v">${r.network.type}</div></div></article>
 <article class="card"><h4>Network range</h4><div class="kv"><div class="k">start</div><div class="v mono">${r.network.start_address}</div><div class="k">end</div><div class="v mono">${r.network.end_address}</div><div class="k">cidr</div><div class="v mono">${r.network.cidr}</div></div></article>
 <article class="card"><h4>Source registry</h4><div class="kv"><div class="k">RIR</div><div class="v">${r.rir.name}</div><div class="k">region</div><div class="v">${r.rir.region}</div><div class="k">source</div><div class="v mono">${r.rir.rdap_source}</div></div></article>
 <article class="card"><h4>Geo-location</h4>${r.location?`<div class="kv"><div class="k">city</div><div class="v">${r.location.city||'Unknown'}</div><div class="k">region</div><div class="v">${r.location.region||'Unknown'}</div><div class="k">country</div><div class="v">${r.location.country||'Unknown'}</div></div>`:'<p>No geo-location available for this IP.</p>'}</article></div>`;
}
function renderError(msg,query=''){els.results.innerHTML=`<article class="result-error"><h3>Lookup failed</h3><p>${msg}</p><p><strong>Query:</strong> ${query}</p><button class="chip" data-reset="1">try another address</button></article>`;}
function renderLoading(ip,version,hostname){els.how.hidden=true; const label=hostname?'DNS HOSTNAME':(version==='v4'?'IPV4 ADDRESS':'IPV6 ADDRESS'); const value=ip?(hostname?`${hostname} → ${ip}`:ip):`${hostname} (resolving…)`; els.results.innerHTML=`<article class="result-summary"><div class="summary-main"><div class="k">${label}</div><div class="v mono">${value}</div></div></article><div class="result-grid"><article class="card">Loading…</article><article class="card">Loading…</article></div>`;}
els.form.addEventListener('submit', async e=>{e.preventDefault(); const raw=els.input.value; let d=detectIPVersion(raw); let hostname=null;
 if(!d){
  const trimmed=raw.trim();
  if(!isValidHostname(trimmed)){els.msg.textContent='Enter a valid IPv4 address, IPv6 address, or DNS hostname.';return;}
  hostname=trimmed.toLowerCase(); els.msg.textContent=''; renderLoading(null,null,hostname);
  try{ d=await resolveHostname(hostname); if(!d){renderError('Could not resolve this hostname to an IP address.',hostname);return;} }
  catch(err){renderError(err.message,hostname);return;}
 }
 if(isReserved(d.version,d.addr)){els.msg.textContent='That address is reserved/private and cannot be looked up publicly.'; return;}
 els.msg.textContent=''; renderLoading(d.addr,d.version,hostname); try{renderResult(await lookup(d.addr,d.version,hostname));}catch(err){renderError(err.message,hostname||d.addr);} });
els.chips.forEach(c=>c.addEventListener('click',()=>{els.input.value=c.dataset.example; els.input.focus();}));
els.results.addEventListener('click', async e=>{const ex=e.target.closest('[data-export]'); if(ex&&lastReport){const t=ex.dataset.export==='json'?reportToJSON(lastReport):ex.dataset.export==='text'?reportToText(lastReport):reportToMarkdown(lastReport);flashButton(ex,(await copyToClipboard(t))?'copied':'failed',!(await copyToClipboard(t)));return;} const cp=e.target.closest('[data-copy]'); if(cp){flashButton(cp,(await copyToClipboard(cp.dataset.copy))?'copied':'failed');} if(e.target.closest('[data-reset]')){els.input.focus();}});
(function initTheme(){const t=localStorage.getItem('theme')||'dark';document.documentElement.classList.toggle('light',t==='light');els.themeBtn.textContent=t==='light'?'☾':'☼';})();
els.themeBtn.addEventListener('click',()=>{const l=document.documentElement.classList.toggle('light');localStorage.setItem('theme',l?'light':'dark');els.themeBtn.textContent=l?'☾':'☼';});
