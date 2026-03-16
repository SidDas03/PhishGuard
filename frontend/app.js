/**
 * PhishGuard v5 SOC Dashboard
 * Features: URL scan, bulk scan, file upload, email scan, watchlist, PDF reports
 */

const API_BASE = 'http://localhost:8000';

// ── Connection ───────────────────────────────────────────────────────────────
let backendOnline = false;

async function checkBackend() {
  const dot    = document.getElementById('conn-indicator');
  const label  = document.getElementById('conn-label');
  const banner = document.getElementById('offline-banner');
  try {
    const res = await fetch(API_BASE + '/api/health');
    if (!res.ok) throw new Error();
    backendOnline = true;
    if (dot)    { dot.style.background = 'var(--green)'; dot.classList.add('pulse'); }
    if (label)  label.textContent = 'All Systems Operational';
    if (banner) banner.style.display = 'none';
  } catch {
    backendOnline = false;
    if (dot)    { dot.style.background = 'var(--red)'; dot.classList.remove('pulse'); }
    if (label)  label.textContent = 'Backend Offline';
    if (banner) banner.style.display = 'flex';
  }
}
checkBackend();
setInterval(checkBackend, 10000);

// ── Router ────────────────────────────────────────────────────────────────────
function navigate(view) {
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelector(`.nav-item[data-view="${view}"]`)?.classList.add('active');
  document.getElementById(`view-${view}`)?.classList.add('active');
  const titles = {
    dashboard: ['SOC Dashboard','Overview'],   scanner:  ['URL Scanner','Threat Analysis'],
    history:   ['Scan History','Log'],         analytics:['Analytics','Intelligence'],
    bulk:      ['Bulk Scanner','File Upload'], email:    ['Email Scanner','Phishing Email Analysis'],
    watchlist: ['Watchlist','Scheduled Monitor'], api:   ['API Reference','REST Endpoints'],
  };
  const [t,b] = titles[view] || ['PhishGuard',''];
  const vt = document.getElementById('view-title');
  const bs = document.getElementById('breadcrumb-sub');
  if (vt) vt.textContent = t;
  if (bs) bs.textContent = b;
  if (view==='dashboard') loadDashboard();
  if (view==='history')   loadHistory();
  if (view==='analytics') loadAnalytics();
  if (view==='watchlist') loadWatchlist();
}
document.querySelectorAll('.nav-item').forEach(btn =>
  btn.addEventListener('click', () => navigate(btn.dataset.view)));

// ── Clock ─────────────────────────────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toUTCString().replace(' GMT',' UTC');
}
setInterval(updateClock, 1000); updateClock();

// ── API helper ────────────────────────────────────────────────────────────────
async function api(path, options = {}) {
  try {
    const res = await fetch(API_BASE + path, {
      headers: { 'Content-Type': 'application/json' }, ...options
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) { console.warn('API:', path, e.message); return null; }
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  const data = await api('/api/dashboard');
  if (!data) { renderDemoData(); return; }
  renderStats(data.stats);
  renderRecentTable(data.recent_scans);
  renderRingChart(data.threat_distribution);
  renderIndicators(data.top_indicators);
  renderTrends(data.trends);
}

function renderStats(s) {
  if (!s) return;
  animCount('s-total', s.total_scans||0);
  animCount('s-phish', s.phishing_detected||0);
  animCount('s-susp',  s.suspicious_detected||0);
  animCount('s-safe',  s.safe_scanned||0);
  const sr = document.getElementById('s-rate');
  if (sr) sr.textContent = (s.detection_rate||0)+'%';
  const ratio = (s.phishing_detected+s.suspicious_detected)/Math.max(s.total_scans,1);
  const lvl = document.getElementById('threat-value');
  if (lvl) {
    if (ratio>.5)      { lvl.textContent='HIGH';     lvl.style.color='var(--red)'; }
    else if (ratio>.3) { lvl.textContent='MODERATE'; lvl.style.color='var(--orange)'; }
    else               { lvl.textContent='LOW';      lvl.style.color='var(--green)'; }
  }
}

function animCount(id, target) {
  const el = document.getElementById(id); if (!el) return;
  let cur=0; const step=Math.max(1,Math.ceil(target/30));
  const iv = setInterval(()=>{ cur=Math.min(cur+step,target); el.textContent=cur; if(cur>=target)clearInterval(iv); },30);
}

function renderRecentTable(scans) {
  const tbody = document.getElementById('recent-tbody'); if (!tbody||!scans) return;
  tbody.innerHTML = scans.map(s=>`
    <tr onclick="showScanDetail('${s.scan_id}',${JSON.stringify(s).replace(/"/g,'&quot;')})">
      <td><span class="scan-id-badge">${s.scan_id}</span></td>
      <td><div class="url-cell" title="${escHtml(s.url)}">${escHtml(s.url)}</div></td>
      <td>${riskBadge(s.risk_score,s.risk_level)}</td>
      <td><span style="font-size:0.6rem;color:${classColor(s.classification)}">${s.classification||'—'}</span></td>
      <td style="color:var(--text3);font-size:0.62rem;">${timeAgo(s.timestamp)}</td>
    </tr>`).join('');
}

const RING_COLORS = { CONFIRMED_PHISHING:'#ff2d55',LIKELY_PHISHING:'#ff8c00',SUSPICIOUS:'#ffd60a',POTENTIALLY_UNSAFE:'#00e5ff',LIKELY_SAFE:'#00ff88' };

function renderRingChart(dist) {
  const canvas = document.getElementById('ring-chart'); if(!canvas||!dist) return;
  const ctx=canvas.getContext('2d'), labels=Object.keys(dist), values=Object.values(dist);
  const total=values.reduce((a,b)=>a+b,0);
  const rt=document.getElementById('ring-total'); if(rt) rt.textContent=total;
  const cx=110,cy=110,r=80,inner=55; ctx.clearRect(0,0,220,220);
  let angle=0;
  labels.forEach((l,i)=>{ const s=(values[i]/total)*Math.PI*2; ctx.beginPath(); ctx.moveTo(cx,cy); ctx.arc(cx,cy,r,angle,angle+s); ctx.closePath(); ctx.fillStyle=RING_COLORS[l]||'#3a5070'; ctx.fill(); angle+=s; });
  ctx.beginPath(); ctx.arc(cx,cy,inner,0,Math.PI*2); ctx.fillStyle='#0e1520'; ctx.fill();
  const legend=document.getElementById('ring-legend');
  if(legend) legend.innerHTML=labels.map((l,i)=>`<div class="ring-legend-item"><div class="ring-legend-dot" style="background:${RING_COLORS[l]||'#3a5070'}"></div><span>${l.replace(/_/g,' ')} (${values[i]})</span></div>`).join('');
}

function renderIndicators(indicators) {
  const el=document.getElementById('indicators-list'); if(!el||!indicators?.length) return;
  const max=indicators[0]?.count||1;
  el.innerHTML=indicators.slice(0,8).map(ind=>`
    <div class="ind-item">
      <div class="ind-name">${escHtml(ind.indicator)}</div>
      <div class="ind-bar-wrap"><div class="ind-bar" style="width:${(ind.count/max)*100}%"></div></div>
      <div class="ind-count">${ind.count}</div>
    </div>`).join('');
}

function renderTrends(trends) {
  const el=document.getElementById('trend-bars'); if(!el||!trends?.length) return;
  el.innerHTML='';
  const maxT=Math.max(...trends.map(t=>t.total),1);
  [...trends].reverse().forEach(d=>{
    const div=document.createElement('div'); div.className='trend-day';
    div.innerHTML=`<div class="trend-bar-wrap"><div class="trend-bar phish" style="height:${Math.round((d.phishing/maxT)*100)}px"></div><div class="trend-bar safe" style="height:${Math.round((d.safe/maxT)*100)}px"></div></div><div class="trend-label">${(d.day||'').slice(5)}</div>`;
    el.appendChild(div);
  });
}

function renderDemoData() {
  animCount('s-total',42); animCount('s-phish',18); animCount('s-susp',7); animCount('s-safe',17);
  const sr=document.getElementById('s-rate'); if(sr) sr.textContent='42.9%';
  renderRingChart({CONFIRMED_PHISHING:14,LIKELY_PHISHING:4,SUSPICIOUS:7,LIKELY_SAFE:17});
}

// ── URL Scanner ───────────────────────────────────────────────────────────────
function setUrl(url) { const el=document.getElementById('url-input'); if(el) el.value=url; }
let scanInProgress=false;

async function startScan() {
  if (scanInProgress) return;
  const input=document.getElementById('url-input');
  const url=input?input.value.trim():'';
  if (!url) { flashInput(); return; }
  if (!backendOnline) { renderScanError(url,true); return; }

  scanInProgress=true;
  const btn=document.getElementById('scan-btn'), btnTxt=document.getElementById('scan-btn-text');
  const resultEl=document.getElementById('scan-result'), progEl=document.getElementById('scan-progress');
  if(btn) btn.disabled=true; if(btnTxt) btnTxt.textContent='SCANNING...';
  if(resultEl) resultEl.style.display='none'; if(progEl) progEl.style.display='block';

  const modules=['URL Analysis','Domain Intelligence','SSL Inspection','ML Detection','Content Analysis','Threat Intelligence'];
  const modEl=document.getElementById('module-progress');
  if(modEl) modEl.innerHTML=modules.map((m,i)=>`<div class="mod-item" id="mod-${i}"><div class="mod-name">${m}</div><div class="mod-bar-wrap"><div class="mod-bar" id="mod-bar-${i}"></div></div><div class="mod-status pending" id="mod-status-${i}">PENDING</div></div>`).join('');

  const animP=animateModules(modules);
  const result=await api('/api/scan',{method:'POST',body:JSON.stringify({
    url, deep_scan:false,
    check_content:  document.getElementById('opt-content')?.checked??true,
    check_ssl:      document.getElementById('opt-ssl')?.checked??true,
    check_threat_intel: document.getElementById('opt-ti')?.checked??true,
  })});
  await animP;
  if(progEl) progEl.style.display='none';
  if(result&&!result.error) renderScanResult(result);
  else renderScanError(url,false,result?.error);
  scanInProgress=false;
  if(btn) btn.disabled=false; if(btnTxt) btnTxt.textContent='ANALYZE';
}

function animateModules(modules) {
  return new Promise(resolve=>{
    let i=0;
    function next() {
      if(i>=modules.length){resolve();return;}
      const bar=document.getElementById(`mod-bar-${i}`), status=document.getElementById(`mod-status-${i}`);
      if(!bar){resolve();return;}
      if(status){status.textContent='SCANNING';status.className='mod-status active';}
      let w=0;
      const fill=setInterval(()=>{
        w=Math.min(w+Math.random()*15+5,100); bar.style.width=w+'%';
        if(w>=100){clearInterval(fill); if(status){status.textContent='DONE';status.className='mod-status done';} i++; setTimeout(next,150);}
      },60);
    }
    next();
  });
}

function renderScanResult(r) {
  const el=document.getElementById('scan-result'); if(!el) return;
  el.style.display='block';
  const sc=scoreToColor(r.risk_score), circ=2*Math.PI*45, offset=circ-(r.risk_score/100)*circ;
  const checks=r.checks||{};
  const moduleKeys=['url_analysis','domain_intelligence','ssl_inspection','ml_detection','content_analysis','threat_intelligence'];
  const moduleLabels=['URL ANALYSIS','DOMAIN INTEL','SSL INSPECT','ML DETECT','CONTENT ANAL','THREAT INTEL'];
  const modScores=moduleKeys.map((k,i)=>{
    const score=checks[k]?.score||0, color=score>70?'var(--red)':score>40?'var(--orange)':'var(--green)';
    return `<div class="module-score-cell"><div class="module-score-name">${moduleLabels[i]}</div><div class="module-score-bar-wrap"><div class="module-score-bar" style="width:${score}%;background:${color}"></div></div><div class="module-score-val" style="color:${color}">${typeof score==='number'?score.toFixed(1):score}</div></div>`;
  }).join('');

  const ml=checks.ml_detection||{};
  const mlProb=ml.phishing_probability!=null?(ml.phishing_probability*100).toFixed(1)+'%':'—';
  const rfProb=ml.rf_probability!=null?(ml.rf_probability*100).toFixed(1)+'%':null;
  const gbProb=ml.gb_probability!=null?(ml.gb_probability*100).toFixed(1)+'%':null;
  const urlData=checks.url_analysis||{};
  const isTrusted=urlData.trusted_tld, isRealBrand=urlData.real_brand;

  const extraBadges=[
    isTrusted?`<span class="result-badge" style="background:rgba(0,255,136,0.1);color:var(--green);border:1px solid rgba(0,255,136,0.2)">✓ TRUSTED TLD</span>`:'',
    isRealBrand?`<span class="result-badge" style="background:rgba(0,255,136,0.1);color:var(--green);border:1px solid rgba(0,255,136,0.2)">✓ REAL BRAND</span>`:'',
  ].filter(Boolean).join('');

  const mlBreakdown=(rfProb||gbProb)?`<div class="ml-breakdown">${rfProb?`<span class="ml-model-badge">RF: ${rfProb}</span>`:''} ${gbProb?`<span class="ml-model-badge">GB: ${gbProb}</span>`:''}<span class="ml-model-badge" style="color:var(--purple)">ENSEMBLE: ${mlProb}</span></div>`:'';

  const topFeatures=ml.top_features||[];
  const featureBreakdown=topFeatures.length?`<div class="feature-breakdown"><div class="feature-title">ML FEATURE IMPORTANCE</div>${topFeatures.map(f=>`<div class="feature-row"><div class="feature-name">${escHtml(f.feature)}</div><div class="feature-bar-wrap"><div class="feature-bar" style="width:${Math.min(f.importance*500,100)}%"></div></div><div class="feature-val">${f.value}</div></div>`).join('')}</div>`:'';

  const indicators=(r.indicators||[]).map(ind=>{
    const sev=ind.severity||0, sevClass=sev>=30?'high':sev>=15?'med':'low';
    return `<div class="indicator-card"><div class="ind-sev ${sevClass}">${sev}</div><div class="ind-body"><div class="ind-check">${escHtml(ind.check||'')}</div><div class="ind-detail">${escHtml(ind.detail||'')}</div><div class="ind-source">SOURCE: ${escHtml(ind.source||'')}</div></div></div>`;
  }).join('');

  // PDF download button
  const pdfBtn=`<button class="btn-mini" onclick="downloadReport('${r.scan_id}')" style="background:rgba(255,45,85,0.1);color:var(--red);border-color:rgba(255,45,85,0.3)">⬇ PDF REPORT</button>`;

  el.innerHTML=`
    <div class="result-header">
      <div><div class="result-url">${escHtml(r.url)}</div>
      <div class="result-id">SCAN ID: ${r.scan_id} · ${r.scan_duration_ms}ms · ${new Date(r.timestamp).toLocaleString()}</div></div>
      <div>${pdfBtn}</div>
    </div>
    <div class="result-score-section">
      <div class="score-ring">
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="45" fill="none" stroke="var(--border2)" stroke-width="8"/>
          <circle cx="60" cy="60" r="45" fill="none" stroke="${sc}" stroke-width="8" stroke-dasharray="${circ}" stroke-dashoffset="${offset}" stroke-linecap="round"/>
        </svg>
        <div class="score-ring-num"><span class="score-num" style="color:${sc}">${r.risk_score}</span><span class="score-label">RISK SCORE</span></div>
      </div>
      <div class="result-meta">
        <div class="result-class" style="color:${sc}">${(r.classification||'').replace(/_/g,' ')}</div>
        <div class="result-rec">${r.recommendation}</div>
        <div class="result-badges">
          <span class="result-badge" style="background:rgba(0,0,0,0.2);color:${sc};border:1px solid ${sc}40">${r.risk_level}</span>
          <span class="result-badge" style="background:rgba(0,229,255,0.08);color:var(--accent2);border:1px solid var(--border2)">CONFIDENCE: ${r.confidence}%</span>
          <span class="result-badge" style="background:rgba(191,90,242,0.1);color:var(--purple);border:1px solid rgba(191,90,242,0.2)">ML: ${mlProb}</span>
          ${extraBadges}
        </div>
        ${mlBreakdown}
      </div>
    </div>
    <div class="module-scores-grid">${modScores}</div>
    ${featureBreakdown}
    <div class="indicators-section">
      <div class="indicators-title">DETECTION INDICATORS (${r.indicators?.length||0} TRIGGERS)</div>
      ${indicators||'<div style="color:var(--text3);font-size:0.65rem;padding:12px 0;">No significant indicators detected — URL appears safe</div>'}
    </div>`;
}

function renderScanError(url, backendDown=false, serverError=null) {
  const el=document.getElementById('scan-result'); if(!el) return;
  el.style.display='block';
  let message='', steps='';
  if (backendDown) {
    message='Cannot reach the PhishGuard backend server.';
    steps=`<div style="text-align:left;margin-top:16px;"><div style="color:var(--text);font-size:0.65rem;margin-bottom:10px;letter-spacing:0.1em;">HOW TO START THE SERVER:</div><div style="background:var(--bg);border:1px solid var(--border2);border-radius:6px;padding:12px 14px;font-size:0.65rem;line-height:2.2;"><div><span style="color:var(--text3);">1.</span> Open Command Prompt</div><div><span style="color:var(--text3);">2.</span> <code style="color:var(--accent2);">cd path\\to\\pg\\backend</code></div><div><span style="color:var(--text3);">3.</span> First time only: <code style="color:var(--accent2);">pip install -r requirements.txt</code></div><div><span style="color:var(--text3);">4.</span> First time only: <code style="color:var(--accent2);">python train_model.py</code></div><div><span style="color:var(--text3);">5.</span> Start server: <code style="color:var(--accent2);">python main.py</code></div><div><span style="color:var(--text3);">6.</span> Keep that window open, then retry</div></div></div>`;
  } else {
    message=serverError?`Server error: ${escHtml(serverError)}`:'Scan request failed — server may have crashed.';
    steps=`<div style="color:var(--text3);font-size:0.6rem;margin-top:10px;">Try unchecking SSL Inspection and Content Analysis, then scan again. If still failing, restart: <code style="color:var(--accent2);">python main.py</code></div>`;
  }
  el.innerHTML=`<div style="padding:28px 32px;"><div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;"><div style="font-size:1.6rem;">⚠</div><div><div style="color:var(--orange);font-size:0.78rem;font-weight:700;letter-spacing:0.1em;margin-bottom:4px;">SCAN FAILED</div><div style="color:var(--text2);font-size:0.65rem;">${message}</div></div></div>${steps}<div style="margin-top:16px;padding:10px 14px;background:var(--bg3);border-radius:4px;font-size:0.6rem;color:var(--text3);">Target: <span style="color:var(--text2);">${escHtml(url)}</span></div></div>`;
}

function flashInput() {
  const el=document.getElementById('url-input'); if(!el) return;
  el.style.outline='1px solid var(--red)'; setTimeout(()=>{ el.style.outline=''; },1000);
}

document.getElementById('url-input')?.addEventListener('keydown', e=>{ if(e.key==='Enter') startScan(); });

// ── PDF Download ──────────────────────────────────────────────────────────────
function downloadReport(scanId) {
  window.open(`${API_BASE}/api/report/${scanId}`, '_blank');
}

// ── Bulk Scanner ──────────────────────────────────────────────────────────────
async function startBulkScan() {
  const fileInput=document.getElementById('bulk-file');
  const file=fileInput?.files[0];
  if (!file) { alert('Please select a .txt or .csv file first'); return; }
  if (!backendOnline) { alert('Backend server is not running'); return; }

  const btn=document.getElementById('bulk-btn');
  if(btn) { btn.disabled=true; btn.textContent='SCANNING...'; }
  const resultEl=document.getElementById('bulk-results');
  if(resultEl) resultEl.innerHTML='<div style="color:var(--accent);font-size:0.7rem;padding:20px;">⟳ Scanning URLs from file...</div>';

  const formData=new FormData();
  formData.append('file', file);

  try {
    const res=await fetch(`${API_BASE}/api/scan/file`, { method:'POST', body:formData });
    const data=await res.json();
    renderBulkResults(data);
  } catch(e) {
    if(resultEl) resultEl.innerHTML=`<div style="color:var(--red);padding:20px;">Error: ${e.message}</div>`;
  }
  if(btn) { btn.disabled=false; btn.textContent='SCAN FILE'; }
}

function renderBulkResults(data) {
  const el=document.getElementById('bulk-results'); if(!el) return;
  if(data.error) { el.innerHTML=`<div style="color:var(--red);padding:20px;">Error: ${escHtml(data.error)}</div>`; return; }
  const results=data.results||[];
  el.innerHTML=`
    <div class="bulk-summary">
      <div class="bulk-stat danger"><span>${data.phishing||0}</span><label>PHISHING</label></div>
      <div class="bulk-stat warn"><span>${data.suspicious||0}</span><label>SUSPICIOUS</label></div>
      <div class="bulk-stat safe"><span>${data.safe||0}</span><label>SAFE</label></div>
      <div class="bulk-stat"><span>${data.total||0}</span><label>TOTAL</label></div>
    </div>
    <div class="bulk-table-wrap">
      <table class="scan-table">
        <thead><tr><th>URL</th><th>RISK SCORE</th><th>CLASSIFICATION</th><th>REPORT</th></tr></thead>
        <tbody>${results.map(r=>`
          <tr>
            <td><div class="url-cell" title="${escHtml(r.url||'')}">
              ${r.error?`<span style="color:var(--red)">${escHtml(r.error)}</span>`:escHtml(r.url||'')}
            </div></td>
            <td>${r.risk_score!=null?riskBadge(r.risk_score,r.risk_level):'—'}</td>
            <td><span style="font-size:0.6rem;color:${classColor(r.classification)}">${r.classification||r.status||'—'}</span></td>
            <td>${r.scan_id?`<button class="btn-mini" onclick="downloadReport('${r.scan_id}')">PDF</button>`:'—'}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

// ── Email Scanner ─────────────────────────────────────────────────────────────
async function startEmailScan() {
  const body    = document.getElementById('email-body')?.value?.trim();
  const subject = document.getElementById('email-subject')?.value?.trim();
  const sender  = document.getElementById('email-sender')?.value?.trim();

  if (!body) { alert('Please paste the email body'); return; }
  if (!backendOnline) { alert('Backend server is not running'); return; }

  const btn=document.getElementById('email-btn');
  if(btn) { btn.disabled=true; btn.textContent='SCANNING...'; }
  const resultEl=document.getElementById('email-results');
  if(resultEl) resultEl.innerHTML='<div style="color:var(--accent);font-size:0.7rem;padding:20px;">⟳ Extracting and scanning URLs from email...</div>';

  const data=await api('/api/email/scan',{method:'POST',body:JSON.stringify({body,subject,sender})});

  if(btn) { btn.disabled=false; btn.textContent='SCAN EMAIL'; }
  if(!data) { if(resultEl) resultEl.innerHTML='<div style="color:var(--red);padding:20px;">Scan failed. Check server.</div>'; return; }
  renderEmailResults(data);
}

function renderEmailResults(data) {
  const el=document.getElementById('email-results'); if(!el) return;
  const sc=scoreToColor(data.email_risk_score);
  const indicators=(data.email_indicators||[]).map(ind=>`
    <div class="indicator-card" style="margin-bottom:6px;">
      <div class="ind-sev ${ind.severity>=25?'high':ind.severity>=15?'med':'low'}">${ind.severity}</div>
      <div class="ind-body"><div class="ind-check">${escHtml(ind.check)}</div><div class="ind-detail">${escHtml(ind.detail)}</div></div>
    </div>`).join('');

  const urlRows=(data.url_results||[]).map(r=>`
    <tr>
      <td><div class="url-cell" title="${escHtml(r.url||'')}">${escHtml(r.url||'')}</div></td>
      <td>${r.risk_score!=null?riskBadge(r.risk_score,r.risk_level):'—'}</td>
      <td><span style="font-size:0.6rem;color:${classColor(r.classification)}">${r.classification||'—'}</span></td>
      <td>${r.scan_id?`<button class="btn-mini" onclick="downloadReport('${r.scan_id}')">PDF</button>`:'—'}</td>
    </tr>`).join('');

  el.innerHTML=`
    <div style="display:flex;align-items:center;gap:20px;padding:20px 0;border-bottom:1px solid var(--border);margin-bottom:16px;">
      <div style="font-family:var(--font-head);font-size:2.5rem;font-weight:800;color:${sc}">${data.email_risk_score}</div>
      <div>
        <div style="font-size:1rem;color:${sc};font-weight:700;margin-bottom:4px;">${data.email_risk_level?.replace(/_/g,' ')}</div>
        <div style="font-size:0.65rem;color:var(--text2)">${data.urls_found} URL${data.urls_found!==1?'s':''} found · ${data.phishing_urls} phishing · ${data.obfuscated_urls} obfuscated</div>
      </div>
    </div>
    ${indicators?`<div style="font-size:0.6rem;letter-spacing:0.15em;color:var(--text3);margin-bottom:10px;">EMAIL INDICATORS</div>${indicators}`:''}
    ${urlRows?`<div style="font-size:0.6rem;letter-spacing:0.15em;color:var(--text3);margin:14px 0 8px;">URL SCAN RESULTS</div>
    <table class="scan-table"><thead><tr><th>URL</th><th>SCORE</th><th>CLASSIFICATION</th><th>REPORT</th></tr></thead><tbody>${urlRows}</tbody></table>`:''}`;
}

// ── Watchlist ─────────────────────────────────────────────────────────────────
async function loadWatchlist() {
  const data=await api('/api/watchlist');
  renderWatchlist(data?.watchlist||[]);
  const results=await api('/api/watchlist/results');
  renderWatchlistResults(results?.results||[]);
}

async function addToWatchlist() {
  const urlEl=document.getElementById('wl-url');
  const intEl=document.getElementById('wl-interval');
  const url=urlEl?.value?.trim();
  const interval=parseInt(intEl?.value||'60');
  if(!url) { alert('Please enter a URL'); return; }
  const data=await api('/api/watchlist',{method:'POST',body:JSON.stringify({url,interval_minutes:interval})});
  if(data&&!data.error) { if(urlEl) urlEl.value=''; loadWatchlist(); }
  else alert(data?.error||'Failed to add');
}

async function removeFromWatchlist(url) {
  await api(`/api/watchlist/${encodeURIComponent(url)}`,{method:'DELETE'});
  loadWatchlist();
}

function renderWatchlist(entries) {
  const el=document.getElementById('watchlist-entries'); if(!el) return;
  if(!entries.length) { el.innerHTML='<div style="color:var(--text3);font-size:0.65rem;padding:20px;text-align:center;">No domains being monitored. Add one above.</div>'; return; }
  el.innerHTML=`<table class="scan-table"><thead><tr><th>URL</th><th>INTERVAL</th><th>LAST SCORE</th><th>CHECKS</th><th>ADDED</th><th></th></tr></thead><tbody>${entries.map(e=>`
    <tr>
      <td><div class="url-cell">${escHtml(e.url)}</div></td>
      <td style="color:var(--text2)">${e.interval_minutes}m</td>
      <td>${e.last_score!=null?riskBadge(e.last_score,''):'—'}</td>
      <td style="color:var(--text2)">${e.check_count||0}</td>
      <td style="color:var(--text3);font-size:0.6rem;">${e.added_at?new Date(e.added_at).toLocaleDateString():'—'}</td>
      <td><button class="btn-mini" style="color:var(--red)" onclick="removeFromWatchlist('${escHtml(e.url)}')">REMOVE</button></td>
    </tr>`).join('')}</tbody></table>`;
}

function renderWatchlistResults(results) {
  const el=document.getElementById('watchlist-results'); if(!el) return;
  const alerts=results.filter(r=>r.alert);
  if(!results.length) { el.innerHTML='<div style="color:var(--text3);font-size:0.65rem;padding:16px;">No monitoring results yet. Results appear after the first scheduled check.</div>'; return; }
  el.innerHTML=`
    ${alerts.length?`<div style="background:rgba(255,140,0,0.1);border:1px solid rgba(255,140,0,0.3);border-radius:6px;padding:12px 16px;margin-bottom:12px;font-size:0.65rem;color:var(--orange);">⚠ ${alerts.length} ALERT${alerts.length!==1?'S':''}: Risk score changed significantly</div>`:''}
    <table class="scan-table"><thead><tr><th>URL</th><th>SCORE</th><th>CHANGE</th><th>CLASSIFICATION</th><th>CHECKED</th></tr></thead>
    <tbody>${results.slice(0,20).map(r=>`
      <tr style="${r.alert?'background:rgba(255,140,0,0.05)':''}">
        <td><div class="url-cell">${escHtml(r.url)}</div></td>
        <td>${riskBadge(r.score,'')}</td>
        <td style="color:${r.score_change>=20?'var(--red)':'var(--text2)'}">${r.score_change>=0?'+':''}${r.score_change}</td>
        <td><span style="font-size:0.6rem;color:${classColor(r.classification)}">${r.classification||'—'}</span></td>
        <td style="color:var(--text3);font-size:0.6rem;">${r.checked_at?timeAgo(r.checked_at):'—'}</td>
      </tr>`).join('')}
    </tbody></table>`;
}

// ── History ───────────────────────────────────────────────────────────────────
let historyData=[];
async function loadHistory() {
  const data=await api('/api/history?limit=100');
  historyData=data?.scans||[]; renderHistoryTable(historyData);
}

function renderHistoryTable(scans) {
  const tbody=document.getElementById('history-tbody'); if(!tbody) return;
  tbody.innerHTML=scans.map(s=>`
    <tr onclick="showScanDetail('${s.scan_id}',${JSON.stringify(s).replace(/"/g,'&quot;')})">
      <td><span class="scan-id-badge">${s.scan_id}</span></td>
      <td><div class="url-cell" title="${escHtml(s.url)}">${escHtml(s.url)}</div></td>
      <td>${riskBadge(s.risk_score,s.risk_level)}</td>
      <td><span style="font-size:0.6rem;color:${classColor(s.classification)}">${s.classification||'—'}</span></td>
      <td style="color:var(--text2)">${s.confidence||'—'}%</td>
      <td style="color:var(--text3);font-size:0.6rem;">${s.timestamp?new Date(s.timestamp).toLocaleString():'—'}</td>
      <td style="display:flex;gap:4px;">
        <button class="btn-mini" onclick="event.stopPropagation();showScanDetail('${s.scan_id}',${JSON.stringify(s).replace(/"/g,'&quot;')})">VIEW</button>
        ${s.scan_id?`<button class="btn-mini" style="color:var(--red)" onclick="event.stopPropagation();downloadReport('${s.scan_id}')">PDF</button>`:''}
      </td>
    </tr>`).join('');
}

document.getElementById('history-filter')?.addEventListener('input', e=>{
  const q=e.target.value.toLowerCase();
  renderHistoryTable(historyData.filter(s=>s.url?.toLowerCase().includes(q)||s.classification?.toLowerCase().includes(q)||s.scan_id?.toLowerCase().includes(q)));
});

async function clearHistory() {
  if(!confirm('Clear all scan history?')) return;
  await api('/api/history',{method:'DELETE'}); historyData=[]; renderHistoryTable([]);
}

// ── Detail Modal ──────────────────────────────────────────────────────────────
function showScanDetail(scanId, data) {
  const modal=document.getElementById('modal'), content=document.getElementById('modal-content');
  if(!modal||!content) return; modal.style.display='flex';
  const color=scoreToColor(data.risk_score);
  const indicators=(data.indicators||[]).map(ind=>`
    <div class="indicator-card" style="margin-bottom:6px;">
      <div class="ind-sev ${ind.severity>=30?'high':ind.severity>=15?'med':'low'}">${ind.severity||0}</div>
      <div class="ind-body"><div class="ind-check">${escHtml(ind.check||'')}</div><div class="ind-detail">${escHtml(ind.detail||'')}</div><div class="ind-source">SOURCE: ${escHtml(ind.source||'')}</div></div>
    </div>`).join('');
  content.innerHTML=`
    <div style="margin-bottom:20px;">
      <div style="font-size:0.6rem;color:var(--text3);letter-spacing:0.15em;margin-bottom:6px;">SCAN — ${data.scan_id}</div>
      <div style="font-size:0.75rem;color:var(--text2);word-break:break-all;margin-bottom:14px;">${escHtml(data.url)}</div>
      <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
        <div style="font-family:var(--font-head);font-size:2.2rem;font-weight:800;color:${color}">${data.risk_score}</div>
        <div><div style="font-size:0.8rem;color:${color};font-weight:700;margin-bottom:4px;">${(data.classification||'').replace(/_/g,' ')}</div><div style="font-size:0.65rem;color:var(--text2)">${data.recommendation||''}</div></div>
      </div>
    </div>
    ${indicators?`<div style="font-size:0.6rem;letter-spacing:0.15em;color:var(--text3);margin-bottom:10px;">INDICATORS</div>${indicators}`:''}
    <div style="display:flex;gap:8px;margin-top:16px;">
      ${data.scan_id?`<button class="btn-mini" style="color:var(--red)" onclick="downloadReport('${data.scan_id}')">⬇ Download PDF Report</button>`:''}
    </div>
    <div style="margin-top:12px;font-size:0.6rem;color:var(--text3);">Scanned: ${data.timestamp?new Date(data.timestamp).toLocaleString():'—'} · Confidence: ${data.confidence||'—'}%</div>`;
}
function closeModal(e) { if(!e||e.target===document.getElementById('modal')) document.getElementById('modal').style.display='none'; }

// ── Analytics ─────────────────────────────────────────────────────────────────
let analyticsLoaded=false;
async function loadAnalytics() {
  if(analyticsLoaded) return; analyticsLoaded=true;
  const data=await api('/api/dashboard');
  if(data) renderBarChart(data.threat_distribution||{});
}

function renderBarChart(dist) {
  const canvas=document.getElementById('bar-chart'); if(!canvas) return;
  const labels=Object.keys(dist), values=Object.values(dist), colors=labels.map(l=>RING_COLORS[l]||'#3a5070');
  const maxVal=Math.max(...values,1), w=canvas.offsetWidth||400, h=240;
  canvas.width=w; canvas.height=h;
  const ctx=canvas.getContext('2d'); ctx.clearRect(0,0,w,h);
  const barW=Math.min(60,(w-40)/labels.length-10), spacing=(w-40)/labels.length;
  labels.forEach((label,i)=>{
    const x=20+spacing*i+spacing/2-barW/2, barH=Math.round((values[i]/maxVal)*(h-60)), y=h-30-barH;
    ctx.fillStyle=colors[i]; ctx.globalAlpha=0.8;
    ctx.beginPath(); if(ctx.roundRect) ctx.roundRect(x,y,barW,barH,3); else ctx.rect(x,y,barW,barH); ctx.fill(); ctx.globalAlpha=1;
    ctx.fillStyle='#c8d8e8'; ctx.font='10px monospace'; ctx.textAlign='center'; ctx.fillText(values[i],x+barW/2,y-6);
    ctx.fillStyle='#3a5070'; ctx.font='9px monospace'; ctx.fillText(label.replace('_',' ').replace('CONFIRMED ','').replace('LIKELY ',''),x+barW/2,h-8);
  });
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function riskBadge(score,level) {
  const cls={MINIMAL:'minimal',LOW:'low',MEDIUM:'medium',HIGH:'high',CRITICAL:'critical'}[level]||'low';
  return `<span class="risk-badge risk-${cls}">${typeof score==='number'?score.toFixed(1):score||0}</span>`;
}
function classColor(cls) {
  return {CONFIRMED_PHISHING:'var(--red)',LIKELY_PHISHING:'var(--orange)',SUSPICIOUS:'var(--yellow)',POTENTIALLY_UNSAFE:'var(--accent)',LIKELY_SAFE:'var(--green)',LIKELY_LEGITIMATE:'var(--green)'}[cls]||'var(--text2)';
}
function scoreToColor(s) {
  if(s>=85) return '#ff2d55'; if(s>=65) return '#ff8c00'; if(s>=45) return '#ffd60a'; if(s>=25) return '#00e5ff'; return '#00ff88';
}
function timeAgo(ts) {
  if(!ts) return '—'; const m=Math.floor((Date.now()-new Date(ts))/60000);
  if(m<1) return 'just now'; if(m<60) return `${m}m ago`; const h=Math.floor(m/60);
  if(h<24) return `${h}h ago`; return `${Math.floor(h/24)}d ago`;
}
function escHtml(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadDashboard();
