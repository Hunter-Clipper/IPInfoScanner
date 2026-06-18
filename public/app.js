// ── Config ─────────────────────────────────────────────────────────────────
// When served by the Node.js container, use the same origin (empty string = relative).
// When served by Cloudflare Pages standalone, fall back to the CF Worker URL.
const WORKER_BASE = (window.location.hostname === 'ipinfo.hunterclipper.com' || window.location.hostname === 'hunterclipper.com')
  ? 'https://ipscan.hunter-clipper.workers.dev'
  : '';
const STORAGE_KEYS = { vt:'ipi_key_vt', shodan:'ipi_key_shodan', ipinfo:'ipi_key_ipinfo', proxycheck:'ipi_key_proxycheck' };
const HISTORY_KEY  = 'ipi_scan_history';
const THEME_KEY    = 'ipi_theme';
const MAX_HISTORY  = 50;

const $ = id => document.getElementById(id);

// ── Theme ──────────────────────────────────────────────────────────────────
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  $('btn-dark').classList.toggle('active', t === 'dark');
  $('btn-light').classList.toggle('active', t === 'light');
  try { localStorage.setItem(THEME_KEY, t); } catch {}
}
(function(){
  const saved = (() => { try { return localStorage.getItem(THEME_KEY); } catch { return null; } })();
  applyTheme(saved || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
})();
$('btn-dark').addEventListener('click',  () => applyTheme('dark'));
$('btn-light').addEventListener('click', () => applyTheme('light'));

// ── API key helpers ────────────────────────────────────────────────────────
function getKey(n)      { try { return localStorage.getItem(STORAGE_KEYS[n]) || ''; } catch { return ''; } }
function setKey(n, val) { try { val ? localStorage.setItem(STORAGE_KEYS[n], val) : localStorage.removeItem(STORAGE_KEYS[n]); } catch {} }

function refreshPills() {}

// ── Scan History ───────────────────────────────────────────────────────────
function getHistory() { try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch { return []; } }
function saveHistory(h) { try { localStorage.setItem(HISTORY_KEY, JSON.stringify(h)); } catch {} }

function addToHistory(entry) {
  let h = getHistory();
  // Remove duplicate if same IP already exists
  h = h.filter(e => e.ip !== entry.ip);
  h.unshift(entry);
  if (h.length > MAX_HISTORY) h = h.slice(0, MAX_HISTORY);
  saveHistory(h);
  renderHistory();
}

function renderHistory() {
  const h = getHistory();
  $('history-badge').textContent = h.length;
  const list = $('history-list');
  if (!h.length) {
    list.innerHTML = '<div class="history-empty">No scans yet.<br>Results appear here after each scan.</div>';
    return;
  }
  list.innerHTML = h.map((e, i) => {
    const riskColor = e.riskScore >= 65 ? 'var(--red)' : e.riskScore >= 25 ? 'var(--amber)' : e.riskScore >= 12 ? '#fbbf24' : 'var(--green)';
    const icon = e.isTor ? '🧅' : e.riskScore >= 65 ? '🚨' : e.riskScore >= 25 ? '⚠️' : e.riskScore >= 12 ? '🔔' : '✅';
    const ago  = timeAgo(e.timestamp);
    return `<div class="history-item" onclick="loadFromHistory(${i})">
      <div class="history-item-icon">${icon}</div>
      <div class="history-item-main">
        <div class="history-item-ip">${e.resolvedFrom ? esc(e.resolvedFrom) + ' → ' : ''}${esc(e.ip)}</div>
        <div class="history-item-meta">${esc(e.country || '')} ${esc(e.city || '')} · ${ago}</div>
      </div>
      <div class="history-item-risk" style="color:${riskColor}">${e.riskScore}</div>
      <button class="history-item-del" onclick="deleteHistory(event,${i})" title="Remove">✕</button>
    </div>`;
  }).join('');
}

function loadFromHistory(i) {
  const e = getHistory()[i];
  if (!e) return;
  $('ip-input').value = e.resolvedFrom || e.ip;
  closeHistory();
  lookup(e.resolvedFrom || e.ip);
}

function deleteHistory(ev, i) {
  ev.stopPropagation();
  const h = getHistory();
  h.splice(i, 1);
  saveHistory(h);
  renderHistory();
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000)   return 'just now';
  if (diff < 3600000) return Math.floor(diff/60000) + 'm ago';
  if (diff < 86400000)return Math.floor(diff/3600000) + 'h ago';
  return Math.floor(diff/86400000) + 'd ago';
}

// History panel open/close
function openHistory()  {
  $('history-overlay').classList.add('open');
  $('history-panel').classList.add('open');
  renderHistory();
}
function closeHistory() {
  $('history-overlay').classList.remove('open');
  $('history-panel').classList.remove('open');
}
$('history-btn').addEventListener('click', openHistory);
$('history-close').addEventListener('click', closeHistory);
$('history-overlay').addEventListener('click', closeHistory);

function openHelp()  { $('help-overlay').classList.add('open'); $('help-panel').classList.add('open'); }
function closeHelp() { $('help-overlay').classList.remove('open'); $('help-panel').classList.remove('open'); }
$('help-btn').addEventListener('click', openHelp);
$('help-close').addEventListener('click', closeHelp);
$('help-overlay').addEventListener('click', closeHelp);

function closeTopMenu() { $('top-menu').classList.remove('open'); }
$('hamburger-btn').addEventListener('click', e => { e.stopPropagation(); $('top-menu').classList.toggle('open'); });
document.addEventListener('click', e => { if (!$('hamburger-wrap').contains(e.target)) closeTopMenu(); });
$('menu-history').addEventListener('click', () => { closeTopMenu(); openHistory(); });
$('menu-settings').addEventListener('click', () => { closeTopMenu(); openModal(); });
$('menu-help').addEventListener('click', () => { closeTopMenu(); openHelp(); });
$('history-clear').addEventListener('click', () => { saveHistory([]); renderHistory(); });

// ── Modal ──────────────────────────────────────────────────────────────────
function openModal() {
  ['vt','shodan','ipinfo','proxycheck'].forEach(n => {
    const inp = $('k-' + n);
    inp.value = getKey(n); inp.type = 'password';
    inp.classList.toggle('has-value', !!inp.value);
  });
  $('modal-overlay').classList.add('open');
  setTimeout(() => $('k-vt').focus(), 50);
}
function closeModal() { $('modal-overlay').classList.remove('open'); }
$('settings-btn').addEventListener('click', openModal);
$('modal-cancel').addEventListener('click', closeModal);
$('modal-overlay').addEventListener('click', e => { if (e.target === $('modal-overlay')) closeModal(); });
$('modal-save').addEventListener('click', () => {
  ['vt','shodan','ipinfo','proxycheck'].forEach(n => setKey(n, $('k-' + n).value.trim()));
  refreshPills(); closeModal();
});
$('modal-clear-all').addEventListener('click', () => {
  ['vt','shodan','ipinfo','proxycheck'].forEach(n => { setKey(n,''); $('k-'+n).value=''; $('k-'+n).classList.remove('has-value'); });
  refreshPills();
});
document.querySelectorAll('.eye-btn').forEach(btn => {
  btn.addEventListener('click', () => { const i = $(btn.dataset.target); i.type = i.type==='password'?'text':'password'; });
});

// ── Helpers ────────────────────────────────────────────────────────────────
function setStatus(msg, type='') { $('sdot').className='status-dot '+type; $('stext').textContent=msg; }
function setLoading(on) { $('lookup-btn').disabled=$('my-ip-btn').disabled=on; $('lookup-btn').classList.toggle('btn-loading',on); }
function esc(s) { return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function v(x,fb='—') { return (x===null||x===undefined||x===''||x==='null'||x===false)?fb:esc(String(x)); }
function kv(k,val,cls='') { return `<div class="kv"><span class="kv-key">${k}</span><span class="kv-val ${cls}">${val}</span></div>`; }
function cardHead(icon,title) { return `<div class="card-header"><span>${icon}</span>${title}</div>`; }
function tag(txt,col='gray') { return `<span class="tag tag-${col}">${txt}</span>`; }
function flagEl(label,active) { return `<div class="flag-item ${active?'on':'off'}"><div class="flag-dot"></div>${label}</div>`; }
function fmtDate(d) { if(!d) return '—'; try { return new Date(d).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}); } catch { return d; } }

// ── Share / URL ────────────────────────────────────────────────────────────
function updateUrl(ip) {
  const u = new URL(window.location.href);
  u.searchParams.set('scan', ip);
  window.history.replaceState({}, '', u.toString());
  $('share-url').textContent = u.toString();
  $('share-bar').classList.add('visible');
}
$('fresh-scan-btn').addEventListener('click', () => lookup($('ip-input').value.trim(), true));

$('share-copy').addEventListener('click', () => {
  navigator.clipboard.writeText($('share-url').textContent).then(() => {
    $('share-copy').textContent='Copied!'; $('share-copy').classList.add('copied');
    setTimeout(()=>{ $('share-copy').textContent='Copy'; $('share-copy').classList.remove('copied'); }, 2000);
  });
});

// ── Main lookup ────────────────────────────────────────────────────────────
function timeSince(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60)   return `${s}s`;
  if (s < 3600) return `${Math.floor(s/60)}m`;
  return `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m`;
}

async function lookup(ip, fresh = false) {
  ip = ip.trim();
  if (!ip) { $('ip-input').focus(); return; }
  $('ip-input').value = ip;
  setLoading(true);
  $('results').classList.remove('visible');
  $('empty').style.display = 'none';
  $('cache-bar').classList.remove('visible');
  document.title = 'IP Scanner';
  $('sources').style.display = 'none';
  $('raw-box').style.display = 'none';
  $('raw-toggle').childNodes[0].textContent = '▶ show raw API data'; $('raw-copy')?.classList.remove('visible');
  // Reset AI panel
  $('ai-result').classList.remove('visible');
  $('ai-btn-label').textContent = 'Analyse with Gemini AI';
  $('ai-btn-icon').textContent = '✨';
  $('ai-btn').disabled = false;
  $('ai-shortcut').classList.remove('visible');
  lastScanData = null;
  setStatus(fresh ? `Re-scanning ${ip} (bypassing cache)…` : `Scanning ${ip}…`, 'loading');
  document.title = 'IP Scanner — ' + ip;
  updateUrl(ip);

  const headers = { 'X-IP': ip, 'X-No-Cache': String(Date.now()) };
  if (getKey('vt'))         headers['X-VT-Key']         = getKey('vt');
  if (getKey('shodan'))     headers['X-Shodan-Key']      = getKey('shodan');
  if (getKey('ipinfo'))     headers['X-Ipinfo-Token']    = getKey('ipinfo');
  if (getKey('proxycheck')) headers['X-Proxycheck-Key']  = getKey('proxycheck');

  let data;
  try {
    const freshParam = fresh ? '&fresh=1' : '';
    const r = await fetch(`${WORKER_BASE}/lookup?ip=${encodeURIComponent(ip)}&_=${Date.now()}${freshParam}`, { method:'GET', headers, cache:'no-store' });
    if (!r.ok) { const e = await r.json().catch(()=>({error:'Unknown error'})); throw new Error(e.error || `HTTP ${r.status}`); }
    data = await r.json();
  } catch (e) {
    setStatus(`Error: ${e.message}`, 'error');
    setLoading(false);
    $('empty').style.display='block';
    $('empty').querySelector('.empty-icon').textContent='⚠️';
    $('empty').querySelector('.empty-text').textContent=e.message;
    return;
  }

  if (data._cached && data._cachedAt) {
    $('cache-bar-text').textContent = `Cached result · scanned ${timeSince(data._cachedAt)} ago`;
    $('cache-bar').classList.add('visible');
  }

  const { sources, resolvedFrom, resolvedIpv4, resolvedIpv6, isDomain, isTorConfirmed, torListSize, workerColo, workerCountry } = data;
  const ipapi  = sources.ipapi      || {};
  const ipinfo = sources.ipinfo     || {};
  const pcRaw  = sources.proxycheck || {};
  const vtData = sources.virustotal;
  const ipapis = sources.ipapis     || {};
  const whois      = sources.whois      || null;
  const vtDomain   = sources.vtDomain   || null;
  const domainWhois= sources.domainWhois|| null;
  const shodan = sources.shodan     || null;
  const dnsbl  = sources.dnsbl      || null;
  const pc     = pcRaw[data.ip]     || {};

  try {
  const resolvedIp  = v(data.ip || ipapi.query || ipinfo.ip || ip);
  const country     = v(ipapi.country     || ipinfo.country);
  const countryCode = v(ipapi.countryCode || '').toLowerCase();
  const region      = v(ipapi.regionName  || ipinfo.region);
  const city        = v(ipapi.city        || ipinfo.city);
  const lat         = v(ipapi.lat);
  const lon         = v(ipapi.lon);
  const timezone    = v(ipapi.timezone    || ipinfo.timezone);
  const isp         = v(ipapi.isp         || pc.provider);
  const org         = v(ipapi.org         || ipinfo.org);
  const asnNum      = v(ipapi.as?.split(' ')[0] || pc.asn || ipinfo.org?.split(' ')[0]);
  const asnOrg      = v(pc.organisation   || ipapi.as || ipinfo.org);
  const rdns        = v(ipapi.reverse     || pc.hostname || ipinfo.hostname);
  const ipVer       = resolvedIp.includes(':') ? 'IPv6' : 'IPv4';
  const postal      = v(ipapi.zip         || ipinfo.postal);
  const pcType      = v(pc.type, '');
  const pcrisk      = parseInt(pc.risk ?? 0) || 0;

  const pcLow      = pcType.toLowerCase();
  const isTor      = isTorConfirmed || pcLow.includes('tor') || (ipapis?.security?.tor===true);
  const isVpn      = !isTor && (pcLow.includes('vpn') || (ipapi.proxy===true && !pcLow.includes('proxy')));
  const isProxy    = !isTor && !isVpn && (pcLow.includes('proxy') || pcType==='PBL' || pcType==='CBL' || ipapi.proxy===true);
  const isHosting  = ipapi.hosting===true || pcType==='DCH' || pcLow.includes('hosting');
  const isMobile   = ipapi.mobile===true;
  const isRelay    = pcLow.includes('relay');
  const isSatellite= pcLow.includes('satellite');
  const isAnon     = isVpn || isTor || isProxy;
  const isBogon    = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$|fc|fd)/i.test(resolvedIp);

  const vtStats    = vtData?.data?.attributes?.last_analysis_stats || {};
  const vtMalCount = (vtStats.malicious||0) + (vtStats.suspicious||0);
  const dnsblCount = dnsbl?.listed || 0;

  // ── Risk scoring — weighted additive model ──────────────────────────────
  let riskScore = 0;

  if (pcrisk >= 75)      riskScore += 25;
  else if (pcrisk >= 50) riskScore += 15;
  else if (pcrisk >= 25) riskScore += 8;

  if (isTor) {
    riskScore += 60;
  }

  if (vtMalCount > 0 && (vtStats.harmless + vtStats.undetected + vtMalCount) > 0) {
    const vtTotal2 = (vtStats.malicious||0)+(vtStats.suspicious||0)+(vtStats.harmless||0)+(vtStats.undetected||0);
    if (vtMalCount >= 10)      riskScore += 40;
    else if (vtMalCount >= 5)  riskScore += 28;
    else if (vtMalCount >= 2)  riskScore += 18;
    else                       riskScore += 8;
  }

  const dnsblLists   = dnsbl?.lists || [];
  const aggressiveDnsbl = ['UCEPROTECT L2','UCEPROTECT L3'];
  const seriousHits  = dnsblLists.filter(l => l.listed && !aggressiveDnsbl.includes(l.name)).length;
  const aggressiveHits = dnsblLists.filter(l => l.listed && aggressiveDnsbl.includes(l.name)).length;
  riskScore += seriousHits   * 18;
  riskScore += aggressiveHits * 6;

  if (isVpn)          riskScore += 10;
  if (isProxy)        riskScore += 15;
  if (isHosting)      riskScore += 4;

  const badSignals = (isTor?1:0) + (isVpn?1:0) + (isProxy?1:0) +
                     (vtMalCount>0?1:0) + (seriousHits>0?1:0) + (pcrisk>=50?1:0);
  if (badSignals >= 3) riskScore = Math.round(riskScore * 1.2);
  if (badSignals >= 4) riskScore = Math.round(riskScore * 1.15);

  const vtTotalEngines = (vtStats.malicious||0)+(vtStats.suspicious||0)+(vtStats.harmless||0)+(vtStats.undetected||0);
  if (vtMalCount === 0 && vtTotalEngines > 20) riskScore -= 5;
  if (dnsblCount === 0 && (dnsbl?.checked||0) > 10)                riskScore -= 5;
  if (pcrisk === 0)                                                 riskScore -= 3;

  riskScore = Math.max(0, Math.min(100, riskScore));

  const level  = (isTor || riskScore >= 65) ? 'dangerous'
               : (riskScore >= 25 || (isVpn && vtMalCount > 0) || seriousHits > 0) ? 'suspicious'
               : (isVpn || isProxy || riskScore >= 12) ? 'caution'
               : 'clean';
  const emoji  = isTor?'🧅':level==='dangerous'?'🚨':level==='suspicious'?'⚠️':level==='caution'?'🔔':'✅';
  const tTitle = isTor?'Tor Exit Node Detected':level==='dangerous'?'High-Risk IP':level==='suspicious'?'Suspicious — Multiple Threat Indicators':level==='caution'?'Low Concern — Privacy Tool Detected':'Clean — No Threats Found';
  const tSub   = isTor?'Confirmed Tor network exit node'
               : dnsblCount>0?`Listed on ${dnsblCount} blacklist${dnsblCount>1?'s':''}`
               : vtMalCount>0?`Flagged by ${vtMalCount} VirusTotal engine${vtMalCount>1?'s':''}`
               : isVpn?'VPN provider detected'
               : isProxy?'Proxy / anonymiser'
               : isHosting?'Data centre / hosting ASN'
               : 'No known threat indicators';
  const scoreColor = riskScore>=65?'var(--red)':riskScore>=25?'var(--amber)':riskScore>=12?'#f59e0b':'var(--green)';

    $('threat-banner').innerHTML = `
      <div class="threat-banner ${level}">
        <div class="threat-icon">${emoji}</div>
        <div style="flex:1;min-width:0">
          <div class="threat-title">${tTitle}</div>
          <div class="threat-sub">${tSub}</div>
        </div>
        <div style="text-align:right;flex-shrink:0">
          <div class="threat-score" style="color:${scoreColor}">${riskScore}</div>
          <div class="score-label">Risk / 100</div>
        </div>
      </div>`;

    const safeCode = /^[a-z]{2}$/.test(countryCode) ? countryCode : '';
    const flagImg = safeCode ? `<img src="https://flagcdn.com/16x12/${safeCode}.png" width="16" height="12" style="border-radius:2px;vertical-align:middle;margin-right:5px" alt="">` : '';

    // Basic info
    $('c-basic').innerHTML = cardHead('🌐','Basic Info') + [
      resolvedFrom ? kv('Domain', `<span style="color:var(--accent);font-weight:600">${esc(resolvedFrom)}</span>`) : '',
      kv('IP Address', `<span style="color:var(--accent);font-weight:600">${esc(resolvedIp)}</span>`),
      resolvedIpv4 && resolvedIpv6 ? kv('IPv4', `<span style="color:var(--accent)">${esc(resolvedIpv4)}</span>`) : '',
      resolvedIpv4 && resolvedIpv6 ? kv('IPv6', `<span style="color:var(--accent)">${esc(resolvedIpv6)}</span>`) : '',
      resolvedFrom ? kv('DNS Resolved', tag('Yes','green')) : '',
      kv('Version', ipVer),
      kv('Reverse DNS', rdns),
      kv('Bogon / Private', isBogon ? tag('Yes','amber') : tag('No — Public','green')),
      kv('Continent', v(ipapi.continent)),
    ].join('');

    // Geo
    $('c-geo').innerHTML = cardHead('📍','Geolocation') + [
      kv('Country', flagImg + country),
      kv('Region', region),
      kv('City', city),
      kv('Coordinates', (lat!=='—'&&lon!=='—')?`${lat}, ${lon}`:'—'),
      kv('Timezone', timezone),
      kv('Postal Code', postal),
    ].join('');

    // ASN
    $('c-asn').innerHTML = cardHead('🔌','Network / ASN') + [
      kv('ASN', asnNum, 'accent'),
      kv('ASN Org', asnOrg),
      kv('ISP', isp),
      kv('Organisation', org),
      kv('Open Port', v(pc.port)),
    ].join('');

    // Abuse / risk
    $('c-abuse').innerHTML = cardHead('🛡️','Abuse / Risk') + [
      kv('Risk Score', `<span style="color:${scoreColor};font-weight:600">${riskScore} / 100</span>`),
      `<div class="risk-bar"><div class="risk-fill" style="width:${riskScore}%;background:${scoreColor}"></div></div>`,
      kv('Level', tag(riskScore>=65?'High':riskScore>=25?'Medium':riskScore>=12?'Low':'Clean', riskScore>=65?'red':riskScore>=25?'amber':riskScore>=12?'amber':'green')),
      kv('Proxy Type', pcType||'—'),
      kv('Last Seen', v(pc.seen)),
      kv('Blacklists', dnsblCount>0 ? tag(`${dnsblCount} listed`,'red') : (dnsbl ? tag('Clean','green') : tag('Checking…','gray'))),
      kv('Tor List', isTorConfirmed ? tag('⚠ Confirmed','red') : torListSize>0 ? tag(`Clean / ${torListSize.toLocaleString()} nodes`,'green') : tag('Unavailable','gray')),
    ].join('');

    // Flags
    $('c-flags').innerHTML = cardHead('🚩','Privacy & Threat Flags') + `
      <div class="flags-grid">
        ${flagEl('VPN', isVpn)}
        ${flagEl('Proxy', isProxy)}
        ${flagEl('Tor Exit Node', isTor)}
        ${flagEl('Data Centre / Hosting', isHosting)}
        ${flagEl('Anonymous / Masked', isAnon)}
        ${flagEl('Mobile Network', isMobile)}
        ${flagEl('Relay', isRelay)}
        ${flagEl('Satellite ISP', isSatellite)}
        ${flagEl('Bogon / Private', isBogon)}
        ${flagEl('VT Malicious', vtMalCount>0)}
        ${flagEl('DNSBL Listed', dnsblCount>0)}
      </div>`;

    // WHOIS
    try { renderWhoisCards(whois); } catch(e) { console.error('WHOIS render error:', e); }

    // Shodan
    try { renderShodanCard(shodan); } catch(e) { console.error('Shodan render error:', e); }

    // DNSBL
    try { renderDnsblCard(dnsbl, resolvedIp); } catch(e) { console.error('DNSBL render error:', e); }

    // VT
    try { renderVtCard(vtData, resolvedIp); } catch(e) { console.error('VT render error:', e); }

    // Domain-specific sections
    if (isDomain) {
      $('domain-sections').style.display = 'block';
      try { renderDomainWhoisCard(domainWhois, resolvedFrom); } catch(e) { console.error('Domain WHOIS render error:', e); }
      try { renderDomainVtCard(vtDomain, resolvedFrom); } catch(e) { console.error('Domain VT render error:', e); }
    } else {
      $('domain-sections').style.display = 'none';
    }

    try { $('raw-box').textContent = JSON.stringify(data, null, 2); } catch(e) { $('raw-box').textContent = 'Could not serialise: ' + e.message; }

    $('results').classList.add('visible');
    $('sources').style.display = 'block';
    const resolveNote = resolvedFrom ? ' (' + resolvedFrom + ' → ' + data.ip + ')' : '';
    setStatus('Scan complete' + resolveNote, 'success');
    document.title = 'IP Scanner — ' + (resolvedFrom || data.ip);
    lastScanData = data;
    $('ai-shortcut').classList.add('visible');

    addToHistory({
      ip: data.ip, resolvedFrom, timestamp: Date.now(),
      country:   typeof country   !== 'undefined' ? country   : '',
      city:      typeof city      !== 'undefined' ? city      : '',
      riskScore: typeof riskScore !== 'undefined' ? riskScore : 0,
      isTor:     typeof isTor     !== 'undefined' ? isTor     : false,
    });

  } catch(e) {
    console.error('Render error:', e);
  } finally {
    setLoading(false);
  }
}

// ── WHOIS cards renderer ───────────────────────────────────────────────────
function renderWhoisCards(whois) {
  if (!whois) {
    $('c-whois').innerHTML  = cardHead('📋','WHOIS / RDAP') + `<div style="color:var(--text-faint);font-size:.78rem;padding:.5rem 0">No WHOIS data returned.</div>`;
    $('c-whois2').innerHTML = cardHead('📋','Registration') + `<div style="color:var(--text-faint);font-size:.78rem;padding:.5rem 0">—</div>`;
    return;
  }
  $('c-whois').innerHTML = cardHead('📋',`WHOIS · ${whois.registry||''}`) + [
    kv('Handle', v(whois.handle)),
    kv('Name', v(whois.name)),
    kv('Network', v(whois.network)),
    kv('IP Range', whois.startAddress&&whois.endAddress?`${whois.startAddress} – ${whois.endAddress}`:'—'),
    kv('Country', v(whois.country)),
    kv('Type', v(whois.type)),
  ].join('');
  $('c-whois2').innerHTML = cardHead('📋','Registration') + [
    kv('Registrant', v(whois.registrant)),
    kv('Abuse Contact', v(whois.abuseContact)),
    kv('Tech Contact', v(whois.techContact)),
    kv('Registered', fmtDate(whois.registered)),
    kv('Last Changed', fmtDate(whois.lastChanged)),
    whois.remarks ? kv('Remarks', `<span style="font-size:.67rem">${whois.remarks.substring(0,80)}${whois.remarks.length>80?'…':''}</span>`) : '',
  ].join('');
}

// ── Shodan card renderer ───────────────────────────────────────────────────
function renderShodanCard(shodan) {
  const card = $('c-shodan');
  if (!shodan || shodan.error) {
    const msg = shodan?.error==='invalid_key'  ? 'Invalid Shodan API key — check your key in ⚙ Manage.'
              : shodan?.status===403           ? 'Shodan API key does not have access to this endpoint. A paid Shodan plan is required for host lookups.'
              : shodan?.error==='not_found'    ? 'This IP has no Shodan data (not yet scanned by Shodan).'
              : shodan?.error==='rate_limit'   ? 'Shodan rate limit hit.'
              : shodan?.error==='api_error'    ? 'Shodan API error (status ' + (shodan.status||'?') + '). A paid Shodan plan may be required.'
              : 'Shodan returned no data.';
    card.innerHTML = cardHead('🔭','Shodan') + '<div class="vt-locked"><div class="vt-locked-icon">📭</div><div class="vt-locked-text">' + msg + '</div></div>';
    return;
  }

  const vulnList = shodan.vulns.length
    ? shodan.vulns.slice(0,10).map(v => `<span class="shodan-vuln"><a href="https://nvd.nist.gov/vuln/detail/${v}" target="_blank" style="color:inherit">${v}</a></span>`).join('')
    : '';

  const services = (shodan.services || []).map(s =>
    `<div class="shodan-svc">
      <div class="shodan-port">${s.port}/${s.transport||'tcp'}</div>
      <div class="shodan-info">
        <div class="product">${v(s.product,'Unknown service')}${s.version?' '+esc(s.version):''}</div>
        ${s.banner?`<div class="banner">${esc(s.banner)}</div>`:''}
      </div>
    </div>`
  ).join('');

  card.innerHTML = cardHead('🔭',`Shodan · ${shodan.ports.length} open port${shodan.ports.length!==1?'s':''}`) + `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin-bottom:.75rem">
      ${kv('Organisation', v(shodan.org))}
      ${kv('ISP', v(shodan.isp))}
      ${kv('ASN', v(shodan.asn))}
      ${kv('OS', v(shodan.os))}
      ${kv('Last Scan', fmtDate(shodan.lastUpdate))}
      ${kv('Open Ports', shodan.ports.slice(0,12).join(', ')+(shodan.ports.length>12?'…':'') || '—')}
      ${shodan.hostnames.length ? kv('Hostnames', shodan.hostnames.slice(0,3).join(', ')) : ''}
      ${shodan.tags.length ? kv('Tags', shodan.tags.map(t=>`<span class="tag tag-blue">${t}</span>`).join(' ')) : ''}
    </div>
    ${vulnList ? `<div style="margin-bottom:.75rem"><div class="vt-label">CVEs / Vulnerabilities</div>${vulnList}</div>` : ''}
    ${services ? `<div class="vt-label">Services & Banners</div><div class="shodan-services">${services}</div>` : ''}
    <div style="margin-top:.75rem;font-size:.67rem;color:var(--text-faint)">
      <a href="https://www.shodan.io/host/${shodan.ip}" target="_blank" style="color:var(--accent)">View full report on Shodan ↗</a>
    </div>`;
}

// ── DNSBL card renderer ────────────────────────────────────────────────────
function renderDnsblCard(dnsbl, ip) {
  const card = $('c-dnsbl');
  if (!dnsbl) {
    card.innerHTML = cardHead('📋','Blacklist / DNSBL Check') + `<div style="color:var(--text-faint);font-size:.78rem;padding:.5rem 0">DNSBL check unavailable (IPv6 not supported).</div>`;
    return;
  }
  if (dnsbl.ipv6) {
    card.innerHTML = cardHead('📋','Blacklist / DNSBL Check') + `<div style="color:var(--text-faint);font-size:.78rem;padding:.5rem 0">DNSBL checks are IPv4 only.</div>`;
    return;
  }

  const listed  = dnsbl.lists.filter(l => l.listed);
  const clean   = dnsbl.lists.filter(l => !l.listed && !l.error);
  const errored = dnsbl.lists.filter(l => l.error);
  const scoreColor = listed.length>3?'var(--red)':listed.length>0?'var(--amber)':'var(--green)';

  const totalLists = dnsbl.total || dnsbl.lists.length;
  card.innerHTML = cardHead('📋',`Blacklist / DNSBL — ${totalLists} lists checked`) + `
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:.85rem">
      <div class="vt-stat ${listed.length?'mal':'cln'}"><strong>${listed.length}</strong>Listed</div>
      <div class="vt-stat cln"><strong>${clean.length}</strong>Clean</div>
      <div class="vt-stat und"><strong>${errored.length}</strong>Unavailable</div>
      <div class="vt-stat und"><strong>${totalLists}</strong>Total</div>
    </div>
    ${listed.length ? `
      <div class="vt-label" style="color:var(--red)">⚠ Listed on ${listed.length} blacklist${listed.length>1?'s':''}</div>
      <div class="dnsbl-grid">
        ${listed.map(l=>`<div class="dnsbl-item listed"><div class="dnsbl-dot"></div><span>${l.name}</span><span style="margin-left:auto;font-size:.6rem;opacity:.75">${l.codeDesc||l.returnCode||''}</span></div>`).join('')}
      </div>
      <div class="vt-label" style="margin-top:.85rem">Clean lists</div>` : `<div class="vt-label" style="color:var(--green)">✓ Not listed on any checked blacklist</div>`}
    <div class="dnsbl-grid">
      ${clean.map(l=>`<div class="dnsbl-item clean"><div class="dnsbl-dot"></div>${l.name}</div>`).join('')}
    </div>
    ${errored.length ? `
      <div class="vt-label" style="margin-top:.85rem">Unavailable / errored</div>
      <div class="dnsbl-grid">
        ${errored.map(l=>`<div class="dnsbl-item error" title="${l.errorCode?'Blocked — requires dedicated DNS resolver':l.timeout?'Timeout':'Query failed'}"><div class="dnsbl-dot"></div>${l.name}${l.timeout?' (timeout)':''}</div>`).join('')}
      </div>
      <div style="margin-top:.5rem;font-size:.67rem;color:var(--text-faint);font-family:'JetBrains Mono',monospace">Some lists block public DNS resolvers (Cloudflare DoH) or were unreachable. Their results are excluded from the count.</div>` : ''}`;
}

// ── VT card renderer ───────────────────────────────────────────────────────
function renderVtCard(vtData, ip) {
  const card = $('c-vt');
  if (!vtData || vtData.error) {
    const msg = vtData?.error==='invalid_key'?'Invalid API key.':vtData?.error==='rate_limit'?'Rate limit (4/min on free tier).':'No VT data.';
    card.innerHTML = cardHead('🦠','VirusTotal Scan') + `<div class="vt-locked"><div class="vt-locked-icon">⚠️</div><div class="vt-locked-text">${msg}</div></div>`;
    return;
  }
  const attr  = vtData?.data?.attributes || {};
  const stats = attr?.last_analysis_stats || {};
  const engines = attr?.last_analysis_results || {};
  const malCount = stats.malicious||0, susCount=stats.suspicious||0;
  const clnCount = (stats.undetected||0)+(stats.harmless||0);
  const total    = malCount+susCount+clnCount+(stats.timeout||0);
  const sc = malCount>5?'var(--red)':malCount>0?'var(--amber)':'var(--green)';
  const lastDate = attr.last_analysis_date ? new Date(attr.last_analysis_date*1000).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}) : '—';
  const entries  = Object.entries(engines);
  const flagged  = entries.filter(([,r])=>r.category==='malicious'||r.category==='suspicious');
  const clean    = entries.filter(([,r])=>r.category==='undetected'||r.category==='harmless').slice(0,8);
  const eng = ([name,res]) => {
    const bad = res.category==='malicious'||res.category==='suspicious';
    return `<div class="vt-engine ${bad?'malicious':'clean'}"><div class="vt-engine-dot"></div><span class="vt-engine-name">${esc(name)}</span><span class="vt-engine-result">${esc(res.result||res.category)}</span></div>`;
  };
  card.innerHTML = cardHead('🦠',`VirusTotal — ${total} engines`) + `
    <div class="vt-summary-row">
      <div class="vt-stat mal"><strong>${malCount}</strong>Malicious</div>
      <div class="vt-stat sus"><strong>${susCount}</strong>Suspicious</div>
      <div class="vt-stat cln"><strong>${clnCount}</strong>Clean</div>
      <div class="vt-stat und"><strong>${total}</strong>Total</div>
    </div>
    ${[kv('Reputation',`<span style="color:${attr.reputation<0?'var(--red)':'var(--green)'}">${v(attr.reputation)}</span>`),kv('Last Analysis',lastDate),kv('Network',v(attr.network)),kv('AS Owner',v(attr.as_owner)),kv('Country',v(attr.country))].join('')}
    ${flagged.length?`<div class="vt-label">Flagged by ${flagged.length} engine${flagged.length>1?'s':''}</div><div class="vt-engines-grid">${flagged.map(eng).join('')}</div>`:''}
    ${clean.length?`<div class="vt-label">Sample clean engines</div><div class="vt-engines-grid">${clean.map(eng).join('')}</div>`:''}
    <div style="margin-top:.75rem;font-size:.67rem;color:var(--text-faint)">
      <a href="https://www.virustotal.com/gui/ip-address/${ip}" target="_blank" style="color:var(--accent)">Full report on VirusTotal ↗</a>
    </div>`;
}

// ── My IP ──────────────────────────────────────────────────────────────────
$('my-ip-btn').addEventListener('click', async () => {
  const btn = $('my-ip-btn');
  btn.disabled=true; btn.textContent='…';
  setStatus('Detecting your IP via Cloudflare…','loading');
  try {
    const r = await fetch(`${WORKER_BASE}/myip?_=${Date.now()}`, { cache:'no-store' });
    const d = await r.json();
    if (d.ip && d.ip!=='unknown') { $('ip-input').value=d.ip; lookup(d.ip); }
    else setStatus('Could not detect IP.','error');
  } catch { setStatus('Worker unreachable.','error'); }
  btn.textContent='My IP'; btn.disabled=false;
});

$('lookup-btn').addEventListener('click', () => lookup($('ip-input').value));
$('ip-input').addEventListener('keydown', e => { if(e.key==='Enter') lookup($('ip-input').value); });

// ── Domain card renderers ─────────────────────────────────────────────────────
function renderDomainWhoisCard(dw, domain) {
  const card = $('c-domain-whois');
  if (!card) return;
  if (!dw) {
    card.innerHTML = cardHead('🌐', 'Domain WHOIS') +
      '<div style="color:var(--text-faint);font-size:.78rem;padding:.5rem 0">No domain WHOIS data available.</div>';
    return;
  }
  let ageStr = '—';
  if (dw.registered) {
    const days = Math.floor((Date.now() - new Date(dw.registered)) / 86400000);
    ageStr = days > 365 ? Math.floor(days/365) + ' yr' + (Math.floor(days/365)>1?'s':'') : days + ' days';
  }
  const nsStr = dw.nameservers?.slice(0,3).join(', ') || '—';
  card.innerHTML = cardHead('🌐', 'Domain WHOIS') + [
    kv('Domain',      v(dw.domain || domain)),
    kv('Registrar',   v(dw.registrar)),
    kv('Registered',  fmtDate(dw.registered)),
    kv('Domain Age',  ageStr),
    kv('Expires',     fmtDate(dw.expiry)),
    kv('Updated',     fmtDate(dw.updated)),
    kv('Status',      v(dw.status)),
    kv('Nameservers', nsStr),
    dw.abuseEmail ? kv('Abuse Email', v(dw.abuseEmail)) : '',
  ].join('');
}

function renderDomainVtCard(vt, domain) {
  const card = $('c-domain-vt');
  if (!card) return;
  if (!vt || vt.error) {
    const msg = vt?.error === 'not_found'   ? 'Domain not yet in VirusTotal database.'
              : vt?.error === 'invalid_key' ? 'Invalid VT API key.'
              : vt?.error === 'rate_limit'  ? 'Rate limit hit.'
              : 'No VT domain data.';
    card.innerHTML = cardHead('🦠', 'Domain VirusTotal') +
      '<div class="vt-locked"><div class="vt-locked-icon">📭</div><div class="vt-locked-text">' + msg + '</div></div>';
    return;
  }

  try {
    const total    = (vt.malicious||0)+(vt.suspicious||0)+(vt.harmless||0)+(vt.undetected||0);
    const cats     = Object.values(vt.categories||{}).slice(0,3).join(', ') || '—';
    const ranks    = Object.entries(vt.popularityRanks||{}).slice(0,2).map(function(e){return e[0]+':#'+e[1].rank;}).join(', ') || '—';

    let certValid = '—';
    try {
      const vto = vt.lastHttpsCert?.validTo;
      if (vto) {
        const d = typeof vto === 'number' ? new Date(vto * 1000) : new Date(vto);
        if (!isNaN(d.getTime())) certValid = fmtDate(d.toISOString());
      }
    } catch(e) { certValid = '—'; }

    const repColor = (vt.reputation||0) < 0 ? 'var(--red)' : 'var(--green)';

    let html = cardHead('🦠', 'Domain VT — ' + total + ' engines');
    html += '<div class="vt-summary-row">';
    html += '<div class="vt-stat ' + (vt.malicious ? 'mal' : 'cln') + '"><strong>' + (vt.malicious||0) + '</strong>Malicious</div>';
    html += '<div class="vt-stat ' + (vt.suspicious ? 'sus' : 'cln') + '"><strong>' + (vt.suspicious||0) + '</strong>Suspicious</div>';
    html += '<div class="vt-stat cln"><strong>' + ((vt.harmless||0)+(vt.undetected||0)) + '</strong>Clean</div>';
    html += '</div>';
    html += kv('Reputation', '<span style="color:' + repColor + '">' + v(vt.reputation) + '</span>');
    html += kv('Registrar', v(vt.registrar));
    html += kv('Categories', cats);
    html += kv('Popularity', ranks);
    html += kv('SSL Issuer', v(vt.lastHttpsCert?.issuer));
    html += kv('SSL Expires', certValid);
    if (vt.tags && vt.tags.length) {
      html += kv('Tags', vt.tags.slice(0,4).map(function(t){return '<span class="tag tag-gray">'+t+'</span>';}).join(' '));
    }
    html += '<div style="margin-top:.75rem;font-size:.67rem;color:var(--text-faint)">';
    html += '<a href="https://www.virustotal.com/gui/domain/' + domain + '" target="_blank" style="color:var(--accent)">Full domain report on VirusTotal ↗</a>';
    html += '</div>';
    card.innerHTML = html;
  } catch(e) {
    card.innerHTML = cardHead('🦠', 'Domain VirusTotal') +
      '<div class="vt-locked"><div class="vt-locked-icon">⚠️</div><div class="vt-locked-text">Error rendering VT data: ' + e.message + '</div></div>';
  }
}

// ── AI Analysis ───────────────────────────────────────────────────────────────
let lastScanData = null;

// Simple markdown → HTML renderer (handles **bold**, bullet lists, newlines)
function renderMarkdown(text) {
  return '<p>' + text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^[-•]\s+(.+)$/gm, '<li>$1</li>')
    .replace(/(<li>[\s\S]+?<\/li>)/g, '<ul>$1</ul>')
    .replace(/<\/ul>\s*<ul>/g, '')
    .replace(/\n{2,}/g, '</p><p>')
    .replace(/\n/g, '<br>')
    + '</p>';
}

$('ai-shortcut').addEventListener('click', () => {
  $('ai-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
  setTimeout(() => { if (!$('ai-result').classList.contains('visible')) $('ai-btn').click(); }, 400);
});

$('ai-btn').addEventListener('click', async () => {
  if (!lastScanData) return;

  const btn   = $('ai-btn');
  const label = $('ai-btn-label');
  const icon  = $('ai-btn-icon');

  btn.disabled = true;
  icon.innerHTML = '<div class="ai-spinner"></div>';
  label.textContent = 'Analysing…';
  $('ai-result').classList.remove('visible');

  try {
    const d   = lastScanData;
    const src = d.sources || {};
    const ia  = src.ipapi      || {};
    const pc  = (src.proxycheck || {})[d.ip] || {};
    const ii  = src.ipapis     || {};
    const vt  = src.virustotal?.data?.attributes?.last_analysis_stats || {};
    const sh  = src.shodan     || {};
    const wh  = src.whois      || {};
    const bl  = src.dnsbl      || {};
    const pcLow = (pc.type||'').toLowerCase();

    const dw  = src.domainWhois || {};
    const vd  = src.vtDomain    || {};

    const slim = {
      ip:              d.ip,
      resolvedFrom:    d.resolvedFrom || null,
      country:         ia.country     || null,
      city:            ia.city        || null,
      isp:             ia.isp         || pc.provider || null,
      org:             ia.org         || null,
      asn:             ia.as          || pc.asn || null,
      rdns:            ia.reverse     || pc.hostname || null,
      ipType:          pc.type        || null,
      isMobile:        !!ia.mobile,
      isHosting:       !!ia.hosting,
      isProxy:         ia.proxy===true || pcLow.includes('proxy'),
      isVpn:           pcLow.includes('vpn') || !!ii?.security?.vpn,
      isTor:           !!d.isTorConfirmed,
      riskScore:       d.riskScore    || 0,
      pcRisk:          parseInt(pc.risk||0)||0,
      vtMalCount:      (vt.malicious||0)+(vt.suspicious||0),
      vtTotal:         (vt.malicious||0)+(vt.suspicious||0)+(vt.undetected||0)+(vt.harmless||0),
      dnsblListed:     bl.listed  || 0,
      dnsblChecked:    bl.checked || 0,
      dnsblNames:      (bl.lists||[]).filter(l=>l.listed).map(l=>l.name).join(', ')||'none',
      shodanPorts:     (sh.ports||[]).slice(0,10).join(', ')||'none',
      shodanVulns:     (sh.vulns||[]).slice(0,5).join(', ')||'none',
      shodanOS:        sh.os||null,
      whoisRegistrant: wh.registrant   || null,
      whoisAbuse:      wh.abuseContact || null,
      isDomain:        !!d.isDomain,
      resolvedIpv4:    d.resolvedIpv4  || null,
      resolvedIpv6:    d.resolvedIpv6  || null,
      domainRegistrar:      dw.registrar    || null,
      domainRegistrant:     dw.registrant   || null,
      domainRegistered:     dw.registered   || null,
      domainExpiry:         dw.expiry       || null,
      domainStatus:         dw.status       || null,
      domainNameservers:    (dw.nameservers||[]).slice(0,3).join(', ') || null,
      domainAbuseEmail:     dw.abuseEmail   || null,
      vtDomainMalicious:    vd.malicious    || 0,
      vtDomainSuspicious:   vd.suspicious   || 0,
      vtDomainHarmless:     (vd.harmless||0)+(vd.undetected||0),
      vtDomainReputation:   vd.reputation   ?? null,
      vtDomainCategories:   Object.values(vd.categories||{}).slice(0,3).join(', ') || null,
      vtDomainRegistrar:    vd.registrar    || null,
      vtDomainSslIssuer:    vd.lastHttpsCert?.issuer  || null,
      vtDomainSslExpiry:    vd.lastHttpsCert?.validTo || null,
      vtDomainTags:         (vd.tags||[]).slice(0,4).join(', ') || null,
    };

    const r = await fetch(`${WORKER_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-No-Cache': String(Date.now()) },
      body: JSON.stringify(slim),
      cache: 'no-store',
    });

    const result = await r.json();

    if (!r.ok || result.error) {
      const errMsg = result.error || 'Unknown error';
      const isRateLimit = errMsg.toLowerCase().includes('rate limit') || errMsg.toLowerCase().includes('wait');
      $('ai-body').innerHTML = `<div class="ai-error">⚠ ${errMsg}</div>`;
      $('ai-result').classList.add('visible');
      icon.textContent = isRateLimit ? '⏳' : '⚠️';
      label.textContent = isRateLimit ? 'Rate limited — wait 60s and retry' : 'Failed — try again';
      btn.disabled = false;
    } else {
      $('ai-body').innerHTML = renderMarkdown(result.analysis);
      $('ai-model-label').textContent = result.model || 'gemini-3.1-flash-lite';
      $('ai-result').classList.add('visible');
      icon.textContent = '✅';
      label.textContent = 'Re-analyse';
      btn.disabled = false;
    }
  } catch (e) {
    $('ai-body').innerHTML = `<div class="ai-error">⚠ Could not reach worker: ${e.message}</div>`;
    icon.textContent = '⚠️';
    label.textContent = 'Analysis failed — try again';
    btn.disabled = false;
  }
});

// ── Raw data toggle & copy ──────────────────────────────────────────────────
$('raw-toggle').addEventListener('click', () => {
  const open = $('raw-box').style.display === 'block';
  $('raw-box').style.display = open ? 'none' : 'block';
  $('raw-toggle').childNodes[0].textContent = (open ? '▶' : '▼') + ' show raw API data';
  $('raw-copy').classList.toggle('visible', !open);
});
$('raw-copy').addEventListener('click', (e) => {
  e.stopPropagation();
  navigator.clipboard.writeText($('raw-box').textContent).then(() => {
    $('raw-copy').textContent = 'Copied!';
    $('raw-copy').classList.add('copied');
    setTimeout(() => { $('raw-copy').textContent = 'Copy'; $('raw-copy').classList.remove('copied'); }, 2000);
  });
});

// ── Init ───────────────────────────────────────────────────────────────────
refreshPills();
renderHistory();
(function(){
  const ip = new URLSearchParams(window.location.search).get('scan');
  if (ip) { $('ip-input').value=ip; setTimeout(()=>lookup(ip), 300); }
})();
