// MetasBank Geo-Restriction Script
// Blocks access from restricted countries
(function() {
  var BLOCKED = ['NG','IN','GH','CM','GN','SN','ML','BF','NE','TD','SL','LR','GM','GW'];
  var CACHE_KEY = 'mb_geo';
  var CACHE_TTL = 86400000;

  function showBlocked() {
    document.documentElement.innerHTML = '<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Restricted</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:"Segoe UI",Roboto,Arial,sans-serif;background:#0a0a1a;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh}.box{text-align:center;max-width:420px;padding:40px}.icon{width:80px;height:80px;margin:0 auto 24px;border-radius:50%;background:rgba(255,71,87,0.1);border:2px solid rgba(255,71,87,0.3);display:flex;align-items:center;justify-content:center;font-size:36px}.box h1{font-size:20px;font-weight:700;margin-bottom:8px;color:#ff4757}.box p{font-size:13px;color:#8892a5;line-height:1.6}.box .note{margin-top:20px;padding:12px;border-radius:8px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);font-size:11px;color:#555e6e}</style></head><body><div class="box"><div class="icon">&#128683;</div><h1>Access Restricted</h1><p>MetasBank is not available in your region. This service is restricted to authorized jurisdictions only.</p><div class="note">If you believe this is an error, please contact support@metasbank.com</div></div></body>';
  }

  function check(cached) {
    if (cached && cached.ts && (Date.now() - cached.ts < CACHE_TTL)) {
      if (BLOCKED.indexOf(cached.cc) !== -1) showBlocked();
      return true;
    }
    return false;
  }

  var raw = localStorage.getItem(CACHE_KEY);
  var cached = null;
  try { cached = JSON.parse(raw); } catch(e) {}
  if (check(cached)) return;

  fetch('https://ipwho.is/').then(function(r) { return r.json(); }).then(function(d) {
    if (d && d.country_code) {
      var cc = d.country_code.toUpperCase();
      localStorage.setItem(CACHE_KEY, JSON.stringify({ cc: cc, ts: Date.now() }));
      if (BLOCKED.indexOf(cc) !== -1) showBlocked();
    }
  }).catch(function() {});
})();
