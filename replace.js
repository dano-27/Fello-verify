const fs = require('fs');
let content = fs.readFileSync('public/index.html', 'utf8');

// 1. Add Neutral Status CSS
content = content.replace(
  '.check-fail::before { background: var(--danger); }',
  '.check-fail::before { background: var(--danger); }\n    .check-neutral::before { background: #ccc; }\n    .check-neutral .check-status { color: #aaa; }'
);

// 2. Score Card flex-wrap
content = content.replace(
  'gap: 36px;',
  'gap: 36px;\n      flex-wrap: wrap;'
);

// 3. Score Card ID
content = content.replace(
  '<div class="score-card">',
  '<div class="score-card" id="score-card">'
);

// 4. Change grid id
content = content.replace(
  '<div class="checks-grid" id="checks-grid"></div>',
  '<div id="checks-container"></div>'
);

// 5. Update renderChecks
content = content.replace(
  "const grid = document.getElementById('checks-grid');\n    grid.innerHTML = '';",
  `const container = document.getElementById('checks-container');
    container.innerHTML = '';

    const coreSection = document.createElement('div');
    coreSection.innerHTML = '<h3 style="font-family:Montserrat,sans-serif;font-size:14px;font-weight:700;color:var(--black);margin:0 0 12px 4px;letter-spacing:-0.3px;">Core Verification</h3>';
    const coreGrid = document.createElement('div');
    coreGrid.className = 'checks-grid';
    coreSection.appendChild(coreGrid);
    container.appendChild(coreSection);

    const enhancedSection = document.createElement('div');
    enhancedSection.style.marginTop = '16px';
    enhancedSection.innerHTML = '<h3 style="font-family:Montserrat,sans-serif;font-size:14px;font-weight:700;color:var(--muted);margin:0 0 12px 4px;letter-spacing:-0.3px;">🏢 Enhanced Signals <span style="font-weight:400;font-size:11px;color:#aaa;">(bonus only — won\\'t lower score)</span></h3>';
    const enhancedGrid = document.createElement('div');
    enhancedGrid.className = 'checks-grid';
    enhancedSection.appendChild(enhancedGrid);
    container.appendChild(enhancedSection);`
);

// Change grid.appendChild to coreGrid.appendChild for first 6 checks
content = content.replace(/grid\.appendChild\(card\);/g, 'coreGrid.appendChild(card);');
content = content.replace(/grid\.appendChild\(wsCard\);/g, 'coreGrid.appendChild(wsCard);');
content = content.replace(/grid\.appendChild\(whCard\);/g, 'coreGrid.appendChild(whCard);');
content = content.replace(/grid\.appendChild\(gpCard\);/g, 'coreGrid.appendChild(gpCard);');
content = content.replace(/grid\.appendChild\(pvCard\);/g, 'coreGrid.appendChild(pvCard);');
content = content.replace(/grid\.appendChild\(spCard\);/g, 'coreGrid.appendChild(spCard);');
content = content.replace(/grid\.appendChild\(brCard\);/g, 'coreGrid.appendChild(brCard);');

// Change for Tranco, Wiki, SEC
content = content.replace(/grid\.appendChild\(trCard\);/g, 'enhancedGrid.appendChild(trCard);');
content = content.replace(/grid\.appendChild\(wpCard\);/g, 'enhancedGrid.appendChild(wpCard);');
content = content.replace(/grid\.appendChild\(secCard\);/g, 'enhancedGrid.appendChild(secCard);');

// Update Tranco logic
content = content.replace(
  "let trStatus = tr.status === 'found' && tr.isTopSite ? 'pass' : tr.status === 'found' ? 'warn' : 'fail';",
  "let trStatus = tr.status === 'found' && tr.isTopSite ? 'pass' : tr.status === 'found' ? 'warn' : 'neutral';"
);

// Update Wiki logic
content = content.replace(
  "const wpStatus = wp.status === 'found' ? 'pass' : 'fail';",
  "const wpStatus = wp.status === 'found' ? 'pass' : 'neutral';"
);

// Update SEC logic
content = content.replace(
  "const secStatus = sec.status === 'found' && sec.isPublicCompany ? 'pass' : 'fail';",
  "const secStatus = sec.status === 'found' && sec.isPublicCompany ? 'pass' : 'neutral';"
);

// Update statusIcon
content = content.replace(
  "const statusIcon = { pass:'✅', warn:'⚠️', fail:'❌', skipped:'⏭️', error:'💥' };",
  "const statusIcon = { pass:'✅', warn:'⚠️', fail:'❌', skipped:'⏭️', error:'💥', neutral:'<span style=\"color:#aaa;font-size:18px;\">—</span>' };"
);

// Add extractedCompanyName
content = content.replace(
  "document.getElementById('r-time').textContent = 'Verified ' + ago(d.verifiedAt);",
  `if (d.extractedCompanyName) {
      const domainEl = document.getElementById('r-domain');
      if (domainEl) {
        domainEl.innerHTML += \`<div style="font-size:11px;color:var(--primary);margin-top:2px;">🏢 Detected: \${esc(d.extractedCompanyName)}</div>\`;
      }
    }
    document.getElementById('r-time').textContent = 'Verified ' + ago(d.verifiedAt);`
);

// Add Score Breakdown
content = content.replace(
  "if (d.reason) dec.textContent += ' — ' + d.reason;",
  `if (d.reason) dec.textContent += ' — ' + d.reason;

    const oldBd = document.getElementById('score-breakdown');
    if (oldBd) oldBd.remove();

    if (d.scoreBreakdown) {
      const bd = d.scoreBreakdown;
      const categories = [
        { key: 'emailSignals', label: 'Email', icon: '📧' },
        { key: 'infrastructure', label: 'DNS & SSL', icon: '🔧' },
        { key: 'websiteContent', label: 'Website', icon: '🌐' },
        { key: 'domainAge', label: 'Domain Age', icon: '📋' },
        { key: 'companyEnrichment', label: 'Company Data', icon: '🏢' },
        { key: 'googlePlaces', label: 'Google Places', icon: '🗺️' },
        { key: 'phoneValidation', label: 'Phone', icon: '📞' },
        { key: 'onlinePresence', label: 'Online Presence', icon: '🔍' },
        { key: 'webHistory', label: 'Web History', icon: '🕰️' },
        { key: 'enterpriseBonus', label: 'Enterprise Bonus', icon: '⭐' },
      ];
      
      let breakdownHTML = '<div id="score-breakdown" style="flex-basis:100%;margin-top:16px;padding-top:16px;border-top:1px solid var(--border);">';
      breakdownHTML += '<div style="font-size:11px;font-weight:700;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px;">Score Breakdown</div>';
      breakdownHTML += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 16px;">';
      for (const cat of categories) {
        const bdData = bd[cat.key];
        if (!bdData) continue;
        const pct = bdData.max > 0 ? Math.round((bdData.earned / bdData.max) * 100) : 0;
        const barColor = bdData.earned === 0 ? '#eee' : pct >= 70 ? 'var(--success)' : pct >= 40 ? 'var(--warning)' : 'var(--danger)';
        breakdownHTML += \`<div style="display:flex;align-items:center;gap:6px;padding:3px 0;">\`;
        breakdownHTML += \`<span style="font-size:10px;width:14px;">\${cat.icon}</span>\`;
        breakdownHTML += \`<span style="font-size:10px;color:var(--muted);width:85px;white-space:nowrap;overflow:hidden;">\${cat.label}</span>\`;
        breakdownHTML += \`<div style="flex:1;height:4px;background:#eee;border-radius:2px;overflow:hidden;"><div style="height:100%;width:\${pct}%;background:\${barColor};border-radius:2px;"></div></div>\`;
        breakdownHTML += \`<span style="font-size:10px;font-weight:600;color:var(--black);width:30px;text-align:right;">\${bdData.earned}/\${bdData.max}</span>\`;
        breakdownHTML += \`</div>\`;
      }
      breakdownHTML += '</div></div>';
      
      document.getElementById('score-card').insertAdjacentHTML('beforeend', breakdownHTML);
    }`
);

fs.writeFileSync('public/index.html', content);
