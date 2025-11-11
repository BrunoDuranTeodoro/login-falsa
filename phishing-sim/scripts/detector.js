/* scripts/detector.js
   Detecta sinais visuais e técnicos de phishing numa página estática.
   - Executa no submit do form (não envia nada)
   - Salva um relatório em localStorage como "phish_report"
   - Redireciona para explicacao.html onde você lê/mostra o relatório
*/

/* CONFIG: domínios "oficiais" para checagem de typosquatting (adicione os que quiser) */
const KNOWN_DOMAINS = [
  "senai.com.br",
  "senai.br",
  "gmail.com",
  "google.com",
  "microsoft.com",
  "outlook.com"
];

/* UTIL: verifica se string é um IP */
function isIPAddress(host) {
  // IPv4 simples e IPv6 (encurtado)
  const ipv4 = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
  const ipv6 = /^[0-9a-f:]+$/i;
  if (ipv4.test(host)) return true;
  // Um check relaxado IPv6 (muitos navegadores mostram em colchetes ou não)
  if (host.includes(':') && ipv6.test(host.replace(/\[|\]/g, ''))) return true;
  return false;
}

/* UTIL: distância de Levenshtein (para typosquatting simples) */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({length: m+1}, () => new Array(n+1).fill(0));
  for (let i=0;i<=m;i++) dp[i][0]=i;
  for (let j=0;j<=n;j++) dp[0][j]=j;
  for (let i=1;i<=m;i++){
    for (let j=1;j<=n;j++){
      dp[i][j] = Math.min(
        dp[i-1][j]+1,
        dp[i][j-1]+1,
        dp[i-1][j-1] + (a[i-1]===b[j-1] ? 0 : 1)
      );
    }
  }
  return dp[m][n];
}

/* DETECTORS principais */
function detectProtocol() {
  const proto = window.location.protocol; // 'http:' ou 'https:'
  return {
    key: 'protocol',
    value: proto,
    suspicious: proto !== 'https:',
    detail: proto === 'https:' ? 'Conexão via HTTPS (criptografada) — porém verifique o certificado.' :
                                'HTTP detectado — tráfego não criptografado (sinal de risco).'
  };
}

function detectHostname() {
  const host = window.location.hostname; // sem porta
  let suspicious = false;
  const reasons = [];

  if (isIPAddress(host)) {
    suspicious = true;
    reasons.push('Hostname é um endereço IP (URLs oficiais raramente usam IPs para login).');
  }

  if (/^xn--/.test(host)) {
    suspicious = true;
    reasons.push('Punycode detectado (xn--) — possível uso de homograph attacks com caracteres unicode.');
  }

  // subdomínios excessivos
  const parts = host.split('.').filter(Boolean);
  if (parts.length >= 4) {
    suspicious = true;
    reasons.push('Muitos subdomínios (ex.: a.b.c.example.com) — pode ser tentativa de disfarce.');
  }

  // comprimento suspeito
  if (host.length > 40) {
    suspicious = true;
    reasons.push('Hostname muito longo — utilizado às vezes em golpes para confundir.');
  }

  return {
    key: 'hostname',
    value: host,
    suspicious,
    detail: reasons.length ? reasons.join(' ') : 'Hostname aparenta normalidade sintática.'
  };
}

function detectTyposquatting(host) {
  // compara com lista conhecida e retorna possíveis matches com pequenas distâncias
  const candidates = [];
  const plain = host.toLowerCase();
  for (const kd of KNOWN_DOMAINS) {
    const dist = levenshtein(plain, kd);
    // heurística: distância pequena ou domínio contendo nome conhecido com sufixos estranhos
    if (dist > 0 && dist <= 2) {
      candidates.push({domain: kd, distance: dist});
    }
    if (plain.includes(kd) && plain !== kd) {
      candidates.push({domain: kd, distance: 0, note: 'contém domínio oficial como substring'});
    }
  }
  if (candidates.length) {
    return {
      key: 'typosquatting',
      value: candidates,
      suspicious: true,
      detail: 'Possível typosquatting/registro parecido detectado — veja candidatos similares.'
    };
  } else {
    return {
      key: 'typosquatting',
      value: null,
      suspicious: false,
      detail: 'Nenhum typosquatting evidente na lista de verificação base.'
    };
  }
}

function detectFormsAndActions() {
  const forms = Array.from(document.querySelectorAll('form'));
  const results = [];
  forms.forEach((f, idx) => {
    const action = f.getAttribute('action');
    const method = (f.getAttribute('method') || 'GET').toUpperCase();
    const inputs = Array.from(f.querySelectorAll('input, button, textarea')).map(i => i.type || i.tagName.toLowerCase());
    let suspicious = false;
    const reasons = [];

    if (!action) {
      reasons.push('Form sem atributo "action" — em páginas reais isso costuma apontar para endpoints.');
    } else {
      // se action aponta para outro host, é suspeito
      try {
        const aurl = new URL(action, window.location.href);
        if (aurl.hostname !== window.location.hostname) {
          suspicious = true;
          reasons.push(`Form envia para host externo: ${aurl.hostname}`);
        }
        if (aurl.protocol !== 'https:' && aurl.protocol !== '') {
          reasons.push(`Form action usa protocolo não-HTTPS (${aurl.protocol})`);
        }
      } catch(err){
        reasons.push('Form action inválida/relativa (verificar).');
      }
    }

    // se pede cpf, cartão e etc -> risco (só heurística textual)
    const names = inputs.join(' ').toLowerCase();
    if (/cpf|cartao|credit|numero do cartao|senha banc|senha única|pin/.test(names)) {
      suspicious = true;
      reasons.push('Inputs sensíveis detectados (CPF/cartão/senha bancária) — não pedir isso em login comum.');
    }

    results.push({
      formIndex: idx,
      action: action || null,
      method,
      inputTypes: inputs,
      suspicious,
      detail: reasons.length ? reasons.join(' ') : 'Form parece normal (heurística básica).'
    });
  });

  return {
    key: 'forms',
    value: results,
    suspicious: results.some(r => r.suspicious),
    detail: 'Analisados ' + results.length + ' form(s) na página.'
  };
}

function detectLinks() {
  const links = Array.from(document.querySelectorAll('a[href]'));
  const flagged = [];
  links.forEach(a => {
    const href = a.getAttribute('href').trim();
    // não seguir links (unsafe) — só analisar o texto da href
    // heurísticas:
    const isMail = href.startsWith('mailto:');
    const isTel = href.startsWith('tel:');
    const isData = href.startsWith('data:');
    const suspicious = /tinyurl\.com|bit\.ly|goo\.gl|t\.co|tiny\.cc|ow\.ly|is\.gd/.test(href) || /%[0-9A-Fa-f]{2}/.test(href) && href.length>100;
    if (suspicious || isData) {
      flagged.push({href, suspicious: true, reason: isData ? 'Link com data URI (embebido) — suspeito' : 'Encurtador ou link muito ofuscado'});
    }
    // punycode em link
    if (/xn--/.test(href)) flagged.push({href, suspicious:true, reason:'Punycode detectado'});
    // links que apontam pra IPs
    if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(href)) flagged.push({href, suspicious:true, reason:'Link para endereço IP'});
  });

  return {
    key: 'links',
    value: {total: links.length, flagged},
    suspicious: flagged.length > 0,
    detail: `${links.length} link(s) encontrados; ${flagged.length} marcados como potencialmente suspeitos.`
  };
}

function detectExternalAssets() {
  // imagens/scripts apontando pra domínios externos podem ser pistas
  const imgs = Array.from(document.images).map(i => i.src);
  const extern = imgs.filter(src => {
    try {
      const u = new URL(src, window.location.href);
      return u.hostname !== window.location.hostname;
    } catch (e) {
      return false;
    }
  });
  return {
    key: 'assets',
    value: {imagesTotal: imgs.length, external: extern},
    suspicious: extern.length > 0,
    detail: extern.length ? `Imagens/carregamentos externos detectados (${extern.length})` : 'Nenhuma imagem externa detectada.'
  };
}

/* monta o relatório completo */
function buildReport() {
  const proto = detectProtocol();
  const host = detectHostname();
  const typo = detectTyposquatting(host.value);
  const forms = detectFormsAndActions();
  const links = detectLinks();
  const assets = detectExternalAssets();

  const summary = [
    proto, host, typo, forms, links, assets
  ];

  // pontuação simples
  let score = 100;
  summary.forEach(item => { if (item.suspicious) score -= 15; });
  if (score < 0) score = 0;

  return {
    timestamp: new Date().toISOString(),
    url: window.location.href,
    score,
    issues: summary,
    note: 'Relatório gerado localmente para fins educacionais. Nenhum dado sensível foi transmitido para servidor.'
  };
}

/* Função pública para ser chamada no submit do form */
function runDetectorAndRedirect() {
  try {
    const report = buildReport();
    // salva no localStorage (explicacao.html irá ler)
    localStorage.setItem('phish_report', JSON.stringify(report));
    // também salvar um resumo legível pra demo
    localStorage.setItem('phish_report_summary', JSON.stringify({
      timestamp: report.timestamp,
      url: report.url,
      score: report.score
    }));
    // redireciona pra página educativa
    window.location.href = 'explicacao.html';
  } catch (err) {
    console.error('Erro no detector:', err);
    // mesmo se der pau, tenta redirecionar com mínimo de info
    localStorage.setItem('phish_report', JSON.stringify({timestamp:new Date().toISOString(), url:window.location.href, error: String(err)}));
    window.location.href = 'explicacao.html';
  }
}

/* Hook: adiciona listener ao form com id "fake-login" (ou qualquer form se quiser) */
(function attachListener() {
  const f = document.getElementById('fake-login');
  if (f) {
    f.addEventListener('submit', function(e) {
      e.preventDefault();
      // opcional: coleta campos (apenas para demo) MAS NÃO ARMAZENAR SENHAS
      // aqui não salvamos senha; apenas executamos o detector e redirect
      runDetectorAndRedirect();
    });
  } else {
    // se não encontrou o form, deixa uma função global pra testes
    window.runDetectorAndRedirect = runDetectorAndRedirect;
    console.warn('Detector: form "fake-login" não encontrado. Chame runDetectorAndRedirect() manualmente.');
  }
})();
