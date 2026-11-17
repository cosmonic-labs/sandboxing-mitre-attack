//! The single-file branded UI (Cosmonic night mode) served by the `runner`
//! component.
//!
//! Each button calls `/run` on this component, which hands a job to the
//! runner's step interpreter. The page renders the JSON report as it comes
//! back: every row is the runtime's own answer to a real call.

pub const PAGE: &str = r###"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cosmonic Sandbox — Container escape (no socket, no runtime API)</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;600;700;800&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#090D18; --bg2:#0C1120; --panel:#111728; --card:#151D31; --card2:#121A2C;
    --line:#26324B; --line2:#2E3B57;
    --purple:#685BC7; --purple-lt:#8F84E6; --purple-dim:rgba(104,91,199,.16);
    --green:#00C389; --green-dim:rgba(0,195,137,.14); --green-line:rgba(0,195,137,.45);
    --red:#E07A58; --red-dim:rgba(224,122,88,.15); --red-line:rgba(224,122,88,.5);
    --amber:#F5B544;
    --ink:#EAEEF7; --muted:#93A0B8; --faint:#5C6880;
    --mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
    --sans:'Plus Jakarta Sans',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0}
  body{
    background:
      radial-gradient(900px 500px at 82% -8%, rgba(104,91,199,.22), transparent 60%),
      radial-gradient(700px 500px at 0% 0%, rgba(0,195,137,.08), transparent 55%),
      var(--bg);
    color:var(--ink); font-family:var(--sans); line-height:1.55;
    -webkit-font-smoothing:antialiased;
  }
  .wrap{max-width:1100px; margin:0 auto; padding:28px 20px 72px}
  a{color:var(--purple-lt); text-decoration:none} a:hover{text-decoration:underline}

  /* top bar */
  .top{display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:34px}
  .brand{display:flex; align-items:center; gap:11px; font-weight:800; letter-spacing:-.01em; font-size:19px; color:var(--ink)}
  .brand:hover{text-decoration:none; opacity:.9}
  .brand .mark{width:26px;height:26px;border-radius:8px;
    background:linear-gradient(135deg,var(--purple),#4b3fb0);
    display:grid;place-items:center;box-shadow:0 0 0 1px rgba(143,132,230,.5),0 8px 22px rgba(104,91,199,.4)}
  .brand .mark svg{width:15px;height:15px}
  .brand small{font-weight:600;color:var(--muted);font-size:12px;letter-spacing:.14em;text-transform:uppercase;margin-left:2px}
  .legend{display:flex;gap:14px;font-size:12.5px;color:var(--muted);align-items:center;flex-wrap:wrap}
  .legend b{font-weight:600}
  .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:1px}
  .dot.g{background:var(--green)} .dot.d{background:transparent;box-shadow:inset 0 0 0 1.5px var(--faint)} .dot.b{background:var(--red)}

  /* blog callout */
  .callout{display:flex;align-items:center;gap:15px;margin:0 0 28px;padding:15px 18px;border-radius:14px;
    border:1px solid var(--purple);background:linear-gradient(135deg,rgba(104,91,199,.2),rgba(104,91,199,.05));
    box-shadow:0 0 0 1px rgba(143,132,230,.22),0 20px 46px -30px rgba(104,91,199,.95);
    transition:border-color .15s ease, transform .05s ease}
  .callout:hover{text-decoration:none;border-color:var(--purple-lt);transform:translateY(-1px)}
  .callout .flag{flex:none;font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
    color:#fff;background:linear-gradient(135deg,var(--purple),#4b3fb0);padding:6px 11px;border-radius:8px;
    box-shadow:0 8px 20px -10px rgba(104,91,199,.8)}
  .callout .ct{flex:1;min-width:0}
  .callout .ct .h{display:block;color:var(--ink);font-weight:800;font-size:15.5px;letter-spacing:-.01em}
  .callout .ct .d{display:block;color:var(--muted);font-size:13px;margin-top:3px}
  .callout .arr{flex:none;color:var(--purple-lt);font-weight:800;font-size:22px;line-height:1}
  @media(max-width:620px){.callout{gap:12px;padding:13px 15px}.callout .arr{display:none}}

  /* hero */
  .eyebrow{color:var(--purple-lt);font-weight:700;font-size:12.5px;letter-spacing:.16em;text-transform:uppercase;margin:0 0 10px}
  h1{font-size:clamp(28px,5vw,46px);line-height:1.04;letter-spacing:-.02em;margin:0 0 14px;font-weight:800}
  h1 .u{color:var(--purple-lt)}
  .lede{font-size:clamp(15px,2.1vw,18px);color:#C3CCDD;max-width:68ch;margin:0 0 6px}
  .lede b{color:var(--ink)}
  .brand .logo{height:28px;width:auto;display:block}
  .heroimg{display:block;margin:24px 0 2px;border:1px solid var(--line);border-radius:16px;overflow:hidden;box-shadow:0 26px 64px -32px rgba(0,0,0,.85)}
  .heroimg img{display:block;width:100%;height:auto}

  /* architecture */
  .arch{display:grid;grid-template-columns:200px 1fr;gap:18px;margin:30px 0 8px;align-items:stretch}
  @media(max-width:760px){.arch{grid-template-columns:1fr}}
  .you{border:1px dashed var(--line2);border-radius:16px;padding:18px;background:linear-gradient(180deg,var(--panel),var(--bg2));display:flex;flex-direction:column;gap:10px;justify-content:center}
  .you .av{width:46px;height:46px;border-radius:50%;background:radial-gradient(circle at 35% 30%,var(--amber),#c98a12);box-shadow:0 0 0 5px rgba(245,181,68,.14)}
  .you h3{margin:2px 0 0;font-size:18px}
  .you p{margin:0;color:var(--muted);font-size:13px}
  .you .ask{margin-top:4px;background:var(--amber);color:#2a1e00;font-weight:700;font-size:12.5px;border-radius:9px;padding:8px 11px;font-family:var(--mono)}

  .sandbox{border:1px dashed var(--purple);border-radius:18px;padding:14px;background:rgba(104,91,199,.05);position:relative}
  .sandbox > .sbtag{position:absolute;top:-10px;left:16px;background:var(--bg);color:var(--purple-lt);font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;padding:0 8px}
  .cards{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
  @media(max-width:820px){.cards{grid-template-columns:1fr}}
  .status{margin:22px 0 0;padding:15px 18px;border-radius:14px;border:1px solid var(--amber);background:rgba(245,181,68,.08);color:#E9DDBF;font-size:14px}
  .status b{color:var(--amber)}
  pre.json{margin:14px 0 0;padding:14px;border:1px solid var(--line);border-radius:11px;background:var(--card2);font-family:var(--mono);font-size:12px;color:#C3CCDD;white-space:pre-wrap;word-break:break-word}
  .card{border:1px solid var(--line);border-radius:14px;background:linear-gradient(180deg,var(--card),var(--card2));padding:15px 15px 13px;position:relative;box-shadow:0 1px 0 rgba(255,255,255,.02) inset,0 18px 40px -28px rgba(0,0,0,.8)}
  .card.ok{border-color:var(--green-line);box-shadow:0 0 0 1px var(--green-line),0 0 34px -10px rgba(0,195,137,.3)}
  .card .role{color:var(--muted);font-size:11px;font-weight:600;letter-spacing:.1em;text-transform:uppercase}
  .card h4{margin:3px 0 2px;font-size:17px;font-weight:700}
  .card .host{font-family:var(--mono);font-size:12px;color:var(--purple-lt)}
  .card .lock{position:absolute;right:12px;bottom:11px;color:var(--green);opacity:.8}
  .grants{margin-top:11px;display:flex;flex-direction:column;gap:6px}
  .g-row{display:flex;align-items:center;gap:8px;font-size:12.5px}
  .pill{font-family:var(--mono);font-size:11px;font-weight:600;padding:3px 8px;border-radius:7px;white-space:nowrap}
  .pill.g{color:#8ff0cd;background:var(--green-dim);box-shadow:inset 0 0 0 1px var(--green-line)}
  .pill.d{color:var(--faint);background:transparent;box-shadow:inset 0 0 0 1px var(--line)}
  .pill.b{color:#f3b79e;background:var(--red-dim);box-shadow:inset 0 0 0 1px var(--red-line)}
  .g-row .meta{color:var(--muted);font-family:var(--mono);font-size:11.5px}
  .deny{color:var(--faint);font-size:11.5px;font-family:var(--mono);margin-top:3px}

  /* try it */
  .try{margin:34px 0 0;border:1px solid var(--line);border-radius:18px;background:linear-gradient(180deg,var(--panel),var(--bg2));padding:22px}
  .try h2{margin:0 0 4px;font-size:21px;letter-spacing:-.01em}
  .try .sub{color:var(--muted);font-size:14px;margin:0 0 16px}
  .btns{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
  .btn{appearance:none;border:0;cursor:pointer;font-family:var(--sans);font-weight:700;font-size:14.5px;border-radius:11px;padding:12px 18px;transition:transform .05s ease, box-shadow .2s ease}
  .btn:active{transform:translateY(1px)}
  .btn.primary{color:#fff;background:linear-gradient(135deg,var(--purple),#4b3fb0);box-shadow:0 10px 26px -10px rgba(104,91,199,.8)}
  /* attack buttons — red, because clicking one fires a real exploit at the sandbox */
  .btn.attack{color:#fff;background:linear-gradient(135deg,var(--red),#b24a30);box-shadow:0 10px 26px -10px rgba(224,122,88,.8)}
  .btn.attack.all{background:linear-gradient(135deg,#c2452b,#7f3020)}
  .btn.ghost{color:var(--ink);background:transparent;box-shadow:inset 0 0 0 1px var(--line2)}
  .dllinks{margin-top:12px;font-family:var(--mono);font-size:11.5px;color:var(--faint)}
  .dllinks a{color:var(--muted)}
  .btn[disabled]{opacity:.55;cursor:progress}
  .drop{margin-top:14px;border:1.5px dashed var(--line2);border-radius:12px;padding:14px;text-align:center;color:var(--muted);font-size:13px}
  .drop.hot{border-color:var(--purple);background:var(--purple-dim);color:var(--ink)}
  .flow{font-family:var(--mono);font-size:11.5px;color:var(--faint);margin-top:12px}
  .flow b{color:var(--muted);font-weight:600}

  /* result */
  #out{margin-top:18px;display:none}
  .verdict{border-radius:13px;padding:15px 16px;font-size:15px;display:flex;gap:12px;align-items:flex-start}
  .verdict.mit{background:var(--green-dim);box-shadow:inset 0 0 0 1px var(--green-line)}
  .verdict.vuln{background:var(--red-dim);box-shadow:inset 0 0 0 1px var(--red-line)}
  .verdict .ico{font-size:20px;line-height:1.3}
  .verdict b{font-weight:800}
  .stats{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 4px}
  .stat{flex:1;min-width:150px;border:1px solid var(--line);border-radius:11px;padding:11px 13px;background:var(--card2)}
  .stat .n{font-size:24px;font-weight:800;font-family:var(--mono)}
  .stat .k{font-size:11.5px;color:var(--muted);letter-spacing:.03em}
  .stat.good .n{color:var(--green)} .stat.bad .n{color:var(--red)}
  table{width:100%;border-collapse:collapse;margin-top:14px;font-size:12.5px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
  th{color:var(--muted);font-weight:600;font-size:11px;letter-spacing:.05em;text-transform:uppercase}
  td{font-family:var(--mono);vertical-align:top}
  .tag{font-family:var(--mono);font-size:10.5px;font-weight:600;padding:2px 7px;border-radius:6px}
  .tag.red{color:#f3b79e;background:var(--red-dim);box-shadow:inset 0 0 0 1px var(--red-line)}
  .tag.grn{color:#8ff0cd;background:var(--green-dim);box-shadow:inset 0 0 0 1px var(--green-line)}
  .err{color:var(--red);font-family:var(--mono);font-size:13px}
  /* explainer table: which button fires which bug */
  .bugtable{margin:6px 0 4px}
  .bugtable td{font-family:var(--sans);vertical-align:top;color:var(--muted);font-size:13px}
  .bugtable td:nth-child(2){font-family:var(--mono);font-size:11.5px;color:var(--red-tint,#f3b79e);white-space:nowrap}
  /* phones: each row becomes a card — tag + vulnerability, description below */
  @media(max-width:620px){
    .bugtable,.bugtable tbody{display:block}
    .bugtable thead{display:none}
    .bugtable tr{display:grid;grid-template-columns:auto 1fr;align-items:center;gap:6px 10px;padding:12px 0;border-bottom:1px solid var(--line)}
    .bugtable td{padding:0;border:0}
    .bugtable td:nth-child(2){white-space:normal}
    .bugtable td:nth-child(3){grid-column:1/-1}
  }
  .bugtag{display:inline-block;font-family:var(--mono);font-size:11px;font-weight:700;padding:3px 9px;border-radius:7px;white-space:nowrap;color:#f3b79e;background:var(--red-dim);box-shadow:inset 0 0 0 1px var(--red-line)}
  .cloaknote{font-family:var(--mono);font-size:10.5px;color:#f3b79e;margin-top:3px}
  .landpath{font-family:var(--mono);font-size:11px;color:#8ff0cd;margin-left:6px;word-break:break-all}

  /* learn */
  .learn{margin:40px 0 0}
  .learn h2{font-size:21px;margin:0 0 4px}
  .learn p.sub{color:var(--muted);margin:0 0 18px;font-size:14px}
  .links{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media(max-width:680px){.links{grid-template-columns:1fr}}
  .lk{display:block;border:1px solid var(--line);border-radius:13px;padding:15px 16px;background:var(--card2);transition:border-color .15s ease, transform .05s ease}
  .lk:hover{border-color:var(--purple);text-decoration:none;transform:translateY(-1px)}
  .lk .t{color:var(--ink);font-weight:700;font-size:15px;display:flex;align-items:center;gap:8px}
  .lk .t .arr{color:var(--purple-lt);font-weight:700}
  .lk .d{color:var(--muted);font-size:13px;margin-top:4px}
  .foot{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);color:var(--faint);font-size:12.5px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
  .foot code{font-family:var(--mono);color:var(--muted)}
  .foot .legal{display:flex;gap:6px 14px;flex-wrap:wrap;align-items:center}
  .foot .legal button{appearance:none;border:0;background:none;padding:0;font:inherit;color:var(--purple-lt);cursor:pointer}
  .foot .legal button:hover{text-decoration:underline}
  .steps td{font-size:12px}
  .steps td.res{color:#f3b79e}
  .steps td.why{font-family:var(--sans);color:var(--muted);font-size:12px}
  .steps tr.job td{font-family:var(--sans);font-weight:700;color:var(--ink);font-size:13.5px;padding-top:16px}
  .steps tr.job td small{font-weight:500;color:var(--muted);font-family:var(--mono);font-size:11.5px;margin-left:8px}
  .scope{margin:14px 0 0;padding:13px 16px;border-radius:12px;border:1px solid var(--line2);background:var(--card2);color:var(--muted);font-size:13px}
  .scope b{color:var(--ink)}
  details{margin-top:14px} summary{cursor:pointer;color:var(--muted);font-size:13px}
  @media(max-width:760px){.steps td.why{display:none}.steps th.why{display:none}}
</style>
<!-- Cosmonic analytics, only where Cosmonic hosts this demo: a local copy (on
     Cosmonic Desktop, say) loads none of it. /site.js is consent-gated: the
     HubSpot cookie banner loads first, then Google Tag Manager and Apollo only
     once consent allows. The Ahrefs beacon is cookieless. -->
<script>
  if (/(^|\.)[ck]osmonic\.com$/.test(location.hostname)) {
    [['/site.js'], ['https://analytics.ahrefs.com/analytics.js', '8tGIHvyVLh6u4Ygcn/24CA']].forEach(function (t) {
      var s = document.createElement('script');
      s.src = t[0];
      s.async = true;
      if (t[1]) s.setAttribute('data-key', t[1]);
      document.head.appendChild(s);
    });
  }
</script>
</head>
<body>
<div class="wrap">

  <div class="top">
    <a class="brand" href="https://cosmonic.com/" target="_blank" rel="noopener" aria-label="Cosmonic — cosmonic.com">
      <svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 191.08 42.03"><g id="Layer_2" data-name="Layer 2"><g id="Layer_1-2" data-name="Layer 1"><path fill="#8FA0B8" d="M95.08,20a7.93,7.93,0,0,0-1.18-.33c-1-.2-2-.35-3-.57a8,8,0,0,1-1.79-.58,1.51,1.51,0,0,1-.42-2.43,2.47,2.47,0,0,1,.92-.64,4.86,4.86,0,0,1,3.54,0,2.2,2.2,0,0,1,1.49,1.85.17.17,0,0,1,0,.07.13.13,0,0,0,.12.11h0l2.62-.79a.43.43,0,0,0,.3-.51A4.29,4.29,0,0,0,96,13.61a7.76,7.76,0,0,0-7.42-.92,5.42,5.42,0,0,0-3.54,5.66,4,4,0,0,0,3,3.24c1.21.37,2.48.56,3.72.87a10.92,10.92,0,0,1,2.21.69,1.67,1.67,0,0,1,.3,2.82,2.9,2.9,0,0,1-1,.56,5,5,0,0,1-3.13.08,2.7,2.7,0,0,1-2.07-1.95c0-.07-.07-.21-.07-.21a.11.11,0,0,0-.11-.11h0l-2.71.81a.43.43,0,0,0-.29.53,4.93,4.93,0,0,0,2.33,3.05,8.76,8.76,0,0,0,7.85.43,4.86,4.86,0,0,0,3.12-3.58A4.74,4.74,0,0,0,95.08,20Z"/><path fill="#8FA0B8" d="M123.89,13.51A6.44,6.44,0,0,0,115,14.59l-.41.51c-2-3.61-7.25-4-10.4-.44-.21-.72-.41-1.41-.59-2.07h-2.4V29.43h3.43v-.64c0-2.82,0-5.64,0-8.46a5.15,5.15,0,0,1,1.78-4.25A3.22,3.22,0,0,1,111.73,18a10.28,10.28,0,0,1,.17,1.91c0,2.95,0,5.9,0,8.85v.66h3.39c0-1,0-2,0-2.94,0-2.35,0-4.69.07-7a4.43,4.43,0,0,1,1.27-3,3.48,3.48,0,0,1,3.67-1,3,3,0,0,1,2.13,2.62,9.88,9.88,0,0,1,.16,1.8c0,3,0,5.94,0,8.9v.66H126a2,2,0,0,0,0-.29c0-3.68,0-7.37,0-11A5.91,5.91,0,0,0,123.89,13.51Z"/><path fill="#8FA0B8" d="M74.29,12.13A8.75,8.75,0,0,0,65.22,21a9.08,9.08,0,0,0,18.15,0A8.77,8.77,0,0,0,74.29,12.13ZM74.2,26.57a5.36,5.36,0,0,1-5.43-5.63,5.52,5.52,0,1,1,11,.14A5.33,5.33,0,0,1,74.2,26.57Z"/><path fill="#8FA0B8" d="M137.56,12.13A8.74,8.74,0,0,0,128.45,21a9.08,9.08,0,0,0,18.15.08A8.77,8.77,0,0,0,137.56,12.13Zm-.05,14.44A5.36,5.36,0,0,1,132,21a5.52,5.52,0,1,1,11,0A5.33,5.33,0,0,1,137.51,26.57Z"/><path fill="#8FA0B8" d="M162.65,14.53a6.61,6.61,0,0,0-7-2.13,7,7,0,0,0-3.87,2.49c-.25-.81-.47-1.56-.7-2.31h-2.38V29.43h3.46v-.69c0-2.9,0-5.79,0-8.69a4.57,4.57,0,0,1,3.92-4.71,3.57,3.57,0,0,1,4.32,2.95,9.36,9.36,0,0,1,.16,1.91c0,2.87,0,5.75,0,8.63v.59h3.46a1.08,1.08,0,0,0,0-.19c0-3.52,0-7,0-10.55A7,7,0,0,0,162.65,14.53Z"/><path fill="#8FA0B8" d="M59.23,23.78A4.9,4.9,0,0,1,57,26a5.36,5.36,0,0,1-6.71-1.55A5.88,5.88,0,0,1,50.76,17a5.45,5.45,0,0,1,8.52,1.13c.1.17.27.42.42.43,1.06,0,2.12,0,3.18,0-.2-3.41-4.28-6.49-8.48-6.46a8.7,8.7,0,0,0-8.77,8.57,8.68,8.68,0,0,0,8.31,9.17,8.35,8.35,0,0,0,9-6.55c-1,0-1.95,0-2.9,0A.74.74,0,0,0,59.23,23.78Z"/><path fill="#8FA0B8" d="M188.16,23.31a.7.7,0,0,0-.76.44A4.92,4.92,0,0,1,185.19,26a5.35,5.35,0,0,1-6.78-1.6A5.86,5.86,0,0,1,179,17a5.46,5.46,0,0,1,8.48,1.19c.1.17.28.41.43.42,1.05,0,2.11,0,3.18,0a8.23,8.23,0,0,0-8.93-6.43,8.66,8.66,0,0,0-8.34,9.07,8.72,8.72,0,0,0,8.68,8.66c4.19.12,8.33-3,8.61-6.57C190.1,23.32,189.13,23.33,188.16,23.31Z"/><path fill="#8FA0B8" d="M167.74,29.42h3.43V12.57h-3.43Z"/><path fill="#8FA0B8" d="M171.17,7.05h-3.42v3.42h3.42Z"/><path fill="#8F84E6" d="M17.47,32.38C15.36,26.74,12.59,24,6.92,21.89a.93.93,0,0,1,0-1.75c5.67-2.11,8.44-4.86,10.55-10.5a.93.93,0,0,1,1.76,0c1.7,5.7,3.67,9.57,16.62,9.82a.93.93,0,0,0,.94-.93V12.17a3.35,3.35,0,0,0-1.65-2.88L20.07.46a3.3,3.3,0,0,0-3.35,0L1.65,9.29A3.35,3.35,0,0,0,0,12.18V29.87a3.33,3.33,0,0,0,1.65,2.88l15.07,8.83a3.34,3.34,0,0,0,3.35,0l15.07-8.83a3.33,3.33,0,0,0,1.65-2.88V23.45a.93.93,0,0,0-.95-.93c-13,.25-14.91,4.12-16.61,9.81A.92.92,0,0,1,17.47,32.38Z"/></g></g></svg>
      <small>Sandbox</small>
    </a>
    <div class="legend">
      <span><span class="dot g"></span><b>granted</b></span>
      <span><span class="dot d"></span><b>denied</b></span>
      <span><span class="dot b"></span><b>blocked</b></span>
    </div>
  </div>

  <a class="callout" href="https://cosmonic.com/ai-sandbox/principles/" target="_blank" rel="noopener">
    <span class="flag">Principle</span>
    <span class="ct"><span class="h">You can't execute what you don't have</span>
    <span class="d">A sandbox doesn't have to recognize the attack. It starts with nothing and hands the code only what you grant.</span></span>
    <span class="arr">→</span>
  </a>

  <p class="eyebrow">Sandboxing: container escape · MITRE ATT&amp;CK T1609 / T1610</p>
  <h1>You can't escape through<br>a socket that <span class="u">isn't there</span>.</h1>
  <p class="lede">A CI <b>runner</b> executes the steps of whatever job it is handed. A poisoned job goes looking for the container runtime's control plane: <b>docker.sock</b>, the Docker API, the kubelet, the pod's service-account token. On a runner that was handed the Docker socket, reaching it is the first step of the well-known escape. Here the same runner is a WebAssembly component with <b>no filesystem, no sockets, no process spawn and no outbound hosts</b>.</p>

  <a class="heroimg" href="/hero.png" target="_blank" rel="noopener"><img src="/hero.png" alt="A poisoned CI job tries the Docker socket, containerd, the Docker API, the service-account token, the kubelet and the Kubernetes API; inside a Cosmonic sandbox every attempt is blocked."></a>

  <div class="arch">
    <div class="you">
      <div class="av"></div>
      <h3>Attacker</h3>
      <p>Opens a pull request that edits the pipeline file</p>
      <div class="ask">poisoned job →</div>
    </div>
    <div class="sandbox">
      <span class="sbtag">one workload · one sandbox</span>
      <div class="cards" style="grid-template-columns:1fr">
        <div class="card ok">
          <div class="role">CI runner · UI · entrypoint</div>
          <h4>runner</h4>
          <div class="host">container-escape-sandbox.localhost</div>
          <div class="grants">
            <div class="g-row"><span class="pill g">http in</span><span class="meta">this page and /run</span></div>
            <div class="g-row"><span class="pill d">filesystem</span><span class="meta">no volume: no /var/run, no /proc, no token</span></div>
            <div class="g-row"><span class="pill d">sockets</span><span class="meta">wasi:sockets is not imported</span></div>
            <div class="g-row"><span class="pill d">process spawn</span><span class="meta">WASI has no such interface</span></div>
            <div class="g-row"><span class="pill d">egress</span><span class="meta">allowedHosts: []</span></div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="try">
    <h2>Try it: hand the runner a poisoned job</h2>
    <p class="sub">Each button hands the runner a job. The runner executes every step; each step is a real call, and the result shown is the runtime's own answer. These are reachability probes: they ask read-only questions and would do nothing more if one were answered.</p>
    <table class="bugtable">
      <thead><tr><th>Button</th><th>ATT&amp;CK</th><th>What the job tries</th></tr></thead>
      <tbody>
        <tr><td><span class="bugtag">docker.sock</span></td><td>T1609 · T1610</td><td>Start the <code>docker</code> CLI, open <code>/var/run/docker.sock</code> and containerd's socket, and ping the Docker API over TCP.</td></tr>
        <tr><td><span class="bugtag">kubelet</span></td><td>T1613 · T1552.007</td><td>Start <code>kubectl</code>, read the service-account token and <code>/proc</code>, and ask the Kubernetes API server and a kubelet for a read-only answer.</td></tr>
      </tbody>
    </table>
    <div class="btns">
      <button class="btn attack" id="runDocker">Escape via docker.sock</button>
      <button class="btn attack" id="runKube">Reach the kubelet / API server</button>
      <button class="btn attack all" id="runAll">Run all</button>
    </div>
    <div class="dllinks">job files: <a href="/job?mode=docker">/job?mode=docker</a> · <a href="/job?mode=kube">/job?mode=kube</a> · JSON: <a href="/run?mode=all">/run?mode=all</a></div>
    <div class="flow" id="target"></div>

    <div id="out">
      <div id="verdict"></div>
      <div class="stats" id="stats"></div>
      <table class="steps" id="steps"></table>
      <div class="scope" id="scope"></div>
      <details><summary>Raw JSON</summary><pre class="json" id="json"></pre></details>
    </div>
  </div>

  <div class="learn">
    <h2>Where the runtime's own isolation is tested</h2>
    <p class="sub">This is a structural boundary: there is no host function behind the call. That Wasm code cannot reach outside its imports and its linear memory is the runtime's job, tested upstream and cited here, not re-proved:</p>
    <div class="links">
      <a class="lk" href="https://github.com/bytecodealliance/wasmtime/blob/main/crates/fuzzing/src/oracles/memory.rs" target="_blank" rel="noopener">
        <div class="t">wasmtime memory.rs <span class="arr">→</span></div>
        <div class="d">The fuzzing oracle for in-bounds and out-of-bounds linear-memory access.</div>
      </a>
      <a class="lk" href="https://github.com/bytecodealliance/wasmtime/blob/main/crates/fuzzing/src/oracles/stacks.rs" target="_blank" rel="noopener">
        <div class="t">wasmtime stacks.rs <span class="arr">→</span></div>
        <div class="d">The oracle that checks the runtime's view of the call stack.</div>
      </a>
      <a class="lk" href="https://github.com/bytecodealliance/wasmtime/blob/main/fuzz/fuzz_targets/differential.rs" target="_blank" rel="noopener">
        <div class="t">differential.rs <span class="arr">→</span></div>
        <div class="d">Differential fuzzing against the spec interpreter, wasmi and V8.</div>
      </a>
      <a class="lk" href="https://github.com/WebAssembly/testsuite" target="_blank" rel="noopener">
        <div class="t">Wasm core spec tests <span class="arr">→</span></div>
        <div class="d">The specification's own test suite; Wasmtime is also fuzzed continuously on oss-fuzz.</div>
      </a>
    </div>
  </div>

  <div class="foot">
    <span>Reachability probes only · read-only targets · nothing is created or started.</span>
    <span class="legal">
      <a href="https://cosmonic.com/ai-sandbox/" target="_blank" rel="noopener">cosmonic.com/ai-sandbox</a>
      <a href="https://cosmonic.com/legal/privacy-policy/" target="_blank" rel="noopener">Privacy</a>
      <a href="https://cosmonic.com/legal/cookie-policy/" target="_blank" rel="noopener">Cookies</a>
      <span id="cookie-prefs-item" hidden><button type="button" id="cookie-prefs">Cookie Preferences</button></span>
      <span>© 2026 Cosmonic</span>
    </span>
  </div>

</div>

<script>
  document.getElementById('target').innerHTML =
    '<b>GET</b> /run?mode=…  →  the runner executes each step of the job  →  <b>the runtime answers</b>';

  const $ = (id)=>document.getElementById(id);
  const BUTTONS = {
    runDocker: {mode:'docker', label:'Escape via docker.sock'},
    runKube:   {mode:'kube',   label:'Reach the kubelet / API server'},
    runAll:    {mode:'all',    label:'Run all'},
  };
  const btns = Object.keys(BUTTONS).map($);

  function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
  function stat(cls,n,k){return '<div class="stat '+cls+'"><div class="n">'+esc(n)+'</div><div class="k">'+k+'</div></div>'}

  async function send(id){
    btns.forEach(b=>b.disabled=true);
    $(id).textContent='… running the job';
    $('out').style.display='block';
    try{
      const res = await fetch('/run?mode='+BUTTONS[id].mode);
      const text = await res.text();
      if(!res.ok) throw new Error('HTTP '+res.status+' '+text);
      render(JSON.parse(text));
    }catch(e){
      $('verdict').innerHTML='<div class="verdict vuln"><span class="ico">⚠</span><div>The request failed.<br><span class="err">'+esc(e)+'</span></div></div>';
      $('stats').innerHTML=''; $('steps').innerHTML=''; $('scope').innerHTML=''; $('json').textContent='';
    }finally{
      btns.forEach(b=>{b.disabled=false; b.textContent=BUTTONS[b.id].label;});
    }
  }
  Object.keys(BUTTONS).forEach(id=>$(id).addEventListener('click', ()=>send(id)));
  // /#docker, /#kube or /#all fires that job on load.
  const auto = {'#docker':'runDocker','#kube':'runKube','#all':'runAll'}[location.hash];
  if(auto) send(auto);

  function render(r){
    const ok = r.blocked===r.attempts;
    $('verdict').innerHTML =
      '<div class="verdict '+(ok?'mit':'vuln')+'"><span class="ico">'+(ok?'⦸':'⚠')+'</span><div>'+esc(r.verdict)+'</div></div>';
    const w = r.world||{};
    $('stats').innerHTML = [
      stat('', r.attempts, 'attempts made by the job'),
      stat(ok?'good':'bad', r.blocked, 'failed: nothing to reach'),
      stat(ok?'good':'bad', r.attempts-r.blocked, 'reached a runtime control plane'),
      stat(w.imports_wasi_sockets?'bad':'good', w.imports_wasi_sockets?'yes':'none', 'wasi:sockets imports'),
    ].join('');
    let rows = '<thead><tr><th>Block</th><th>Attempt</th><th>The runtime\'s answer</th><th class="why">Why</th></tr></thead><tbody>';
    (r.techniques||[]).forEach(t=>{
      rows += '<tr class="job"><td colspan="4">'+esc(t.name)+'<small>'+esc(t.attack)+'</small></td></tr>';
      (t.steps||[]).forEach(s=>{
        rows += '<tr><td><span class="tag '+(s.blocked?'red':'grn')+'">'+esc(s.block)+'</span></td>'+
          '<td>'+esc(s.action)+'<br><span style="color:var(--faint)">'+esc(s.target)+'</span></td>'+
          '<td class="res">'+esc(s.result)+'</td><td class="why">'+esc(s.why)+'</td></tr>';
      });
    });
    $('steps').innerHTML = rows+'</tbody>';
    $('scope').innerHTML = '<b>What this shows, and what it does not.</b> '+esc(r.scope)+
      '<br><br><b>The world.</b> '+esc(w.note)+' Imports: <span style="font-family:var(--mono);font-size:12px">'+esc((w.imports||[]).join(', '))+'</span>';
    $('json').textContent = JSON.stringify(r, null, 2);
  }
</script>
</body>
</html>
"###;
