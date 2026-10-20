<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UniFi Blocker Pro</title>
<meta name="description" content="UniFi Blocker Pro for Home Assistant: block a whole address range, block new cameras automatically, and see what every device tries to reach.">
<style>
  :root { --bg:#0a150e; --card:#0f1a12; --line:#1b3526; --text:#e2e8f0; --mut:#94a3b8; --acc:#52b788; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:16px/1.5 Inter, system-ui, Arial, sans-serif; }
  main { max-width: 860px; margin: 0 auto; padding: 32px 20px 60px; }
  h1 { font-size: 30px; margin: 0 0 6px; }
  h2 { font-size: 19px; margin: 0 0 10px; }
  p { margin: 0 0 10px; }
  .sub { color: var(--mut); margin-bottom: 26px; }
  .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 18px; }
  ul { margin: 0; padding-left: 20px; } li { margin: 4px 0; }
  .price { font-size: 38px; font-weight: 900; margin: 6px 0; }
  .price small { font-size: 14px; font-weight: 600; }
  .muted { color: var(--mut); font-size: 14px; }
  button { background: var(--acc); color: #071008; border: 0; border-radius: 10px; padding: 12px 20px; font: inherit; font-weight: 700; cursor: pointer; }
  .thanks { display: none; border-color: var(--acc); margin-bottom: 18px; }
  a { color: var(--acc); }
  code { background: #0c1a0e; border: 1px solid var(--line); border-radius: 6px; padding: 1px 6px; }
</style>
</head>
<body>
<main>
  <div class="card thanks" id="thanks">
    <h2>Thanks for buying UniFi Blocker Pro</h2>
    <p>Your key (<code>UBLOK-…</code>) is on its way to the email you paid with. In Home Assistant open <b>UniFi Blocker → Tools → UniFi Blocker Pro → Enter licence key</b>.</p>
  </div>

  <h1>UniFi Blocker Pro</h1>
  <p class="sub">UniFi Blocker for Home Assistant stays free: find and identify every device, block cameras device by device, and see what's wrong. Pro adds the automation and the traffic detail.</p>

  <div class="grid">
    <div class="card">
      <h2>Pro adds</h2>
      <ul>
        <li><b>Block a whole range.</b> One switch cuts every address in your local-only range off from the internet, with time sync still allowed.</li>
        <li><b>New cameras blocked automatically</b> the moment they join, with a notification and one click to undo.</li>
        <li><b>Traffic insight.</b> What each device tries to reach, port sweeps, devices using their own DNS, 24-hour traffic and spikes, and an alert when a device that should be cut off gets through.</li>
        <li><b>Mining tracker.</b> Live hashrate, temperatures, power and profit per rig.</li>
        <li><b>Themes:</b> Day, Graphite, Ocean, Dusk and High contrast.</li>
      </ul>
    </div>
    <div class="card">
      <h2>Free, always</h2>
      <ul>
        <li>Finding, identifying and sorting every device on the network</li>
        <li>Recommendations and UniFi's security log</li>
        <li>Firmware warnings (known-exploited bugs)</li>
        <li>Port scans and ONVIF camera discovery</li>
        <li>Block internet, local-only and quarantine, device by device</li>
        <li>New-device and new-camera notifications</li>
      </ul>
      <p class="muted" style="margin-top:10px">If Pro lapses, nothing is undone: blocks already on your controller stay, and can always be turned off.</p>
    </div>
  </div>

  <div class="card" style="text-align:center;margin-top:16px">
    <div class="price">$35 <small>CAD / year</small></div>
    <p class="muted">One-time PayPal payment · key valid 1 year · emailed automatically · works on 2 Home Assistant installs</p>
    <form action="https://www.paypal.com/cgi-bin/webscr" method="post" target="_top">
      <input type="hidden" name="cmd" value="_xclick">
      <input type="hidden" name="business" value="garry@bcmail.net">
      <input type="hidden" name="item_name" value="UniFi Blocker Pro — 1 year license">
      <input type="hidden" name="item_number" value="unifiblocker-pro-annual">
      <input type="hidden" name="amount" value="35.00">
      <input type="hidden" name="currency_code" value="CAD">
      <input type="hidden" name="no_shipping" value="1">
      <input type="hidden" name="notify_url" value="https://traks.ca/license/?action=ipn">
      <input type="hidden" name="return" value="https://unifiblocker.enerx.ca/pro/?bought=1">
      <button type="submit">Buy UniFi Blocker Pro with PayPal</button>
    </form>
    <p class="muted" style="margin-top:14px">Want to try it first? Start a free 30-day trial in Home Assistant: <b>UniFi Blocker → Tools → UniFi Blocker Pro</b>. Renewing? Pay with the same email and your key is extended.</p>
  </div>

  <p class="muted" style="margin-top:22px">UniFi Blocker is open source (GPL-3.0): <a href="https://github.com/gbroeckling/unifiblocker">github.com/gbroeckling/unifiblocker</a>. Questions: <a href="mailto:hello@traks.ca">hello@traks.ca</a></p>
</main>
<script>
  if (new URLSearchParams(location.search).has("bought")) document.getElementById("thanks").style.display = "block";
</script>
</body>
</html>
