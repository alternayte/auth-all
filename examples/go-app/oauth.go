package main

// oauthPage is the login page and the consent page of the OAuth provider. The
// authorize route sends the browser here with a request identifier. The page
// signs the user in with a password when the request needs it, shows the
// client with its host, and posts the decision. It calls the Auth-All routes
// directly, so it needs no build step.
const oauthPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 2rem auto; padding: 0 1rem; }
  input, button { font: inherit; padding: .4rem .6rem; margin: .2rem 0; }
  input { width: 100%; box-sizing: border-box; }
  section { border-top: 1px solid #ccc; padding: .5rem 0 1rem; }
  [hidden] { display: none; }
  #status { white-space: pre-wrap; background: #f4f4f4; padding: .5rem; min-height: 2rem; }
  .host { font-family: ui-monospace, monospace; }
</style>
</head>
<body>
<h1>Authorize an application</h1>
<p id="status">Loading the request.</p>
<section id="sign-in" hidden>
  <h2>Sign in</h2>
  <input id="email" type="email" placeholder="Email" autocomplete="username">
  <input id="password" type="password" placeholder="Password" autocomplete="current-password">
  <button id="sign-in-button">Sign in</button>
</section>
<section id="consent" hidden>
  <h2 id="client-name"></h2>
  <p>Host: <span class="host" id="client-host"></span></p>
  <p id="client-kind"></p>
  <p>The application asks for these scopes:</p>
  <ul id="scopes"></ul>
  <p id="resources"></p>
  <button id="approve">Allow</button>
  <button id="deny">Deny</button>
</section>
<script>
const base = "/api/auth";
const status = document.getElementById("status");
const requestId = new URLSearchParams(location.search).get("request_id");
async function call(method, path, body) {
  const res = await fetch(base + path, {
    method, credentials: "same-origin",
    headers: body === undefined ? {} : {"Content-Type": "application/json"},
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error((data.error && data.error.code) || res.status);
  return data;
}
function show(message) { status.textContent = message; }
const kinds = {
  static: "This application is part of this site.",
  dynamic: "This application registered itself. No administrator checked it.",
  cimd: "This application describes itself at its host. No administrator checked it.",
};
async function decide(approve) {
  const out = await call("POST", "/oauth2/decide", { requestId, approve });
  location.href = out.redirectTo;
}
async function load() {
  if (!requestId) { show("The page has no request identifier."); return; }
  const request = await call("GET", "/oauth2/request?request_id=" + encodeURIComponent(requestId));
  document.getElementById("sign-in").hidden = !request.needsSignIn;
  if (request.needsSignIn) { show("Sign in to continue."); return; }
  if (request.consentGranted) { show("You allowed this application before."); await decide(true); return; }
  document.getElementById("client-name").textContent = request.clientName || request.clientId;
  document.getElementById("client-host").textContent = request.clientHost || "(none)";
  document.getElementById("client-kind").textContent = kinds[request.clientKind] || "";
  const list = document.getElementById("scopes");
  list.replaceChildren(...request.scopes.map(s => { const li = document.createElement("li"); li.textContent = s; return li; }));
  document.getElementById("resources").textContent =
    (request.resources || []).length ? "For: " + request.resources.join(", ") : "";
  document.getElementById("consent").hidden = false;
  show("Check the name and the host before you allow access.");
}
async function run(fn) { try { await fn(); } catch (e) { show("Error: " + e.message); } }
document.getElementById("sign-in-button").onclick = () => run(async () => {
  const out = await call("POST", "/sign-in/email", {
    email: document.getElementById("email").value, password: document.getElementById("password").value });
  if (out.mfaRequired) throw new Error("this example does not ask for a TOTP code");
  await load();
});
document.getElementById("approve").onclick = () => run(() => decide(true));
document.getElementById("deny").onclick = () => run(() => decide(false));
run(load);
</script>
</body>
</html>
`
