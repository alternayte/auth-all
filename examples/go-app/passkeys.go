package main

// passkeyPage signs a user in with a password, registers a passkey, and signs
// the user in with the passkey. It calls the Auth-All routes directly, so it
// needs no build step.
const passkeyPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Passkeys</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 2rem auto; padding: 0 1rem; }
  input, button { font: inherit; padding: .4rem .6rem; margin: .2rem 0; }
  input { width: 100%; box-sizing: border-box; }
  section { border-top: 1px solid #ccc; padding: .5rem 0 1rem; }
  #status { white-space: pre-wrap; background: #f4f4f4; padding: .5rem; min-height: 2rem; }
</style>
</head>
<body>
<h1>Passkeys</h1>
<p id="status">Signed out.</p>
<section>
  <h2>Password</h2>
  <input id="email" type="email" placeholder="Email" autocomplete="username">
  <input id="password" type="password" placeholder="Password" autocomplete="current-password">
  <button id="sign-in">Sign in with password</button>
</section>
<section>
  <h2>Passkey</h2>
  <input id="name" placeholder="Passkey name" value="This device">
  <button id="register">Register a passkey</button>
  <button id="passkey">Sign in with a passkey</button>
  <ul id="list"></ul>
</section>
<section>
  <button id="sign-out">Sign out</button>
</section>
<script>
const base = "/api/auth";
const status = document.getElementById("status");
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
async function refresh() {
  const session = await call("GET", "/session");
  if (!session.user) { show("Signed out."); document.getElementById("list").innerHTML = ""; return; }
  show("Signed in as " + session.user.email + ".");
  const page = await call("GET", "/passkeys");
  document.getElementById("list").innerHTML = page.passkeys.map(p => "<li>" + p.name + "</li>").join("");
}
async function run(fn) { try { await fn(); await refresh(); } catch (e) { show("Error: " + e.message); } }
document.getElementById("sign-in").onclick = () => run(async () => {
  const out = await call("POST", "/sign-in/email", {
    email: document.getElementById("email").value, password: document.getElementById("password").value });
  if (out.mfaRequired) throw new Error("this example does not ask for a TOTP code");
});
document.getElementById("register").onclick = () => run(async () => {
  const begin = await call("POST", "/passkeys/register/begin");
  const created = await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(begin.options.publicKey) });
  await call("POST", "/passkeys/register/finish", {
    ceremony: begin.ceremony, name: document.getElementById("name").value, credential: created.toJSON() });
});
document.getElementById("passkey").onclick = () => run(async () => {
  const begin = await call("POST", "/passkeys/sign-in/begin");
  const assertion = await navigator.credentials.get({
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(begin.options.publicKey) });
  const out = await call("POST", "/passkeys/sign-in/finish", { ceremony: begin.ceremony, credential: assertion.toJSON() });
  if (out.mfaRequired) throw new Error("the passkey had no user verification, so TOTP is required");
});
document.getElementById("sign-out").onclick = () => run(() => call("POST", "/sign-out"));
refresh();
</script>
</body>
</html>
`
