# Attack module

`attack-module` executes one structured curl request at a time for the agent's isolated local lab. It accepts `{ "method": "POST", "url": "http://127.0.0.1:PORT/api/posts", "body": { "title": "...", "content": "..." } }` and returns `{ success, status, bodyJson, setCookie, error }`. The default stored-XSS loop uses GET for the Alice session and one bounded canary POST. The explicitly selected legacy BOLA profile also supports fixture setup and one DELETE check.

```js
const { executeCurl } = require('./index');
const result = await executeCurl(command, {
  allowedOrigin: 'http://127.0.0.1:PORT',
  cookie: 'session=TRUSTED_COOKIE',
  signal: abortController.signal,
});
```

The trusted gateway supplies the exact loopback origin and private session cookie. It must not expose `setCookie` or the `cookie` argument to agent events. Before calling this module, the gateway validates the fixed canary sequence and evaluates the repository's real `guardrail` ruleset. It returns the decision inside the agent-facing `attack.result` JSON; a denied request never reaches curl. The module rejects extra command fields, external URLs, unsupported methods, and raw curl flags. It invokes curl without a shell, follows no redirects, ignores proxy settings, and caps time and response size.

Run `npm test` from this directory to exercise the module against a temporary loopback HTTP server.
