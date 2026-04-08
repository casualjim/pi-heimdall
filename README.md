# pi-heimdall

Guardian extensions for [pi](https://github.com/badlogic/pi-mono) that protect
against accidental secret exposure through tool calls.

Named after Heimdall, watcher of the Bifröst — the one who sees everything
coming and slams the gate shut when it shouldn't pass.

Ported from the equivalent [opencode](https://opencode.ai) plugins.

## What it does

pi-heimdall ships four independent extensions. Each one intercepts tool calls
before they run (and, in one case, after they return) and blocks or redacts
anything that would leak secrets to the LLM context.

| Extension | Tool | Blocks / redacts |
|---|---|---|
| `env-protect` | `read` | Reading `.env`, `.env.*`, `.envrc`, `*.env` — except `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.defaults` |
| `kubectl-secret-guard` | `bash` | `kubectl get secrets`, `kubectl patch ... finalizers`, `kubectl exec` into a pod that dumps env / `/var/run/secrets` / `app.ini` |
| `sops-secret-guard` | `bash` | Any `sops` invocation that would decrypt content: `sops decrypt`, `sops -d`, `sops --decrypt`, `sops exec-env`, `sops exec-file`, `sops edit`, and bare `sops <file>` |
| `secret-guard` | `bash` | Commands that reference secret env var names from a project `.env.json`, and redacts their values from bash output (plaintext, base64, rot13, reversed, hex, and hexdump-decoded) |

All four are **independent** — enable whichever subset you need.

## Install

### Global (all projects)

```bash
pi install git:github.com/casualjim/pi-heimdall
```

### Project-local

```bash
pi install -l git:github.com/casualjim/pi-heimdall
```

Project-local installs land in `.pi/settings.json` and are picked up
automatically for every run in that directory.

### From a local clone

```bash
git clone https://github.com/casualjim/pi-heimdall ~/src/pi-heimdall
pi install ~/src/pi-heimdall
```

### Drop into `.pi/extensions/` manually

Pi auto-discovers any `.ts` file in `~/.pi/agent/extensions/` (global) or
`.pi/extensions/` (project). You can copy or symlink individual files:

```bash
mkdir -p .pi/extensions
ln -s ~/src/pi-heimdall/extensions/secret-guard.ts .pi/extensions/
```

This is useful when you want only some of the guards active.

### Try without installing

```bash
pi -e git:github.com/casualjim/pi-heimdall
```

## Enabling / disabling individual guards

Use pi's package filter to narrow down which files load:

```json
{
  "packages": [
    {
      "source": "git:github.com/casualjim/pi-heimdall",
      "extensions": [
        "extensions/env-protect.ts",
        "extensions/sops-secret-guard.ts"
      ]
    }
  ]
}
```

Or use `pi config` interactively.

## Configuring `secret-guard`

`secret-guard` is the only guard that needs configuration. Create a `.env.json`
at your project root listing the environment variables that should be treated
as secrets. **Values in the JSON are ignored — only the keys matter.** The
actual secret values are captured from `process.env` when pi starts.

```json
{
  "GITHUB_TOKEN": "",
  "OPENAI_API_KEY": "",
  "STRIPE_SECRET_KEY": "",
  "AWS_SECRET_ACCESS_KEY": ""
}
```

With this in place:

- Any bash command that mentions `GITHUB_TOKEN` as a whole word is blocked.
- Any bash output containing the actual value of `GITHUB_TOKEN` (in plaintext,
  base64, rot13, reversed, raw hex, or hexdump form) is replaced with
  `[REDACTED]`.

Even without `.env.json`, `secret-guard` still applies a generic
trailing-pattern redaction: anything matching `*(SECRET|KEY|TOKEN|PASSWORD|PASS|APIKEY|CREDENTIAL|PRIVATE)=...`
in bash output gets its value masked.

### A `sops` key is ignored

If your `.env.json` uses the key `sops` (for example, it's a sops-encrypted
file with a `sops` metadata section), that key is skipped so pi-heimdall
doesn't try to match literal metadata as a secret name.

## How the guards communicate with the LLM

When a guard blocks a tool call it returns a `reason` string that is delivered
back to the model as the tool result. Every reason includes an explicit
instruction such as:

> *Ask the user to run this command directly in their terminal if needed.
> Never attempt to bypass this protection or ask the user to disable it.*

This keeps the model from going into "creative workaround" mode and trying a
different command to accomplish the same leak.

If a pi TUI is attached, a warning notification is also shown so you can see
the block in real time.

## Layout

```
extensions/
├── env-protect.ts
├── kubectl-secret-guard.ts
├── secret-guard.ts
└── sops-secret-guard.ts
```

Each file is a standalone extension. There is no shared runtime state between
them — you can delete any file and the others will keep working.

## Development

```bash
npm install           # optional: only for editor tooling / type checks
npm run typecheck     # type-check the extensions
npm run check:pack    # verify the package tarball contents
```

GitHub Actions runs the same checks on pushes and pull requests to `main`.

Pi loads `.ts` files directly via [jiti](https://github.com/unjs/jiti), so no
build step is required at runtime.

## License

MIT © casualjim
