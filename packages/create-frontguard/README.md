# create-frontguard

Set up [FrontGuard](https://github.com/juliocarneiro/frontguard) in an existing project:

```sh
npm create frontguard
# or: pnpm create frontguard / yarn create frontguard / bun create frontguard
```

It installs `frontguard`, creates a config, adds a `security` script and a GitHub Actions workflow.
Flags are forwarded to `frontguard init` (`--yes`, `--no-ci`, `--no-install`, `--json`, `--pm <name>`).
