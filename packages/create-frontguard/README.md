# @juliocarneiro/create-frontguard

Set up [FrontGuard](https://github.com/juliocarneiro/frontguard) in an existing project:

```sh
npm create @juliocarneiro/frontguard
# or: pnpm create @juliocarneiro/frontguard / yarn create @juliocarneiro/frontguard / bun create @juliocarneiro/frontguard
```

It installs `@juliocarneiro/frontguard`, creates a config, adds a `security` script and a GitHub Actions workflow.
Flags are forwarded to `frontguard init` (`--yes`, `--no-ci`, `--no-install`, `--json`, `--pm <name>`).
