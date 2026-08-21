# AGENTS.md — pi agent config

Personal pi configuration. TypeScript extensions in `extensions/`, shared modules in
`lib/`. Pi loads them at runtime via jiti — **there is no build step**, so typechecking
is the only static validation these files get.

## Typecheck your output

After editing any file in `extensions/` or `lib/`, run:

```sh
npm --prefix npm run typecheck
```

(or `cd npm && npm run typecheck`). This runs `tsc --noEmit -p ../tsconfig.json`
with the repo's pinned compiler. **Always run it before finishing a task that touched
extension code.** A clean exit is the minimum bar for done.

Notes:

- The `node_modules` for this repo lives at `npm/node_modules` (gitignored). The root
  `tsconfig.json` points `typeRoots`/`paths` at it, which is why plain `npx tsc` from
  the repo root does **not** work — it downloads a bogus `tsc` package. Use the npm
  script above instead.
- `npm/package.json` holds the type packages as `devDependencies`:
  - `@earendil-works/pi-coding-agent` / `pi-tui` are pinned to the exact pi runtime
    version (currently `0.84.1`) so editor types match the running pi. **Bump these
    pins when pi is upgraded.**
  - `@types/node`, `shell-quote`, `typescript` are also devDeps.
- `npm/` is gitignored, so if `npm/package.json` is missing on a fresh checkout,
  re-add the devDependencies above and run `npm install` in `npm/`.
- Extensions may import each other with explicit `.ts` extensions
  (`import { analyze } from "./lib/care/engine.ts"`) — `allowImportingTsExtensions` is set.
- Type errors are not merely cosmetic: they can reveal stale schemas. Example:
  `diff-syntax.ts` read `event.input.file_path`, which the write tool schema dropped
  in favor of `path` — the typecheck caught the dead branch.

## Guard extension

The `extensions/guard/` extension is self-contained (its own `package.json` +
`node_modules`). After editing anything under `extensions/guard/`, run its tests:

```sh
cd extensions/guard && npm test
```

This runs the `node:test` suite (`node --test`). Run both this and the repo typecheck
before finishing guard work.

### Config schema

`guard.jsonc` (repo root) is validated by `extensions/guard/guard.schema.json`, wired up
via the file's `$schema`. **If you touch the config in the extension — the `CareConfig`
interface, `DEFAULT_CONFIG`, or how `index.ts` reads a field — update the schema to
match** (properties, enum values, defaults, descriptions). Keep `guard.jsonc` and the
docs (`extensions/guard/docs/safety-tiers.md`, `extensions/guard/docs/care-integration.md`)
in sync with any default changes.
