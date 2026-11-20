#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { findSkills, checkSkill, RULES } from '../src/index.js';

const VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const HELP = `skillcheck ${VERSION}: lint and security-scan Agent Skills before you install them

Usage
  skillcheck [target...] [options]

Targets (default: the current folder)
  ./path                     a skill folder, a SKILL.md, or a repo full of skills
  owner/repo                 a GitHub repository (shallow-cloned to a temp folder)
  https://github.com/owner/repo/tree/main/skills/name
  https://…  or  git@…       any other git URL

Options
  --strict        fail on warnings too
  --ignore a,b    skip these rules
  --json          machine-readable output
  -h, --help      show this help
  -v, --version   show the version

Exit codes: 0 clean, 1 problems found, 2 usage or clone error`;

const fail = msg => { console.error(`skillcheck: ${msg}`); process.exit(2); };

let opts;
try {
  opts = parseArgs({
    allowPositionals: true,
    options: {
      strict: { type: 'boolean' },
      ignore: { type: 'string', multiple: true },
      json: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
} catch (e) { fail(e.message); }
const { values, positionals } = opts;
if (values.help) { console.log(HELP); process.exit(0); }
if (values.version) { console.log(VERSION); process.exit(0); }

const ignore = new Set((values.ignore ?? []).flatMap(s => s.split(',')).map(s => s.trim()).filter(Boolean));
for (const rule of ignore) if (!(rule in RULES)) fail(`unknown rule "${rule}" (see --help)`);

// ---------- Scan ----------

const targets = [];
let missing = false;
for (const arg of positionals.length ? positionals : ['.']) {
  const t = resolveTarget(arg);
  try {
    const skills = findSkills(t.root).map(dir => {
      const r = checkSkill(dir);
      return { ...r, findings: r.findings.filter(f => !ignore.has(f.rule)) };
    });
    if (!skills.length) { missing = true; console.error(`skillcheck: no SKILL.md found in ${t.label}`); }
    targets.push({ ...t, skills });
  } finally {
    if (t.tmp) fs.rmSync(t.tmp, { recursive: true, force: true, maxRetries: 3 });
  }
}

function resolveTarget(arg) {
  if (fs.existsSync(arg)) return { label: arg, root: path.resolve(arg), base: process.cwd() };
  const gh = /^(?:https:\/\/github\.com\/|github:)?([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:\/tree\/([^/]+)(?:\/(.+?))?)?\/?$/.exec(arg);
  if (gh) {
    const [, owner, repo, branch, sub] = gh;
    const { tmp, dest } = clone(`https://github.com/${owner}/${repo}.git`, repo, branch, arg);
    const root = path.join(dest, sub ?? '');
    if (path.relative(dest, root).startsWith('..') || !fs.existsSync(root)) {
      fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 3 });
      fail(`${sub} not found in ${owner}/${repo}`);
    }
    return { label: sub ? `${owner}/${repo}/${sub}` : `${owner}/${repo}`, root, base: dest, tmp };
  }
  if (/^(https:\/\/|git@)\S+$/.test(arg)) {
    const { tmp, dest } = clone(arg, path.basename(arg).replace(/\.git$/, '') || 'repo', null, arg);
    return { label: arg, root: dest, base: dest, tmp };
  }
  fail(`${arg}: no such file or folder`);
}

function clone(url, name, branch, label) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'skillcheck-'));
  const dest = path.join(tmp, name);
  try {
    // Only https and ssh: no ext::/file:// transports, no prompts, no LFS downloads.
    execFileSync('git', [
      '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', '-c', 'protocol.ssh.allow=always',
      'clone', '--quiet', '--depth', '1', '--no-tags', ...(branch ? ['--branch', branch] : []), '--', url, dest,
    ], { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'never', GIT_LFS_SKIP_SMUDGE: '1' } });
  } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 3 });
    const why = String(e.stderr || e.message).trim().split('\n').pop();
    fail(`${label} is not a local path, and cloning ${url} failed: ${why}`);
  }
  return { tmp, dest };
}

// ---------- Report ----------

const all = targets.flatMap(t => t.skills.map(s => ({ ...s, base: t.base })));
const findings = all.flatMap(s => s.findings);
const errors = findings.filter(f => f.severity === 'error').length;
const warnings = findings.length - errors;
const posix = p => p.split(path.sep).join('/');
// Everything printed may come from an untrusted skill: neutralise control and invisible characters.
const safe = s => String(s).replace(/[\x00-\x1f\x7f-\x9f\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\uFE00-\uFE0F\u{e0000}-\u{e01ef}]/gu,
  ch => `\\u{${ch.codePointAt(0).toString(16)}}`);

if (values.json) {
  console.log(JSON.stringify({
    version: VERSION,
    targets: targets.map(t => ({
      target: t.label,
      skills: t.skills.map(s => ({
        name: s.name,
        path: posix(path.relative(t.base, s.dir)) || '.',
        findings: s.findings.map(f => ({ ...f, file: posix(path.relative(t.base, f.file)) })),
      })),
    })),
    summary: { skills: all.length, errors, warnings },
  }, null, 2));
} else {
  const tty = process.stdout.isTTY || process.env.GITHUB_ACTIONS === 'true';
  const color = ('FORCE_COLOR' in process.env || tty) && !('NO_COLOR' in process.env);
  const paint = code => s => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const red = paint(31), yellow = paint(33), green = paint(32), dim = paint(2), bold = paint(1);

  for (const s of all) {
    if (!s.findings.length) continue;
    const bad = s.findings.some(f => f.severity === 'error');
    console.log(`\n${bad ? red('✖') : yellow('!')} ${bold(safe(s.name))}  ${dim(safe(posix(path.relative(s.base, s.dir)) || '.'))}`);
    for (const f of s.findings) {
      const where = `${posix(path.relative(s.dir, f.file))}:${f.line}`;
      console.log(`  ${f.severity === 'error' ? red('error') : yellow('warn ')}  ${f.rule.padEnd(21)} ${safe(f.message)}  ${dim(safe(where))}`);
      if (f.snippet) console.log(dim(`         │ ${safe(f.snippet)}`));
    }
  }
  const clean = all.filter(s => !s.findings.length).length;
  const icon = errors ? red('✖') : warnings ? yellow('!') : green('✔');
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
  if (all.length) console.log(`\n${icon} ${plural(all.length, 'skill')} checked: ${plural(errors, 'error')}, ${plural(warnings, 'warning')}, ${clean} clean`);

  // Inline annotations on pull requests when running in GitHub Actions.
  if (process.env.GITHUB_ACTIONS === 'true') {
    const prop = s => safe(s).replace(/%/g, '%25').replace(/:/g, '%3A').replace(/,/g, '%2C');
    for (const s of all) {
      if (s.base !== process.cwd()) continue; // remote clones have no file in this checkout
      for (const f of s.findings) {
        const level = f.severity === 'error' ? 'error' : 'warning';
        console.log(`::${level} file=${prop(posix(path.relative(s.base, f.file)))},line=${f.line},title=${prop(`skillcheck ${f.rule}`)}::${safe(f.message).replace(/%/g, '%25')}`);
      }
    }
  }
}

process.exitCode = missing ? 2 : errors || (values.strict && warnings) ? 1 : 0;
