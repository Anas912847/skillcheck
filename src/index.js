// skillcheck: lint and security-scan Agent Skills (https://agentskills.io/specification).
// Zero dependencies on purpose: a scanner you run on untrusted code should not pull in a supply chain.
import fs from 'node:fs';
import path from 'node:path';

export const RULES = {
  // Spec: the skill may not load at all.
  'filename-case': 'error',
  'frontmatter-missing': 'error',
  'frontmatter-yaml': 'error',
  'frontmatter-comment': 'warn',
  'name-missing': 'error',
  'name-invalid': 'error',
  'name-mismatch': 'error',
  'description-missing': 'error',
  'description-too-long': 'error',
  'compatibility-invalid': 'error',
  'metadata-invalid': 'error',
  // Quality: the skill loads, but agents will use it badly.
  'description-vague': 'warn',
  'unknown-field': 'warn',
  'body-too-long': 'warn',
  'broken-link': 'warn',
  'link-outside': 'warn',
  'broad-tools': 'warn',
  // Security: what the skill can make your agent do.
  'hidden-unicode': 'error',
  'invisible-chars': 'warn',
  'prompt-injection': 'error',
  'concealment': 'warn',
  'remote-exec': 'error',
  'obfuscated-exec': 'error',
  'exfil-endpoint': 'warn',
  'secret-access': 'warn',
  'persistence': 'warn',
  'agent-config': 'warn',
  'destructive-command': 'warn',
  'binary-file': 'warn',
  'symlink': 'warn',
};

const SPEC_FIELDS = new Set(['name', 'description', 'license', 'compatibility', 'metadata', 'allowed-tools']);
const SKIP_DIRS = new Set(['.git', 'node_modules']);
const SKILL_FILE = /^skill\.md$/i;
const NAME = /^[\p{Ll}\p{Nd}]+(-[\p{Ll}\p{Nd}]+)*$/u;
const TRIGGER = /\b(use[sd]?|using|when|whenever|trigger\w*|invoke\w*)\b|quand|lorsqu|utilis/i;
const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const EXEC_EXT = /\.(exe|dll|so|dylib|bin|msi|scr|jar|class|pyc|node|wasm)$/i;

// Bidi overrides (Trojan Source), Unicode tags (ASCII smuggling an LLM reads but a human can't see)
// and supplementary variation selectors (emoji smuggling).
const SMUGGLING = /[‪-‮⁦-⁩\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;
// Zero-width characters and stray BOMs: often legit (emoji regexes, BOM stripping) but able to hide text.
// A ZWJ right after a non-ASCII char is an emoji sequence, so it is allowed.
const INVISIBLE = /[​‌⁠-⁤᠎﻿]|(?<![^\x00-\x7F])‍|[︀-️]{2,}/gu;
const ANY_HIDDEN = /[‪-‮⁦-⁩\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}​-‍⁠-⁤᠎﻿︀-️]{2,}/gu;

// The curl/wget patterns need a URL, a host or a variable, so prose like "never run `curl | sh`" stays quiet.
const FETCH = String.raw`\b(curl|wget)\b[^|\n]*(https?:\/\/|\$\{?\w|\b[\w-]+\.[a-z]{2,}\b)[^|\n]*`;
const PATTERNS = [
  ['remote-exec', new RegExp(FETCH + String.raw`\|\s*(sudo\s+)?(-\S+\s+)*(ba|z|da|k|fi)?sh\b`, 'i')],
  ['remote-exec', new RegExp(FETCH + String.raw`\|\s*(sudo\s+)?(python[\d.]*|node|perl|ruby|php)(\s+-)?\s*($|[;&|)'"\x60])`, 'i')],
  ['remote-exec', /\b(ba|z|da)?sh\s+(-c\s+)?["']?(<\(|\$\()\s*(curl|wget)\b/i],
  ['remote-exec', /\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]*\|\s*(iex|Invoke-Expression)\b/i],
  ['remote-exec', /\b(iex|Invoke-Expression)\b[^\n]*\b(DownloadString|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b/i],
  ['obfuscated-exec', /\bbase64\s+(-d|--decode|-D)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i],
  ['obfuscated-exec', /\b(eval|Function)\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent)\s*\(/],
  ['obfuscated-exec', /\b(exec|eval)\s*\(\s*(base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads)/],
  ['obfuscated-exec', /\b(powershell|pwsh)(\.exe)?\b[^\n]*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i],
  ['obfuscated-exec', /\bFromBase64String\b[^\n]*\b(iex|Invoke-Expression)\b|\b(iex|Invoke-Expression)\b[^\n]*\bFromBase64String\b/i],
  // A quoted phrase is usually a skill warning about injection, not doing it.
  ['prompt-injection', /(?<![“"'‘`])\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(of\s+)?(the\s+|your\s+|my\s+)?(previous|prior|above|earlier|preceding|system|original)\s+(instructions?|prompts?|rules|directives|guidelines|messages)\b/i],
  // "Don't tell the user to …" and "never … without telling the user" are normal guidance.
  ['concealment', /\b(do\s+not|don['’]t|never)\s+(tell|inform|notify)\s+(the\s+)?user\b(?!\s+(to|how|they)\b)/i],
  ['concealment', /(?<!\b(?:never|not|don['’]t|doesn['’]t)\b[^.]*)\bwithout\s+(telling|informing|notifying)\s+(the\s+)?user\b/i],
  ['concealment', /\b(hide|conceal)\s+(this|it|these|that)\s+from\s+(the\s+)?user\b/i],
  ['concealment', /\b(silently|secretly|covertly)\s+(send|upload|post|exfiltrate|transmit|forward)\b/i],
  ['exfil-endpoint', /\b(discord(app)?\.com\/api\/webhooks|hooks\.slack\.com\/(services|workflows)|api\.telegram\.org\/bot|webhook\.site|pipedream\.net|requestbin\.|pastebin\.com|paste\.ee|hastebin\.|transfer\.sh|0x0\.st|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator\.net)/i],
  ['secret-access', /(~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE)[\/\\]\.(ssh|aws|gnupg|kube|docker|config[\/\\]gh)\b/i],
  ['secret-access', /\b(id_rsa|id_ed25519|id_ecdsa)\b|\.aws[\/\\]credentials\b|\.git-credentials\b|\.netrc\b|\.pypirc\b|\bwallet\.dat\b|\bcookies\.sqlite\b|\blogins\.json\b|\bLogin Data\b/],
  ['secret-access', /JSON\.stringify\(\s*process\.env\s*\)|\bdict\(\s*os\.environ\s*\)|\bprintenv\s*(\||>)|\benv\s*\|\s*(curl|nc|wget)\b/],
  ['secret-access', /\bsecurity\s+(find-(generic|internet)-password|dump-keychain)\b/],
  ['persistence', /(~|\$HOME|\$\{HOME\})\/\.(bashrc|zshrc|bash_profile|zprofile|zshenv|profile)\b/],
  ['persistence', /\bcrontab\s+-|\/etc\/cron|\bLaunch(Agents|Daemons)\b|\bsystemctl\s+(--user\s+)?enable\b|\bschtasks(\.exe)?\s+\/create\b|\\CurrentVersion\\Run\b|\bauthorized_keys\b/i],
  ['agent-config', /--dangerously-skip-permissions|\bbypassPermissions\b|--dangerously-bypass-approvals-and-sandbox|--yolo\b/],
  ['agent-config', /\.claude[\/\\]settings(\.local)?\.json|\.cursor[\/\\]mcp\.json|\.codex[\/\\]config\.toml|claude_desktop_config\.json/],
  ['destructive-command', /\brm\s+(-[a-zA-Z]+\s+)*-[a-zA-Z]*[rR][a-zA-Z]*(\s+-[a-zA-Z]+)*\s+["']?(\/|~\/?|\$\{?HOME\}?\/?)\*?["']?(\s|;|&|\||$)/],
  ['destructive-command', /\bmkfs(\.\w+)?\s|\bdd\s+[^\n]*\bof=\/dev\/(sd|nvme|disk|hd)|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\bFormat-Volume\b/i],
];

const MESSAGES = {
  'remote-exec': 'downloads a script and runs it immediately: whatever the server sends gets executed',
  'obfuscated-exec': 'decodes and executes hidden code',
  'prompt-injection': "tries to override the agent's instructions",
  'concealment': 'asks the agent to hide what it does from the user',
  'exfil-endpoint': 'talks to a webhook, paste or tunnel service, a common way to smuggle data out',
  'secret-access': 'reads credentials, keys or environment secrets',
  'persistence': 'installs something that outlives the session (shell profile, cron, autostart, SSH keys)',
  'agent-config': 'changes agent permissions or config: a skill could grant itself more power',
  'destructive-command': 'can wipe a disk or a home directory',
};

// ---------- Frontmatter: a YAML subset, enough for SKILL.md ----------

export function parseFrontmatter(text) {
  const lines = text.replace(/^﻿/, '').split(/\r?\n/);
  const none = { data: {}, at: {}, problems: [], body: lines, bodyLine: 1 };
  if (lines[0].trimEnd() !== '---') return { ...none, error: 'missing' };
  const end = lines.findIndex((l, i) => i > 0 && /^(---|\.\.\.)\s*$/.test(l));
  if (end === -1) return { ...none, error: 'unclosed' };
  return { ...parseYaml(lines.slice(1, end)), body: lines.slice(end + 1), bodyLine: end + 2 };
}

function parseYaml(lines) {
  const data = {}, at = {}, problems = [];
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].trim() || /^\s*#/.test(lines[i])) continue;
    const lineNo = i + 2; // 1-based, after the opening ---
    const m = /^([\w.-]+)[ \t]*:(?:[ \t]+(.*))?$/.exec(lines[i]);
    if (!m) {
      problems.push({ line: lineNo, message: `can't parse "${lines[i].trim().slice(0, 60)}"` });
      continue;
    }
    const key = m[1], raw = (m[2] ?? '').trim();
    at[key] = lineNo;
    const block = [];
    while (i + 1 < lines.length && (!lines[i + 1].trim() || /^[ \t]/.test(lines[i + 1]) || (!raw && /^-(\s|$)/.test(lines[i + 1])))) {
      block.push(lines[++i]);
    }
    if (/^[|>][+-]?\d?$/.test(raw)) data[key] = blockScalar(raw, block);
    else if (!raw || raw.startsWith('#')) data[key] = collection(block);
    else data[key] = scalar(raw, block, lineNo, problems);
  }
  return { data, at, problems };
}

function scalar(raw, block, line, problems) {
  let value = [raw, ...block.map(l => l.trim()).filter(Boolean)].join(' ');
  if (value[0] === '"' || value[0] === "'") {
    if (value.length < 2 || value.at(-1) !== value[0]) problems.push({ line, message: 'quoted value is never closed' });
    return unquote(value);
  }
  if (value[0] === '[') return value.slice(1, -1).split(',').map(s => unquote(s.trim())).filter(Boolean);
  const comment = value.search(/\s#/);
  if (comment !== -1) {
    problems.push({ line, warn: true, message: 'everything after " #" is a YAML comment and gets dropped; quote the value to keep it' });
    value = value.slice(0, comment).trimEnd();
  }
  if (/:(\s|$)/.test(value)) problems.push({ line, message: 'unquoted value contains ": ", which strict YAML parsers reject; wrap the value in quotes' });
  else if (/^(- |[@`%&*!|>{])/.test(value)) problems.push({ line, message: `unquoted value can't start with "${value[0]}"; wrap it in quotes` });
  return value;
}

function collection(block) {
  const items = block.map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  if (!items.length) return null;
  if (items.every(l => /^-(\s|$)/.test(l))) return items.map(l => unquote(l.slice(1).trim()));
  const map = {};
  for (const l of items) {
    const kv = /^([^:]+?)\s*:(?:\s+(.*))?$/.exec(l);
    if (kv) map[unquote(kv[1])] = unquote(kv[2]?.trim() ?? '');
  }
  return map;
}

function blockScalar(indicator, block) {
  const filled = block.filter(l => l.trim());
  if (!filled.length) return '';
  const indent = Math.min(...filled.map(l => l.match(/^[ \t]*/)[0].length));
  const lines = block.map(l => l.slice(indent));
  let blankTail = 0;
  while (!lines.at(-1).trim()) { lines.pop(); blankTail++; }
  const text = indicator[0] === '|'
    ? lines.join('\n')
    : lines.join('\n').split(/\n\s*\n/).map(p => p.split('\n').join(' ')).join('\n');
  // Chomping: "-" strips the final newline, "+" keeps every trailing one, default keeps exactly one.
  return text + (indicator.includes('-') ? '' : '\n'.repeat(indicator.includes('+') ? blankTail + 1 : 1));
}

function unquote(s) {
  if (s.length >= 2 && s[0] === '"' && s.at(-1) === '"') {
    try { return JSON.parse(s); } catch { return s.slice(1, -1); }
  }
  if (s.length >= 2 && s[0] === "'" && s.at(-1) === "'") return s.slice(1, -1).replace(/''/g, "'");
  return s;
}

// ---------- Discovery ----------

/** Every folder holding a SKILL.md under root. A skill's own subfolders are its resources, not more skills. */
export function findSkills(root) {
  root = path.resolve(root);
  if (fs.statSync(root).isFile()) return SKILL_FILE.test(path.basename(root)) ? [path.dirname(root)] : [];
  const found = [];
  (function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    if (entries.some(e => e.isFile() && SKILL_FILE.test(e.name))) return found.push(dir);
    for (const e of entries) if (e.isDirectory() && !SKIP_DIRS.has(e.name)) walk(path.join(dir, e.name));
  })(root);
  return found;
}

// ---------- Checks ----------

/** Lint one skill folder. Findings carry absolute file paths. */
export function checkSkill(dir) {
  dir = path.resolve(dir);
  const entry = fs.readdirSync(dir).find(n => SKILL_FILE.test(n));
  if (!entry) throw new Error(`no SKILL.md in ${dir}`);
  const file = path.join(dir, entry);
  const findings = [];
  const add = (rule, f, line, message, snippet) =>
    findings.push({ rule, severity: RULES[rule], file: f, line, message, ...(snippet && { snippet }) });

  if (entry !== 'SKILL.md') add('filename-case', file, 1, `rename ${entry} to SKILL.md (file names are case-sensitive on Linux)`);
  const fm = parseFrontmatter(fs.readFileSync(file, 'utf8'));
  lintFrontmatter(fm, dir, file, add);
  lintBody(fm, dir, file, add);
  for (const f of walk(dir)) scanFile(f, add);
  // SKILL.md first, then the other files in path order.
  findings.sort((a, b) => (a.file !== file) - (b.file !== file) || (a.file < b.file ? -1 : a.file > b.file) || a.line - b.line);

  const name = typeof fm.data.name === 'string' && fm.data.name ? fm.data.name : path.basename(dir);
  return { name, dir, findings };
}

function lintFrontmatter({ error, data, at, problems }, dir, file, add) {
  if (error) {
    return add('frontmatter-missing', file, 1, error === 'missing'
      ? 'SKILL.md must start with YAML frontmatter between --- lines'
      : 'frontmatter is never closed with ---');
  }
  for (const p of problems) add(p.warn ? 'frontmatter-comment' : 'frontmatter-yaml', file, p.line, p.message);

  const { name, description, compatibility, metadata } = data;
  if (typeof name !== 'string' || !name) add('name-missing', file, at.name ?? 1, 'frontmatter needs a name');
  else {
    if (name.length > 64 || !NAME.test(name)) {
      add('name-invalid', file, at.name, `name "${name}" must be 1-64 lowercase letters, digits and single hyphens`);
    }
    const folder = path.basename(dir);
    if (name !== folder) add('name-mismatch', file, at.name, `name "${name}" must match its folder "${folder}"`);
  }

  if (typeof description !== 'string' || !description.trim()) {
    add('description-missing', file, at.description ?? 1, 'frontmatter needs a description saying what the skill does and when to use it');
  } else if (description.length > 1024) {
    add('description-too-long', file, at.description, `description is ${description.length} characters (max 1024)`);
  } else if (description.length < 40 || !TRIGGER.test(description)) {
    add('description-vague', file, at.description, 'description should say what the skill does and when to use it ("Use when …"), so agents know when to load it');
  }

  if (compatibility != null && (typeof compatibility !== 'string' || !compatibility || compatibility.length > 500)) {
    add('compatibility-invalid', file, at.compatibility, 'compatibility must be a 1-500 character string');
  }
  if (metadata != null && (typeof metadata !== 'object' || Array.isArray(metadata))) {
    add('metadata-invalid', file, at.metadata, 'metadata must be a map of string keys to string values');
  }

  const extra = Object.keys(data).filter(k => !SPEC_FIELDS.has(k));
  if (extra.length) add('unknown-field', file, at[extra[0]], `not in the Agent Skills spec, other agents may ignore: ${extra.join(', ')}`);

  const tools = [].concat(data['allowed-tools'] ?? []).join(' ').match(/[\w.-]+(\([^)]*\))?/g) ?? [];
  for (const t of tools) {
    if (/^(Bash|PowerShell|Shell)(\(\s*\*?(:\*)?\s*\))?$/i.test(t)) {
      add('broad-tools', file, at['allowed-tools'], `allowed-tools pre-approves "${t}" without limits; scope it, e.g. Bash(git:*)`);
    }
  }
}

function lintBody({ body, bodyLine }, dir, file, add) {
  const tokens = Math.round(body.join('\n').length / 4); // rough: ~4 characters per token
  if (body.length > 500 || tokens > 5000) {
    add('body-too-long', file, bodyLine, `body is ${body.length} lines / ~${tokens} tokens; keep SKILL.md under 500 lines / 5000 tokens and move details to references/`);
  }
  let fenced = false;
  body.forEach((line, i) => {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    if (fenced) return;
    for (const [, target] of line.replace(/`[^`]*`/g, '').matchAll(/\]\(\s*<?([^)\s>]+)>?(?:\s+["'][^)]*)?\)/g)) {
      if (/^([a-z][\w+.-]*:|#|\/)/i.test(target)) continue; // URLs, anchors, absolute paths
      let rel = target.replace(/[#?].*$/, '');
      try { rel = decodeURIComponent(rel); } catch { /* keep as written */ }
      if (!rel) continue;
      const abs = path.resolve(dir, rel);
      const inside = path.relative(dir, abs);
      if (inside.startsWith('..') || path.isAbsolute(inside)) {
        add('link-outside', file, bodyLine + i, `"${target}" points outside the skill folder and won't exist once the skill is installed on its own`);
      } else if (!fs.existsSync(abs)) {
        add('broken-link', file, bodyLine + i, `"${target}" does not exist`);
      }
    }
  });
}

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isSymbolicLink()) yield { file: p, symlink: true };
    else if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) yield* walk(p); }
    else if (e.isFile()) yield { file: p };
  }
}

function scanFile({ file, symlink }, add) {
  if (symlink) {
    let target = '?';
    try { target = fs.readlinkSync(file); } catch { /* unreadable link */ }
    return add('symlink', file, 1, `symlink to "${target}": the agent reads whatever it points to`);
  }
  let buf;
  try {
    const { size } = fs.statSync(file);
    buf = size > MAX_TEXT_BYTES ? readHead(file) : fs.readFileSync(file);
    if (EXEC_EXT.test(file) || isExecutable(buf)) add('binary-file', file, 1, 'ships a compiled binary: its behaviour cannot be reviewed from source');
    if (size > MAX_TEXT_BYTES) return;
  } catch { return; }

  let text;
  if (buf[0] === 0xff && buf[1] === 0xfe) text = buf.toString('utf16le');
  else if (buf.subarray(0, 8000).includes(0)) return; // images, fonts, archives
  else text = buf.toString('utf8');
  text.split(/\r?\n/).forEach((line, i) => scanLine(line, i, file, add));
}

function scanLine(line, i, file, add) {
  const smuggling = [...line.matchAll(SMUGGLING)];
  const invisible = [...line.matchAll(INVISIBLE)].filter(m => !(i === 0 && m.index === 0 && m[0] === '﻿'));
  if (smuggling.length || invisible.length) {
    const counts = {};
    for (const m of [...smuggling, ...invisible]) {
      for (const ch of m[0]) {
        const code = 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
        counts[code] = (counts[code] ?? 0) + 1;
      }
    }
    const codes = Object.entries(counts).slice(0, 5).map(([c, n]) => (n > 1 ? `${c}×${n}` : c)).join(', ');
    const hiddenText = [...line]
      .map(ch => ch.codePointAt(0))
      .filter(cp => cp >= 0xE0020 && cp <= 0xE007E)
      .map(cp => String.fromCharCode(cp - 0xE0000))
      .join('');
    const shown = clip(line.replace(ANY_HIDDEN, m => `⟨${[...m].length} hidden⟩`), 0);
    if (hiddenText) add('hidden-unicode', file, i + 1, `${hiddenText.length} invisible Unicode tag characters spell out hidden text: "${hiddenText.slice(0, 120)}"`, shown);
    else if (smuggling.length) add('hidden-unicode', file, i + 1, `invisible characters (${codes}) can reorder or hide text from human reviewers`, shown);
    else add('invisible-chars', file, i + 1, `zero-width characters (${codes}): often harmless, but they can hide text from reviewers`, shown);
  }
  const hit = new Set();
  for (const [rule, re] of PATTERNS) {
    if (hit.has(rule)) continue;
    const m = re.exec(line);
    if (m) {
      hit.add(rule);
      add(rule, file, i + 1, MESSAGES[rule], clip(line, m.index));
    }
  }
}

function clip(line, at) {
  const start = Math.max(0, at - 30);
  return line.slice(start, start + 120).trim().replace(/^[\uDC00-\uDFFF]|[\uD800-\uDBFF]$/g, '');
}

function readHead(file) {
  const fd = fs.openSync(file, 'r');
  try {
    const head = Buffer.alloc(8);
    fs.readSync(fd, head, 0, 8, 0);
    return head;
  } finally { fs.closeSync(fd); }
}

function isExecutable(buf) {
  const hex = buf.subarray(0, 4).toString('hex');
  return hex.startsWith('4d5a') // Windows PE (MZ)
    || hex === '7f454c46' // ELF
    || ['cffaedfe', 'cefaedfe', 'feedfacf', 'feedface', 'cafebabe'].includes(hex) // Mach-O, fat binaries
    || hex === '0061736d'; // WebAssembly
}
