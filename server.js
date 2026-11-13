const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Passwords come from environment variables (set as secrets on the host), never from the code.
const plain = [process.env.PASSWORD_1, process.env.PASSWORD_2, process.env.PASSWORD_3];
if (plain.some((p) => !p)) {
  console.error('Set PASSWORD_1, PASSWORD_2 and PASSWORD_3 environment variables.');
  process.exit(1);
}
// Hash them in memory at startup; plain text is not kept around for comparisons.
const hashes = plain.map((p) => {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: crypto.scryptSync(p, salt, 64).toString('hex') };
});
// Optional hints, one env var per password. Separate several hints with |
const hints = [process.env.HINT_1, process.env.HINT_2, process.env.HINT_3]
  .map((h) => (h || '').split('|').map((x) => x.trim()).filter(Boolean));
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const PORT = process.env.PORT || 3000;

function matches(input, { salt, hash }) {
  const got = crypto.scryptSync(String(input || ''), salt, 64);
  return crypto.timingSafeEqual(got, Buffer.from(hash, 'hex'));
}
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const app = express();
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 60 * 60 * 1000 }
}));

// At most 10 password attempts per IP every 15 minutes
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false,
  message: 'Too many attempts. Try again in 15 minutes.' });

const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>
:root{color-scheme:dark}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#141414;color:#e6e6e6;max-width:420px;margin:15vh auto;padding:0 1rem;line-height:1.5}
h1{font-weight:600;font-size:1.5rem;color:#fff}
input,button{font-size:1rem;padding:.7rem .8rem;width:100%;box-sizing:border-box;margin-top:.6rem;border-radius:10px;border:1px solid #333}
input{background:#1e1e1e;color:#fff;outline:none}
input:focus{border-color:#7c5cff}
button{background:#7c5cff;color:#fff;border:none;cursor:pointer;font-weight:600}
button:hover{background:#6a4be6}
.err{color:#ff6b6b}
.hint{margin-top:1.2rem;padding:.6rem .9rem;background:#1c1c1c;border:1px solid #2a2a2a;border-radius:10px;color:#aaa}
.hint ul{margin:.3rem 0 0;padding-left:1.2rem}
img{max-width:100%;border-radius:10px;display:block}
figure{margin:1.2rem 0}figcaption{color:#999;font-size:.9rem;margin-top:.4rem}
button.secondary{background:#2a2a2a}button.secondary:hover{background:#333}
</style></head><body>${body}</body></html>`;

function requireStep(step) {
  return (req, res, next) => ((req.session.step || 0) >= step ? next() : res.redirect('/'));
}

app.get('/', (req, res) => {
  const step = req.session.step || 0;
  if (step >= 3) return res.redirect('/protected');
  const err = req.session.error;
  req.session.error = null;
  res.send(page('Password', `<h1>Password ${step + 1} of 3</h1>
    <form method="POST" action="/check">
      <input type="password" name="password" required autofocus>
      <button>Continue</button>
    </form>${hints[step].length ? `<div class="hint"><strong>Hint${hints[step].length > 1 ? 's' : ''}:</strong><ul>${hints[step].map((h) => `<li>${esc(h)}</li>`).join('')}</ul></div>` : ''}${err ? `<p class="err">${esc(err)}</p>` : ''}`));
});

app.post('/check', limiter, (req, res) => {
  const step = req.session.step || 0;
  if (step < 3 && matches(req.body.password, hashes[step])) {
    req.session.regenerate(() => { req.session.step = step + 1; res.redirect('/'); });
  } else {
    req.session.error = 'Incorrect password';
    res.redirect('/');
  }
});

// Turns content.md into simple HTML.
// "# Title" = heading, "![caption](photo.jpg)" = picture from the images folder, blank line = new paragraph.
function renderContent() {
  let md = '';
  try { md = fs.readFileSync(path.join(__dirname, 'content.md'), 'utf8'); } catch { md = '# Access granted'; }
  return md.replace(/\r/g, '').split(/\n\s*\n/).map((block) => {
    const b = block.trim();
    if (!b) return '';
    const img = b.match(/^!\[(.*?)\]\((.+?)\)$/);
    if (img) {
      const file = path.basename(img[2]);
      return `<figure><img src="/images/${encodeURIComponent(file)}" alt="${esc(img[1])}">${img[1] ? `<figcaption>${esc(img[1])}</figcaption>` : ''}</figure>`;
    }
    const h = b.match(/^(#{1,3})\s+(.*)$/);
    if (h) return `<h${h[1].length}>${esc(h[2])}</h${h[1].length}>`;
    return `<p>${esc(b).replace(/\n/g, '<br>')}</p>`;
  }).join('\n');
}

// Pictures are only served after all three passwords are accepted.
app.get('/images/:file', requireStep(3), (req, res) => {
  const file = path.join(__dirname, 'images', path.basename(req.params.file));
  if (!fs.existsSync(file)) return res.status(404).send('Not found');
  res.sendFile(file);
});

app.get('/protected', requireStep(3), (req, res) => {
  res.send(page('Welcome', `${renderContent()}
    <form method="POST" action="/logout" style="margin-top:2rem"><button class="secondary">Log out</button></form>`));
});

app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
