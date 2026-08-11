require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const os = require('os');

const app = express();
app.use(express.static(__dirname));
app.get('/manifest.json', (req, res) => {
  res.status(200);
  res.type('application/manifest+json');

  res.send({
    background_color: "#ffffff",
    dir: "ltr",
    display: "standalone",
    name: "Trendora Workflow",
    orientation: "any",
    scope: "/",
    short_name: "Trendora",
    start_url: "/",
    theme_color: "#ffffff",
    id: "/",
    description: "Trendora helps affiliate marketers manage the entire product workflow — from sourcing and preparing products for Easy Order to creating marketing media and tracking customer delivery.",
    lang: "en",
    display_override: [
      "window-controls-overlay",
      "standalone"
    ],
    icons: [
      {
        src: "/launchericon-48x48.png",
        sizes: "48x48",
        type: "image/png"
      },
      {
        src: "/launchericon-72x72.png",
        sizes: "72x72",
        type: "image/png"
      },
      {
        src: "/launchericon-96x96.png",
        sizes: "96x96",
        type: "image/png"
      },
      {
        src: "/launchericon-144x144.png",
        sizes: "144x144",
        type: "image/png"
      },
      {
        src: "/launchericon-192x192.png",
        sizes: "192x192",
        type: "image/png"
      },
      {
        src: "/launchericon-512x512.png",
        sizes: "512x512",
        type: "image/png"
      }
    ]
  });
});
app.get('/launchericon-512x512.png', (req, res) => {
  res.sendFile(path.join(__dirname, 'launchericon-512x512.png'));
});
app.get('/launchericon-192x192.png', (req, res) => {
  res.sendFile(
    path.join(process.cwd(), 'launchericon-192x192.png')
  );
});
app.get('/launchericon-144x144.png', (req, res) => {
  res.sendFile(path.join(__dirname, 'launchericon-144x144.png'));
});

app.get('/launchericon-96x96.png', (req, res) => {
  res.sendFile(path.join(__dirname, 'launchericon-96x96.png'));
});

app.get('/launchericon-72x72.png', (req, res) => {
  res.sendFile(path.join(__dirname, 'launchericon-72x72.png'));
});

app.get('/launchericon-48x48.png', (req, res) => {
  res.sendFile(path.join(__dirname, 'launchericon-48x48.png'));
});
app.get('/pwabuilder-sw.js', (req, res) => {
  res.type('application/javascript');
  res.sendFile(path.join(__dirname, 'pwabuilder-sw.js'));
});
app.use(express.json({ limit: '2mb' }));

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.warn('WARNING: Set JWT_SECRET in environment variables.');
}

const transporter = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || 'false') === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    })
  : null;

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

function makeCode() {
  return String(crypto.randomInt(100000, 1000000));
}

async function sendCode(email, code, purpose) {
  if (!transporter) {
    console.log(`[DEV] ${purpose} code for ${email}: ${code}`);
    return;
  }

  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: email,
    subject:
      purpose === 'verify'
        ? 'Trendora email verification code'
        : 'Trendora password reset code',
    text: `Your Trendora code is ${code}. It expires in 10 minutes.`
  });
}

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';

    if (!h.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Authentication required.'
      });
    }

    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({
      error: 'Session expired. Please sign in again.'
    });
  }
}

async function issueCode(user, purpose) {
  const code = makeCode();
  const expires = Date.now() + 10 * 60 * 1000;

  const { error } = await supabase
    .from('verification_codes')
    .insert({
      user_id: user.id,
      email: user.email,
      purpose,
      code_hash: hashCode(code),
      expires_at: expires
    });

  if (error) throw error;

  await sendCode(user.email, code, purpose);
}

function tokenFor(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({
        error: 'All fields are required.'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters.'
      });
    }

    const normalized = email.trim().toLowerCase();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
      return res.status(400).json({
        error: 'Invalid email.'
      });
    }

    const { data: existing, error: existingError } = await supabase
      .from('users')
      .select('id')
      .eq('email', normalized)
      .maybeSingle();

    if (existingError) throw existingError;

    if (existing) {
      return res.status(409).json({
        error: 'An account with this email already exists.'
      });
    }

    const { data: user, error } = await supabase
      .from('users')
      .insert({
        first_name: firstName.trim(),
        last_name: lastName.trim(),
        email: normalized,
        password_hash: await bcrypt.hash(password, 12),
        created_at: new Date().toISOString()
      })
      .select('*')
      .single();

    if (error) throw error;

    await issueCode(user, 'verify');

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Could not create account.'
    });
  }
});

app.post('/api/auth/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body;

    const normalized = String(email || '').trim().toLowerCase();

    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('email', normalized)
      .maybeSingle();

    if (userError) throw userError;

    if (!user) {
      return res.status(400).json({
        error: 'Account not found.'
      });
    }

    const { data: rows, error } = await supabase
      .from('verification_codes')
      .select('*')
      .eq('user_id', user.id)
      .eq('purpose', 'verify')
      .eq('used', 0)
      .order('id', { ascending: false })
      .limit(1);

    if (error) throw error;

    const row = rows && rows[0];

    if (
      !row ||
      Date.now() > row.expires_at ||
      row.code_hash !== hashCode(String(code))
    ) {
      return res.status(400).json({
        error: 'Invalid or expired verification code.'
      });
    }

    await supabase
      .from('verification_codes')
      .update({ used: 1 })
      .eq('id', row.id);

    await supabase
      .from('users')
      .update({ email_verified: 1 })
      .eq('id', user.id);

    res.json({
      ok: true,
      token: tokenFor(user)
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Verification failed.'
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const normalized = String(email || '').trim().toLowerCase();

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', normalized)
      .maybeSingle();

    if (error) throw error;

    if (
      !user ||
      !(await bcrypt.compare(password || '', user.password_hash))
    ) {
      return res.status(401).json({
        error: 'Incorrect email or password.'
      });
    }

    if (!user.email_verified) {
      return res.json({
        requiresVerification: true
      });
    }

    res.json({
      token: tokenFor(user)
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Login failed.'
    });
  }
});

app.post('/api/auth/resend-verification', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (error) throw error;

    if (!user) {
      return res.status(400).json({
        error: 'Account not found.'
      });
    }

    if (user.email_verified) {
      return res.status(400).json({
        error: 'Email is already verified.'
      });
    }

    await issueCode(user, 'verify');

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Could not resend verification code.'
    });
  }
});

app.post('/api/auth/request-reset', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (error) throw error;

    if (user) {
      await issueCode(user, 'reset');
    }

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Could not process reset request.'
    });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters.'
      });
    }

    const normalized = String(email || '').trim().toLowerCase();

    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('email', normalized)
      .maybeSingle();

    if (userError) throw userError;

    if (!user) {
      return res.status(400).json({
        error: 'Invalid reset request.'
      });
    }

    const { data: rows, error } = await supabase
      .from('verification_codes')
      .select('*')
      .eq('user_id', user.id)
      .eq('purpose', 'reset')
      .eq('used', 0)
      .order('id', { ascending: false })
      .limit(1);

    if (error) throw error;

    const row = rows && rows[0];

    if (
      !row ||
      Date.now() > row.expires_at ||
      row.code_hash !== hashCode(String(code))
    ) {
      return res.status(400).json({
        error: 'Invalid or expired reset code.'
      });
    }

    await supabase
      .from('verification_codes')
      .update({ used: 1 })
      .eq('id', row.id);

    await supabase
      .from('users')
      .update({
        password_hash: await bcrypt.hash(newPassword, 12)
      })
      .eq('id', user.id);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Password reset failed.'
    });
  }
});
app.post('/api/auth/verify-reset-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    const normalized = String(email || '').trim().toLowerCase();

    if (!/^\d{6}$/.test(String(code || ''))) {
      return res.status(400).json({
        error: 'Invalid or expired reset code.'
      });
    }

    const { data: user, error: userError } = await supabase
      .from('users')
      .select('id')
      .eq('email', normalized)
      .maybeSingle();

    if (userError) throw userError;

    if (!user) {
      return res.status(400).json({
        error: 'Invalid or expired reset code.'
      });
    }

    const { data: rows, error } = await supabase
      .from('verification_codes')
      .select('*')
      .eq('user_id', user.id)
      .eq('purpose', 'reset')
      .eq('used', 0)
      .order('id', { ascending: false })
      .limit(1);

    if (error) throw error;

    const row = rows && rows[0];

    if (
      !row ||
      Date.now() > row.expires_at ||
      row.code_hash !== hashCode(String(code))
    ) {
      return res.status(400).json({
        error: 'Invalid or expired reset code.'
      });
    }

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Could not verify reset code.'
    });
  }
});
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({
        error: 'New password must be at least 8 characters.'
      });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .maybeSingle();

    if (error) throw error;

    if (
      !user ||
      !(await bcrypt.compare(
        currentPassword || '',
        user.password_hash
      ))
    ) {
      return res.status(400).json({
        error: 'Current password is incorrect.'
      });
    }

    await issueCode(user, 'reset');

    res.json({
      ok: true,
      requiresCode: true,
      message: 'A verification code was sent to your email.'
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Could not change password.'
    });
  }
});

app.post('/api/auth/confirm-change-password', auth, async (req, res) => {
  try {
    const { code, newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({
        error: 'New password must be at least 8 characters.'
      });
    }

    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .maybeSingle();

    if (userError) throw userError;

    if (!user) {
      return res.status(400).json({
        error: 'User not found.'
      });
    }

    const { data: rows, error } = await supabase
      .from('verification_codes')
      .select('*')
      .eq('user_id', user.id)
      .eq('purpose', 'reset')
      .eq('used', 0)
      .order('id', { ascending: false })
      .limit(1);

    if (error) throw error;

    const row = rows && rows[0];

    if (
      !row ||
      Date.now() > row.expires_at ||
      row.code_hash !== hashCode(String(code))
    ) {
      return res.status(400).json({
        error: 'Invalid or expired verification code.'
      });
    }

    await supabase
      .from('verification_codes')
      .update({ used: 1 })
      .eq('id', row.id);

    await supabase
      .from('users')
      .update({
        password_hash: await bcrypt.hash(newPassword, 12)
      })
      .eq('id', user.id);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Password change failed.'
    });
  }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const { data: u, error } = await supabase
      .from('users')
      .select(
        'id,first_name,last_name,email,email_verified,avatar,cover'
      )
      .eq('id', req.user.id)
      .maybeSingle();

    if (error) throw error;

    if (!u) {
      return res.status(404).json({
        error: 'User not found.'
      });
    }

    res.json({
      user: {
        id: u.id,
        firstName: u.first_name,
        lastName: u.last_name,
        email: u.email,
        emailVerified: u.email_verified,
        avatar: u.avatar,
        cover: u.cover
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Could not load user.'
    });
  }
});
app.put('/api/me', auth, async (req, res) => {
  try {
    const { firstName, lastName, avatar, cover } = req.body;

    const { data, error } = await supabase
      .from('users')
      .update({
        first_name: firstName,
        last_name: lastName,
        avatar: avatar || '',
        cover: cover || ''
      })
      .eq('id', req.user.id)
      .select()
      .single();

    if (error) throw error;

    res.json({ user: data });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not update profile.' });
  }
});
app.post('/api/auth/logout', (req, res) => {
  res.json({ ok: true });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const port = Number(process.env.PORT || 3000);

app.listen(port, () => {
  console.log(`Trendora V6 running on port ${port}`);
});
