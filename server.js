import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import pg from 'pg';

const { Pool } = pg;

const __dirname =
  path.dirname(
    fileURLToPath(import.meta.url)
  );

const publicDir =
  path.join(
    __dirname,
    'public'
  );

const privateDir =
  path.join(
    __dirname,
    'private_uploads'
  );

fs.mkdirSync(
  privateDir,
  {
    recursive: true,
    mode: 0o700
  }
);

const required = [
  'DATABASE_URL',
  'SESSION_SECRET',
  'APP_URL'
];

for (const key of required) {
  if (!process.env[key]) {
    throw new Error(
      `Missing environment variable: ${key}`
    );
  }
}

const pool =
  new Pool({
    connectionString:
      process.env.DATABASE_URL,

    max: 10,

    ssl:
      process.env.NODE_ENV === 'production'
        ? {
            rejectUnauthorized:
              false
          }
        : false
  });

const app = express();

app.disable(
  'x-powered-by'
);

app.set(
  'trust proxy',
  1
);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],

        scriptSrc: ["'self'"],

        styleSrc: [
          "'self'",
          "'unsafe-inline'"
        ],

        imgSrc: [
          "'self'",
          'data:',
          'blob:'
        ],

        connectSrc: [
          "'self'"
        ],

        objectSrc: [
          "'none'"
        ],

        frameAncestors: [
          "'none'"
        ],

        baseUri: [
          "'self'"
        ],

        formAction: [
          "'self'"
        ]
      }
    }
  })
);

app.use(
  express.json({
    limit: '1mb'
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: '1mb'
  })
);

app.use(
  express.static(
    publicDir,
    {
      index: 'index.html'
    }
  )
);

const authLimiter =
  rateLimit({
    windowMs:
      15 * 60 * 1000,

    limit: 40,

    standardHeaders: true,

    legacyHeaders: false
  });

const upload =
  multer({
    dest: privateDir,

    limits: {
      fileSize:
        8 * 1024 * 1024,

      files: 1
    },

    fileFilter:
      (_req, file, cb) => {

        cb(
          null,

          [
            'image/jpeg',
            'image/png'
          ].includes(
            file.mimetype
          )
        );

      }
  });

const cookieName =
  'alpha1_session';

const pochiNumber =
  process.env.POCHI_DISPLAY_NUMBER ||
  '01018078137';

function nowPlusMinutes(
  minutes
) {
  return new Date(
    Date.now() +
      minutes * 60 * 1000
  );
}

function hashToken(
  token
) {
  return crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
}

function randomToken(
  size = 32
) {
  return crypto
    .randomBytes(size)
    .toString('hex');
}

function parseCookies(
  header = ''
) {
  const out = {};

  for (
    const part of
    header.split(';')
  ) {

    const [
      k,
      ...rest
    ] =
      part
        .trim()
        .split('=');

    if (k) {
      out[k] =
        decodeURIComponent(
          rest.join('=')
        );
    }
  }

  return out;
}

function setSessionCookie(
  res,
  token
) {
  const secure =
    process.env.COOKIE_SECURE !==
    'false';

  res.setHeader(
    'Set-Cookie',

    `${cookieName}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax${
      secure
        ? '; Secure'
        : ''
    }`
  );
}

function clearSessionCookie(
  res
) {
  const secure =
    process.env.COOKIE_SECURE !==
    'false';

  res.setHeader(
    'Set-Cookie',

    `${cookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${
      secure
        ? '; Secure'
        : ''
    }`
  );
}

async function audit(
  userId,
  action,
  detail = {}
) {
  await pool.query(
    `
      INSERT INTO audit_log
        (user_id, action, detail)
      VALUES
        ($1, $2, $3)
    `,
    [
      userId ?? null,
      action,
      detail
    ]
  );
}

async function createSession(
  userId
) {
  const token =
    randomToken();

  const csrf =
    randomToken(24);

  await pool.query(
    `
      INSERT INTO sessions
        (
          user_id,
          token_hash,
          csrf_token,
          expires_at
        )
      VALUES
        ($1, $2, $3, $4)
    `,
    [
      userId,
      hashToken(token),
      csrf,
      nowPlusMinutes(720)
    ]
  );

  return {
    token,
    csrf
  };
}

async function getSession(
  req
) {
  const cookies =
    parseCookies(
      req.headers.cookie
    );

  const token =
    cookies[cookieName];

  if (!token) {
    return null;
  }

  const { rows } =
    await pool.query(
      `
        SELECT
          s.*,
          u.id AS user_id,
          u.email,
          u.phone,
          u.id_number,
          u.role,
          u.status,
          u.wallet_cents,
          u.kyc_status,
          u.front_id_key,
          u.back_id_key

        FROM sessions s

        JOIN users u
          ON u.id = s.user_id

        WHERE
          s.token_hash = $1

          AND s.expires_at > now()
      `,
      [
        hashToken(token)
      ]
    );

  if (!rows[0]) {
    return null;
  }

  return {
    token,
    ...rows[0]
  };
}

async function auth(
  req,
  res,
  next
) {
  req.user =
    await getSession(req);

  if (!req.user) {
    return res
      .status(401)
      .json({
        message:
          'Authentication required'
      });
  }

  if (
    req.user.status !==
    'active'
  ) {
    return res
      .status(403)
      .json({
        message:
          'Account is suspended'
      });
  }

  next();
}

function csrf(
  req,
  res,
  next
) {
  const header =
    req.get(
      'x-csrf-token'
    );

  if (
    !header ||
    header !==
      req.user.csrf_token
  ) {
    return res
      .status(403)
      .json({
        message:
          'Invalid CSRF token'
      });
  }

  next();
}

function parseMoney(
  value
) {
  const n =
    Number(value);

  if (
    !Number.isFinite(n) ||
    n <= 0 ||
    n > 100000000
  ) {
    return null;
  }

  return Math.round(
    n * 100
  );
}

async function initAdmin() {
  const email =
    String(
      process.env
        .ALPHA1_ADMIN_EMAIL ||
        'vinnieyk67652gmail.com'
    )
      .trim()
      .toLowerCase();

  const password =
    process.env
      .ALPHA1_ADMIN_PASSWORD;

  if (!password) {
    throw new Error(
      'Set ALPHA1_ADMIN_PASSWORD on the server before startup.'
    );
  }

  const existing =
    await pool.query(
      `
        SELECT id
        FROM users
        WHERE email = $1
      `,
      [email]
    );

  if (
    !existing.rows[0]
  ) {
    const hash =
      await bcrypt.hash(
        password,
        12
      );

    const r =
      await pool.query(
        `
          INSERT INTO users
            (
              email,
              phone,
              id_number,
              password_hash,
              role
            )
          VALUES
            (
              $1,
              $2,
              $3,
              $4,
              'admin'
            )

          RETURNING id
        `,
        [
          email,
          'ADMIN',

          `ADMIN-${crypto
            .randomBytes(6)
            .toString('hex')}`,

          hash
        ]
      );

    await audit(
      r.rows[0].id,
      'ADMIN_BOOTSTRAPPED'
    );
  }
}

async function mpesaToken() {
  const env =
    process.env.MPESA_ENV ===
    'production'
      ? 'production'
      : 'sandbox';

  const base =
    env === 'production'
      ? 'https://api.safaricom.co.ke'
      : 'https://sandbox.safaricom.co.ke';

  const key =
    process.env
      .MPESA_CONSUMER_KEY;

  const secret =
    process.env
      .MPESA_CONSUMER_SECRET;

  if (
    !key ||
    !secret
  ) {
    throw new Error(
      'M-Pesa Daraja credentials are not configured.'
    );
  }

  const basic =
    Buffer
      .from(
        `${key}:${secret}`
      )
      .toString('base64');

  const r =
    await fetch(
      `${base}/oauth/v1/generate?grant_type=client_credentials`,
      {
        headers: {
          Authorization:
            `Basic ${basic}`
        }
      }
    );

  if (!r.ok) {
    throw new Error(
      `Daraja auth failed: ${r.status}`
    );
  }

  const j =
    await r.json();

  return {
    token:
      j.access_token,

    base
  };
}

async function registerMpesaUrls() {
  const {
    token,
    base
  } =
    await mpesaToken();

  const shortcode =
    process.env
      .MPESA_SHORTCODE;

  const confirmation =
    process.env
      .MPESA_C2B_CONFIRMATION_URL;

  const validation =
    process.env
      .MPESA_C2B_VALIDATION_URL;

  if (
    !shortcode ||
    !confirmation ||
    !validation
  ) {
    throw new Error(
      'M-Pesa C2B environment variables are incomplete.'
    );
  }

  const r =
    await fetch(
      `${base}/mpesa/c2b/v2/registerurl`,
      {
        method: 'POST',

        headers: {
          Authorization:
            `Bearer ${token}`,

          'Content-Type':
            'application/json'
        },

        body:
          JSON.stringify({
            ShortCode:
              shortcode,

            ResponseType:
              process.env
                .MPESA_C2B_RESPONSE_TYPE ||
              'Completed',

            ConfirmationURL:
              confirmation,

            ValidationURL:
              validation
          })
      }
    );

  return {
    ok: r.ok,
    status: r.status,
    body:
      await r.text()
  };
}

/*
 * Health
 */

app.get(
  '/api/health',
  async (_req, res) => {

    const db =
      await pool.query(
        'SELECT now() AS now'
      );

    res.json({
      ok: true,

      service:
        'ALPHA 1',

      database:
        Boolean(
          db.rows[0]
        )
    });
  }
);

/*
 * Registration
 */

app.post(
  '/api/auth/register',
  authLimiter,

  async (
    req,
    res
  ) => {

    const {
      email,
      phone,
      idNumber,
      password
    } = req.body || {};

    if (
      !/^\S+@\S+\.\S+$/.test(
        String(email || '')
      )
    ) {
      return res
        .status(400)
        .json({
          message:
            'Valid email required'
        });
    }

    if (
      String(phone || '')
        .trim()
        .length < 7
    ) {
      return res
        .status(400)
        .json({
          message:
            'Valid phone required'
        });
    }

    if (
      String(idNumber || '')
        .trim()
        .length < 4
    ) {
      return res
        .status(400)
        .json({
          message:
            'Valid ID number required'
        });
    }

    if (
      String(password || '')
        .length < 10
    ) {
      return res
        .status(400)
        .json({
          message:
            'Password must be at least 10 characters'
        });
    }

    const hash =
      await bcrypt.hash(
        password,
        12
      );

    try {

      const r =
        await pool.query(
          `
            INSERT INTO users
              (
                email,
                phone,
                id_number,
                password_hash
              )

            VALUES
              (
                $1,
                $2,
                $3,
                $4
              )

            RETURNING id
          `,
          [
            String(email)
              .trim()
              .toLowerCase(),

            String(phone)
              .trim(),

            String(idNumber)
              .trim(),

            hash
          ]
        );

      const session =
        await createSession(
          r.rows[0].id
        );

      setSessionCookie(
        res,
        session.token
      );

      await audit(
        r.rows[0].id,
        'REGISTERED'
      );

      res
        .status(201)
        .json({
          ok: true,
          csrfToken:
            session.csrf
        });

    } catch (e) {

      if (
        e.code ===
        '23505'
      ) {
        return res
          .status(409)
          .json({
            message:
              'Email or ID number already exists'
          });
      }

      throw e;
    }
  }
);

/*
 * Login
 */

app.post(
  '/api/auth/login',
  authLimiter,

  async (
    req,
    res
  ) => {

    const email =
      String(
        req.body?.email || ''
      )
        .trim()
        .toLowerCase();

    const password =
      String(
        req.body?.password || ''
      );

    const { rows } =
      await pool.query(
        `
          SELECT *
          FROM users
          WHERE email = $1
        `,
        [email]
      );

    const user =
      rows[0];

    if (
      !user ||
      user.status !==
        'active' ||
      !(
        await bcrypt.compare(
          password,
          user.password_hash
        )
      )
    ) {
      return res
        .status(401)
        .json({
          message:
            'Invalid credentials'
        });
    }

    const session =
      await createSession(
        user.id
      );

    setSessionCookie(
      res,
      session.token
    );

    await audit(
      user.id,
      'LOGIN'
    );

    res.json({
      ok: true,

      role:
        user.role,

      csrfToken:
        session.csrf
    });
  }
);

/*
 * Logout
 */

app.post(
  '/api/auth/logout',

  auth,
  csrf,

  async (
    req,
    res
  ) => {

    await pool.query(
      `
        DELETE FROM sessions
        WHERE token_hash = $1
      `,
      [
        hashToken(
          req.user.token
        )
      ]
    );

    clearSessionCookie(
      res
    );

    res.json({
      ok: true
    });
  }
);

/*
 * Current user
 */

app.get(
  '/api/me',

  auth,

  async (
    req,
    res
  ) => {

    res.json({
      user: {
        id:
          req.user.user_id,

        email:
          req.user.email,

        phone:
          req.user.phone,

        idNumber:
          req.user.id_number,

        role:
          req.user.role,

        walletCents:
          req.user.wallet_cents,

        kycStatus:
          req.user.kyc_status
      },

      csrfToken:
        req.user.csrf_token
    });
  }
);

/*
 * KYC - front
 */

app.post(
  '/api/kyc/front',

  auth,
  csrf,

  upload.single(
    'image'
  ),

  async (
    req,
    res
  ) => {

    if (!req.file) {
      return res
        .status(400)
        .json({
          message:
            'Front ID image required'
        });
    }

    const key =
      `${req.user.user_id}/front-${crypto.randomUUID()}${
        path.extname(
          req.file.originalname
        ).toLowerCase() ||
        '.jpg'
      }`;

    const dest =
      path.join(
        privateDir,
        key
      );

    fs.mkdirSync(
      path.dirname(dest),
      {
        recursive: true,
        mode: 0o700
      }
    );

    fs.renameSync(
      req.file.path,
      dest
    );

    await pool.query(
      `
        UPDATE users
        SET
          front_id_key = $1,

          kyc_status =
            CASE
              WHEN back_id_key IS NOT NULL
                THEN 'submitted'
              ELSE 'pending'
            END

        WHERE id = $2
      `,
      [
        key,
        req.user.user_id
      ]
    );

    await audit(
      req.user.user_id,
      'KYC_FRONT_UPLOADED'
    );

    res
      .status(201)
      .json({
        ok: true
      });
  }
);

/*
 * KYC - back
 */

app.post(
  '/api/kyc/back',

  auth,
  csrf,

  upload.single(
    'image'
  ),

  async (
    req,
    res
  ) => {

    if (
      !req.user.front_id_key
    ) {
      return res
        .status(400)
        .json({
          message:
            'Upload the front side first'
        });
    }

    if (!req.file) {
      return res
        .status(400)
        .json({
          message:
            'Back ID image required'
        });
    }

    const key =
      `${req.user.user_id}/back-${crypto.randomUUID()}${
        path.extname(
          req.file.originalname
        ).toLowerCase() ||
        '.jpg'
      }`;

    const dest =
      path.join(
        privateDir,
        key
      );

    fs.mkdirSync(
      path.dirname(dest),
      {
        recursive: true,
        mode: 0o700
      }
    );

    fs.renameSync(
      req.file.path,
      dest
    );

    await pool.query(
      `
        UPDATE users
        SET
          back_id_key = $1,
          kyc_status = 'submitted'
        WHERE id = $2
      `,
      [
        key,
        req.user.user_id
      ]
    );

    await audit(
      req.user.user_id,
      'KYC_BACK_UPLOADED'
    );

    res
      .status(201)
      .json({
        ok: true
      });
  }
);

/*
 * Deposit start
 */

app.post(
  '/api/deposits/start',

  auth,
  csrf,

  async (
    req,
    res
  ) => {

    const amountCents =
      parseMoney(
        req.body?.amount
      );

    if (!amountCents) {
      return res
        .status(400)
        .json({
          message:
            'Invalid amount'
        });
    }

    const expires =
      nowPlusMinutes(1);

    const r =
      await pool.query(
        `
          INSERT INTO deposits
            (
              user_id,
              amount_cents,
              expires_at
            )

          VALUES
            (
              $1,
              $2,
              $3
            )

          RETURNING
            id,
            amount_cents,
            expires_at
        `,
        [
          req.user.user_id,
          amountCents,
          expires
        ]
      );

    await audit(
      req.user.user_id,
      'DEPOSIT_STARTED',
      {
        depositId:
          r.rows[0].id
      }
    );

    res
      .status(201)
      .json({
        deposit: {
          ...r.rows[0],

          displayNumber:
            pochiNumber
        }
      });
  }
);

/*
 * Submit copied M-Pesa confirmation
 */

app.post(
  '/api/deposits/submit-message',

  auth,
  csrf,

  async (
    req,
    res
  ) => {

    const id =
      Number(
        req.body?.depositId
      );

    const reference =
      String(
        req.body?.reference ||
          ''
      ).trim();

    const message =
      String(
        req.body?.message ||
          ''
      ).trim();

    if (
      !id ||
      !reference ||
      message.length < 8
    ) {
      return res
        .status(400)
        .json({
          message:
            'Deposit ID, M-Pesa reference and message are required'
        });
    }

    const r =
      await pool.query(
        `
          UPDATE deposits

          SET
            reference = $1,
            mpesa_message = $2

          WHERE
            id = $3

            AND user_id = $4

            AND status = 'pending'

            AND expires_at > now()

          RETURNING id
        `,
        [
          reference.slice(
            0,
            80
          ),

          message.slice(
            0,
            2000
          ),

          id,

          req.user.user_id
        ]
      );

    if (!r.rows[0]) {
      return res
        .status(410)
        .json({
          message:
            'Deposit request expired or already processed'
        });
    }

    await audit(
      req.user.user_id,
      'DEPOSIT_MESSAGE_SUBMITTED',
      {
        depositId:
          id
      }
    );

    res.json({
      ok: true,
      status:
        'pending_verification'
    });
  }
);

/*
 * User deposit history
 */

app.get(
  '/api/deposits',

  auth,

  async (
    req,
    res
  ) => {

    const { rows } =
      await pool.query(
        `
          SELECT
            id,
            amount_cents,
            status,
            reference,
            mpesa_receipt,
            created_at,
            expires_at

          FROM deposits

          WHERE user_id = $1

          ORDER BY id DESC

          LIMIT 100
        `,
        [
          req.user.user_id
        ]
      );

    res.json({
      deposits:
        rows
    });
  }
);

/*
 * Withdrawal request
 */

app.post(
  '/api/withdrawals',

  auth,
  csrf,

  async (
    req,
    res
  ) => {

    const amountCents =
      parseMoney(
        req.body?.amount
      );

    const destination =
      String(
        req.body?.destination ||
          ''
      ).trim();

    if (
      !amountCents ||
      !destination
    ) {
      return res
        .status(400)
        .json({
          message:
            'Valid amount and destination required'
        });
    }

    const client =
      await pool.connect();

    try {

      await client.query(
        'BEGIN'
      );

      const { rows } =
        await client.query(
          `
            SELECT wallet_cents

            FROM users

            WHERE id = $1

            FOR UPDATE
          `,
          [
            req.user.user_id
          ]
        );

      if (
        !rows[0] ||
        Number(
          rows[0].wallet_cents
        ) < amountCents
      ) {

        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            message:
              'Insufficient wallet balance'
          });
      }

      const r =
        await client.query(
          `
            INSERT INTO withdrawals
              (
                user_id,
                amount_cents,
                destination
              )

            VALUES
              (
                $1,
                $2,
                $3
              )

            RETURNING id
          `,
          [
            req.user.user_id,
            amountCents,
            destination
          ]
        );

      await client.query(
        'COMMIT'
      );

      await audit(
        req.user.user_id,
        'WITHDRAWAL_REQUESTED',
        {
          withdrawalId:
            r.rows[0].id
        }
      );

      res
        .status(201)
        .json({
          ok: true,

          withdrawalId:
            r.rows[0].id
        });

    } catch (e) {

      await client.query(
        'ROLLBACK'
      );

      throw e;

    } finally {

      client.release();

    }
  }
);

/*
 * Admin middleware
 */

function requireAdmin(
  req,
  res,
  next
) {

  if (
    req.user.role !==
    'admin'
  ) {
    return res
      .status(403)
      .json({
        message:
          'Admin only'
      });
  }

  next();
}

/*
 * Admin deposits
 */

app.get(
  '/api/admin/deposits',

  auth,
  requireAdmin,

  async (
    _req,
    res
  ) => {

    const { rows } =
      await pool.query(
        `
          SELECT
            d.*,
            u.email

          FROM deposits d

          JOIN users u
            ON u.id = d.user_id

          ORDER BY d.id DESC

          LIMIT 200
        `
      );

    res.json({
      deposits:
        rows
    });
  }
);

/*
 * Admin approve deposit
 */

app.post(
  '/api/admin/deposits/:id/approve',

  auth,
  requireAdmin,
  csrf,

  async (
    req,
    res
  ) => {

    const depositId =
      Number(
        req.params.id
      );

    const client =
      await pool.connect();

    try {

      await client.query(
        'BEGIN'
      );

      const { rows } =
        await client.query(
          `
            SELECT *

            FROM deposits

            WHERE id = $1

              AND status IN (
                'pending',
                'matched'
              )

            FOR UPDATE
          `,
          [
            depositId
          ]
        );

      const dep =
        rows[0];

      if (!dep) {

        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            message:
              'Deposit not found'
          });
      }

      await client.query(
        `
          UPDATE deposits

          SET
            status = 'approved',
            reviewed_by = $1,
            reviewed_at = now()

          WHERE id = $2
        `,
        [
          req.user.user_id,
          depositId
        ]
      );

      await client.query(
        `
          UPDATE users

          SET
            wallet_cents =
              wallet_cents +
              $1

          WHERE id = $2
        `,
        [
          dep.amount_cents,
          dep.user_id
        ]
      );

      await client.query(
        `
          INSERT INTO ledger_entries
            (
              user_id,
              amount_cents,
              type,
              reference
            )

          VALUES
            (
              $1,
              $2,
              'deposit',
              $3
            )
        `,
        [
          dep.user_id,
          dep.amount_cents,
          `deposit:${depositId}`
        ]
      );

      await client.query(
        'COMMIT'
      );

      await audit(
        req.user.user_id,
        'DEPOSIT_APPROVED',
        {
          depositId
        }
      );

      res.json({
        ok: true
      });

    } catch (e) {

      await client.query(
        'ROLLBACK'
      );

      throw e;

    } finally {

      client.release();

    }
  }
);

/*
 * Admin reject deposit
 */

app.post(
  '/api/admin/deposits/:id/reject',

  auth,
  requireAdmin,
  csrf,

  async (
    req,
    res
  ) => {

    const depositId =
      Number(
        req.params.id
      );

    const r =
      await pool.query(
        `
          UPDATE deposits

          SET
            status = 'rejected',
            reviewed_by = $1,
            reviewed_at = now()

          WHERE id = $2

            AND status IN (
              'pending',
              'matched'
            )

          RETURNING id
        `,
        [
          req.user.user_id,
          depositId
        ]
      );

    if (!r.rows[0]) {
      return res
        .status(404)
        .json({
          message:
            'Deposit not found'
        });
    }

    await audit(
      req.user.user_id,
      'DEPOSIT_REJECTED',
      {
        depositId
      }
    );

    res.json({
      ok: true
    });
  }
);

/*
 * Admin withdrawals
 */

app.get(
  '/api/admin/withdrawals',

  auth,
  requireAdmin,

  async (
    _req,
    res
  ) => {

    const { rows } =
      await pool.query(
        `
          SELECT
            w.*,
            u.email

          FROM withdrawals w

          JOIN users u
            ON u.id = w.user_id

          ORDER BY w.id DESC

          LIMIT 200
        `
      );

    res.json({
      withdrawals:
        rows
    });
  }
);

/*
 * Private KYC image
 */

app.get(
  '/private/id/:userId/:side',

  auth,
  requireAdmin,

  async (
    req,
    res
  ) => {

    const userId =
      Number(
        req.params.userId
      );

    const side =
      req.params.side;

    if (
      ![
        'front',
        'back'
      ].includes(side)
    ) {
      return res
        .status(400)
        .end();
    }

    const field =
      side === 'front'
        ? 'front_id_key'
        : 'back_id_key';

    const { rows } =
      await pool.query(
        `
          SELECT
            ${field} AS key

          FROM users

          WHERE id = $1
        `,
        [
          userId
        ]
      );

    const key =
      rows[0]?.key;

    if (!key) {
      return res
        .status(404)
        .end();
    }

    const absolute =
      path.resolve(
        privateDir,
        key
      );

    const privateRoot =
      path.resolve(
        privateDir
      ) + path.sep;

    if (
      !absolute.startsWith(
        privateRoot
      )
    ) {
      return res
        .status(404)
        .end();
    }

    if (
      !fs.existsSync(
        absolute
      )
    ) {
      return res
        .status(404)
        .end();
    }

    res.sendFile(
      absolute
    );
  }
);

/*
 * M-Pesa C2B validation callback
 */

app.post(
  '/webhooks/mpesa/c2b/validate',

  express.json(),

  async (
    _req,
    res
  ) => {

    /*
     * Production validation rules
     * should be added after the
     * exact Daraja product/account
     * configuration is confirmed.
     */

    res.json({
      ResultCode: '0',
      ResultDesc:
        'Accepted'
    });
  }
);

/*
 * M-Pesa C2B confirmation callback
 */

app.post(
  '/webhooks/mpesa/c2b/confirm',

  express.json(),

  async (
    req,
    res
  ) => {

    const p =
      req.body || {};

    const receipt =
      p.TransID
        ? String(p.TransID)
        : null;

    const amountCents =
      parseMoney(
        p.TransAmount
      );

    const reference =
      String(
        p.BillRefNumber ||
          ''
      ).trim();

    const transTime =
      String(
        p.TransTime ||
          ''
      ).trim();

    try {

      await pool.query(
        `
          INSERT INTO mpesa_events
            (
              transaction_type,
              trans_id,
              trans_time,
              trans_amount_cents,
              business_short_code,
              bill_ref_number,
              phone_hash,
              raw_payload
            )

          VALUES
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7,
              $8
            )

          ON CONFLICT (trans_id)
          DO NOTHING
        `,
        [
          p.TransactionType ||
            null,

          receipt,

          transTime ||
            null,

          amountCents,

          p.BusinessShortCode ||
            null,

          reference ||
            null,

          p.MSISDN
            ? crypto
                .createHash('sha256')
                .update(
                  String(
                    p.MSISDN
                  )
                )
                .digest('hex')
            : null,

          p
        ]
      );

      if (
        receipt &&
        amountCents &&
        reference
      ) {

        const d =
          await pool.query(
            `
              UPDATE deposits

              SET
                status = 'matched',
                mpesa_receipt = $1,
                mpesa_transaction_time =
                  to_timestamp(
                    $2,
                    'YYYYMMDDHH24MISS'
                  )

              WHERE
                reference = $3

                AND amount_cents = $4

                AND status = 'pending'

                AND expires_at > now()

              RETURNING id
            `,
            [
              receipt,
              transTime,
              reference,
              amountCents
            ]
          );

        if (
          d.rows[0]
        ) {

          await audit(
            null,
            'MPESA_DEPOSIT_MATCHED',
            {
              depositId:
                d.rows[0].id,

              receipt
            }
          );
        }
      }

      res.json({
        ResultCode: 0,
        ResultDesc:
          'Accepted'
      });

    } catch (e) {

      console.error(
        'M-Pesa confirmation error:',
        e
      );

      /*
       * Do not cause Safaricom
       * to repeatedly resend
       * an already received event
       * because of an internal error.
       */

      res.json({
        ResultCode: 0,
        ResultDesc:
          'Accepted'
      });
    }
  }
);

/*
 * Admin registers M-Pesa URLs
 */

app.get(
  '/api/integrations/mpesa/register-urls',

  auth,
  requireAdmin,

  async (
    _req,
    res
  ) => {

    try {

      const result =
        await registerMpesaUrls();

      res.json(
        result
      );

    } catch (e) {

      res
        .status(500)
        .json({
          message:
            e.message
        });
    }
  }
);

/*
 * Market connection status
 */

app.get(
  '/api/market/status',

  auth,

  async (
    _req,
    res
  ) => {

    const configured =
      Boolean(
        process.env
          .BROKER_PROVIDER &&

        process.env
          .CTRADER_CLIENT_ID &&

        process.env
          .CTRADER_CLIENT_SECRET
      );

    res.json({
      configured,

      provider:
        process.env
          .BROKER_PROVIDER ||
        null,

      liveReady:
        configured &&
        process.env
          .NODE_ENV ===
          'production'
    });
  }
);

/*
 * Start broker OAuth
 */

app.get(
  '/auth/ctrader/start',

  auth,

  (
    req,
    res
  ) => {

    if (
      !process.env
        .CTRADER_CLIENT_ID ||
      !process.env
        .CTRADER_REDIRECT_URI
    ) {
      return res
        .status(503)
        .send(
          'cTrader credentials are not configured.'
        );
    }

    const params =
      new URLSearchParams({
        client_id:
          process.env
            .CTRADER_CLIENT_ID,

        redirect_uri:
          process.env
            .CTRADER_REDIRECT_URI,

        scope:
          'accounts',

        product:
          'web'
      });

    res.redirect(
      `https://id.ctrader.com/my/settings/openapi/grantingaccess/?${params.toString()}`
    );
  }
);

/*
 * Live quotes
 */

app.get(
  '/api/market/quotes',

  auth,

  async (
    _req,
    res
  ) => {

    if (
      !process.env
        .BROKER_PROVIDER
    ) {
      return res
        .status(503)
        .json({
          message:
            'Broker integration not configured'
        });
    }

    return res
      .status(501)
      .json({
        message:
          'Broker adapter credentials are required before live quotes are enabled.'
      });
  }
);

/*
 * Real trading endpoint
 *
 * This intentionally refuses to
 * fake an execution. A real broker
 * adapter must be connected first.
 */

app.post(
  '/api/trades',

  auth,
  csrf,

  async (
    req,
    res
  ) => {

    if (
      !process.env
        .BROKER_PROVIDER
    ) {
      return res
        .status(503)
        .json({
          message:
            'Broker integration not configured'
        });
    }

    const {
      pair,
      side,
      volume,
      stopLoss,
      takeProfit
    } =
      req.body || {};

    if (
      !pair ||
      ![
        'BUY',
        'SELL'
      ].includes(side) ||
      !Number.isFinite(
        Number(volume)
      ) ||
      Number(volume) <= 0
    ) {
      return res
        .status(400)
        .json({
          message:
            'Invalid trade request'
        });
    }

    /*
     * No fabricated trade.
     */

    return res
      .status(503)
      .json({
        message:
          'Live broker execution is not enabled until the cTrader/broker account is connected.'
      });
  }
);

/*
 * 404
 */

app.use(
  (_req, res) =>
    res
      .status(404)
      .json({
        message:
          'Not found'
      })
);

/*
 * Global errors
 */

app.use(
  (
    err,
    _req,
    res,
    _next
  ) => {

    console.error(
      err
    );

    res
      .status(500)
      .json({
        message:
          'Internal server error'
      });
  }
);

/*
 * Start
 */

await pool.query(
  fs.readFileSync(
    path.join(
      __dirname,
      'schema.sql'
    ),
    'utf8'
  )
);

await initAdmin();

const port =
  Number(
    process.env.PORT ||
    3000
  );

app.listen(
  port,
  () => {

    console.log(
      `ALPHA 1 server listening on :${port}`
    );

  }
);
