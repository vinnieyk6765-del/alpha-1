CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL,
  id_number TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
    CHECK (role IN ('user','admin')),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','suspended')),
  wallet_cents BIGINT NOT NULL DEFAULT 0
    CHECK (wallet_cents >= 0),
  kyc_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (
      kyc_status IN (
        'pending',
        'submitted',
        'verified',
        'rejected'
      )
    ),
  front_id_key TEXT,
  back_id_key TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  csrf_token TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS deposits (
  id BIGSERIAL PRIMARY KEY,

  user_id BIGINT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,

  amount_cents BIGINT NOT NULL
    CHECK (amount_cents > 0),

  reference TEXT,

  mpesa_message TEXT,

  mpesa_receipt TEXT UNIQUE,

  mpesa_transaction_time TIMESTAMPTZ,

  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (
      status IN (
        'pending',
        'matched',
        'approved',
        'rejected',
        'expired'
      )
    ),

  expires_at TIMESTAMPTZ NOT NULL,

  reviewed_by BIGINT
    REFERENCES users(id)
    ON DELETE SET NULL,

  reviewed_at TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS withdrawals (
  id BIGSERIAL PRIMARY KEY,

  user_id BIGINT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,

  amount_cents BIGINT NOT NULL
    CHECK (amount_cents > 0),

  destination TEXT NOT NULL,

  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (
      status IN (
        'pending',
        'processing',
        'paid',
        'rejected',
        'failed'
      )
    ),

  provider_reference TEXT,

  reviewed_by BIGINT
    REFERENCES users(id)
    ON DELETE SET NULL,

  reviewed_at TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ledger_entries (
  id BIGSERIAL PRIMARY KEY,

  user_id BIGINT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,

  amount_cents BIGINT NOT NULL,

  type TEXT NOT NULL
    CHECK (
      type IN (
        'deposit',
        'withdrawal',
        'adjustment',
        'trade_pnl',
        'trade_fee'
      )
    ),

  reference TEXT NOT NULL,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS trades (
  id BIGSERIAL PRIMARY KEY,

  user_id BIGINT NOT NULL
    REFERENCES users(id)
    ON DELETE CASCADE,

  broker_account_id TEXT,

  broker_position_id TEXT,

  pair TEXT NOT NULL,

  side TEXT NOT NULL
    CHECK (side IN ('BUY','SELL')),

  volume REAL NOT NULL
    CHECK (volume > 0),

  entry_price NUMERIC,

  stop_loss NUMERIC,

  take_profit NUMERIC,

  status TEXT NOT NULL DEFAULT 'OPEN',

  pnl_cents BIGINT NOT NULL DEFAULT 0,

  opened_at TIMESTAMPTZ,

  closed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mpesa_events (
  id BIGSERIAL PRIMARY KEY,

  transaction_type TEXT,

  trans_id TEXT UNIQUE,

  trans_time TEXT,

  trans_amount_cents BIGINT,

  business_short_code TEXT,

  bill_ref_number TEXT,

  phone_hash TEXT,

  raw_payload JSONB NOT NULL,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,

  user_id BIGINT
    REFERENCES users(id)
    ON DELETE SET NULL,

  action TEXT NOT NULL,

  detail JSONB,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_token
ON sessions(token_hash);

CREATE INDEX IF NOT EXISTS idx_deposits_user
ON deposits(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_withdrawals_user
ON withdrawals(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_trades_user
ON trades(user_id, id DESC);

CREATE INDEX IF NOT EXISTS idx_mpesa_receipt
ON mpesa_events(trans_id);
