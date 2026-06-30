-- Fake SRE runbook + incident database.
-- Loaded automatically via /docker-entrypoint-initdb.d on first start.

CREATE TABLE runbooks (
  id           SERIAL PRIMARY KEY,
  name         VARCHAR(255) NOT NULL,
  content      TEXT NOT NULL,
  last_updated TIMESTAMP DEFAULT NOW()
);

INSERT INTO runbooks (name, content) VALUES
('cpu-alert',
 'Step 1: Check load average with uptime. Step 2: Identify high-CPU processes with top. Step 3: Kill or throttle offending processes.'),
('disk-full',
 'Step 1: Find large files with du -ahx. Step 2: Rotate logs with logrotate. Step 3: Archive or delete logs older than 30 days.'),
('db-connection-pool',
 'Step 1: Inspect pg_stat_activity for idle-in-transaction sessions. Step 2: Terminate stuck backends. Step 3: Restart the connection pooler.'),
('cert-expiry',
 'Step 1: Check expiry with openssl x509 -enddate. Step 2: Renew via cert-manager. Step 3: Verify the new chain and reload the ingress.');

CREATE TABLE incidents (
  id         VARCHAR(32) PRIMARY KEY,
  title      VARCHAR(255) NOT NULL,
  severity   VARCHAR(8) NOT NULL,
  status     VARCHAR(32) NOT NULL DEFAULT 'investigating',
  runbook_id INTEGER REFERENCES runbooks(id),
  created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO incidents (id, title, severity, status, runbook_id) VALUES
('INC-1042', 'Payments API returning 500s',        'SEV2', 'investigating', 3),
('INC-1043', 'Disk pressure on log aggregator',    'SEV3', 'mitigated',     2),
('INC-1041', 'Database CPU sustained above 90%',   'SEV2', 'resolved',      1);

CREATE TABLE audit_log (
  id        SERIAL PRIMARY KEY,
  actor     VARCHAR(64) NOT NULL,
  action    VARCHAR(255) NOT NULL,
  ts        TIMESTAMP DEFAULT NOW()
);

INSERT INTO audit_log (actor, action) VALUES
('sre-agent', 'read runbook cpu-alert'),
('sre-agent', 'queried incidents where status=investigating');
