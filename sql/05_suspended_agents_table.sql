CREATE TABLE IF NOT EXISTS DEMO.SUSPENDED_AGENTS (
    agent_id     VARCHAR(100),
    suspended_at TIMESTAMP,
    reason       VARCHAR(500),
    released_at  TIMESTAMP
);
