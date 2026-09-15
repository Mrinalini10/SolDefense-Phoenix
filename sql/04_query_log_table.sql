CREATE TABLE IF NOT EXISTS DEMO.QUERY_LOG (
    id            INT IDENTITY,
    agent_id      VARCHAR(100),
    raw_sql       VARCHAR(2000000),
    rewritten_sql VARCHAR(2000000),
    logged_at     TIMESTAMP
);
