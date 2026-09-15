CREATE SCHEMA IF NOT EXISTS DEMO;

CREATE TABLE IF NOT EXISTS DEMO.CUSTOMERS (
    id          INT,
    name        VARCHAR(100),
    ssn         VARCHAR(11),
    credit_card VARCHAR(20),
    email       VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS DEMO.REFUNDS (
    id            INT,
    customer_id   INT,
    refund_date   DATE,
    refund_amount DECIMAL(10,2)
);

INSERT INTO DEMO.CUSTOMERS VALUES
(1, 'Alice Chen',   '123-45-6789', '4111111111111111', 'alice@example.com'),
(2, 'Bob Martinez', '987-65-4321', '4222222222222222', 'bob@example.com'),
(3, 'Carla Nguyen', '555-11-2222', '4333333333333333', 'carla@example.com'),
(4, 'David Osei',   '444-22-3333', '4444444444444444', 'david@example.com');

INSERT INTO DEMO.REFUNDS VALUES
(1, 1, '2026-01-15', 49.99),
(2, 2, '2026-01-20', 120.00),
(3, 1, '2026-02-02', 15.50),
(4, 3, '2026-02-10', 89.00);
