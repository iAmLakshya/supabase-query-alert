INSERT INTO users (email, password_hash) VALUES
    ('alice@example.com', '$2b$12$abc123hashedpassword1'),
    ('bob@example.com', '$2b$12$def456hashedpassword2'),
    ('carol@example.com', '$2b$12$ghi789hashedpassword3');

INSERT INTO orders (user_id, total) VALUES
    (1, 99.99),
    (1, 149.50),
    (2, 25.00),
    (3, 299.99),
    (2, 75.25);
