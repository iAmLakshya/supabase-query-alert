CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

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
