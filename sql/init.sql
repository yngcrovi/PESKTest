CREATE TABLE IF NOT EXISTS "user" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE,
    password BYTEA NOT NULL,
    salt BYTEA NOT NULL,
    create_dt TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "role" (
    id SERIAL PRIMARY KEY,
    name varchar(150)
);

CREATE TABLE IF NOT EXISTS user_role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES "user"(id),
    role_id int4 REFERENCES "role"(id)
);

INSERT INTO "role" (name) VALUES ('Админ'), ('Пользователь');