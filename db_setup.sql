-- 1. Create the database
CREATE DATABASE IF NOT EXISTS insecure_login;

-- 2. Create a new MySQL user (optional but recommended for realism)
CREATE USER IF NOT EXISTS 'vulnuser'@'localhost' IDENTIFIED BY 'vulnpass';

-- 3. Grant all privileges to the user on the insecure_login database
GRANT ALL PRIVILEGES ON insecure_login.* TO 'vulnuser'@'localhost';

-- 4. Apply the privilege changes
FLUSH PRIVILEGES;

-- 5. Use the database
USE insecure_login;

-- 6. Create the users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255)
);

-- 7. Insert sample user data
INSERT INTO users (username, password) VALUES ('admin', 'adminpass');
INSERT INTO users (username, password) VALUES ('testuser', 'test123');
