# Blue Team SQL Injection Attack Simulation Snort IDS

## 🎯Project Overview
This project uses an Ubuntu VM to execute a series of Snort 3 rulesets, creating an intrusion detection system (IDS) which mitigates against SQL injection attacks. 

## 📚 Table of Contents
- [Project Overview](#project-overview)
- [Requirements](#requirements)
- [Snort 3 Installation](#snort-3-installation)
- [SQL Login Page](#sql-login-page)
- [SQL Injection Rules](#sql-injection-attack-rulesets)
- [Attack Commands](#kali-linux-commands-to-initiate-sqli-attack)
- [Detection with Snort](#snort-3-acting-as-intrusion-detection-system-ids)
- [Blocking Malicious IPs](#malicious-ip-address-blocked-using-iptables)

## Requirements
Ubuntu VM
Kali Linux VM (optional, used as attacking machine)

## Snort 3 Installation
1.	Update system packages
```
sudo apt update
sudo apt upgrade
```
2.	Install dependencies
```
sudo apt install -y build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev luajit hwloc libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkg-config libhwloc-dev cmake cpputest libsqlite3-dev uuid-dev libcmocka-dev libnetfilter-queue-dev libmnl-dev autotools-dev libluajit-5.1-dev libunwind-dev
```
3.	Create directory for source files
```
mkdir snort-source-files
cd snort-source-files
```
4.	Download and Install DAQ
(Please note you may need to install git onto Ubuntu VM)
```
git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make
sudo make install
```
5.	Install TCMalloc for performance (optional but recommended)
```
cd ../
wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.8/gperftools-2.8.tar.gz
tar xzf gperftools-2.8.tar.gz
cd gperftools-2.8/
./configure
make
sudo make install
```
6.	Install Snort 3
```
cd ../
git clone git://github.com/snortadmin/snort3.git
cd snort3/
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
make
make install
ldconfig
```
7.	Verify Installation
``` 
snort -v
```

## SQL Login Page
1.	Install Apache, PHP, and MySQL (or MariaDB) on Ubuntu VM
```
sudo apt update
sudo apt install apache2 php libapache2-mod-php mariadb-server php-mysql
```
2.	Set up the database
```
sudo mysql
```
3.	Create MySQL Script for login page
```
-- Please note MySQL must be entered in command by command and cannot be copied and pasted in as an entire script.

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

-- 6. Create the users table (if it doesn’t already exist)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255)
);

-- 7. Insert sample user data
INSERT INTO users (username, password) VALUES ('admin', 'adminpass');
INSERT INTO users (username, password) VALUES ('testuser', 'test123');
```
4.	Create login page using prepared statements
```
sudo nano /var/www/html/login.php

<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

$conn = new mysqli('localhost', 'vulnuser', 'vulnpass', 'insecure_login');

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user = $_POST['username'];
    $pass = $_POST['password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
    $stmt->bind_param("ss", $user, $pass);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $result->num_rows > 0) {
        echo "Login successful!";
    } else {
        echo "Login failed!";
    }

    $stmt->close();
}
?>

<form method="POST">
    Username: <input type="text" name="username"><br>
    Password: <input type="text" name="password"><br>
    <input type="submit" value="Login">
</form>
```
![alt text](/images/image-3.png)

![alt text](/images/image-4.png)

## SQL injection attack rulesets
1.	Create a directory for ruleset
```
mkdir /usr/local/etc/rules
```
2.	Download community rules
```
wget https://www.snort.org/downloads/community/snort3-community-rules.tar.gz
tar xzf snort3-community-rules.tar.gz -C /usr/local/etc/rules/
```
3.	Configure Snort
```
sudo nano /usr/local/etc/snort/snort.lua
```
```
#set network configuration in file

#1. Configure defaults
HOME_NET = ‘<Your Home Network’s IP address>’ e.g. ‘192.168.57.0/24’
EXTERNAL_NET = ‘!$HOME_NET’

#Configure path for rules under 5. Configure detection 
ips =
{
    enable_builtin_rules = true,
    variables = default_variables,

    {
        '/usr/local/etc/rules/snort3-community-rules/snort3-community.rules',
        '/usr/local/etc/rules/sql-injection.rules',
        '/usr/local/etc/rules/dos.rules',
    }
}

#Configure event filters under 6. Configure filters
event_filter =
{
    -- reduce the number of events logged for some rules
    { gid = 1, sid = 1, type = 'limit', track = 'by_src', count = 2, seconds = >
    { gid = 1, sid = 2, type = 'both',  track = 'by_dst', count = 5, seconds = >
    { gid = 1, sid = 2000001, type = "limit", track = "by_src", count = 100, se>
    { gid = 1, sid = 2000002, type = "limit", track = "by_src", count = 50, sec>
    { gid = 1, sid = 2000003, type = "limit", track = "by_src", count = 50, sec>
}

#Configure alerts to file under 7. Configure outputs
alert_fast = { file = true }
```
4.	Create custom SQL injection rules
```
sudo nano /usr/local/etc/rules/sql-injection.rules
```
```
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection - SELECT Statement"; content:"SELECT"; sid:1000002; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection - UNION Statement"; content:"UNION"; sid:1000003; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection - OR 1=1"; content:"OR 1=1"; sid:1000004; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection - Comment Characters"; content:"--"; sid:1000005; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection - Quote Characters"; pcre:"/(\%27)|(\')|(\-\-)|(\%23)|(#)/i"; sid:1000006; rev:1;)
```
![alt text](/images/image-2.png)

## Kali Linux commands to initiate SQLi attack
```
curl -X POST -d "username=admin' -- &password=anything" http://192.168.27.136/login.php
```

## Snort 3 acting as Intrusion Detection System (IDS)

![alt text](/images/image-1.png)

![alt text](/images/image.png)

## Malicious IP address blocked using iptables
```
sudo iptables -A INPUT -s 192.168.27.134 -p tcp --dport 80 -j DROP
```