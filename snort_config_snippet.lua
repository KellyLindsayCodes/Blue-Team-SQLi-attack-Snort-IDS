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