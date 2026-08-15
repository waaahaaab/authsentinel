"""
test_parser.py — Vérifie que parser.py extrait correctement
les informations de vraies lignes de /var/log/auth.log.

20 lignes réelles (collectées sur la machine, voir notes/patterns.md),
avec variations (IPs, users, timestamps différents) pour couvrir
davantage de cas concrets sur chacun des 6 patterns.
"""

from authsentinel.parser import parse_line


# --- 1. Failed password (4 variantes) ---

def test_failed_password_basique():
    line = "2026-08-05T21:12:53.922295+01:00 WAHAB sshd-session[31772]: Failed password for wahab from 127.0.0.1 port 34612 ssh2"
    event = parse_line(line)
    assert event.event_type == "failed_password"
    assert event.user == "wahab"
    assert event.ip == "127.0.0.1"


def test_failed_password_ip_externe():
    line = "2026-08-05T21:13:27.036801+01:00 WAHAB sshd-session[31772]: Failed password for admin from 192.168.1.50 port 22001 ssh2"
    event = parse_line(line)
    assert event.event_type == "failed_password"
    assert event.user == "admin"
    assert event.ip == "192.168.1.50"


def test_failed_password_ancien_format_sshd():
    # Sans "-session", format OpenSSH plus ancien
    line = "2026-08-05T21:13:31.138108+01:00 WAHAB sshd[9999]: Failed password for root from 10.0.0.1 port 5000 ssh2"
    event = parse_line(line)
    assert event.event_type == "failed_password"
    assert event.user == "root"
    assert event.ip == "10.0.0.1"


def test_failed_password_autre_user():
    line = "2026-08-05T21:14:00.000000+01:00 WAHAB sshd-session[40001]: Failed password for testuser from 172.16.0.5 port 41000 ssh2"
    event = parse_line(line)
    assert event.event_type == "failed_password"
    assert event.user == "testuser"
    assert event.ip == "172.16.0.5"


# --- 2. Accepted password (3 variantes) ---

def test_accepted_password_basique():
    line = "2026-08-05T19:48:54.428019+01:00 WAHAB sshd-session[10281]: Accepted password for wahab from 127.0.0.1 port 44768 ssh2"
    event = parse_line(line)
    assert event.event_type == "accepted_password"
    assert event.user == "wahab"
    assert event.ip == "127.0.0.1"


def test_accepted_password_ip_externe():
    line = "2026-08-05T19:50:00.000000+01:00 WAHAB sshd-session[10300]: Accepted password for admin from 203.0.113.7 port 51000 ssh2"
    event = parse_line(line)
    assert event.event_type == "accepted_password"
    assert event.user == "admin"
    assert event.ip == "203.0.113.7"


def test_accepted_password_ancien_format_sshd():
    line = "2026-08-05T19:51:00.000000+01:00 WAHAB sshd[10310]: Accepted password for wahab from 192.168.0.1 port 22 ssh2"
    event = parse_line(line)
    assert event.event_type == "accepted_password"
    assert event.user == "wahab"
    assert event.ip == "192.168.0.1"


# --- 3. sudo command (4 variantes) ---

def test_sudo_ls():
    line = "2026-08-05T19:57:25.263329+01:00 WAHAB sudo: wahab : TTY=/dev/pts/3 ; PWD=/home/wahab ; USER=root ; COMMAND=/usr/bin/ls /root"
    event = parse_line(line)
    assert event.event_type == "sudo_command"
    assert event.user == "wahab"


def test_sudo_useradd():
    line = "2026-08-05T21:14:34.292739+01:00 WAHAB sudo: wahab : TTY=/dev/pts/3 ; PWD=/home/wahab ; USER=root ; COMMAND=/usr/sbin/useradd -m testuser"
    event = parse_line(line)
    assert event.event_type == "sudo_command"
    assert event.user == "wahab"


def test_sudo_autre_utilisateur():
    line = "2026-08-05T22:00:00.000000+01:00 WAHAB sudo: admin : TTY=/dev/pts/5 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update"
    event = parse_line(line)
    assert event.event_type == "sudo_command"
    assert event.user == "admin"


def test_sudo_systemctl():
    line = "2026-08-05T19:47:32.879531+01:00 WAHAB sudo: wahab : TTY=/dev/pts/3 ; PWD=/home/wahab ; USER=root ; COMMAND=/usr/bin/systemctl enable --now ssh"
    event = parse_line(line)
    assert event.event_type == "sudo_command"
    assert event.user == "wahab"


# --- 4. new_user (2 variantes) ---

def test_new_user_testuser():
    line = "2026-08-05T21:14:34.310904+01:00 WAHAB useradd[31905]: new user: name=testuser, UID=1001, GID=1001, home=/home/testuser, shell=/bin/sh, from=/dev/pts/4"
    event = parse_line(line)
    assert event.event_type == "new_user"
    assert event.user == "testuser"


def test_new_user_autre_nom():
    line = "2026-08-05T22:05:00.000000+01:00 WAHAB useradd[40002]: new user: name=backupadmin, UID=1002, GID=1002, home=/home/backupadmin, shell=/bin/bash, from=/dev/pts/6"
    event = parse_line(line)
    assert event.event_type == "new_user"
    assert event.user == "backupadmin"


# --- 5. FAILED su (2 variantes) ---

def test_failed_su_root():
    line = "2026-08-05T20:14:08.357892+01:00 WAHAB su[11269]: FAILED SU (to root) wahab on pts/3"
    event = parse_line(line)
    assert event.event_type == "failed_su"
    assert event.user == "wahab"


def test_failed_su_autre_cible():
    line = "2026-08-05T22:10:00.000000+01:00 WAHAB su[40003]: FAILED SU (to admin) testuser on pts/7"
    event = parse_line(line)
    assert event.event_type == "failed_su"
    assert event.user == "testuser"


# --- 6. session opened / closed (5 variantes) ---

def test_session_opened_sudo():
    line = "2026-08-05T19:43:39.778346+01:00 WAHAB sudo: pam_unix(sudo:session): session opened for user root(uid=0) by wahab(uid=1000)"
    event = parse_line(line)
    assert event.event_type == "session_opened"
    assert event.user == "root"


def test_session_closed_sudo():
    line = "2026-08-05T19:46:16.136089+01:00 WAHAB sudo: pam_unix(sudo:session): session closed for user root"
    event = parse_line(line)
    assert event.event_type == "session_closed"
    assert event.user == "root"


def test_session_opened_sshd():
    line = "2026-08-05T19:48:54.432622+01:00 WAHAB sshd-session[10281]: pam_unix(sshd:session): session opened for user wahab(uid=1000) by wahab(uid=0)"
    event = parse_line(line)
    assert event.event_type == "session_opened"
    assert event.user == "wahab"


def test_session_closed_sshd():
    line = "2026-08-05T19:57:17.978151+01:00 WAHAB sshd-session[10281]: pam_unix(sshd:session): session closed for user wahab"
    event = parse_line(line)
    assert event.event_type == "session_closed"
    assert event.user == "wahab"


def test_session_opened_autre_user():
    line = "2026-08-05T22:15:00.000000+01:00 WAHAB sudo: pam_unix(sudo:session): session opened for user root(uid=0) by admin(uid=1002)"
    event = parse_line(line)
    assert event.event_type == "session_opened"
    assert event.user == "root"


# --- Bonus : lignes de bruit qui ne doivent PAS être parsées ---

def test_ligne_bruit_server_listening():
    line = "2026-08-05T19:47:33.898154+01:00 WAHAB sshd-session[9926]: Server listening on 0.0.0.0 port 22."
    event = parse_line(line)
    assert event is None


def test_ligne_vide():
    assert parse_line("") is None
    assert parse_line("   ") is None
