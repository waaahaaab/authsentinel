# Patterns auth.log — Ubuntu 26.04 LTS (resolute)

⚠️ Format des timestamps : ISO 8601 avec microsecondes et timezone
(`2026-08-05T21:12:51.304209+01:00`), PAS le format syslog classique
(`Aug 5 21:12:51`). Impact direct sur le parsing (datetime.fromisoformat).

⚠️ Le process SSH s'appelle `sshd-session[PID]` sur les versions récentes
d'OpenSSH (9.8+), pas seulement `sshd[PID]`.

## 1. Failed password (échec connexion SSH)

2026-08-05T21:12:53.922295+01:00 WAHAB sshd-session[31772]: Failed password for wahab from 127.0.0.1 port 34612 ssh2

Note : peut se répéter plusieurs fois d'affilée (3 tentatives max avant
fermeture par OpenSSH) + ligne `PAM X more authentication failures`.

## 2. Accepted password (connexion SSH réussie)

2026-08-05T19:48:54.428019+01:00 WAHAB sshd-session[10281]: Accepted password for wahab from 127.0.0.1 port 44768 ssh2


## 3. sudo COMMAND

2026-08-05T19:57:25.263329+01:00 WAHAB sudo: wahab : TTY=/dev/pts/3 ; PWD=/home/wahab ; USER=root ; COMMAND=/usr/bin/ls /root


## 4. new user

2026-08-05T21:14:34.310799+01:00 WAHAB useradd[31905]: new group: name=testuser, GID=1001
2026-08-05T21:14:34.310904+01:00 WAHAB useradd[31905]: new user: name=testuser, UID=1001, GID=1001, home=/home/testuser, shell=/bin/sh, from=/dev/pts/4

Note : toujours précédé d'une ligne "new group" du même nom (comportement Debian/Ubuntu par défaut).

## 5. FAILED su

2026-08-05T20:14:08.357892+01:00 WAHAB su[11269]: FAILED SU (to root) wahab on pts/3

Note : précédé de 2 lignes internes PAM (unix_chkpwd, pam_unix authentication failure) — le pattern le plus fiable à cibler reste la ligne finale "FAILED SU".

## 6. session opened/closed

2026-08-05T19:43:39.778346+01:00 WAHAB sudo: pam_unix(sudo:session): session opened for user root(uid=0) by wahab(uid=1000)
2026-08-05T19:46:16.136089+01:00 WAHAB sudo: pam_unix(sudo:session): session closed for user root

Existe aussi pour SSH : `pam_unix(sshd:session): session opened/closed for user [user]`