#!/bin/sh
# ReadyHai Linux host probe. POSIX sh, read-only (only a mktemp dir, removed on exit).
# Emits ONE JSON object on stdout. Never prints environment or file contents beyond the fields below.
PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin
export LC_ALL=C
T=$(mktemp -d 2>/dev/null || echo "")
trap '[ -n "$T" ] && rm -rf "$T"' EXIT INT TERM
have() { command -v "$1" >/dev/null 2>&1; }
# escape stdin lines into JSON string content (one per line)
esc() { tr '\t' ' ' | tr -d '\000-\010\013-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }
jv() { printf '"%s"' "$(printf '%s' "$1" | esc | tr -d '\n')"; }
# stdin lines -> JSON array of strings
jarr() { _a=$(esc | sed 's/^/"/; s/$/"/' | tr '\n' ',' | sed 's/,$//'); printf '[%s]' "$_a"; }
num() { case "$1" in ''|*[!0-9]*) printf 'null';; *) printf '%s' "$1";; esac; }
PARTIAL=""
partial() { PARTIAL="$PARTIAL$1
"; }
SUDO=""
if [ "$(id -u)" != "0" ] && have sudo && sudo -n true >/dev/null 2>&1; then SUDO="sudo -n"; fi
[ "$(id -u)" != "0" ] && [ -z "$SUDO" ] && partial "not root and no passwordless sudo: some checks limited"

# --- os
OS_ID=""; OS_VER=""
if [ -r /etc/os-release ]; then
  OS_ID=$(. /etc/os-release 2>/dev/null; printf '%s' "$ID")
  OS_VER=$(. /etc/os-release 2>/dev/null; printf '%s' "$VERSION_ID")
fi
KERNEL=$(uname -r 2>/dev/null)
UPTIME=$(cut -d. -f1 /proc/uptime 2>/dev/null)

# --- pending updates (offline, cache only)
PU_MGR=""; PU_COUNT=""; PU_SEC=""
if have apt-get; then
  PU_MGR=apt
  S=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst ')
  if [ -n "$S" ] || apt-get -s upgrade >/dev/null 2>&1; then
    PU_COUNT=$(printf '%s' "$S" | grep -c '^Inst ')
    PU_SEC=$(printf '%s' "$S" | grep -ci 'security')
  fi
elif have dnf; then
  PU_MGR=dnf
  PU_COUNT=$(dnf -q --cacheonly check-update 2>/dev/null | grep -cE '^[A-Za-z0-9_.+-]+\.[a-z0-9_]+ +[0-9]')
elif have yum; then
  PU_MGR=yum
  PU_COUNT=$(yum -q -C check-update 2>/dev/null | grep -cE '^[A-Za-z0-9_.+-]+\.[a-z0-9_]+ +[0-9]')
elif have apk; then
  PU_MGR=apk
  PU_COUNT=$(apk version -l '<' 2>/dev/null | grep -c '<')
elif have zypper; then
  PU_MGR=zypper
  PU_COUNT=$(zypper -q --no-refresh lu 2>/dev/null | grep -c '^v ')
fi

# --- listening ports
if have ss; then
  LISTEN=$(ss -tlnpH 2>/dev/null || ss -tln 2>/dev/null | tail -n +2)
elif have netstat; then
  LISTEN=$(netstat -tlnp 2>/dev/null | tail -n +3)
else LISTEN=""; partial "no ss/netstat: listening ports unavailable"; fi
LISTEN_J=$(printf '%s\n' "$LISTEN" | awk 'NF>=4 {p=""; for(i=5;i<=NF;i++) if ($i ~ /users:/) p=$i; print $4 " " p}' | head -200 | jarr)

# --- failed units
if have systemctl && [ -d /run/systemd/system ]; then
  FAILED=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | head -50)
  SYSTEMD=true
else FAILED=""; SYSTEMD=false; fi

# --- disks
DISKS=$(df -P -k 2>/dev/null | tail -n +2 | awk '$1 ~ /^\// && $6 !~ /^\/(snap|boot\/efi)/ {gsub("%","",$5); print $6 "\t" $5 "\t" $1}' | head -50 \
  | sed 's/\\/\\\\/g; s/"/\\"/g' | awk -F'\t' '{printf "%s{\"mount\":\"%s\",\"use_pct\":%s,\"dev\":\"%s\"}", (NR>1?",":""), $1, $2+0, $3}')

# --- memory
MT=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)
MA=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)

# --- firewall
FW_UFW=absent; FW_FWD=absent; FW_NFT=absent; FW_IPT=absent
if have ufw; then
  if $SUDO ufw status 2>/dev/null | grep -qi 'status: active'; then FW_UFW=active
  elif [ -n "$SUDO" ] || [ "$(id -u)" = 0 ]; then FW_UFW=inactive
  else FW_UFW=unknown; fi
fi
if have firewall-cmd; then
  if firewall-cmd --state 2>/dev/null | grep -q running; then FW_FWD=active; else FW_FWD=inactive; fi
fi
if have nft; then
  N=$($SUDO nft list ruleset 2>/dev/null | grep -c 'rule\|accept\|drop\|reject')
  if [ "${N:-0}" -gt 0 ]; then FW_NFT=active; elif [ -n "$SUDO" ] || [ "$(id -u)" = 0 ]; then FW_NFT=inactive; else FW_NFT=unknown; fi
fi
if have iptables; then
  N=$($SUDO iptables -S 2>/dev/null | grep -c '^-A')
  if [ "${N:-0}" -gt 0 ]; then FW_IPT=active; elif [ -n "$SUDO" ] || [ "$(id -u)" = 0 ]; then FW_IPT=inactive; else FW_IPT=unknown; fi
fi
FW_ANY=false
case "$FW_UFW$FW_FWD$FW_NFT$FW_IPT" in *active*) case "$FW_UFW$FW_FWD$FW_NFT$FW_IPT" in *inactive*|*active*) FW_ANY=maybe;; esac;; esac
for x in $FW_UFW $FW_FWD $FW_NFT $FW_IPT; do [ "$x" = active ] && FW_ANY=true; done
[ "$FW_ANY" = maybe ] && FW_ANY=false
FW_UNKNOWN=false
for x in $FW_UFW $FW_FWD $FW_NFT $FW_IPT; do [ "$x" = unknown ] && FW_UNKNOWN=true; done

# --- sshd
PRL=""; PWA=""; SSHSRC=""
if have sshd && SSHT=$($SUDO sshd -T 2>/dev/null) && [ -n "$SSHT" ]; then
  PRL=$(printf '%s\n' "$SSHT" | awk '$1=="permitrootlogin"{print $2}')
  PWA=$(printf '%s\n' "$SSHT" | awk '$1=="passwordauthentication"{print $2}')
  SSHSRC="sshd -T"
elif [ -r /etc/ssh/sshd_config ]; then
  CF=/etc/ssh/sshd_config
  FILES="$CF $(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null)"
  PRL=$(cat $FILES 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{v=tolower($2)} END{print v}')
  PWA=$(cat $FILES 2>/dev/null | awk 'tolower($1)=="passwordauthentication"{v=tolower($2)} END{print v}')
  SSHSRC="sshd_config (defaults not resolved)"
  [ -z "$PRL" ] && PRL=default
  [ -z "$PWA" ] && PWA=default
else partial "sshd config not readable"; fi

# --- accounts / sudo
UID0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd 2>/dev/null)
NOPW=""
if [ -n "$SUDO" ] || [ "$(id -u)" = 0 ]; then
  NOPW=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^[[:space:]]*#' | grep -c 'NOPASSWD')
  [ -z "$NOPW" ] && NOPW=0
  # unreadable sudoers via plain cat when not root: retry with sudo
  if [ "$(id -u)" != 0 ]; then NOPW=$($SUDO sh -c 'cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null' | grep -v '^[[:space:]]*#' | grep -c 'NOPASSWD'); fi
else partial "sudoers not readable (no root/sudo)"; fi

# --- time sync
TS=null; TSD=""
if have timedatectl; then
  v=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  case "$v" in yes) TS=true;; no) TS=false;; esac
  TSD=timedatectl
fi
if [ "$TS" != true ]; then
  if have chronyc && chronyc tracking >/dev/null 2>&1; then TS=true; TSD=chrony
  elif have ntpq && ntpq -p >/dev/null 2>&1; then TS=true; TSD=ntp
  elif [ -n "$(ps 2>/dev/null | grep -E 'chronyd|ntpd|systemd-timesyncd' | grep -v grep)" ]; then TS=true; TSD=daemon
  elif [ "$TS" = null ] && [ -z "$TSD" ]; then TS=false; fi
fi

# --- error lines
ERRS=""
if have journalctl; then
  ERRS=$($SUDO journalctl -p err -b --no-pager -o cat 2>/dev/null | tail -200)
fi
if [ -z "$ERRS" ] && [ -r /var/log/syslog ]; then ERRS=$(grep -i error /var/log/syslog 2>/dev/null | tail -200)
elif [ -z "$ERRS" ] && [ -r /var/log/messages ]; then ERRS=$(grep -i error /var/log/messages 2>/dev/null | tail -200); fi

# --- docker
DOCK=""
if have docker && docker ps >/dev/null 2>&1; then
  DOCK=$(docker ps -a --format '{{.Names}}	{{.Status}}	{{.ID}}' 2>/dev/null | head -100 | while IFS='	' read -r n s i; do
    r=$(docker inspect -f '{{.RestartCount}}' "$i" 2>/dev/null)
    printf '{"name":%s,"status":%s,"restarts":%s}\n' "$(jv "$n")" "$(jv "$s")" "$(num "$r")"
  done | tr '\n' ',' | sed 's/,$//')
fi

# --- packages
PK=""
if have dpkg-query; then
  PK=$(dpkg-query -W -f '${Package} ${Version}\n' 2>/dev/null)
elif have rpm; then
  PK=$(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null)
elif have apk; then
  PK=$(apk info -v 2>/dev/null | sed 's/^\(.*\)-\([^-]*-r[0-9]*\)$/\1 \2/')
fi
PK_J=$(printf '%s\n' "$PK" | head -5000 | grep ' ' | esc | sed 's/^\([^ ]*\) \(.*\)$/{"name":"\1","version":"\2"}/' | tr '\n' ',' | sed 's/,$//')

# --- emit
printf '{"probe":"linux","os":{"id":%s,"version":%s,"kernel":%s},"uptime_secs":%s,' "$(jv "$OS_ID")" "$(jv "$OS_VER")" "$(jv "$KERNEL")" "$(num "$UPTIME")"
printf '"pending_updates":{"manager":%s,"count":%s,"security":%s},' "$(jv "$PU_MGR")" "$(num "$PU_COUNT")" "$(num "$PU_SEC")"
printf '"listening":%s,"systemd":%s,"failed_units":%s,"disks":[%s],' "$LISTEN_J" "$SYSTEMD" "$(printf '%s\n' "$FAILED" | grep . | jarr)" "$DISKS"
printf '"memory":{"total_kb":%s,"available_kb":%s},' "$(num "$MT")" "$(num "$MA")"
printf '"firewall":{"ufw":"%s","firewalld":"%s","nftables":"%s","iptables":"%s","any_active":%s,"unknown":%s},' "$FW_UFW" "$FW_FWD" "$FW_NFT" "$FW_IPT" "$FW_ANY" "$FW_UNKNOWN"
printf '"sshd":{"permitrootlogin":%s,"passwordauthentication":%s,"source":%s},' "$(jv "$PRL")" "$(jv "$PWA")" "$(jv "$SSHSRC")"
printf '"uid0_extra":%s,"nopasswd_sudo":%s,"time_sync":%s,' "$(printf '%s\n' "$UID0" | grep . | jarr)" "$(num "$NOPW")" "$TS"
printf '"error_lines":%s,"docker":[%s],"packages":[%s],' "$(printf '%s\n' "$ERRS" | grep . | jarr)" "$DOCK" "$PK_J"
printf '"partial":%s}\n' "$(printf '%s' "$PARTIAL" | grep . | jarr)"
