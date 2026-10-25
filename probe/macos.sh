#!/bin/bash
# ReadyHai macOS host probe. bash 3.2 + BSD tools. Read-only. Emits ONE JSON object.
export LC_ALL=C
PARTIAL=()
partial() { PARTIAL[${#PARTIAL[@]}]="$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
esc() { tr '\t' ' ' | tr -d '\000-\010\013-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }
jv() { printf '"%s"' "$(printf '%s' "$1" | esc | tr -d '\n')"; }
jarr() { local a; a=$(esc | sed 's/^/"/; s/$/"/' | tr '\n' ',' | sed 's/,$//'); printf '[%s]' "$a"; }
# run with a timeout (no GNU timeout on macOS): $1 secs, rest cmd
tmo() {
  local s=$1; shift
  "$@" & local p=$!
  ( sleep "$s"; kill "$p" 2>/dev/null ) >/dev/null 2>&1 & local w=$!
  wait "$p" 2>/dev/null; local rc=$?
  kill "$w" 2>/dev/null; wait "$w" 2>/dev/null
  return $rc
}
b() { [ "$1" = "1" ] && printf true || { [ "$1" = "0" ] && printf false || printf null; }; }

PN=$(sw_vers -productName 2>/dev/null); PV=$(sw_vers -productVersion 2>/dev/null); PB=$(sw_vers -buildVersion 2>/dev/null)
KERNEL=$(uname -r 2>/dev/null)
BOOT=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9]*\).*/\1/p')
UPT=""; [ -n "$BOOT" ] && UPT=$(( $(date +%s) - BOOT ))

LISTEN=$(lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | awk 'NR>1{print $1 " " $9}' | sort -u | head -200)
[ -z "$LISTEN" ] && partial "lsof returned nothing (limited visibility without sudo)"

FW=null; FWS=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
case "$FWS" in *enabled*|*"State = 1"*|*"State = 2"*) FW=1;; *disabled*|*"State = 0"*) FW=0;; *) partial "socketfilterfw state unavailable";; esac

SIP=null; S=$(csrutil status 2>/dev/null)
case "$S" in *enabled*) SIP=1;; *disabled*) SIP=0;; *) partial "csrutil status unavailable";; esac
GK=null; S=$(spctl --status 2>/dev/null)
case "$S" in *enabled*) GK=1;; *disabled*) GK=0;; *) partial "spctl status unavailable";; esac
FV=null; S=$(fdesetup status 2>/dev/null)
case "$S" in *"is On"*) FV=1;; *"is Off"*) FV=0;; *) partial "fdesetup status unavailable (needs admin)";; esac

PRL=""; PWA=""; SSHSRC=""
if SSHT=$(sudo -n sshd -T 2>/dev/null) && [ -n "$SSHT" ]; then
  PRL=$(printf '%s\n' "$SSHT" | awk '$1=="permitrootlogin"{print $2}')
  PWA=$(printf '%s\n' "$SSHT" | awk '$1=="passwordauthentication"{print $2}')
  SSHSRC="sshd -T"
elif [ -r /etc/ssh/sshd_config ]; then
  F="/etc/ssh/sshd_config"; for x in /etc/ssh/sshd_config.d/*.conf; do [ -r "$x" ] && F="$F $x"; done
  PRL=$(cat $F 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{v=tolower($2)} END{print v}')
  PWA=$(cat $F 2>/dev/null | awk 'tolower($1)=="passwordauthentication"{v=tolower($2)} END{print v}')
  SSHSRC="sshd_config (defaults not resolved)"
  [ -z "$PRL" ] && PRL=default; [ -z "$PWA" ] && PWA=default
else partial "sshd config not readable"; fi

ERRS=""
if have log; then
  ERRS=$(tmo 60 log show --predicate 'messageType == error' --last 1h --style compact 2>/dev/null | tail -200)
  [ -z "$ERRS" ] && partial "unified log empty or timed out"
fi

BREW=""
if have brew; then BREW=$(brew list --versions 2>/dev/null | head -3000 | esc | sed 's/^\([^ ]*\) \(.*\)$/{"name":"\1","version":"\2"}/' | tr '\n' ',' | sed 's/,$//'); fi

# TCC probe: a protected folder read failing means partial coverage
ls "$HOME/Library/Mail" >/dev/null 2>&1 || partial "TCC: ~/Library/Mail not readable (Full Disk Access not granted)"

DISKS=$(df -Pk 2>/dev/null | tail -n +2 | awk '$1 ~ /^\/dev\// {gsub("%","",$5); print $6 "\t" $5}' | sed 's/\\/\\\\/g; s/"/\\"/g' | awk -F'\t' '{printf "%s{\"mount\":\"%s\",\"use_pct\":%s}", (NR>1?",":""), $1, $2+0}')

printf '{"probe":"macos","os":{"name":%s,"version":%s,"build":%s,"kernel":%s},"uptime_secs":%s,' "$(jv "$PN")" "$(jv "$PV")" "$(jv "$PB")" "$(jv "$KERNEL")" "${UPT:-null}"
printf '"listening":%s,"firewall_enabled":%s,"sip_enabled":%s,"gatekeeper_enabled":%s,"filevault_on":%s,' "$(printf '%s\n' "$LISTEN" | grep . | jarr)" "$(b $FW)" "$(b $SIP)" "$(b $GK)" "$(b $FV)"
printf '"sshd":{"permitrootlogin":%s,"passwordauthentication":%s,"source":%s},"disks":[%s],' "$(jv "$PRL")" "$(jv "$PWA")" "$(jv "$SSHSRC")" "$DISKS"
printf '"error_lines":%s,"packages":[%s],' "$(printf '%s\n' "$ERRS" | grep . | jarr)" "$BREW"
if [ ${#PARTIAL[@]} -gt 0 ]; then P=$(printf '%s\n' "${PARTIAL[@]}" | jarr); else P='[]'; fi
printf '"partial":%s}\n' "$P"
