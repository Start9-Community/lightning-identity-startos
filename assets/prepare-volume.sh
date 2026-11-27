#!/bin/sh
# Lays out the `main` volume so each subcontainer owns exactly its slice.
# Runs as root before every start (StartOS mounts volumes root-owned).
set -eu
root="${1:?volume root}"
: "${EDGE_UID:=1001}" "${CORE_UID:=1002}" "${GUARD_UID:=1003}"

own() { # dir uid mode
  mkdir -p "$root/$1"
  chown "$2:$2" "$root/$1"
  chmod "$3" "$root/$1"
}
own edge        "$EDGE_UID"  0700   # relay event store
own core        "$CORE_UID"  0700   # core.db, master.key
own identities  "$CORE_UID"  0755   # edge.json: core writes, edge reads
own credentials "$GUARD_UID" 0755   # recv.macaroon: guard writes, core reads
own guard       "$GUARD_UID" 0700   # guard state, authorizations
mkdir -p "$root/site"; chmod 0755 "$root/site"   # optional static site, operator-owned
# Where the Upload Site action receives an archive. No daemon mounts it. An
# archive is deleted once it has been unpacked; what is left after two hours
# was abandoned (a prepared upload lives 30 minutes, a transfer an hour).
mkdir -p "$root/upload"; chown 0:0 "$root/upload"; chmod 0700 "$root/upload"
find "$root/upload" -mindepth 1 -mmin +120 -delete 2>/dev/null || true
# Each socket sits in a folder only its server can write, so no other process
# can create a socket at that path; clients connect, servers check peer uids.
mkdir -p "$root/run"; chown 0:0 "$root/run"; chmod 0755 "$root/run"
own run/guard   "$GUARD_UID" 0755   # guard.sock
own run/core    "$CORE_UID"  0755   # edge-core.sock
rm -f "$root"/run/guard/*.sock "$root"/run/core/*.sock
# Tighten anything the processes created with a looser umask. core owns the
# folder, so the key may be a link: never follow it as root.
key="$root/core/master.key"
if [ -f "$key" ] && [ ! -L "$key" ]; then chmod 0600 "$key"; fi
exit 0
