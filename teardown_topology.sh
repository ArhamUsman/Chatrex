#!/bin/bash
set -euo pipefail
export LC_ALL=C

namespaces=(client r1 r2 server)

if (( $# != 0 )); then
    printf 'Usage: %s\n' "$0" >&2
    exit 2
fi

if (( EUID != 0 )); then
    printf 'Error: this script must run as root; invoke it with sudo.\n' >&2
    exit 1
fi

for required_command in ip awk; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        printf 'Error: required command not found: %s\n' "$required_command" >&2
        exit 1
    fi
done

namespace_exists() {
    local wanted=$1
    ip netns list | awk -v wanted="$wanted" '$1 == wanted { found=1 } END { exit !found }'
}

status=0
for namespace in "${namespaces[@]}"; do
    if namespace_exists "$namespace"; then
        if ip netns del "$namespace"; then
            printf '[+] Deleted namespace %s.\n' "$namespace"
        else
            printf 'Error: failed to delete namespace %s.\n' "$namespace" >&2
            status=1
        fi
    else
        printf '[*] Namespace %s is not present.\n' "$namespace"
    fi
done

exit "$status"
