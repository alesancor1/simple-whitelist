#!/usr/bin/env bash
set -euo pipefail

SET="ipset-whitelist"
TMPSET="${SET}-new"

INTERVAL="${UPDATE_INTERVAL:-300}"
WHITELIST_FILE="${WHITELIST_FILE:-/etc/simple-whitelist/whitelist.txt}"

CHAIN="IPSET-WHITELIST"
USE_CHAIN=true

PORTS=()
PROTOCOLS=()
ALLOW_NETWORKS=()

# ---------------------------------------------------------------------------
# Configuration
#
# --protocol PROTOCOL:
#   Restrict this IP protocol. Can be specified multiple times.
#
#   If omitted, all IP protocols are restricted.
#
# --port PORT:
#   Restrict this destination port. Can be specified multiple times.
#
#   --port requires at least one --protocol.
#
#   When multiple protocols and ports are specified, all combinations are
#   protected.
#
# --allow ADDRESS_OR_CIDR:
#   Always allow this IPv4 address or network. Can be repeated.
#
# The --allow options and the whitelist file are combined.
#
# Examples:
#
#   ./whitelist.sh
#       Restrict all protocols and all ports.
#
#   ./whitelist.sh --protocol tcp
#       Restrict all TCP ports.
#
#   ./whitelist.sh --protocol tcp --port 25565
#       Restrict TCP/25565.
#
#   ./whitelist.sh --protocol tcp --port 25565 --port 25566
#       Restrict TCP/25565 and TCP/25566.
#
#   ./whitelist.sh --protocol tcp --protocol udp --port 25565
#       Restrict TCP/25565 and UDP/25565.
#
#   ./whitelist.sh --protocol tcp --protocol udp \
#       --port 25565 --port 25566
#       Restrict all four combinations.
#
#   ./whitelist.sh --protocol icmp
#       Restrict ICMP.
#
#   ./whitelist.sh --allow 192.168.1.0/24
#       Allow this network in addition to the whitelist file.
#
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:

    --protocol PROTOCOL
        Restrict this IP protocol.
        Can be specified multiple times.

        If omitted, all IP protocols are restricted.

    --port PORT
        Restrict this destination port.
        Can be specified multiple times.

        Requires at least one --protocol.

        All combinations of protocols and ports are protected.

    --allow ADDRESS_OR_CIDR
        Always allow this IPv4 address or network.
        Can be specified multiple times.

        These entries are combined with the whitelist file.

    --chain NAME
        Use a dedicated iptables chain with this name.
        Default: IPSET-WHITELIST

    --no-chain
        Do not create/use a dedicated chain.
        Rules are added directly to DOCKER-USER.

    -h, --help
        Show this help.

Environment:

    WHITELIST_FILE
        Path to the whitelist file.
        Default: /etc/simple-whitelist/whitelist.txt

    UPDATE_INTERVAL
        Update interval in seconds.
        Default: 300

Examples:

    # Restrict everything:
    $0

    # Restrict all TCP:
    $0 --protocol tcp

    # Restrict one TCP port:
    $0 --protocol tcp --port 25565

    # Restrict multiple TCP ports:
    $0 --protocol tcp --port 25565 --port 25566

    # Restrict TCP and UDP on port 25565:
    $0 --protocol tcp --protocol udp --port 25565

    # Restrict TCP and UDP on multiple ports:
    $0 --protocol tcp --protocol udp \\
       --port 25565 --port 25566

    # Restrict ICMP:
    $0 --protocol icmp

    # Combine whitelist file and explicit allow:
    $0 --protocol tcp --port 25565 \\
       --allow 192.168.1.0/24

The whitelist file and --allow are cumulative.

If neither the whitelist file nor --allow contains any entries,
all protected traffic is denied.
EOF
}

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

is_valid_port() {
    local port="$1"

    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    (( port >= 1 && port <= 65535 ))
}

is_ipv4() {
    local ip="$1"
    local IFS=.
    local octets=()

    read -r -a octets <<< "$ip"

    [[ ${#octets[@]} -eq 4 ]] || return 1

    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( octet <= 255 )) || return 1
    done
}

is_cidr() {
    local value="$1"
    local ip prefix

    [[ "$value" == */* ]] || return 1

    ip="${value%/*}"
    prefix="${value#*/}"

    is_ipv4 "$ip" || return 1
    [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
    (( prefix <= 32 )) || return 1
}

is_hostname() {
    local hostname="$1"

    [[ "$hostname" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]
}

is_valid_chain_name() {
    local name="$1"

    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] &&
        (( ${#name} <= 28 ))
}

is_valid_protocol() {
    local protocol="$1"

    # Numeric IP protocol.
    if [[ "$protocol" =~ ^[0-9]+$ ]]; then
        (( protocol >= 0 && protocol <= 255 ))
        return
    fi

    # Protocol names known by the system.
    getent protocols "$protocol" >/dev/null 2>&1
}

protocol_supports_ports() {
    case "$1" in
        tcp|udp|sctp|dccp)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --protocol)
            [[ $# -ge 2 ]] || {
                echo "ERROR: --protocol requires a value" >&2
                exit 1
            }

            is_valid_protocol "$2" || {
                echo "ERROR: invalid protocol: $2" >&2
                exit 1
            }

            PROTOCOLS+=("$2")
            shift 2
            ;;

        --protocol=*)
            protocol="${1#*=}"

            is_valid_protocol "$protocol" || {
                echo "ERROR: invalid protocol: $protocol" >&2
                exit 1
            }

            PROTOCOLS+=("$protocol")
            shift
            ;;

        --port)
            [[ $# -ge 2 ]] || {
                echo "ERROR: --port requires a value" >&2
                exit 1
            }

            is_valid_port "$2" || {
                echo "ERROR: invalid port: $2" >&2
                exit 1
            }

            PORTS+=("$2")
            shift 2
            ;;

        --port=*)
            port="${1#*=}"

            is_valid_port "$port" || {
                echo "ERROR: invalid port: $port" >&2
                exit 1
            }

            PORTS+=("$port")
            shift
            ;;

        --allow)
            [[ $# -ge 2 ]] || {
                echo "ERROR: --allow requires an IPv4 address or CIDR" >&2
                exit 1
            }

            if ! is_ipv4 "$2" && ! is_cidr "$2"; then
                echo "ERROR: invalid --allow value: $2" >&2
                exit 1
            fi

            ALLOW_NETWORKS+=("$2")
            shift 2
            ;;

        --allow=*)
            value="${1#*=}"

            if ! is_ipv4 "$value" && ! is_cidr "$value"; then
                echo "ERROR: invalid --allow value: $value" >&2
                exit 1
            fi

            ALLOW_NETWORKS+=("$value")
            shift
            ;;

        --chain)
            [[ $# -ge 2 ]] || {
                echo "ERROR: --chain requires a name" >&2
                exit 1
            }

            is_valid_chain_name "$2" || {
                echo "ERROR: invalid chain name: $2" >&2
                exit 1
            }

            CHAIN="$2"
            USE_CHAIN=true
            shift 2
            ;;

        --chain=*)
            CHAIN="${1#*=}"

            is_valid_chain_name "$CHAIN" || {
                echo "ERROR: invalid chain name: $CHAIN" >&2
                exit 1
            }

            USE_CHAIN=true
            shift
            ;;

        --no-chain)
            USE_CHAIN=false
            shift
            ;;

        -h|--help)
            usage
            exit 0
            ;;

        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate protocol/port combination
# ---------------------------------------------------------------------------

if [[ ${#PORTS[@]} -gt 0 && ${#PROTOCOLS[@]} -eq 0 ]]; then
    echo "ERROR: --port requires at least one --protocol" >&2
    exit 1
fi

if [[ ${#PORTS[@]} -gt 0 ]]; then
    for protocol in "${PROTOCOLS[@]}"; do
        if ! protocol_supports_ports "$protocol"; then
            echo "ERROR: protocol '$protocol' does not support --port" >&2
            exit 1
        fi
    done
fi

# Remove duplicate ports.
if [[ ${#PORTS[@]} -gt 0 ]]; then
    mapfile -t PORTS < <(
        printf '%s\n' "${PORTS[@]}" | awk '!seen[$0]++'
    )
fi

# Remove duplicate protocols.
if [[ ${#PROTOCOLS[@]} -gt 0 ]]; then
    mapfile -t PROTOCOLS < <(
        printf '%s\n' "${PROTOCOLS[@]}" | awk '!seen[$0]++'
    )
fi

# Remove duplicate --allow entries.
if [[ ${#ALLOW_NETWORKS[@]} -gt 0 ]]; then
    mapfile -t ALLOW_NETWORKS < <(
        printf '%s\n' "${ALLOW_NETWORKS[@]}" | awk '!seen[$0]++'
    )
fi

# ---------------------------------------------------------------------------
# Whitelist file
# ---------------------------------------------------------------------------

if [[ ! -f "$WHITELIST_FILE" ]]; then
    echo "Whitelist file does not exist: $WHITELIST_FILE"

    if [[ -f /templates/whitelist.txt.template ]]; then
        echo "Copying whitelist template to $WHITELIST_FILE"
        cp /templates/whitelist.txt.template "$WHITELIST_FILE"
    else
        echo "No whitelist template found, creating empty whitelist"
        touch "$WHITELIST_FILE"
    fi

    chown 1000:1000 "$WHITELIST_FILE"
    chmod 0644 "$WHITELIST_FILE"
fi

# hash:net supports both individual IPs and CIDR networks.
ipset create "$SET" hash:net family inet -exist

# ---------------------------------------------------------------------------
# Build firewall rules
# ---------------------------------------------------------------------------

build_rule_for_protocol() {
    local target="$1"
    local protocol="$2"
    local port="$3"
    local network

    # Explicit --allow entries.
    for network in "${ALLOW_NETWORKS[@]}"; do
        if [[ -n "$port" ]]; then
            iptables -A "$target" \
                -s "$network" \
                -p "$protocol" \
                --dport "$port" \
                -j ACCEPT
        else
            iptables -A "$target" \
                -s "$network" \
                -p "$protocol" \
                -j ACCEPT
        fi
    done

    # Whitelist ipset.
    if [[ -n "$port" ]]; then
        iptables -A "$target" \
            -p "$protocol" \
            --dport "$port" \
            -m set --match-set "$SET" src \
            -j ACCEPT
    else
        iptables -A "$target" \
            -p "$protocol" \
            -m set --match-set "$SET" src \
            -j ACCEPT
    fi

    # Deny everything else.
    if [[ -n "$port" ]]; then
        iptables -A "$target" \
            -p "$protocol" \
            --dport "$port" \
            -j DROP
    else
        iptables -A "$target" \
            -p "$protocol" \
            -j DROP
    fi
}

build_rules() {
    local target="$1"
    local protocol
    local port

    if [[ ${#PROTOCOLS[@]} -eq 0 ]]; then
        # No protocol specified:
        # protect all IP protocols.
        #
        # A port cannot be specified in this mode, as there is no protocol
        # to which the port belongs.
        for network in "${ALLOW_NETWORKS[@]}"; do
            iptables -A "$target" \
                -s "$network" \
                -j ACCEPT
        done

        iptables -A "$target" \
            -m set --match-set "$SET" src \
            -j ACCEPT

        iptables -A "$target" \
            -j DROP

    elif [[ ${#PORTS[@]} -eq 0 ]]; then
        # Protocols specified, but no ports:
        # protect all ports for each protocol.
        for protocol in "${PROTOCOLS[@]}"; do
            build_rule_for_protocol "$target" "$protocol" ""
        done

    else
        # Protocols + ports:
        # protect every protocol/port combination.
        for protocol in "${PROTOCOLS[@]}"; do
            for port in "${PORTS[@]}"; do
                build_rule_for_protocol "$target" "$protocol" "$port"
            done
        done
    fi

    # Anything not handled by this whitelist continues through DOCKER-USER.
    iptables -A "$target" -j RETURN
}

# ---------------------------------------------------------------------------
# Configure iptables
# ---------------------------------------------------------------------------

if "$USE_CHAIN"; then

    # Create dedicated chain if necessary.
    iptables -N "$CHAIN" 2>/dev/null || true

    # Remove existing jumps to our chain.
    while iptables -C DOCKER-USER -j "$CHAIN" 2>/dev/null; do
        iptables -D DOCKER-USER -j "$CHAIN"
    done

    # Rebuild dedicated chain.
    iptables -F "$CHAIN"

    # Existing connections must be accepted before the whitelist.
    iptables -C DOCKER-USER \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
    iptables -I DOCKER-USER 1 \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    build_rules "$CHAIN"

    # Jump to our whitelist chain.
    iptables -I DOCKER-USER 2 -j "$CHAIN"

else

    echo "WARNING: --no-chain mode enabled."
    echo "Rules are being added directly to DOCKER-USER."
    echo "Changing configuration may leave old rules in place."

    TEMP_CHAIN="${CHAIN}-TMP"

    iptables -N "$TEMP_CHAIN" 2>/dev/null || true
    iptables -F "$TEMP_CHAIN"

    build_rules "$TEMP_CHAIN"

    while read -r rule; do
        [[ "$rule" == "-A $TEMP_CHAIN "* ]] || continue

        rule="${rule#-A $TEMP_CHAIN }"

        # Do not copy the RETURN rule.
        [[ "$rule" == "-j RETURN" ]] && continue

        # shellcheck disable=SC2086
        iptables -C DOCKER-USER $rule 2>/dev/null ||
            iptables -A DOCKER-USER $rule
    done < <(iptables-save -t filter)

    iptables -F "$TEMP_CHAIN"
    iptables -X "$TEMP_CHAIN"
fi

# ---------------------------------------------------------------------------
# Update whitelist
# ---------------------------------------------------------------------------

update() {
    local entries=()
    local ips=()
    local line value resolved
    local resolved_ips=()
    local line_number=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        ((++line_number))

        # Remove leading/trailing whitespace.
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"

        # Ignore empty lines and comments.
        [[ -z "$line" ]] && continue
        [[ "$line" == \#* ]] && continue

        entries+=("$line")
    done < "$WHITELIST_FILE"

    # -----------------------------------------------------------------------
    # Parse whitelist file.
    # -----------------------------------------------------------------------

    for value in "${entries[@]}"; do

        # Plain IPv4.
        if is_ipv4 "$value"; then
            ips+=("$value")
            continue
        fi

        # CIDR.
        if is_cidr "$value"; then
            ips+=("$value")
            continue
        fi

        # DNS hostname.
        if ! is_hostname "$value"; then
            echo "ERROR: invalid whitelist entry: $value"
            return 1
        fi

        # Resolve all IPv4 A records.
        mapfile -t resolved_ips < <(
            dig +short A "$value" |
                grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
        )

        if [[ ${#resolved_ips[@]} -eq 0 ]]; then
            echo "ERROR: could not resolve IPv4 address for $value"
            return 1
        fi

        for resolved in "${resolved_ips[@]}"; do
            if ! is_ipv4 "$resolved"; then
                echo "ERROR: invalid IPv4 returned by DNS for $value: $resolved"
                return 1
            fi

            ips+=("$resolved")
        done
    done

    # -----------------------------------------------------------------------
    # Add explicit --allow entries.
    # -----------------------------------------------------------------------

    for value in "${ALLOW_NETWORKS[@]}"; do
        ips+=("$value")
    done

    # -----------------------------------------------------------------------
    # Build new ipset.
    # -----------------------------------------------------------------------

    ipset create "$TMPSET" hash:net family inet -exist
    ipset flush "$TMPSET"

    for ip in "${ips[@]}"; do
        ipset add "$TMPSET" "$ip"
    done

    # -----------------------------------------------------------------------
    # Detect whether anything actually changed.
    # -----------------------------------------------------------------------

    local old_members
    local new_members

    old_members="$(
        ipset save "$SET" |
            awk '$1 == "add" { print $3 }' |
            sort
    )"

    new_members="$(
        ipset save "$TMPSET" |
            awk '$1 == "add" { print $3 }' |
            sort
    )"

    if [[ "$old_members" == "$new_members" ]]; then
        ipset destroy "$TMPSET"

        echo "No changes detected on update. Whitelist is up to date"
        return 0
    fi

    # -----------------------------------------------------------------------
    # Atomically replace the active set.
    # -----------------------------------------------------------------------

    ipset swap "$TMPSET" "$SET"
    ipset destroy "$TMPSET"

    echo "Whitelist updated from: $WHITELIST_FILE"

    if [[ ${#PROTOCOLS[@]} -eq 0 ]]; then
        echo "Protected protocols: ALL"
    else
        echo "Protected protocols: ${PROTOCOLS[*]}"
    fi

    if [[ ${#PORTS[@]} -eq 0 ]]; then
        echo "Protected ports: ALL"
    else
        echo "Protected ports: ${PORTS[*]}"
    fi

    if [[ ${#ALLOW_NETWORKS[@]} -gt 0 ]]; then
        echo "Additional --allow entries: ${ALLOW_NETWORKS[*]}"
    fi

    echo
    ipset list "$SET"
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

while true; do
    update || echo "Not updated, preserving previous whitelist."
    sleep "$INTERVAL"
done
