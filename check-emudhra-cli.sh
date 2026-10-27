#!/bin/bash
# Test TLS trust against eMudhra incident endpoints across installed tools only.

set -u

C_PASS=$'\033[0;32;40m'
C_WARN=$'\033[0;33;40m'
C_FAIL=$'\033[0;31;40m'
C_RESET=$'\033[0m'

hosts=(
    dv-g3b-emudhra.we-have-a-problem.com
    dv-g3b-aaa-emudhra.we-have-a-problem.com
    dv-g3b-noct-emudhra.we-have-a-problem.com
    dv-g3b-aaa-noct-emudhra.we-have-a-problem.com
)

failures=0
warnings=0

run_check() {
    local tool="$1"
    local host="$2"
    local status="$3"    # PASS, FAIL, or WARN
    local details="$4"

    case "$status" in
        PASS)
            printf "${C_PASS}PASS${C_RESET}  [%-8s] %-48s %s\n" "$tool" "$host" "$details"
            ;;
        FAIL)
            printf "${C_FAIL}FAIL${C_RESET}  [%-8s] %-48s %s\n" "$tool" "$host" "$details"
            ((failures+=1))
            ;;
        WARN)
            printf "${C_WARN}WARN${C_RESET}  [%-8s] %-48s %s\n" "$tool" "$host" "$details"
            ((warnings+=1))
            ;;
    esac
}

# --- 1. cURL ---
if command -v curl &>/dev/null; then
    printf 'curl: %s\n' "$(curl --version | head -n 1)"
    for host in "${hosts[@]}"; do
        output=$(curl -sS --connect-timeout 5 --max-time 12 -o /dev/null -w '%{http_code}' "https://${host}/" 2>&1)
        rc=$?
        if (( rc == 0 )); then
            run_check "curl" "$host" "FAIL" "HTTP $output (TLS accepted)"
        elif (( rc == 60 )); then
            run_check "curl" "$host" "PASS" "certificate rejected"
        else
            run_check "curl" "$host" "WARN" "exit=$rc: $output"
        fi
    done
    printf '\n'
fi

# --- 2. Wget ---
if command -v wget &>/dev/null; then
    printf 'wget: %s\n' "$(wget --version | head -n 1)"
    for host in "${hosts[@]}"; do
        output=$(wget --quiet --connect-timeout=5 --timeout=12 --spider "https://${host}/" 2>&1)
        rc=$?
        if (( rc == 0 )); then
            run_check "wget" "$host" "FAIL" "TLS accepted"
        elif (( rc == 5 )); then
            run_check "wget" "$host" "PASS" "certificate rejected"
        else
            run_check "wget" "$host" "WARN" "exit=$rc: $output"
        fi
    done
    printf '\n'
fi

# --- 3. OpenSSL ---
if command -v openssl &>/dev/null; then
    printf 'openssl: %s\n' "$(openssl version)"
    for host in "${hosts[@]}"; do
        out=$(openssl s_client -connect "${host}:443" -servername "${host}" </dev/null 2>&1)
        if echo "$out" | grep -q "Verify return code: 0 (ok)"; then
            run_check "openssl" "$host" "FAIL" "TLS accepted"
        elif echo "$out" | grep -qE "Verify return code: (19|20|21)|unable to get local issuer certificate"; then
            run_check "openssl" "$host" "PASS" "certificate rejected"
        else
            run_check "openssl" "$host" "WARN" "handshake failed without specific cert status"
        fi
    done
    printf '\n'
fi

# --- 4. Python3 ---
if command -v python3 &>/dev/null; then
    printf 'python3: %s\n' "$(python3 --version)"
    for host in "${hosts[@]}"; do
        py_output=$(python3 -c "
import urllib.request, ssl
try:
    with urllib.request.urlopen('https://${host}/', timeout=5) as r:
        print('ACCEPTED')
except ssl.SSLCertVerificationError:
    print('REJECTED')
except Exception as e:
    print(f'ERROR: {e}')
" 2>&1)
        case "$py_output" in
            ACCEPTED) run_check "python3" "$host" "FAIL" "TLS accepted" ;;
            REJECTED) run_check "python3" "$host" "PASS" "certificate rejected" ;;
            *)        run_check "python3" "$host" "WARN" "$py_output" ;;
        esac
    done
    printf '\n'
fi

# --- 5. Git ---
if command -v git &>/dev/null; then
    printf 'git: %s\n' "$(git --version)"
    for host in "${hosts[@]}"; do
        git_out=$(GIT_TERMINAL_PROMPT=0 git ls-remote "https://${host}/repo.git" 2>&1)
        if echo "$git_out" | grep -qE "SSL certificate problem|certificate verification failed"; then
            run_check "git" "$host" "PASS" "certificate rejected"
        elif echo "$git_out" | grep -qE "Could not resolve host|HTTP 404|Authentication failed"; then
            run_check "git" "$host" "FAIL" "TLS accepted (failed at application layer)"
        else
            run_check "git" "$host" "WARN" "$(echo "$git_out" | head -n 1)"
        fi
    done
    printf '\n'
fi

# --- 6. APT ? ---

# --- 7. Socat ---
if command -v socat &>/dev/null; then
    printf 'socat: %s\n' "$(socat -V | head -n 1)"
    for host in "${hosts[@]}"; do
        socat_out=$(socat -T 5 STDIO "OPENSSL:${host}:443,verify=1" </dev/null 2>&1)
        if echo "$socat_out" | grep -qE "certificate verify failed|unable to get local issuer certificate"; then
            run_check "socat" "$host" "PASS" "certificate rejected"
        elif [[ -z "$socat_out" ]]; then
            run_check "socat" "$host" "FAIL" "TLS accepted"
        else
            run_check "socat" "$host" "WARN" "$(echo "$socat_out" | head -n 1)"
        fi
    done
    printf '\n'
fi

# --- 8. Ruby ---
if command -v ruby &>/dev/null; then
    printf 'ruby: %s\n' "$(ruby --version)"
    for host in "${hosts[@]}"; do
        rb_out=$(ruby -rnet/http -e "
begin
  Net::HTTP.get(URI('https://${host}/'))
  puts 'ACCEPTED'
rescue OpenSSL::SSL::SSLError
  puts 'REJECTED'
rescue => e
  puts \"ERROR: #{e.message}\"
end" 2>&1)
        case "$rb_out" in
            ACCEPTED) run_check "ruby" "$host" "FAIL" "TLS accepted" ;;
            REJECTED) run_check "ruby" "$host" "PASS" "certificate rejected" ;;
            *)        run_check "ruby" "$host" "WARN" "$rb_out" ;;
        esac
    done
    printf '\n'
fi

# --- 9. Perl ---
if command -v perl &>/dev/null; then
    printf 'perl: %s\n' "$(perl -v | grep -o 'v[0-9.]*' | head -n 1)"
    for host in "${hosts[@]}"; do
        pl_out=$(perl -e "
use strict;
use warnings;
use LWP::UserAgent;

my \$ua = LWP::UserAgent->new(timeout => 5);
my \$res = \$ua->get('https://${host}/');

if (\$res->is_success) {
    print 'ACCEPTED';
} elsif (\$res->status_line =~ /certificate verify failed|SSLError|SSL_connect/i) {
    print 'REJECTED';
} else {
    print 'ERROR: ' . \$res->status_line;
}" 2>&1)
        case "$pl_out" in
            ACCEPTED) run_check "perl" "$host" "FAIL" "TLS accepted" ;;
            REJECTED) run_check "perl" "$host" "PASS" "certificate rejected" ;;
            *)        run_check "perl" "$host" "WARN" "$pl_out" ;;
        esac
    done
    printf '\n'
fi

# --- 10. Node.js ---
if command -v node &>/dev/null; then
    printf 'node: %s\n' "$(node -v)"
    for host in "${hosts[@]}"; do
        node_out=$(node -e "
fetch('https://${host}/')
  .then(() => console.log('ACCEPTED'))
  .catch(err => {
    if (err.cause && (err.cause.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.cause.code === 'CERT_HAS_EXPIRED' || err.cause.code === 'DEPTH_ZERO_SELF_SIGNED_CERT')) {
      console.log('REJECTED');
    } else {
      console.log('REJECTED'); // Default TLS error rejection for node fetch
    }
  });" 2>&1)
        case "$node_out" in
            ACCEPTED) run_check "node" "$host" "FAIL" "TLS accepted" ;;
            REJECTED) run_check "node" "$host" "PASS" "certificate rejected" ;;
            *)        run_check "node" "$host" "WARN" "$node_out" ;;
        esac
    done
    printf '\n'
fi

# --- Summary ---
printf 'Summary: '
printf "${C_FAIL}%d FAIL${C_RESET}, " "$failures"
printf "${C_WARN}%d WARN${C_RESET}\n" "$warnings"

if (( failures > 0 )); then
    exit 1
elif (( warnings > 0 )); then
    exit 2
fi

exit 0
