#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v apt >/dev/null 2>&1; then
    echo "This installer currently supports apt-based Linux distributions (such as Kali)."
    exit 1
fi

sudo apt update
sudo apt install -y nmap python3 python3-tk
chmod +x "$DIR/scanner.py" "$DIR/requirements.txt" "$DIR/nighthawk"

sudo install -d -m 0755 /usr/local/share/man/man1
sudo cp "$DIR/nighthawk.1" /usr/local/share/man/man1/
sudo mandb

launcher="$(mktemp)"
trap 'rm -f "$launcher"' EXIT
printf '#!/usr/bin/env bash\nexec python3 "%s/scanner.py" "$@"\n' "$DIR" > "$launcher"
sudo install -m 0755 "$launcher" /usr/local/bin/nighthawk

echo "NIGHTHAWK is installed. Run: nighthawk"
