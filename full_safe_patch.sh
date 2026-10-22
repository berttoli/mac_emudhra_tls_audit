orig=/etc/ssl/cert.pem
tmp=$(mktemp) || exit 1

awk '/^(###|===) /{skip=0}
     /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}
     !skip' "$orig" > "$tmp"

before=$(grep -c 'BEGIN CERTIFICATE' "$orig")
after=$(grep -c 'BEGIN CERTIFICATE' "$tmp")

echo "Before: $before certificates"
echo "After:  $after certificates"

if [ "$((before - after))" -eq 2 ]; then
    sudo cp -p "$orig" "$orig.bak.$(date +%Y%m%d%H%M%S)" &&
    sudo tee "$orig" < "$tmp" > /dev/null &&
    echo "System CA bundle updated."
else
    echo "ABORT: Unexpected certificate count."
fi

rm -f "$tmp"
