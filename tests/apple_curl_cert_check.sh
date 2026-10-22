/usr/bin/curl -q --noproxy '*' \
  --max-time 12 \
  -sS -o /dev/null \
  https://dv-g3b-emudhra.we-have-a-problem.com/

echo "Apple curl exit code: $?"
