/usr/bin/curl -q --noproxy '*' \
  --connect-timeout 6 --max-time 12 \
  https://dv-g3b-emudhra.we-have-a-problem.com/
echo "First test exit code: $?"

/usr/bin/curl -q --noproxy '*' \
  --connect-timeout 6 --max-time 12 \
  https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
echo "Second test exit code: $?"
