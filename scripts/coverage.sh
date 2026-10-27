#!/usr/bin/env bash
# Prints a Markdown table of statement coverage per package, and the total,
# from a Go cover profile. Run the tests with -coverpkg=./... so a package
# exercised by another package's tests counts as covered; a block that
# several test binaries report counts once, as covered if any of them ran it.
# The fake GitHub used by the tests is left out.
# Usage: scripts/coverage.sh [coverage.out]
set -euo pipefail
cd "$(dirname "$0")/.."

profile="${1:-coverage.out}"
module=$(go list -m)

tail -n +2 "$profile" | awk -v module="$module/" '
{
  block = $1
  statements[block] = $2
  if ($3 > 0) hit[block] = 1
}
END {
  for (block in statements) {
    file = block
    sub(/:.*/, "", file)
    sub(module, "", file)
    pkg = file
    sub(/\/[^\/]*$/, "", pkg)
    if (pkg ~ /fakegh/) continue
    total[pkg] += statements[block]
    all += statements[block]
    if (block in hit) {
      covered[pkg] += statements[block]
      allCovered += statements[block]
    }
  }
  print "| Package | Coverage |"
  print "|---|---:|"
  n = 0
  for (pkg in total) names[++n] = pkg
  # insertion sort, for awks without asort
  for (i = 2; i <= n; i++) {
    v = names[i]
    for (j = i - 1; j > 0 && names[j] > v; j--) names[j + 1] = names[j]
    names[j + 1] = v
  }
  for (i = 1; i <= n; i++) {
    pkg = names[i]
    printf "| `%s` | %.1f%% |\n", pkg, 100 * covered[pkg] / total[pkg]
  }
  printf "| **Total** | **%.1f%%** |\n", 100 * allCovered / all
}'
