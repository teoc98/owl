#!/bin/sh
set -o errexit

FILE="README.md"
CMD="owl"

usage=$($CMD --help)

awk -v usage="$usage" '
  BEGIN {state=0; }
  {
    if ($0 ~ /^```$/) {
      print
      if (state == 0) {
      	print usage
      	state = 1
      }
      else if (state == 1) {
      	state = 2
      }
    }
    else {
      if (state == 0 || state == 2) {
      	print
      }
    }
  }
' "$FILE" | tee /dev/stderr | sponge "$FILE"
