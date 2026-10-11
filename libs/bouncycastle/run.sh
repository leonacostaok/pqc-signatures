#!/usr/bin/env bash
# Bouncy Castle (bcprov-jdk18on) harness - see common/CONTRACT.md
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COMMON="$ROOT/common"
DEPS="$HERE/deps"
BUILD="$HERE/build"
BC_VERSION="${BC_VERSION:-1.86}"
MAVEN="https://repo1.maven.org/maven2/org/bouncycastle"
ARTIFACTS=(bcprov-jdk18on bcutil-jdk18on)

export JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
JAVA="$JAVA_HOME/bin/java"
JAVAC="$JAVA_HOME/bin/javac"
# JAVA_TOOL_OPTIONS (proxy settings) prints a banner on every JVM start; it is not needed at run time.
unset JAVA_TOOL_OPTIONS

cp_string() {
  local cp="$BUILD/classes"
  for a in "${ARTIFACTS[@]}"; do cp="$cp:$DEPS/$a-$BC_VERSION.jar"; done
  echo "$cp"
}

fetch() {
  mkdir -p "$DEPS"
  for a in "${ARTIFACTS[@]}"; do
    local jar="$DEPS/$a-$BC_VERSION.jar"
    if [ ! -s "$jar" ] || [ ! -s "$jar.sha256" ]; then
      echo "fetching $a $BC_VERSION from Maven Central" >&2
      curl -fsSL -o "$jar" "$MAVEN/$a/$BC_VERSION/$a-$BC_VERSION.jar"
      curl -fsSL -o "$jar.sha256" "$MAVEN/$a/$BC_VERSION/$a-$BC_VERSION.jar.sha256"
    fi
    local want have
    want="$(tr -d ' \n' < "$jar.sha256" | cut -c1-64)"
    have="$(sha256sum "$jar" | cut -c1-64)"
    if [ "$want" != "$have" ]; then echo "checksum mismatch for $jar" >&2; exit 1; fi
  done
}

build() {
  fetch
  local stamp="$BUILD/.stamp"
  if [ -f "$stamp" ] && [ -z "$(find "$HERE/src" -newer "$stamp" -name '*.java')" ]; then
    return 0
  fi
  mkdir -p "$BUILD/classes"
  local cp=""
  for a in "${ARTIFACTS[@]}"; do cp="$cp:$DEPS/$a-$BC_VERSION.jar"; done
  find "$HERE/src" -name '*.java' > "$BUILD/sources.txt"
  "$JAVAC" --release 21 -Xlint:-options -d "$BUILD/classes" -cp "${cp#:}" @"$BUILD/sources.txt"
  touch "$stamp"
  echo "built libs/bouncycastle (bcprov-jdk18on $BC_VERSION, $("$JAVA" -version 2>&1 | head -1))" >&2
}

run_java() {
  local cp; cp="$(cp_string)"
  exec "$JAVA" -Dpqc.common="$COMMON" -Dpqc.classpath="$cp" -cp "$cp" Bench "$@"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  build) build ;;
  vectors) build >/dev/null; run_java vectors "$@" ;;
  crossverify) build >/dev/null; run_java crossverify "$@" ;;
  bench) build >/dev/null; run_java bench "$@" ;;
  validate) build >/dev/null; run_java validate "$@" ;;
  stages) build >/dev/null; run_java stages "$@" ;;
  memory) build >/dev/null; run_java memory "$@" ;;
  *) echo "usage: $0 build | vectors <out.json> | crossverify <artifacts.json> <out.json> | bench --out <f.jsonl> [--budget-ms N] [--params a,b] [--ops keygen,sign,verify] [--variants id,id] | validate <validation.json.gz> <out.json> | stages --out <f.jsonl> [--budget-ms N] [--params a,b] [--stages x,y] | memory --out <f.jsonl> [--params a,b]" >&2; exit 2 ;;
esac
