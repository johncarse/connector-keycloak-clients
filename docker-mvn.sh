#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "docker-mvn.sh: docker is not available on PATH" >&2
  exit 1
fi

IMAGE="${DOCKER_MVN_IMAGE:-maven:3.9-eclipse-temurin-21}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$(pwd)}"
M2_DIR="${M2_DIR:-$HOME/.m2}"

if [[ ! -d "$M2_DIR" ]]; then
  mkdir -p "$M2_DIR"
fi

if [[ $# -eq 0 ]]; then
  MVN_ARGS=(package)
else
  MVN_ARGS=("$@")
fi

docker run --rm \
  -v "$M2_DIR:/root/.m2" \
  -v "$WORKSPACE_DIR":/workspace \
  -w /workspace \
  -e MAVEN_CONFIG=/root/.m2 \
  "$IMAGE" \
  mvn "${MVN_ARGS[@]}"
