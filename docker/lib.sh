# Shared helpers for docker/*.sh (sourced, not executed).

# `docker info` can hang indefinitely when the daemon is down or its VM is
# stuck; bound it without relying on coreutils `timeout` (absent on macOS).
kx_docker_up() {
  docker info >/dev/null 2>&1 & local pid=$!
  local _
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2>/dev/null || { wait "$pid"; return $?; }
    sleep 1
  done
  kill "$pid" 2>/dev/null
  return 1
}

kx_ensure_image() { # <image> <context dir>
  if ! docker image inspect "$1" >/dev/null 2>&1; then
    echo "building image $1 (one-time)…" >&2
    docker build --platform linux/amd64 -t "$1" "$2" >&2
  fi
}
