# Shared helpers for docker/*.sh (sourced, not executed).

# `docker info` can hang indefinitely when the daemon is down or its VM is
# stuck; bound it without relying on coreutils `timeout` (absent on macOS).
kx_docker_up() {
  # Docker Desktop's Resource Saver pauses the VM when idle; waking can take
  # tens of seconds, so allow up to KX_DOCKER_WAIT (default 45) seconds.
  local limit="${KX_DOCKER_WAIT:-45}" waited=0
  docker info >/dev/null 2>&1 & local pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$limit" ]; then kill "$pid" 2>/dev/null; return 1; fi
    [ "$waited" -eq 5 ] && echo "waiting for Docker engine (resuming from Resource Saver?)…" >&2
    sleep 1; waited=$((waited + 1))
  done
  wait "$pid"
}

kx_ensure_image() { # <image> <context dir>
  if ! docker image inspect "$1" >/dev/null 2>&1; then
    echo "building image $1 (one-time)…" >&2
    docker build --platform linux/amd64 -t "$1" "$2" >&2
  fi
}
