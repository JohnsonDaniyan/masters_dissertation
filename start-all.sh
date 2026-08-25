#!/usr/bin/env bash
# Start or stop the mock Open Banking lab, FAPI scanner API, and FAPI Lens frontend.
#
#   ./start-all.sh              # same as start
#   ./start-all.sh start
#   ./start-all.sh stop
#   ./start-all.sh restart
#   ./start-all.sh status
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$ROOT/.run"
PID_FILE="$RUN_DIR/services.pids"
LAB_PORT="${LAB_PORT:-8000}"
SCANNER_PORT="${SCANNER_PORT:-8080}"
FRONT_PORT="${FRONT_PORT:-3000}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [start|stop|restart|status]

  start     Start the mock lab, scanner API, and frontend (default)
  stop      Stop all three services
  restart   Stop, then start
  status    Show whether each service is running

Ports can be overridden with LAB_PORT, SCANNER_PORT, and FRONT_PORT.
EOF
}

detect_python() {
  local candidate
  for candidate in python3.12 python3.13 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "error: Python 3 is required" >&2
  exit 1
}

ensure_venv() {
  local dir="$1"
  local requirements="$2"
  local python_bin
  python_bin="$(detect_python)"
  if [[ ! -x "$dir/.venv/bin/python" ]]; then
    echo "Creating virtualenv in $dir/.venv"
    "$python_bin" -m venv "$dir/.venv"
  fi
  "$dir/.venv/bin/pip" install -q -r "$requirements"
}

listeners_on_port() {
  lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null || true
}

pid_alive() {
  [[ -n "${1:-}" ]] && kill -0 "$1" 2>/dev/null
}

kill_tree() {
  local pid="$1"
  local child
  if ! pid_alive "$pid"; then
    return 0
  fi
  while read -r child; do
    [[ -n "$child" ]] && kill_tree "$child"
  done < <(pgrep -P "$pid" 2>/dev/null || true)
  kill "$pid" 2>/dev/null || true
}

stop_port() {
  local name="$1"
  local port="$2"
  local pids
  pids="$(listeners_on_port "$port")"
  if [[ -z "$pids" ]]; then
    echo "$name (port $port) already stopped"
    return 0
  fi
  echo "Stopping $name (port $port)…"
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null || true
  sleep 0.3
  pids="$(listeners_on_port "$port")"
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
  fi
}

cmd_stop() {
  if [[ -f "$PID_FILE" ]]; then
    while read -r pid; do
      [[ -z "$pid" ]] && continue
      kill_tree "$pid"
    done < "$PID_FILE"
    rm -f "$PID_FILE"
  fi
  stop_port "Mock Open Banking lab" "$LAB_PORT"
  stop_port "FAPI scanner API" "$SCANNER_PORT"
  stop_port "FAPI Lens" "$FRONT_PORT"
  echo "All services stopped."
}

service_state() {
  local pids
  pids="$(listeners_on_port "$2")"
  if [[ -n "$pids" ]]; then
    echo "$1  running  http://127.0.0.1:$2  pid $(echo "$pids" | tr '\n' ' ')"
  else
    echo "$1  stopped  http://127.0.0.1:$2"
  fi
}

cmd_status() {
  service_state "Mock Open Banking lab" "$LAB_PORT"
  service_state "FAPI scanner API     " "$SCANNER_PORT"
  service_state "FAPI Lens            " "$FRONT_PORT"
}

cmd_start() {
  if [[ -n "$(listeners_on_port "$LAB_PORT")" ||
        -n "$(listeners_on_port "$SCANNER_PORT")" ||
        -n "$(listeners_on_port "$FRONT_PORT")" ]]; then
    echo "One or more services are already running:"
    cmd_status
    echo "Use: $0 stop   or   $0 restart"
    exit 1
  fi

  if ! command -v npm >/dev/null 2>&1; then
    echo "error: npm is required to start the frontend" >&2
    exit 1
  fi

  ensure_venv "$ROOT/mock-lab" "$ROOT/mock-lab/requirements.txt"
  ensure_venv "$ROOT/fapi-scanner" "$ROOT/fapi-scanner/requirements.txt"

  if [[ ! -d "$ROOT/front-end/node_modules" ]]; then
    echo "Installing frontend dependencies"
    (cd "$ROOT/front-end" && npm install)
  fi

  mkdir -p "$RUN_DIR"
  : > "$PID_FILE"

  echo
  echo "Mock Open Banking lab   http://127.0.0.1:${LAB_PORT}"
  echo "FAPI scanner API        http://127.0.0.1:${SCANNER_PORT}"
  echo "FAPI Lens               http://127.0.0.1:${FRONT_PORT}"
  echo "Stop with: $0 stop"
  echo

  (
    cd "$ROOT/mock-lab"
    exec .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port "$LAB_PORT" --reload
  ) &
  echo $! >> "$PID_FILE"

  (
    cd "$ROOT/fapi-scanner"
    exec .venv/bin/uvicorn scanner.api:app --host 127.0.0.1 --port "$SCANNER_PORT" --reload
  ) &
  echo $! >> "$PID_FILE"

  (
    cd "$ROOT/front-end"
    exec npx next dev --port "$FRONT_PORT"
  ) &
  echo $! >> "$PID_FILE"

  echo "Started in the background."
}

case "${1:-start}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart)
    cmd_stop
    cmd_start
    ;;
  status) cmd_status ;;
  -h|--help|help) usage ;;
  *)
    echo "error: unknown command '${1}'" >&2
    usage >&2
    exit 1
    ;;
esac
