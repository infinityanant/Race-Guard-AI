#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${ROOT_DIR}/logs"
mkdir -p "${LOG_DIR}"

AI_PORT=5001
BACKEND_PORT=4000
FRONTEND_PORT=5173

ai_pid=""
backend_pid=""
frontend_pid=""
PYTHON_BIN=""
NODE_BIN=""
NPM_BIN=""
PYTHON_USE_CMD=0
NODE_USE_CMD=0
NPM_USE_CMD=0

cleanup_on_error() {
  echo ""
  echo "Startup failed. Cleaning up background processes..."
  [[ -n "${ai_pid}" ]] && kill "${ai_pid}" 2>/dev/null || true
  [[ -n "${backend_pid}" ]] && kill "${backend_pid}" 2>/dev/null || true
  [[ -n "${frontend_pid}" ]] && kill "${frontend_pid}" 2>/dev/null || true
}
trap cleanup_on_error ERR

is_port_ready() {
  local port="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -s "http://127.0.0.1:${port}" >/dev/null 2>&1
    return $?
  fi

  # Fallback check if curl is unavailable
  (echo >"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1
}

wait_for_port() {
  local name="$1"
  local port="$2"
  local timeout="${3:-30}"
  local elapsed=0

  while (( elapsed < timeout )); do
    if is_port_ready "${port}"; then
      echo "✅ ${name} is ready on port ${port}"
      return 0
    fi
    sleep 1
    ((elapsed+=1))
  done

  echo "❌ ${name} did not become ready on port ${port} within ${timeout}s"
  return 1
}

resolve_python() {
  # Prefer cmd.exe on Windows to avoid Git Bash interpreter mismatches.
  if command -v cmd.exe >/dev/null 2>&1; then
    PYTHON_BIN="py -3"
    PYTHON_USE_CMD=1
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
    return 0
  fi
  return 1
}

resolve_node() {
  if command -v cmd.exe >/dev/null 2>&1; then
    NODE_BIN="node"
    NODE_USE_CMD=1
    return 0
  fi
  if command -v node >/dev/null 2>&1; then
    NODE_BIN="node"
    return 0
  fi
  if [[ -x "/c/Program Files/nodejs/node.exe" ]]; then
    NODE_BIN="/c/Program Files/nodejs/node.exe"
    return 0
  fi
  return 1
}

resolve_npm() {
  if command -v cmd.exe >/dev/null 2>&1; then
    NPM_BIN="npm"
    NPM_USE_CMD=1
    return 0
  fi
  if command -v npm >/dev/null 2>&1; then
    NPM_BIN="npm"
    return 0
  fi
  if command -v npm.cmd >/dev/null 2>&1; then
    NPM_BIN="npm.cmd"
    return 0
  fi
  if [[ -x "/c/Program Files/nodejs/npm.cmd" ]]; then
    NPM_BIN="/c/Program Files/nodejs/npm.cmd"
    return 0
  fi
  return 1
}

ensure_process_started() {
  local pid="$1"
  local name="$2"
  local log_file="$3"
  sleep 1
  if ! kill -0 "${pid}" 2>/dev/null; then
    echo "❌ ${name} exited immediately."
    if [[ -f "${log_file}" ]]; then
      echo "Last log line:"
      sed -n '$p' "${log_file}" || true
    fi
    return 1
  fi
}

get_port_owner_pid() {
  local port="$1"
  if command -v powershell.exe >/dev/null 2>&1; then
    powershell.exe -NoProfile -Command "(Get-NetTCPConnection -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty OwningProcess)" 2>/dev/null | tr -d '\r' | tr -d '\n'
    return 0
  fi
  echo ""
}

ensure_port_free() {
  local name="$1"
  local port="$2"
  local owner_pid
  owner_pid="$(get_port_owner_pid "${port}")"
  if [[ -n "${owner_pid}" ]]; then
    echo "❌ ${name} cannot start: port ${port} is already in use (PID ${owner_pid})."
    echo "Stop the old process on port ${port}, then run start.sh again."
    return 1
  fi
}

resolve_python || { echo "❌ Could not find Python (python/python3/py.exe)"; exit 1; }
resolve_node || { echo "❌ Could not find Node.js (node/node.exe)"; exit 1; }
resolve_npm || { echo "❌ Could not find npm (npm/npm.cmd)"; exit 1; }

ensure_port_free "Flask AI service" "${AI_PORT}"
ensure_port_free "Node backend" "${BACKEND_PORT}"
ensure_port_free "React frontend" "${FRONTEND_PORT}"

echo "Starting AI service..."
(
  cd "${ROOT_DIR}/ai-service"
  if [[ "${PYTHON_USE_CMD}" -eq 1 ]]; then
    nohup cmd.exe /c "${PYTHON_BIN} app.py" > "${LOG_DIR}/ai-service.log" 2>&1 &
  else
    nohup bash -lc "${PYTHON_BIN} app.py" > "${LOG_DIR}/ai-service.log" 2>&1 &
  fi
  echo $! > "${LOG_DIR}/ai-service.pid"
)
ai_pid="$(<"${LOG_DIR}/ai-service.pid")"
echo "AI service PID: ${ai_pid}"
ensure_process_started "${ai_pid}" "AI service" "${LOG_DIR}/ai-service.log"

echo "Starting backend service..."
(
  cd "${ROOT_DIR}/backend"
  if [[ "${NODE_USE_CMD}" -eq 1 ]]; then
    nohup cmd.exe /c "${NODE_BIN} index.js" > "${LOG_DIR}/backend.log" 2>&1 &
  else
    nohup bash -lc "\"${NODE_BIN}\" index.js" > "${LOG_DIR}/backend.log" 2>&1 &
  fi
  echo $! > "${LOG_DIR}/backend.pid"
)
backend_pid="$(<"${LOG_DIR}/backend.pid")"
echo "Backend service PID: ${backend_pid}"
ensure_process_started "${backend_pid}" "Backend service" "${LOG_DIR}/backend.log"

echo "Starting frontend service..."
(
  cd "${ROOT_DIR}/frontend"
  if [[ "${NPM_USE_CMD}" -eq 1 ]]; then
    nohup cmd.exe /c "${NPM_BIN} run dev -- --host 0.0.0.0 --port ${FRONTEND_PORT}" > "${LOG_DIR}/frontend.log" 2>&1 &
  else
    nohup bash -lc "\"${NPM_BIN}\" run dev -- --host 0.0.0.0 --port ${FRONTEND_PORT}" > "${LOG_DIR}/frontend.log" 2>&1 &
  fi
  echo $! > "${LOG_DIR}/frontend.pid"
)
frontend_pid="$(<"${LOG_DIR}/frontend.pid")"
echo "Frontend service PID: ${frontend_pid}"
ensure_process_started "${frontend_pid}" "Frontend service" "${LOG_DIR}/frontend.log"

echo ""
echo "Waiting for services to become ready..."
wait_for_port "Flask AI service" "${AI_PORT}" 45
wait_for_port "Node backend" "${BACKEND_PORT}" 45
wait_for_port "React frontend" "${FRONTEND_PORT}" 60

trap - ERR

echo ""
echo "🚀 All services are running in the background."
echo "AI service:      http://localhost:${AI_PORT}"
echo "Backend API:     http://localhost:${BACKEND_PORT}"
echo "React frontend:  http://localhost:${FRONTEND_PORT}"
echo ""
echo "Logs:"
echo "  ${LOG_DIR}/ai-service.log"
echo "  ${LOG_DIR}/backend.log"
echo "  ${LOG_DIR}/frontend.log"
echo ""
echo "PIDs:"
echo "  AI:       ${ai_pid}"
echo "  Backend:  ${backend_pid}"
echo "  Frontend: ${frontend_pid}"
