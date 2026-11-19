-- The gateway session that holds a WebSocket connection: it alone may
-- sweep the connection's row while it lives (src/websocket.rs).
ALTER TABLE app_http_runs ADD COLUMN IF NOT EXISTS session_id text;
