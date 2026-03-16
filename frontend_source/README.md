# ADFT integrated GUI source

This folder contains the React/Tailwind source used to produce the packaged assets shipped in `adft/webui_dist`.

The official v1.0 runtime path is the Python backend command:

```bash
adft ui -o reports_gui --host 127.0.0.1 --port 8765
```

The browser UI is backend-driven and reads the real ADFT run state exposed by the local server.
