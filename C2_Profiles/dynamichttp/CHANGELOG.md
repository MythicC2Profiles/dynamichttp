
## 2.0.0

### Updated

- made `raw_config` a File rather than a massive String field the user supplies
- split out `jitter`, `kill_date`, and `interval` into separate parameters in the UI instead of within the config
- added `host_file` capabilities similar to `http` and `websocket`
- added `redirect_rules` based on user agents