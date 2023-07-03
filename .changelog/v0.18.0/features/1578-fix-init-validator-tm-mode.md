- Added `NAMADA_LOG_DIR` env var for logging to file(s) and `NAMADA_LOG_ROLLING`
  for setting rolling logs frequency. The rolling frequency can be set to
  never, minutely, hourly or daily. If not set, the default is never.
  ([\#1578](https://github.com/anoma/namada/pull/1578))