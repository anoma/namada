# Matchmaker

The matchmaker is a process that can be activated in any orderbook process. It
tries to match any number of intents to create fulfilling transaction. The
matchmaker is define with three wasm element, a filter, a matchmaker program and
a transaction template.

The filter is a small program that is used to filter in order to prevent
flooding the matchmaker program. This filter logic might be removed in the futur
and any


![matchmaker process](./matchmaker_process.svg "matchmaker process")

[excalidraw link](https://excalidraw.com/#room=92b291c13cfab8fb22a4,OvHfWIrL0jeDzPI-EFZMaw)
