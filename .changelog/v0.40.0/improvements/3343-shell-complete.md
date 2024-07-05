- Added a `namada complete` command to generate shell completions. This command
  requires `--shell` with one of:
  -  bash
  - elvish
  - fish
  - powershell
  - zsh
  - nushell

  To use in e.g. bash, run `namada complete --shell bash > /usr/share/bash-completion/completions/namada.bash`.
  ([\#3343](https://github.com/anoma/namada/pull/3343))