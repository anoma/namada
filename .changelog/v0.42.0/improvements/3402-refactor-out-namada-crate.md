- Added two new crates, namada_vm and namada_vp and removed namada crate that
  contained various loosely related code. Moved the native VP implementations
  to the relevant crates and replaced their cross-dependencies with dependency-
  injection. ([\#3402](https://github.com/anoma/namada/pull/3402))