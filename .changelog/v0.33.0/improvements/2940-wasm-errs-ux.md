- Change the return type of a VP's predicate function to a Result of unit or
  some error. In case Namada users perform invalid state changes, they should
  be met with more descriptive error messages explaining the cause of their tx's
  rejection. ([\#2940](https://github.com/anoma/namada/pull/2940))