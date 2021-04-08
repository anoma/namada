# Intents

tracking issue [#36](https://github.com/heliaxdev/rd-pm/issues/36)

There is only a single intent type that is composed of arbitrary data. Some
informations wildly use might be exported in the futur to specific field, like
`timestamp`.

```rust
struct Intent {
    data: Vec<u8>,
    timestamp: Timestamp
}
```

The arbitrary data will be given to any interested matchmaker to craft valid
transaction. This means that this data encoding must be known the
matchmaker. Some default template will be provided for that encoding for most
general cases.

The user of anoma can define themself there own encoding and an easy plugin
system will be implemented for that. The chosen encoding must define alongside a
matchmaker program, see [matchmaker](./matchmaker.md).
