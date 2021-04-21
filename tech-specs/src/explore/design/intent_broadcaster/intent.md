# Intents

tracking issue [#36](https://github.com/heliaxdev/rd-pm/issues/36)

There is only a single intent type that is composed of arbitrary data and a
possible schema definition.

```rust
struct Intent {
    schema: Option<Key>,
    data: Vec<u8>,
    timestamp: Timestamp
}
```

The arbitrary data will be broadcasted to any interested matchmaker to craft
valid transaction. If the user wants the intent to found a match with a public
matchmaker he must use a known data schema or else no matchmaker will be able to
decode his intent. (see [data schema](../data-schema.md)).
