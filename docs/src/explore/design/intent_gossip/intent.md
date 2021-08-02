# Intents

[Tracking Issue](https://github.com/anoma/anoma/issues/36)

---

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
valid transactions. For an intent to find a match with a public matchmaker, it must use a known data schema or else no matchmaker will be able to decode its data (see [data schema](../data-schema.md)).
