# Encoding specifications generator

This bin crate is used to derive encoding specifications from pre-selected public types via their `BorshSchema` implementations. The `BorshSchema` provides recursive definitions of all the used types and these are also included in the generated specification.

When executed, this crate will generate `documentation/dev/src/specs/encoding/generated-borsh-spec.md` (see `OUTPUT_PATH` in the source). This page is itself included in the `documentation/dev/src/specs/encoding.md` page.
