use std::collections::BTreeMap;

use masp_primitives::transaction::Transaction;
use namada_sdk::borsh::schema::{Declaration, Definition, FieldName, Fields};
use namada_sdk::borsh::BorshSchema;
use namada_sdk::tx::MaspBuilder;
use proptest::test_runner::Reason;

fn is_fixed_sized_array(
    decl: &Declaration,
    defs: &BTreeMap<Declaration, Definition>,
) -> Option<(Declaration, u64)> {
    match defs.get(decl)? {
        Definition::Sequence {
            length_width,
            length_range,
            elements,
        } if *length_width == 0
            && length_range.start() == length_range.end() =>
        {
            Some((elements.clone(), *length_range.start()))
        }
        _ => None,
    }
}

fn is_variable_length_array(
    decl: &Declaration,
    defs: &BTreeMap<Declaration, Definition>,
) -> Option<(Declaration, u8)> {
    match defs.get(decl)? {
        Definition::Sequence {
            length_width,
            length_range,
            elements,
        } if length_range.start() < length_range.end() => {
            Some((elements.clone(), *length_width))
        }
        _ => None,
    }
}

fn is_primitive(decl: &Declaration) -> Option<(&'static str, &'static str)> {
    match decl.as_str() {
        "u8" => Some(("uint8_t", "readByte")),
        "u16" => Some(("uint16_t", "readUint16")),
        "u32" => Some(("uint32_t", "readUint32")),
        "u64" => Some(("uint64_t", "readUint64")),
        "u128" => Some(("uint128_t", "readUint128")),
        "i8" => Some(("int8_t", "readInt8")),
        "i16" => Some(("int16_t", "readInt16")),
        "i32" => Some(("int32_t", "readInt32")),
        "i64" => Some(("int64_t", "readInt64")),
        "i128" => Some(("int128_t", "readInt128")),
        _ => None,
    }
}

fn is_unit(
    decl: &Declaration,
    defs: &BTreeMap<Declaration, Definition>,
) -> Option<Definition> {
    match defs.get(decl)? {
        def @ Definition::Primitive(0) => Some(def.clone()),
        _ => None,
    }
}

fn is_tuple(
    decl: &Declaration,
    defs: &BTreeMap<Declaration, Definition>,
) -> Option<Declaration> {
    match defs.get(decl)? {
        Definition::Tuple { elements: _ } => {
            Some(decl.replace(['(', ')'], "").replace(", ", "_"))
        }
        _ => None,
    }
}

fn mangle_name(decl: &Declaration) -> Declaration {
    decl.replace(['<', '>', '(', ')', '[', ']'], "")
        .replace(", ", "_")
        .replace("; ", "_")
        .replace("::", "_")
}

fn process_field(
    name: &FieldName,
    decl: &Declaration,
    definitions: &BTreeMap<Declaration, Definition>,
    struct_decls: &mut Vec<String>,
    parse_instrs: &mut Vec<String>,
) {
    if let Some(_decl) = is_unit(decl, definitions) {
    } else if let Some((decl, parser)) = is_primitive(decl) {
        parse_instrs.push(format!(
            "  CHECK_ERROR({}(ctx, &obj->{}))",
            parser,
            mangle_name(name)
        ));
        struct_decls.push(format!("  {} {};", decl, mangle_name(name)));
    } else if let Some((decl, len)) = is_fixed_sized_array(decl, definitions) {
        if let Some((decl, parser)) = is_primitive(&decl) {
            if decl == "uint8_t" {
                parse_instrs.push(format!(
                    "  CHECK_ERROR(readBytesAlt(ctx, obj->{}, {}))",
                    mangle_name(name),
                    len
                ));
            } else {
                parse_instrs.push(format!(
                    "  for(uint32_t i = 0; i < {}; i++) {{",
                    len
                ));
                parse_instrs.push(format!(
                    "    {}(ctx, &obj->{}[i])",
                    parser,
                    mangle_name(name)
                ));
                parse_instrs.push("  }}".to_string());
            }
            struct_decls.push(format!(
                "  {} {}[{}];",
                decl,
                mangle_name(name),
                len
            ));
        } else if let Some(decl) = is_tuple(&decl, definitions) {
            struct_decls.push(format!(
                "  {} {}[{}];",
                mangle_name(&decl),
                mangle_name(name),
                len
            ));
        } else {
            struct_decls.push(format!(
                "  {} {}[{}];",
                mangle_name(&decl),
                mangle_name(name),
                len
            ));
        }
    } else if let Some((decl, length_tag_len)) =
        is_variable_length_array(decl, definitions)
    {
        let length_tag = match length_tag_len {
            0 => "unk_size".to_string(),
            1 => {
                struct_decls
                    .push(format!("  uint8_t {}Len;", mangle_name(name)));
                parse_instrs.push(format!(
                    "  CHECK_ERROR(readByte(ctx, &obj->{}Len))",
                    mangle_name(name)
                ));
                format!("obj->{}Len", mangle_name(name))
            }
            2 => {
                struct_decls
                    .push(format!("  uint16_t {}Len;", mangle_name(name)));
                parse_instrs.push(format!(
                    "  CHECK_ERROR(readUint16(ctx, &obj->{}Len))",
                    mangle_name(name)
                ));
                format!("obj->{}Len", mangle_name(name))
            }
            4 => {
                struct_decls
                    .push(format!("  uint32_t {}Len;", mangle_name(name)));
                parse_instrs.push(format!(
                    "  CHECK_ERROR(readUint32(ctx, &obj->{}Len))",
                    mangle_name(name)
                ));
                format!("obj->{}Len", mangle_name(name))
            }
            8 => {
                struct_decls
                    .push(format!("  uint64_t {}Len;", mangle_name(name)));
                parse_instrs.push(format!(
                    "  CHECK_ERROR(readUint64(ctx, &obj->{}Len))",
                    mangle_name(name)
                ));
                format!("obj->{}Len", mangle_name(name))
            }
            _ => panic!("invalid length tag length"),
        };
        if let Some((decl, parser)) = is_primitive(&decl) {
            parse_instrs.push(format!(
                "  if((obj->{} = mem_alloc({} * sizeof({}))) == NULL) {{",
                mangle_name(name),
                length_tag,
                decl
            ));
            parse_instrs
                .push("    return parser_unexpected_error;".to_string());
            parse_instrs.push("  }}".to_string());
            parse_instrs.push(format!(
                "  for(uint32_t i = 0; i < {}; i++) {{",
                length_tag
            ));
            parse_instrs.push(format!(
                "    CHECK_ERROR({}(ctx, &obj->{}[i]))",
                parser,
                mangle_name(name)
            ));
            parse_instrs.push("  }}".to_string());
            struct_decls.push(format!("  {} *{};", decl, mangle_name(name)));
        } else if let Some(decl) = is_tuple(&decl, definitions) {
            parse_instrs.push(format!(
                "  if((obj->{} = mem_alloc({} * sizeof({}))) == NULL) {{",
                mangle_name(name),
                length_tag,
                mangle_name(&decl)
            ));
            parse_instrs
                .push("    return parser_unexpected_error;".to_string());
            parse_instrs.push("  }}".to_string());
            parse_instrs.push(format!(
                "  for(uint32_t i = 0; i < {}; i++) {{",
                length_tag
            ));
            parse_instrs.push(format!(
                "    CHECK_ERROR(read{}(ctx, &obj->{}[i]))",
                mangle_name(&decl),
                mangle_name(name)
            ));
            parse_instrs.push("  }}".to_string());
            struct_decls.push(format!(
                "  {} *{};",
                mangle_name(&decl),
                mangle_name(name)
            ));
        } else if let Some((decl, len)) =
            is_fixed_sized_array(&decl, definitions)
        {
            if let Some((decl, _parser)) = is_primitive(&decl) {
                if decl == "uint8_t" {
                    parse_instrs.push(format!(
                        "  if((obj->{} = mem_alloc({} * sizeof({}[{}]))) == \
                         NULL) {{",
                        mangle_name(name),
                        length_tag,
                        decl,
                        len
                    ));
                    parse_instrs.push(
                        "    return parser_unexpected_error;".to_string(),
                    );
                    parse_instrs.push("  }}".to_string());
                    parse_instrs.push(format!(
                        "  for(uint32_t i = 0; i < {}; i++) {{",
                        length_tag
                    ));
                    parse_instrs.push(format!(
                        "    CHECK_ERROR(readBytesAlt(ctx, obj->{}[i], {}))",
                        mangle_name(name),
                        len
                    ));
                    parse_instrs.push("  }}".to_string());
                }
                struct_decls.push(format!(
                    "  {} (*{})[{}];",
                    decl,
                    mangle_name(name),
                    len
                ));
            } else if let Some(decl) = is_tuple(&decl, definitions) {
                struct_decls.push(format!(
                    "  {} (*{})[{}];",
                    mangle_name(&decl),
                    mangle_name(name),
                    len
                ));
            } else {
                struct_decls.push(format!(
                    "  {} (*{})[{}];",
                    mangle_name(&decl),
                    mangle_name(name),
                    len
                ));
            }
        } else {
            parse_instrs.push(format!(
                "  if((obj->{} = mem_alloc({} * sizeof({}))) == NULL) {{",
                mangle_name(name),
                length_tag,
                mangle_name(&decl)
            ));
            parse_instrs
                .push("    return parser_unexpected_error;".to_string());
            parse_instrs.push("  }}".to_string());
            parse_instrs.push(format!(
                "  for(uint32_t i = 0; i < {}; i++) {{",
                length_tag
            ));
            parse_instrs.push(format!(
                "    CHECK_ERROR(read{}(ctx, &obj->{}[i]))",
                mangle_name(&decl),
                mangle_name(name)
            ));
            parse_instrs.push("  }}".to_string());
            struct_decls.push(format!(
                "  {} *{};",
                mangle_name(&decl),
                mangle_name(name)
            ));
        }
    } else {
        parse_instrs.push(format!(
            "  CHECK_ERROR(read{}(ctx, &obj->{}))",
            mangle_name(decl),
            mangle_name(name)
        ));
        struct_decls.push(format!(
            "  {} {};",
            mangle_name(decl),
            mangle_name(name)
        ));
    }
}

#[tokio::main]
async fn main() -> Result<(), Reason> {
    let mut definitions = BTreeMap::new();
    Transaction::add_definitions_recursively(&mut definitions);
    MaspBuilder::add_definitions_recursively(&mut definitions);
    let mut struct_decls = Vec::new();
    let mut parser_decls = Vec::new();
    let mut parse_instrs = Vec::new();

    println!("{:#?}", definitions);

    for (declaration, definition) in &definitions {
        struct_decls.push("".to_string());
        parse_instrs.push("".to_string());
        let declaration = mangle_name(declaration);
        match definition {
            Definition::Struct {
                fields: Fields::Empty,
            } => {
                struct_decls
                    .push(format!("typedef struct {{}} {};", declaration));
                parser_decls.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj);",
                    declaration, declaration,
                ));
                parse_instrs.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj) {{",
                    declaration, declaration,
                ));
                parse_instrs.push(format!("  return parser_ok;"));
                parse_instrs.push(format!("}}"));
            }
            Definition::Struct {
                fields: Fields::UnnamedFields(fields),
            } => {
                struct_decls.push(format!("typedef struct {{"));
                parser_decls.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj);",
                    declaration, declaration,
                ));
                parse_instrs.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj) {{",
                    declaration, declaration,
                ));
                for (idx, decl) in fields.iter().enumerate() {
                    process_field(
                        &format!("f{}", idx),
                        decl,
                        &definitions,
                        &mut struct_decls,
                        &mut parse_instrs,
                    );
                }
                struct_decls.push(format!("}} {};", declaration));
                parse_instrs.push(format!("  return parser_ok;"));
                parse_instrs.push(format!("}}"));
            }
            Definition::Struct {
                fields: Fields::NamedFields(fields),
            } => {
                struct_decls.push(format!("typedef struct {{"));
                parser_decls.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj);",
                    declaration, declaration,
                ));
                parse_instrs.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj) {{",
                    declaration, declaration,
                ));
                for (name, decl) in fields {
                    process_field(
                        name,
                        decl,
                        &definitions,
                        &mut struct_decls,
                        &mut parse_instrs,
                    );
                }
                struct_decls.push(format!("}} {};", declaration));
                parse_instrs.push(format!("  return parser_ok;"));
                parse_instrs.push(format!("}}"));
            }
            Definition::Tuple { elements } => {
                parser_decls.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj);",
                    declaration, declaration,
                ));
                parse_instrs.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj) {{",
                    declaration, declaration,
                ));
                struct_decls.push(format!("typedef struct {{"));
                for (idx, decl) in elements.iter().enumerate() {
                    process_field(
                        &format!("f{}", idx),
                        decl,
                        &definitions,
                        &mut struct_decls,
                        &mut parse_instrs,
                    );
                }
                struct_decls.push(format!("}} {};", declaration));
                parse_instrs.push(format!("  return parser_ok;"));
                parse_instrs.push(format!("}}"));
            }
            Definition::Enum {
                tag_width: 0,
                variants,
            } => {
                parser_decls.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj);",
                    declaration, declaration,
                ));
                parse_instrs.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj) {{",
                    declaration, declaration,
                ));
                parse_instrs.push(format!("  switch(unk_tag) {{"));
                struct_decls.push(format!("typedef struct {{"));
                struct_decls.push(format!("  union {{"));
                for (discr, name, decl) in variants {
                    parse_instrs.push(format!("  case {}:", discr));
                    process_field(
                        name,
                        decl,
                        &definitions,
                        &mut struct_decls,
                        &mut parse_instrs,
                    );
                    parse_instrs.push(format!("  break;"));
                }
                struct_decls.push(format!("  }};"));
                struct_decls.push(format!("}} {};", declaration));
                parse_instrs.push(format!("  }}"));
                parse_instrs.push(format!("  return parser_ok;"));
                parse_instrs.push(format!("}}"));
            }
            Definition::Enum {
                tag_width: 1,
                variants,
            } => {
                parser_decls.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj);",
                    declaration, declaration,
                ));
                parse_instrs.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj) {{",
                    declaration, declaration,
                ));
                parse_instrs
                    .push(format!("  CHECK_ERROR(readByte(ctx, &obj->tag))"));
                parse_instrs.push(format!("  switch(obj->tag) {{"));
                struct_decls.push(format!("typedef struct {{"));
                struct_decls.push(format!("  uint8_t tag;"));
                struct_decls.push(format!("  union {{"));
                for (discr, name, decl) in variants {
                    parse_instrs.push(format!("  case {}:", discr));
                    process_field(
                        name,
                        decl,
                        &definitions,
                        &mut struct_decls,
                        &mut parse_instrs,
                    );
                    parse_instrs.push(format!("  break;"));
                }
                struct_decls.push(format!("  }};"));
                struct_decls.push(format!("}} {};", declaration));
                parse_instrs.push(format!("  }}"));
                parse_instrs.push(format!("  return parser_ok;"));
                parse_instrs.push(format!("}}"));
            }
            Definition::Enum {
                tag_width: 2,
                variants,
            } => {
                struct_decls.push(format!("typedef struct {{"));
                struct_decls.push(format!("  uint16_t tag;"));
                struct_decls.push(format!("  union {{"));
                for (_discr, name, decl) in variants {
                    process_field(
                        name,
                        decl,
                        &definitions,
                        &mut struct_decls,
                        &mut parse_instrs,
                    );
                }
                struct_decls.push(format!("  }};"));
                struct_decls.push(format!("}} {};", declaration));
            }
            Definition::Enum {
                tag_width: 4,
                variants,
            } => {
                parser_decls.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj);",
                    declaration, declaration,
                ));
                parse_instrs.push(format!(
                    "parser_error_t read{}(parser_context_t *ctx, {} *obj) {{",
                    declaration, declaration,
                ));
                parse_instrs
                    .push(format!("  CHECK_ERROR(readUint32(ctx, &obj->tag))"));
                parse_instrs.push(format!("  switch(obj->tag) {{"));
                struct_decls.push(format!("typedef struct {{"));
                struct_decls.push(format!("  uint32_t tag;"));
                struct_decls.push(format!("  union {{"));
                for (_discr, name, decl) in variants {
                    process_field(
                        name,
                        decl,
                        &definitions,
                        &mut struct_decls,
                        &mut parse_instrs,
                    );
                }
                struct_decls.push(format!("  }};"));
                struct_decls.push(format!("}} {};", declaration));
                parse_instrs.push(format!("  }}"));
                parse_instrs.push(format!("  return parser_ok;"));
                parse_instrs.push(format!("}}"));
            }
            _ => {
                struct_decls.pop();
                parse_instrs.pop();
            }
        }
    }
    for struct_decl in struct_decls {
        println!("{}", struct_decl);
    }
    println!();
    for parser_decl in parser_decls {
        println!("{}", parser_decl);
    }
    println!();
    for parse_instr in parse_instrs {
        println!("{}", parse_instr);
    }
    println!();
    Ok(())
}
