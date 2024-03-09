use criterion::{criterion_group, criterion_main, Criterion};
use lazy_static::lazy_static;
use wasm_instrument::parity_wasm::elements::Instruction::*;
use wasm_instrument::parity_wasm::elements::{
    BlockType, BrTableData, SignExtInstruction,
};
use wasmer::{imports, Instance, Module, Store};

lazy_static! {
static ref WASM_OPTS: Vec<wasm_instrument::parity_wasm::elements::Instruction> = vec![
        Unreachable,
        Nop,
        Block(BlockType::NoResult),
        Loop(BlockType::NoResult),
        // remove from if the cost of i32.const
        If(BlockType::NoResult),
        // Using index 0 for jumps to signal the wasm code to exit the function, i.e. terminate execution (next outermost structured block)
        Br(0u32),
        // remove the cost of i32.const
        BrIf(0u32),
        // remove the cost of i32.const
        BrTable(Box::new(BrTableData {
            table: Box::new([0, 1, 2, 3]),
            default: 0u32,
        })),
        // remove the cost of i64.const
        Return,
        Call(0u32),
        // remove cost of i32.const
        CallIndirect(0u32, 0u8),
        // remove cost of i32.const
        Drop,
        // remove cost of three i32.const
        Select,
        // remove cost of local.set
        GetLocal(0u32),
        // remove the cost of i32.const
        SetLocal(0u32),
        // remove the cost of i32.const
        TeeLocal(0u32),
        GetGlobal(0u32),
        SetGlobal(0u32),
        // remove the cost of i32.const
        I32Load(0u32, 0u32),
        // remove the cost of i32.const
        I64Load(0u32, 0u32),
        // remove the cost of i32.const
        F32Load(0u32, 0u32),
        // remove the cost of i32.const
        F64Load(0u32, 0u32),
        // remove the cost of i32.const
        I32Load8S(0u32, 0u32),
        // remove the cost of i32.const
        I32Load8U(0u32, 0u32),
        // remove the cost of i32.const
        I32Load16S(0u32, 0u32),
        // remove the cost of i32.const
        I32Load16U(0u32, 0u32),
        // remove the cost of i32.const
        I64Load8S(0u32, 0u32),
        // remove the cost of i32.const
        I64Load8U(0u32, 0u32),
        // remove the cost of i32.const
        I64Load16S(0u32, 0u32),
        // remove the cost of i32.const
        I64Load16U(0u32, 0u32),
        // remove the cost of i32.const
        I64Load32S(0u32, 0u32),
        // remove the cost of i32.const
        I64Load32U(0u32, 0u32),
        // remove the cost of two i32.const
        I32Store(0u32, 0u32),
        // remove the cost of a i32.const and a i64.const
        I64Store(0u32, 0u32),
        // remove the cost of a i32.const and a f32.const
        F32Store(0u32, 0u32),
        // remove the cost of a i32.const and a f64.const
        F64Store(0u32, 0u32),
        // remove the cost of two i32.const
        I32Store8(0u32, 0u32),
        // remove the cost of two i32.const
        I32Store16(0u32, 0u32),
        // remove the cost of a i32.const and a i64.const
        I64Store8(0u32, 0u32),
        // remove the cost of a i32.const and a i64.const
        I64Store16(0u32, 0u32),
        // remove the cost of a i32.const and a i64.const
        I64Store32(0u32, 0u32),
        CurrentMemory(0u8),
        // remove the cost of a i32.const
        GrowMemory(0u8),
        I32Const(0i32),
        I64Const(0i64),
        F32Const(0u32),
        F64Const(0u64),
        // remove the cost of a i32.const
        I32Eqz,
        // remove the cost of two i32.const
        I32Eq,
        // remove the cost of two i32.const
        I32Ne,
        // remove the cost of two i32.const
        I32LtS,
        // remove the cost of two i32.const
        I32LtU,
        // remove the cost of two i32.const
        I32GtS,
        // remove the cost of two i32.const
        I32GtU,
        // remove the cost of two i32.const
        I32LeS,
        // remove the cost of two i32.const
        I32LeU,
        // remove the cost of two i32.const
        I32GeS,
        // remove the cost of two i32.const
        I32GeU,
        // remove the cost of a i64.const
        I64Eqz,
        // remove the cost of two i64.const
        I64Eq,
        // remove the cost of two i64.const
        I64Ne,
        // remove the cost of two i64.const
        I64LtS,
        // remove the cost of two i64.const
        I64LtU,
        // remove the cost of two i64.const
        I64GtS,
        // remove the cost of two i64.const
        I64GtU,
        // remove the cost of two i64.const
        I64LeS,
        // remove the cost of two i64.const
        I64LeU,
        // remove the cost of two i64.const
        I64GeS,
        // remove the cost of two i64.const
        I64GeU,
        // remove the cost of two f32.const
        F32Eq,
        // remove the cost of two f32.const
        F32Ne,
        // remove the cost of two f32.const
        F32Lt,
        // remove the cost of two f32.const
        F32Gt,
        // remove the cost of two f32.const
        F32Le,
        // remove the cost of two f32.const
        F32Ge,
        // remove the cost of two f64.const
        F64Eq,
        // remove the cost of two f64.const
        F64Ne,
        // remove the cost of two f64.const
        F64Lt,
        // remove the cost of two f64.const
        F64Gt,
        // remove the cost of two f64.const
        F64Le,
        // remove the cost of two f64.const
        F64Ge,
        // remove the cost of i32.const
        I32Clz,
        // remove the cost of i32.const
        I32Ctz,
        // remove the cost of i32.const
        I32Popcnt,
        // remove the cost of two i32.const
        I32Add,
        // remove the cost of two i32.const
        I32Sub,
        // remove the cost of two i32.const
        I32Mul,
        // remove the cost of two i32.const
        I32DivS,
        // remove the cost of two i32.const
        I32DivU,
        // remove the cost of two i32.const
        I32RemS,
        // remove the cost of two i32.const
        I32RemU,
        // remove the cost of two i32.const
        I32And,
        // remove the cost of two i32.const
        I32Or,
        // remove the cost of two i32.const
        I32Xor,
        // remove the cost of two i32.const
        I32Shl,
        // remove the cost of two i32.const
        I32ShrS,
        // remove the cost of two i32.const
        I32ShrU,
        // remove the cost of two i32.const
        I32Rotl,
        // remove the cost of two i32.const
        I32Rotr,
        // remove cost of i64.const
        I64Clz,
        // remove cost of i64.const
        I64Ctz,
        // remove cost of i64.const
        I64Popcnt,
        // remove cost of two i64.const
        I64Add,
        // remove cost of two i64.const
        I64Sub,
        // remove cost of two i64.const
        I64Mul,
        // remove cost of two i64.const
        I64DivS,
        // remove cost of two i64.const
        I64DivU,
        // remove cost of two i64.const
        I64RemS,
        // remove cost of two i64.const
        I64RemU,
        // remove cost of two i64.const
        I64And,
        // remove cost of two i64.const
        I64Or,
        // remove cost of two i64.const
        I64Xor,
        // remove cost of two i64.const
        I64Shl,
        // remove cost of two i64.const
        I64ShrS,
        // remove cost of two i64.const
        I64ShrU,
        // remove cost of two i64.const
        I64Rotl,
        // remove cost of two i64.const
        I64Rotr,
        // remove cost of a f32.const
        F32Abs,
        // remove cost of a f32.const
        F32Neg,
        // remove cost of a f32.const
        F32Ceil,
        // remove cost of a f32.const
        F32Floor,
        // remove cost of a f32.const
        F32Trunc,
        // remove cost of a f32.const
        F32Nearest,
        // remove cost of a f32.const
        F32Sqrt,
        // remove cost of two f32.const
        F32Add,
        // remove cost of two f32.const
        F32Sub,
        // remove cost of two f32.const
        F32Mul,
        // remove cost of two f32.const
        F32Div,
        // remove cost of two f32.const
        F32Min,
        // remove cost of two f32.const
        F32Max,
        // remove cost of two f32.const
        F32Copysign,
        // remove cost of a f64.const
        F64Abs,
        // remove cost of a f64.const
        F64Neg,
        // remove cost of a f64.const
        F64Ceil,
        // remove cost of a f64.const
        F64Floor,
        // remove cost of a f64.const
        F64Trunc,
        // remove cost of a f64.const
        F64Nearest,
        // remove cost of a f64.const
        F64Sqrt,
        // remove cost of two f64.const
        F64Add,
        // remove cost of two f64.const
        F64Sub,
        // remove cost of two f64.const
        F64Mul,
        // remove cost of two f64.const
        F64Div,
        // remove cost of two f64.const
        F64Min,
        // remove cost of two f64.const
        F64Max,
        // remove cost of two f64.const
        F64Copysign,
        // remove the cost of a i64.const
        I32WrapI64,
        // remove the cost of a f32.const
        I32TruncSF32,
        // remove the cost of a f32.const
        I32TruncUF32,
        // remove the cost of a f64.const
        I32TruncSF64,
        // remove the cost of a f64.const
        I32TruncUF64,
        // remove the cost of a i32.const
        I64ExtendSI32,
        // remove the cost of a i32.const
        I64ExtendUI32,
        // remove the cost of a f32.const
        I64TruncSF32,
        // remove the cost of a f32.const
        I64TruncUF32,
        // remove the cost of a f64.const
        I64TruncSF64,
        // remove the cost of a f64.const
        I64TruncUF64,
        // remove the cost of a i32.const
        F32ConvertSI32,
        // remove the cost of a i32.const
        F32ConvertUI32,
        // remove the cost of a i64.const
        F32ConvertSI64,
        // remove the cost of a i64.const
        F32ConvertUI64,
        // remove the cost of a f64.const
        F32DemoteF64,
        // remove the cost of a i32.const
        F64ConvertSI32,
        // remove the cost of a i32.const
        F64ConvertUI32,
        // remove the cost of a i64.const
        F64ConvertSI64,
        // remove the cost of a i64.const
        F64ConvertUI64,
        // remove the cost of a f32.const
        F64PromoteF32,
        // remove the cost of a f32.const
        I32ReinterpretF32,
        // remove the cost of a f64.const
        I64ReinterpretF64,
        // remove the cost of a i32.const
        F32ReinterpretI32,
        // remove the cost of a i64.const
        F64ReinterpretI64,
        // remove the cost of a i32.load8_s and a i32.const
        SignExt(SignExtInstruction::I32Extend8S),
        // remove the cost of a i32.load16_s and a i32.const
        SignExt(SignExtInstruction::I32Extend16S),
        // remove the cost of a i64.load8_s and a i32.const
        SignExt(SignExtInstruction::I64Extend8S),
        // remove the cost of a i64.load16_s and a i32.const
        SignExt(SignExtInstruction::I64Extend16S),
        // remove the cost of a i64.load32_s and a i32.const
        SignExt(SignExtInstruction::I64Extend32S),
];
    }

fn ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("wasm_opts");

    for (instruction, module_wat) in bench_functions() {
        let module = Module::new(&Store::default(), &module_wat).unwrap();
        let import_object = imports! {};
        let instance = Instance::new(&module, &import_object).unwrap();
        let function = instance.exports.get_function("op").unwrap();

        group.bench_function(format!("{instruction}"), |b| {
            if let Unreachable = instruction {
                b.iter(|| function.call(&[]).unwrap_err());
            } else {
                b.iter(|| function.call(&[]).unwrap());
            }
        });
    }

    group.finish();
}

// NOTE: instructions with base cost
//    - Nop (the base point charing 1 unit of gas)
//    - Else
//    - End
fn bench_functions()
-> Vec<(wasm_instrument::parity_wasm::elements::Instruction, String)> {
    let instructions =
        WASM_OPTS
            .clone()
            .into_iter()
            .map(|instruction| match instruction {
                Unreachable | Nop => {
                    let module_wat = format!(
                        r#"
    (module
      (func (export "op")
            {instruction} 
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                Block(_) | Loop(_) | Br(_) => {
                    let module_wat = format!(
                        r#"
    (module
      (func (export "op")
            ({instruction})
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                If(_) => {
                    let module_wat = format!(
                        r#"
    (module
      (func (export "op")
            i32.const 1
            ({instruction}
                (then 
                    nop           
                )      
            )
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                BrIf(_) | BrTable(_) | Drop => {
                    let module_wat = format!(
                        r#"
    (module
      (func (export "op") 
            i32.const 1
            ({instruction})
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                Return => {
                    let module_wat = format!(
                        r#"
    (module
      (func (export "op") (result i32)
            i32.const 1
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                Call(_) => {
                    let module_wat = format!(
                        r#"
    (module
      (func 
            nop
        )
      (func (export "op")
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                CallIndirect(_, _) => {
                    let module_wat = format!(
                        r#"
    (module
      (type $t0 (func)) 
        (func $f0 (type $t0) (nop))
        (table 1 funcref)
        (elem (i32.const 0) $f0)        
      (func (export "op")
            i32.const 0
            {instruction}
        )
    )
    "#,
                    );

                    (instruction, module_wat)
                }
                Select => {
                    let module_wat = format!(
                        r#"
    (module
      (func (export "op") (result i32)
            i32.const 10
            i32.const 20
            i32.const 0
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                GetLocal(_) => {
                    let module_wat = format!(
                        r#"
    (module
      (func (export "op") (result i32)
            (local i32)
            (local.set 0 (i32.const 10))
            {instruction}
    ))
    "#,
                    );

                    (instruction, module_wat)
                }
                SetLocal(_) => {
                    let module_wat = format!(
                        r#"
    (module
      (func (export "op")
            (local i32)
            ({instruction} (i32.const 10))
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                TeeLocal(_) => {
                    let module_wat = format!(
                        r#"
    (module
      (func (export "op") (result i32)
            (local i32)
            (i32.const 10)
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                GetGlobal(_) => {
                    let module_wat = format!(
                        r#"
    (module
        (global i32 (i32.const 10))
        (func (export "op") (result i32)
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                SetGlobal(_) => {
                    let module_wat = format!(
                        r#"
    (module
        (global (mut i32) (i32.const 10))
        (func (export "op")
            i32.const 2000
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                I32Load(_, _)
                | I64Load(_, _)
                | F32Load(_, _)
                | F64Load(_, _)
                | I32Load8S(_, _)
                | I32Load8U(_, _)
                | I32Load16S(_, _)
                | I32Load16U(_, _)
                | I64Load8S(_, _)
                | I64Load8U(_, _)
                | I64Load16S(_, _)
                | I64Load16U(_, _)
                | I64Load32S(_, _)
                | I64Load32U(_, _) => {
                    let ty = match instruction {
                        I32Load(_, _)
                        | I32Load8S(_, _)
                        | I32Load8U(_, _)
                        | I32Load16S(_, _)
                        | I32Load16U(_, _) => "i32",
                        I64Load(_, _)
                        | I64Load8S(_, _)
                        | I64Load8U(_, _)
                        | I64Load16S(_, _)
                        | I64Load16U(_, _)
                        | I64Load32S(_, _)
                        | I64Load32U(_, _) => "i64",
                        F32Load(_, _) => "f32",
                        F64Load(_, _) => "f64",
                        _ => unreachable!(),
                    };
                    let module_wat = format!(
                        r#"
    (module
        (memory 1)
        (func (export "op") (result {ty})
            i32.const 10
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                I32Store(_, _)
                | I64Store(_, _)
                | F32Store(_, _)
                | F64Store(_, _)
                | I32Store8(_, _)
                | I32Store16(_, _)
                | I64Store8(_, _)
                | I64Store16(_, _)
                | I64Store32(_, _) => {
                    let ty = match instruction {
                        I32Store(_, _) | I32Store8(_, _) | I32Store16(_, _) => {
                            "i32"
                        }
                        I64Store(_, _)
                        | I64Store8(_, _)
                        | I64Store16(_, _)
                        | I64Store32(_, _) => "i64",
                        F32Store(_, _) => "f32",
                        F64Store(_, _) => "f64",
                        _ => unreachable!(),
                    };

                    let module_wat = format!(
                        r#"
    (module
        (memory 1)
        (func (export "op")
            i32.const 0
            {ty}.const 10000
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                CurrentMemory(_) => {
                    let module_wat = format!(
                        r#"
    (module
        (memory 1)
        (func (export "op") (result i32)
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                GrowMemory(_) => {
                    let module_wat = format!(
                        r#"
    (module
        (memory 1)
        (func (export "op") (result i32)
            i32.const 1
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                I32Const(_) | I64Const(_) | F32Const(_) | F64Const(_) => {
                    let ty = match instruction {
                        I32Const(_) => "i32",
                        I64Const(_) => "i64",
                        F32Const(_) => "f32",
                        F64Const(_) => "f64",
                        _ => unreachable!(),
                    };

                    let module_wat = format!(
                        r#"
    (module
        (func (export "op") (result {ty})
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                I32Eqz | I64Eqz | I32Clz | I32Ctz | I32Popcnt | I64Clz
                | I64Ctz | I64Popcnt | F32Abs | F64Abs | F32Neg | F32Ceil
                | F32Floor | F32Trunc | F32Nearest | F32Sqrt | F64Neg
                | F64Ceil | F64Floor | F64Trunc | F64Nearest | F64Sqrt
                | I32WrapI64 | I32TruncSF32 | I32TruncUF32 | I32TruncSF64
                | I32TruncUF64 | I64ExtendSI32 | I64ExtendUI32
                | I64TruncSF32 | I64TruncUF32 | I64TruncSF64 | I64TruncUF64
                | F32ConvertSI32 | F32ConvertUI32 | F32ConvertSI64
                | F32ConvertUI64 | F32DemoteF64 | F64ConvertSI32
                | F64ConvertUI32 | F64ConvertSI64 | F64ConvertUI64
                | F64PromoteF32 | I32ReinterpretF32 | I64ReinterpretF64
                | F32ReinterpretI32 | F64ReinterpretI64 => {
                    let (ty, result) = match instruction {
                        I32Eqz | I32Clz | I32Ctz | I32Popcnt => ("i32", "i32"),
                        I64Eqz | I32WrapI64 => ("i64", "i32"),
                        I64Clz | I64Ctz | I64Popcnt => ("i64", "i64"),
                        F32Abs | F32Neg | F32Ceil | F32Floor | F32Trunc
                        | F32Nearest | F32Sqrt => ("f32", "f32"),
                        F64Abs | F64Neg | F64Ceil | F64Floor | F64Trunc
                        | F64Nearest | F64Sqrt => ("f64", "f64"),
                        I32TruncSF32 | I32TruncUF32 | I32ReinterpretF32 => {
                            ("f32", "i32")
                        }
                        I32TruncSF64 | I32TruncUF64 => ("f64", "i32"),
                        I64ExtendSI32 | I64ExtendUI32 => ("i32", "i64"),
                        I64TruncSF32 | I64TruncUF32 => ("f32", "i64"),
                        I64TruncSF64 | I64TruncUF64 | I64ReinterpretF64 => {
                            ("f64", "i64")
                        }
                        F32ConvertSI32 | F32ConvertUI32 | F32ReinterpretI32 => {
                            ("i32", "f32")
                        }
                        F32ConvertSI64 | F32ConvertUI64 => ("i64", "f32"),
                        F32DemoteF64 => ("f64", "f32"),
                        F64ConvertSI32 | F64ConvertUI32 => ("i32", "f64"),
                        F64ConvertSI64 | F64ConvertUI64 | F64ReinterpretI64 => {
                            ("i64", "f64")
                        }
                        F64PromoteF32 => ("f32", "f64"),
                        _ => unreachable!(),
                    };

                    let module_wat = format!(
                        r#"
    (module
        (func (export "op") (result {result})
            {ty}.const 1000
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                I32Eq | I64Eq | F32Eq | F64Eq | I32Ne | I64Ne | F32Ne
                | F64Ne | I32LtS | I64LtS | F32Lt | F64Lt | I32LtU | I32GtS
                | I32GtU | I32LeS | I32LeU | I32GeS | I32GeU | I64LtU
                | I64GtS | I64GtU | I64LeS | I64LeU | I64GeS | I64GeU
                | F32Gt | F32Le | F32Ge | F64Gt | F64Le | F64Ge | I32Add
                | I64Add | I32Sub | I64Sub | I32Mul | I32DivS | I32DivU
                | I32RemS | I32RemU | I32And | I32Or | I32Xor | I32Shl
                | I32ShrS | I32ShrU | I32Rotl | I32Rotr | I64Mul | I64DivS
                | I64DivU | I64RemS | I64RemU | I64And | I64Or | I64Xor
                | I64Shl | I64ShrS | I64ShrU | I64Rotl | I64Rotr | F32Add
                | F32Sub | F32Mul | F32Div | F32Min | F32Max | F32Copysign
                | F64Add | F64Sub | F64Mul | F64Div | F64Min | F64Max
                | F64Copysign => {
                    let (ty, result) = match instruction {
                        I32Eq | I32Ne | I32LtS | I32LtU | I32GtS | I32GtU
                        | I32LeS | I32LeU | I32GeS | I32GeU | I32Add
                        | I32Sub | I32Mul | I32DivS | I32DivU | I32RemS
                        | I32RemU | I32And | I32Or | I32Xor | I32Shl
                        | I32ShrS | I32ShrU | I32Rotl | I32Rotr => {
                            ("i32", "i32")
                        }
                        I64Eq | I64Ne | I64LtS | I64LtU | I64GtS | I64GtU
                        | I64LeS | I64LeU | I64GeS | I64GeU => ("i64", "i32"),
                        F32Eq | F32Ne | F32Lt | F32Gt | F32Le | F32Ge => {
                            ("f32", "i32")
                        }
                        F64Eq | F64Ne | F64Lt | F64Gt | F64Le | F64Ge => {
                            ("f64", "i32")
                        }
                        I64Add | I64Sub | I64Mul | I64DivS | I64DivU
                        | I64RemS | I64RemU | I64And | I64Or | I64Xor
                        | I64Shl | I64ShrS | I64ShrU | I64Rotl | I64Rotr => {
                            ("i64", "i64")
                        }
                        F32Add | F32Sub | F32Mul | F32Div | F32Min | F32Max
                        | F32Copysign => ("f32", "f32"),
                        F64Add | F64Sub | F64Mul | F64Div | F64Min | F64Max
                        | F64Copysign => ("f64", "f64"),
                        _ => unreachable!(),
                    };
                    let module_wat = format!(
                        r#"
    (module
        (func (export "op") (result {result})
            {ty}.const 2000
            {ty}.const 1000
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }

                SignExt(SignExtInstruction::I32Extend8S)
                | SignExt(SignExtInstruction::I32Extend16S)
                | SignExt(SignExtInstruction::I64Extend8S)
                | SignExt(SignExtInstruction::I64Extend16S)
                | SignExt(SignExtInstruction::I64Extend32S) => {
                    let (load, result) = match instruction {
                        SignExt(SignExtInstruction::I32Extend8S) => {
                            ("i32.load8_s", "i32")
                        }
                        SignExt(SignExtInstruction::I32Extend16S) => {
                            ("i32.load16_s", "i32")
                        }
                        SignExt(SignExtInstruction::I64Extend8S) => {
                            ("i64.load8_s", "i64")
                        }
                        SignExt(SignExtInstruction::I64Extend16S) => {
                            ("i64.load16_s", "i64")
                        }
                        SignExt(SignExtInstruction::I64Extend32S) => {
                            ("i64.load32_s", "i64")
                        }
                        _ => unreachable!(),
                    };
                    let module_wat = format!(
                        r#"
    (module
        (memory 1)
        (func (export "op") (result {result})
            i32.const 0
            {load}
            {instruction}
        ))
    "#,
                    );

                    (instruction, module_wat)
                }
                _ => {
                    panic!("Found an instruction not covered by the benchmarks")
                }
            });

    instructions.collect()
}

criterion_group!(wasm_opcodes, ops);
criterion_main!(wasm_opcodes);
