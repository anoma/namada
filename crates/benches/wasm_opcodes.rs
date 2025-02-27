//! Module to benchmark the wasm instructions. To do so we:
//!    - Generate a benchmark for an empty module to serve as a reference since
//!      we expect the function call itself to represent the majority of the
//!      cost
//!    - All instruction (expect the empty function call) must be repeated a
//!      certain amount of time because the default iteratrions of criterion
//!      don't apply in this case
//!    - Some operations require some other instructions to run correctly, in
//!      this case we need to subtract these costs
//!    - From all operations we must subtract the cost of the empy function call

use std::fmt::Display;

use criterion::{Criterion, criterion_group, criterion_main};
use lazy_static::lazy_static;
use wasm_instrument::parity_wasm::elements::Instruction::*;
use wasm_instrument::parity_wasm::elements::{
    BlockType, BrTableData, SignExtInstruction,
};
use wasmer::{Instance, Module, Store, imports};

// Don't reduce this value too much or it will be impossible to see the
// differences in execution times between the diffent instructions
const ITERATIONS: u64 = 10_000;
const ENTRY_POINT: &str = "op";

lazy_static! {
    static ref EMPTY_MODULE: String = format!(
        r#"
            (module
                (func $f0 nop)
                (func $f1 (result i32) i32.const 1 return)
                (table 1 funcref)
                (elem (i32.const 0) $f0)
                (global $iter (mut i32) (i32.const 0))
                (memory 1)
                (func (export "{ENTRY_POINT}") (param $local_var i32)"#
    );
}

lazy_static! {
    static ref WASM_OPTS: Vec<wasm_instrument::parity_wasm::elements::Instruction> = vec![
        // Unreachable unconditionally traps, so no need to divide its cost by ITERATIONS because we only execute it once
        Unreachable,
        Nop,
        Block(BlockType::NoResult),
        Loop(BlockType::NoResult),
        // remove the cost of i32.const and nop
        If(BlockType::NoResult),
        // Use 0 to exit the current block (branching in a block goes to the end of it, i.e. exits). Remove the cost of block
        Br(0u32),
        // Use 0 to exit the current block. Remove the cost of block and i32.const
        BrIf(0u32),
        // If 0 on top of the stack exit the current block. Remove the cost of block and i32.const:
        BrTable(Box::new(BrTableData {
            table: Box::new([1, 0]),
            default: 0u32,
        })),
        // remove cost of call, i32.const and drop
        Return,
        // remove the cost of nop
        Call(0u32),
        // remove cost of i32.const
        CallIndirect(0u32, 0u8),
        // remove cost of i32.const
        Drop,
        // remove cost of three i32.const and a drop
        Select,
        // remove cost of drop
        GetLocal(0u32),
        // remove the cost of i32.const
        SetLocal(0u32),
        // remove the cost of i32.const and drop
        TeeLocal(0u32),
        // remove cost of drop
        GetGlobal(0u32),
        // remove cost of i32.const
        SetGlobal(0u32),
        // remove the cost of i32.const and drop
        I32Load(0u32, 0u32),
        // remove the cost of i32.const and drop
        I64Load(0u32, 0u32),
        // remove the cost of i32.const and drop
        F32Load(0u32, 0u32),
        // remove the cost of i32.const and drop
        F64Load(0u32, 0u32),
        // remove the cost of i32.const and drop
        I32Load8S(0u32, 0u32),
        // remove the cost of i32.const and drop
        I32Load8U(0u32, 0u32),
        // remove the cost of i32.const and drop
        I32Load16S(0u32, 0u32),
        // remove the cost of i32.const and drop
        I32Load16U(0u32, 0u32),
        // remove the cost of i32.const and drop
        I64Load8S(0u32, 0u32),
        // remove the cost of i32.const and drop
        I64Load8U(0u32, 0u32),
        // remove the cost of i32.const and drop
        I64Load16S(0u32, 0u32),
        // remove the cost of i32.const and drop
        I64Load16U(0u32, 0u32),
        // remove the cost of i32.const and drop
        I64Load32S(0u32, 0u32),
        // remove the cost of i32.const and drop
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
        // remove cost of a drop
        CurrentMemory(0u8),
        // remove the cost of a i32.const and a drop
        GrowMemory(0u8),
        // remove the cost of a drop
        I32Const(0i32),
        // remove the cost of a drop
        I64Const(0i64),
        // remove the cost of a drop
        F32Const(0u32),
        // remove the cost of a drop
        F64Const(0u64),
        // remove the cost of a i32.const and a drop
        I32Eqz,
        // remove the cost of two i32.const and a drop
        I32Eq,
        // remove the cost of two i32.const and a drop
        I32Ne,
        // remove the cost of two i32.const and a drop
        I32LtS,
        // remove the cost of two i32.const and a drop
        I32LtU,
        // remove the cost of two i32.const and a drop
        I32GtS,
        // remove the cost of two i32.const and a drop
        I32GtU,
        // remove the cost of two i32.const and a drop
        I32LeS,
        // remove the cost of two i32.const and a drop
        I32LeU,
        // remove the cost of two i32.const and a drop
        I32GeS,
        // remove the cost of two i32.const and a drop
        I32GeU,
        // remove the cost of a i64.const and a drop
        I64Eqz,
        // remove the cost of two i64.const and a drop
        I64Eq,
        // remove the cost of two i64.const and a drop
        I64Ne,
        // remove the cost of two i64.const and a drop
        I64LtS,
        // remove the cost of two i64.const and a drop
        I64LtU,
        // remove the cost of two i64.const and a drop
        I64GtS,
        // remove the cost of two i64.const and a drop
        I64GtU,
        // remove the cost of two i64.const and a drop
        I64LeS,
        // remove the cost of two i64.const and a drop
        I64LeU,
        // remove the cost of two i64.const and a drop
        I64GeS,
        // remove the cost of two i64.const and a drop
        I64GeU,
        // remove the cost of two f32.const and a drop
        F32Eq,
        // remove the cost of two f32.const and a drop
        F32Ne,
        // remove the cost of two f32.const and a drop
        F32Lt,
        // remove the cost of two f32.const and a drop
        F32Gt,
        // remove the cost of two f32.const and a drop
        F32Le,
        // remove the cost of two f32.const and a drop
        F32Ge,
        // remove the cost of two f64.const and a drop
        F64Eq,
        // remove the cost of two f64.const and a drop
        F64Ne,
        // remove the cost of two f64.const and a drop
        F64Lt,
        // remove the cost of two f64.const and a drop
        F64Gt,
        // remove the cost of two f64.const and a drop
        F64Le,
        // remove the cost of two f64.const and a drop
        F64Ge,
        // remove the cost of i32.const and a drop
        I32Clz,
        // remove the cost of i32.const and a drop
        I32Ctz,
        // remove the cost of i32.const and a drop
        I32Popcnt,
        // remove the cost of two i32.const and a drop
        I32Add,
        // remove the cost of two i32.const and a drop
        I32Sub,
        // remove the cost of two i32.const and a drop
        I32Mul,
        // remove the cost of two i32.const and a drop
        I32DivS,
        // remove the cost of two i32.const and a drop
        I32DivU,
        // remove the cost of two i32.const and a drop
        I32RemS,
        // remove the cost of two i32.const and a drop
        I32RemU,
        // remove the cost of two i32.const and a drop
        I32And,
        // remove the cost of two i32.const and a drop
        I32Or,
        // remove the cost of two i32.const and a drop
        I32Xor,
        // remove the cost of two i32.const and a drop
        I32Shl,
        // remove the cost of two i32.const and a drop
        I32ShrS,
        // remove the cost of two i32.const and a drop
        I32ShrU,
        // remove the cost of two i32.const and a drop
        I32Rotl,
        // remove the cost of two i32.const and a drop
        I32Rotr,
        // remove cost of i64.const and a drop
        I64Clz,
        // remove cost of i64.const and a drop
        I64Ctz,
        // remove cost of i64.const and a drop
        I64Popcnt,
        // remove cost of two i64.const and a drop
        I64Add,
        // remove cost of two i64.const and a drop
        I64Sub,
        // remove cost of two i64.const and a drop
        I64Mul,
        // remove cost of two i64.const and a drop
        I64DivS,
        // remove cost of two i64.const and a drop
        I64DivU,
        // remove cost of two i64.const and a drop
        I64RemS,
        // remove cost of two i64.const and a drop
        I64RemU,
        // remove cost of two i64.const and a drop
        I64And,
        // remove cost of two i64.const and a drop
        I64Or,
        // remove cost of two i64.const and a drop
        I64Xor,
        // remove cost of two i64.const and a drop
        I64Shl,
        // remove cost of two i64.const and a drop
        I64ShrS,
        // remove cost of two i64.const and a drop
        I64ShrU,
        // remove cost of two i64.const and a drop
        I64Rotl,
        // remove cost of two i64.const and a drop
        I64Rotr,
        // remove cost of a f32.const and a drop
        F32Abs,
        // remove cost of a f32.const and a drop
        F32Neg,
        // remove cost of a f32.const and a drop
        F32Ceil,
        // remove cost of a f32.const and a drop
        F32Floor,
        // remove cost of a f32.const and a drop
        F32Trunc,
        // remove cost of a f32.const and a drop
        F32Nearest,
        // remove cost of a f32.const and a drop
        F32Sqrt,
        // remove cost of two f32.const and a drop
        F32Add,
        // remove cost of two f32.const and a drop
        F32Sub,
        // remove cost of two f32.const and a drop
        F32Mul,
        // remove cost of two f32.const and a drop
        F32Div,
        // remove cost of two f32.const and a drop
        F32Min,
        // remove cost of two f32.const and a drop
        F32Max,
        // remove cost of two f32.const and a drop
        F32Copysign,
        // remove cost of a f64.const and a drop
        F64Abs,
        // remove cost of a f64.const and a drop
        F64Neg,
        // remove cost of a f64.const and a drop
        F64Ceil,
        // remove cost of a f64.const and a drop
        F64Floor,
        // remove cost of a f64.const and a drop
        F64Trunc,
        // remove cost of a f64.const and a drop
        F64Nearest,
        // remove cost of a f64.const and a drop
        F64Sqrt,
        // remove cost of two f64.const and a drop
        F64Add,
        // remove cost of two f64.const and a drop
        F64Sub,
        // remove cost of two f64.const and a drop
        F64Mul,
        // remove cost of two f64.const and a drop
        F64Div,
        // remove cost of two f64.const and a drop
        F64Min,
        // remove cost of two f64.const and a drop
        F64Max,
        // remove cost of two f64.const and a drop
        F64Copysign,
        // remove the cost of a i64.const and a drop
        I32WrapI64,
        // remove the cost of a f32.const and a drop
        I32TruncSF32,
        // remove the cost of a f32.const and a drop
        I32TruncUF32,
        // remove the cost of a f64.const and a drop
        I32TruncSF64,
        // remove the cost of a f64.const and a drop
        I32TruncUF64,
        // remove the cost of a i32.const and a drop
        I64ExtendSI32,
        // remove the cost of a i32.const and a drop
        I64ExtendUI32,
        // remove the cost of a f32.const and a drop
        I64TruncSF32,
        // remove the cost of a f32.const and a drop
        I64TruncUF32,
        // remove the cost of a f64.const and a drop
        I64TruncSF64,
        // remove the cost of a f64.const and a drop
        I64TruncUF64,
        // remove the cost of a i32.const and a drop
        F32ConvertSI32,
        // remove the cost of a i32.const and a drop
        F32ConvertUI32,
        // remove the cost of a i64.const and a drop
        F32ConvertSI64,
        // remove the cost of a i64.const and a drop
        F32ConvertUI64,
        // remove the cost of a f64.const and a drop
        F32DemoteF64,
        // remove the cost of a i32.const and a drop
        F64ConvertSI32,
        // remove the cost of a i32.const and a drop
        F64ConvertUI32,
        // remove the cost of a i64.const and a drop
        F64ConvertSI64,
        // remove the cost of a i64.const and a drop
        F64ConvertUI64,
        // remove the cost of a f32.const and a drop
        F64PromoteF32,
        // remove the cost of a f32.const and a drop
        I32ReinterpretF32,
        // remove the cost of a f64.const and a drop
        I64ReinterpretF64,
        // remove the cost of a i32.const and a drop
        F32ReinterpretI32,
        // remove the cost of a i64.const and a drop
        F64ReinterpretI64,
        // remove the cost of a i32.load8_s, a i32.const and a drop
        SignExt(SignExtInstruction::I32Extend8S),
        // remove the cost of a i32.load16_s, a i32.const and a drop
        SignExt(SignExtInstruction::I32Extend16S),
        // remove the cost of a i64.load8_s, a i32.const and a drop
        SignExt(SignExtInstruction::I64Extend8S),
        // remove the cost of a i64.load16_s, a i32.cons and a drop
        SignExt(SignExtInstruction::I64Extend16S),
        // remove the cost of a i64.load32_s, a i32.const and a drop
        SignExt(SignExtInstruction::I64Extend32S),
];
    }

struct WatBuilder {
    wat: String,
    instruction: wasm_instrument::parity_wasm::elements::Instruction,
}

impl Display for WatBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, r#"{}"#, *EMPTY_MODULE)?;

        for _ in 0..ITERATIONS {
            writeln!(f, r#"{}"#, self.wat)?;
        }
        write!(f, r#"))"#)
    }
}

// Use singlepass compiler (the same one used in protocol) to prevent
// optimizations that would compile out the benchmarks since most of them are
// trivial operations
fn get_wasm_store() -> Store {
    Store::new(<wasmer::Engine as wasmer::NativeEngineExt>::new(
        Box::new(wasmer_compiler_singlepass::Singlepass::default()),
        wasmer::Target::default(),
        wasmer::sys::Features::default(),
    ))
}

// An empty wasm module to serve as the base reference for all the other
// instructions since the bigger part of the cost is the function call itself
fn empty_module(c: &mut Criterion) {
    let module_wat = format!(r#"{}))"#, *EMPTY_MODULE);
    let mut store = get_wasm_store();
    let module = Module::new(&store, module_wat).unwrap();
    let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
    let function = instance
        .exports
        .get_function(ENTRY_POINT)
        .unwrap()
        .typed::<i32, ()>(&store)
        .unwrap();

    c.bench_function("empty_module", |b| {
        b.iter(|| function.call(&mut store, 0).unwrap());
    });
}

fn ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("wasm_opts");

    for builder in bench_functions() {
        let mut store = get_wasm_store();
        let module = Module::new(&store, builder.to_string()).unwrap();
        let instance =
            Instance::new(&mut store, &module, &imports! {}).unwrap();
        let function = instance
            .exports
            .get_function(ENTRY_POINT)
            .unwrap()
            .typed::<i32, ()>(&store)
            .unwrap();

        group.bench_function(format!("{}", builder.instruction), |b| {
            if let Unreachable = builder.instruction {
                b.iter(|| function.call(&mut store, 0).unwrap_err());
            } else {
                b.iter(|| function.call(&mut store, 0).unwrap());
            }
        });
    }

    group.finish();
}

fn bench_functions() -> Vec<WatBuilder> {
    let instructions =
        WASM_OPTS
            .clone()
            .into_iter()
            .map(|instruction| match instruction {
                Unreachable | Nop => WatBuilder {
                    wat: format!(r#"{instruction}"#),
                    instruction,
                },
                Block(_) | Loop(_) => WatBuilder {
                    wat: format!(r#"({instruction})"#),
                    instruction,
                },
                If(_) => WatBuilder {
                    wat: format!(
                        r#"
                        i32.const 1
                        ({instruction}
                            (then
                                nop
                            )
                        )"#
                    ),
                    instruction,
                },
                Br(_) => WatBuilder {
                    wat: format!(
                        r#"
                        (block {instruction})
                        "#
                    ),
                    instruction,
                },
                BrIf(_) | BrTable(_) => WatBuilder {
                    wat: format!(
                        r#"
                        (block 
                            i32.const 1
                            {instruction}
                        )
                        "#
                    ),
                    instruction,
                },
                Return => {
                    // To benchmark the return opcode we need to call a function
                    // that returns something and then subtract the cost of
                    // everything. This way we can run the return
                    // opcode ITERATIONS times
                    WatBuilder {
                        wat: r#"
                            call $f1
                            drop
                            "#
                        .to_string(),
                        instruction,
                    }
                }
                Call(_) => WatBuilder {
                    wat: r#"
                            call $f0
                            "#
                    .to_string(),
                    instruction,
                },
                CallIndirect(_, _) | Drop => WatBuilder {
                    wat: format!(
                        r#"
                        i32.const 0
                        {instruction}
                        "#
                    ),
                    instruction,
                },
                Select => WatBuilder {
                    wat: format!(
                        r#"
                        i32.const 10
                        i32.const 20
                        i32.const 0
                        {instruction}
                        drop
                        "#
                    ),
                    instruction,
                },
                GetLocal(_) | GetGlobal(_) | CurrentMemory(_) | I32Const(_)
                | I64Const(_) | F32Const(_) | F64Const(_) => WatBuilder {
                    wat: format!(
                        r#"
                        {instruction}
                        drop
                        "#
                    ),
                    instruction,
                },
                SetLocal(_) | SetGlobal(_) => WatBuilder {
                    wat: format!(
                        r#"
                        i32.const 10
                        {instruction}
                        "#
                    ),
                    instruction,
                },
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
                | I64Load32U(_, _)
                | TeeLocal(_)
                | GrowMemory(_) => WatBuilder {
                    wat: format!(
                        r#"
                        i32.const 1
                        {instruction}
                        drop
                        "#
                    ),
                    instruction,
                },
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

                    WatBuilder {
                        wat: format!(
                            r#"
                            i32.const 0
                            {ty}.const 10000
                            {instruction}
                            "#
                        ),
                        instruction,
                    }
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
                    let ty =
                        match instruction {
                            I32Eqz | I32Clz | I32Ctz | I32Popcnt => "i32",
                            I64Eqz | I32WrapI64 => "i64",
                            I64Clz | I64Ctz | I64Popcnt => "i64",
                            F32Abs | F32Neg | F32Ceil | F32Floor | F32Trunc
                            | F32Nearest | F32Sqrt => "f32",
                            F64Abs | F64Neg | F64Ceil | F64Floor | F64Trunc
                            | F64Nearest | F64Sqrt => "f64",
                            I32TruncSF32 | I32TruncUF32 | I32ReinterpretF32 => {
                                "f32"
                            }
                            I32TruncSF64 | I32TruncUF64 => "f64",
                            I64ExtendSI32 | I64ExtendUI32 => "i32",
                            I64TruncSF32 | I64TruncUF32 => "f32",
                            I64TruncSF64 | I64TruncUF64 | I64ReinterpretF64 => {
                                "f64"
                            }
                            F32ConvertSI32 | F32ConvertUI32
                            | F32ReinterpretI32 => "i32",
                            F32ConvertSI64 | F32ConvertUI64 => "i64",
                            F32DemoteF64 => "f64",
                            F64ConvertSI32 | F64ConvertUI32 => "i32",
                            F64ConvertSI64 | F64ConvertUI64
                            | F64ReinterpretI64 => "i64",
                            F64PromoteF32 => "f32",
                            _ => unreachable!(),
                        };
                    WatBuilder {
                        wat: format!(
                            r#"
                            {ty}.const 1000
                            {instruction}
                            drop
                            "#
                        ),
                        instruction,
                    }
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
                    let ty = match instruction {
                        I32Eq | I32Ne | I32LtS | I32LtU | I32GtS | I32GtU
                        | I32LeS | I32LeU | I32GeS | I32GeU | I32Add
                        | I32Sub | I32Mul | I32DivS | I32DivU | I32RemS
                        | I32RemU | I32And | I32Or | I32Xor | I32Shl
                        | I32ShrS | I32ShrU | I32Rotl | I32Rotr => "i32",
                        I64Eq | I64Ne | I64LtS | I64LtU | I64GtS | I64GtU
                        | I64LeS | I64LeU | I64GeS | I64GeU => "i64",
                        F32Eq | F32Ne | F32Lt | F32Gt | F32Le | F32Ge => "f32",
                        F64Eq | F64Ne | F64Lt | F64Gt | F64Le | F64Ge => "f64",
                        I64Add | I64Sub | I64Mul | I64DivS | I64DivU
                        | I64RemS | I64RemU | I64And | I64Or | I64Xor
                        | I64Shl | I64ShrS | I64ShrU | I64Rotl | I64Rotr => {
                            "i64"
                        }
                        F32Add | F32Sub | F32Mul | F32Div | F32Min | F32Max
                        | F32Copysign => "f32",
                        F64Add | F64Sub | F64Mul | F64Div | F64Min | F64Max
                        | F64Copysign => "f64",
                        _ => unreachable!(),
                    };
                    WatBuilder {
                        wat: format!(
                            r#"
                            {ty}.const 2000
                            {ty}.const 1000
                            {instruction}
                            drop
                            "#
                        ),
                        instruction,
                    }
                }

                SignExt(SignExtInstruction::I32Extend8S)
                | SignExt(SignExtInstruction::I32Extend16S)
                | SignExt(SignExtInstruction::I64Extend8S)
                | SignExt(SignExtInstruction::I64Extend16S)
                | SignExt(SignExtInstruction::I64Extend32S) => {
                    let load = match instruction {
                        SignExt(SignExtInstruction::I32Extend8S) => {
                            "i32.load8_s"
                        }
                        SignExt(SignExtInstruction::I32Extend16S) => {
                            "i32.load16_s"
                        }
                        SignExt(SignExtInstruction::I64Extend8S) => {
                            "i64.load8_s"
                        }
                        SignExt(SignExtInstruction::I64Extend16S) => {
                            "i64.load16_s"
                        }
                        SignExt(SignExtInstruction::I64Extend32S) => {
                            "i64.load32_s"
                        }
                        _ => unreachable!(),
                    };
                    WatBuilder {
                        wat: format!(
                            r#"
                            i32.const 1000
                            {load}
                            {instruction}
                            drop
                            "#
                        ),
                        instruction,
                    }
                }
                _ => {
                    panic!("Found an instruction not covered by the benchmarks")
                }
            });

    instructions.collect()
}

criterion_group!(wasm_opcodes, ops, empty_module);
criterion_main!(wasm_opcodes);
