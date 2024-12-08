// Copyright 2023 Eclipse Labs
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::{
    env,
    fs::{self, File},
    io::BufWriter,
    path::{Path, PathBuf},
    process::Command,
};

use ar::Builder;
use clap::{App, Arg};
use object::{
    write::{Object, Relocation, StandardSegment, Symbol, SymbolSection},
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationKind, SectionKind,
    SymbolFlags, SymbolKind, SymbolScope,
};
use solana_rbpf::{
    assembler::assemble,
    compiler::{Compiler, RiscVRelocation},
    elf::Executable,
    user_error::UserError,
    vm::{Config, SyscallRegistry, TestInstructionMeter},
};

use risc0_build::{get_package, guest_methods, setup_guest_build_env, GuestOptions};

use risc0_zkvm::{
    host::{Prover, Receipt},
    serde::{from_slice, to_vec},
};

const METHODS_DIR: &'static str = env!("METHODS_DIR");

fn main() {
    // Define the command-line arguments using Clap
    let matches = App::new("ZK eBPF tool")
        .author("Eclipse Labs")
        .arg(
            Arg::new("assembler")
                .short('a')
                .long("asm")
                .value_name("FILE")
                .takes_value(true)
                .required_unless_present("elf"),
        )
        .arg(
            Arg::new("elf")
                .short('e')
                .long("elf")
                .value_name("FILE")
                .takes_value(true)
                .required_unless_present("assembler"),
        )
        .arg(
            Arg::new("build_directory")
                .short('d')
                .long("build-directory")
                .value_name("DIR")
                .takes_value(true)
                .default_value("build"),
        )
        .arg(
            Arg::new("no_execute")
                .short('n')
                .long("no-execute")
                .takes_value(false),
        )
        .arg(
            Arg::new("input_data")
                .short('i')
                .long("input-data")
                .value_name("FILE")
                .takes_value(true),
        )
        .get_matches();

    // Determine the build directory
    let target_dir_relative = Path::new(matches.value_of("build_directory").unwrap());
    let target_dir = fs::canonicalize(target_dir_relative).unwrap();
    fs::create_dir_all(&target_dir).unwrap();

    // Determine if the input is assembly code or an ELF file
    let (input_filename, needs_assembly) = if let Some(filename) = matches.value_of("assembler") {
        (filename, true)
    } else {
        (matches.value_of("elf").unwrap(), false)
    };

    // Compile BPF input to RISC-V object archive
    let bpf_dir = compile_bpf(fs::read(input_filename).unwrap(), &target_dir, needs_assembly);

    // Compile the guest methods using the produced BPF code
    let (method_path, method_id_vec) = compile_methods(&target_dir, &bpf_dir);
    let method_id = method_id_vec.as_slice();

    // If not instructed to skip execution, run the prover
    if !matches.is_present("no_execute") {
        eprintln!("Executing program...");

        let input_data = if let Some(filename) = matches.value_of("input_data") {
            Some(fs::read(filename).unwrap())
        } else {
            None
        };

        let (output, receipt) = execute_prover(&method_path, method_id, input_data);

        println!("The final BPF register values were:");
        for i in 0..10 {
            println!(" r{}: {:#018x}", i, output[i]);
        }

        // Verify the receipt
        receipt.verify(method_id).unwrap();
    }
}

// Executes the prover with the given method and optional input data.
// Returns the final register values and the generated receipt.
fn execute_prover<P: AsRef<Path>>(
    method_path: P,
    method_id: &[u8],
    input_data: Option<Vec<u8>>,
) -> ([u64; 10], Receipt) {
    let method_bytes = fs::read(method_path).unwrap();
    let mut prover = Prover::new(&method_bytes, method_id).unwrap();

    // Add input data to the prover
    prover
        .add_input(&to_vec(&input_data.unwrap_or(vec![])).unwrap())
        .unwrap();

    // Run the prover and obtain the receipt
    let receipt = prover.run().unwrap();
    let output: [u64; 10] = from_slice(&receipt.get_journal_vec().unwrap()).unwrap();

    (output, receipt)
}

// Compiles BPF code (either from assembly or ELF) into a RISC-V compatible static library (libbpf.a).
fn compile_bpf<P: AsRef<Path>>(
    input: Vec<u8>,
    target_dir: P,
    needs_assembly: bool,
) -> PathBuf {
    // Configure the BPF VM and syscall registry
    let config = Config {
        encrypt_environment_registers: false,
        noop_instruction_rate: 0,
        ..Config::default()
    };
    let syscall_registry = SyscallRegistry::default();

    // Create an executable from either assembly code or ELF input
    let executable = if needs_assembly {
        assemble::<UserError, TestInstructionMeter>(
            std::str::from_utf8(&input).unwrap(),
            config,
            syscall_registry,
        )
    } else {
        Executable::<UserError, TestInstructionMeter>::from_elf(&input, config, syscall_registry)
            .map_err(|err| format!("Executable constructor failed: {:?}", err))
    }
    .unwrap();

    let (_, text_bytes) = executable.get_text_bytes();
    let mut compiler = Compiler::new::<UserError>(text_bytes, &config).unwrap();
    compiler.compile(&executable).unwrap();

    // Extract relevant data sections from the compiled program
    let bpf_elf_bytes = executable.get_ro_section();
    let pc_offsets_bytes = unsafe {
        std::slice::from_raw_parts(
            compiler.pc_offsets.as_ptr() as *const u8,
            compiler.pc_offsets.len() * std::mem::size_of::<i32>(),
        )
    };
    let riscv_bytes = compiler.result.text_section;

    // Create a new ELF object file
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::Riscv32, Endianness::Little);

    // Add the .rodata section and symbols
    let rodata_section = obj.add_section(
        obj.segment_name(StandardSegment::Data).to_vec(),
        b".rodata".to_vec(),
        SectionKind::ReadOnlyData,
    );
    let bpf_ro_section_size_symbol = obj.add_symbol(Symbol {
        name: b"bpf_ro_section_size".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(rodata_section),
        flags: SymbolFlags::None,
    });
    obj.add_symbol_data(
        bpf_ro_section_size_symbol,
        rodata_section,
        &(bpf_elf_bytes.len() as u32).to_le_bytes(),
        0x10,
    );

    let bpf_ro_section_symbol = obj.add_symbol(Symbol {
        name: b"bpf_ro_section".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(rodata_section),
        flags: SymbolFlags::None,
    });
    obj.add_symbol_data(bpf_ro_section_symbol, rodata_section, bpf_elf_bytes, 0x10);

    let pc_offsets_symbol = obj.add_symbol(Symbol {
        name: b"pc_offsets".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(rodata_section),
        flags: SymbolFlags::None,
    });
    obj.add_symbol_data(pc_offsets_symbol, rodata_section, pc_offsets_bytes, 0x10);

    // Add the .text section and main symbol
    let text_section = obj.add_section(
        obj.segment_name(StandardSegment::Text).to_vec(),
        b".text".to_vec(),
        SectionKind::Text,
    );
    let program_main_symbol = obj.add_symbol(Symbol {
        name: b"program_main".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text_section),
        flags: SymbolFlags::None,
    });
    obj.add_symbol_data(program_main_symbol, text_section, riscv_bytes, 0x1000);

    // Add RISC-V relocations for call and data references
    for reloc in compiler.relocations.iter() {
        let (symbol_name, offset, relocation_code) = match reloc {
            RiscVRelocation::Call { offset, symbol } => (symbol, offset, 18),   // R_RISCV_CALL
            RiscVRelocation::Hi20 { offset, symbol } => (symbol, offset, 26),   // R_RISCV_HI20
            RiscVRelocation::Lo12I { offset, symbol } => (symbol, offset, 27),  // R_RISCV_LO12_I
        };
        let symbol = obj.add_symbol(Symbol {
            name: symbol_name.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Unknown,
            scope: SymbolScope::Unknown,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        let obj_reloc = Relocation {
            offset: *offset as u64,
            size: 0,
            kind: RelocationKind::Elf(relocation_code),
            encoding: RelocationEncoding::Generic,
            symbol,
            addend: 0,
        };
        obj.add_relocation(text_section, obj_reloc).unwrap();
    }

    // Create a directory for BPF-generated objects and archive them
    let bpf_target_dir = target_dir.as_ref().join("bpf-riscv");
    fs::create_dir_all(&bpf_target_dir).unwrap();

    let obj_path = bpf_target_dir.join("bpf.o");
    let obj_file = File::create(&obj_path).unwrap();
    obj.write_stream(BufWriter::new(obj_file)).unwrap();

    let ar_path = bpf_target_dir.join("libbpf.a");
    let ar_file = File::create(&ar_path).unwrap();
    let mut ar_builder = Builder::new(ar_file);
    ar_builder.append_path(&obj_path).unwrap();

    bpf_target_dir
}

// Compiles the guest methods using the previously compiled BPF code.
// Returns the path to the compiled method and the corresponding method ID.
fn compile_methods<P: AsRef<Path>, Q: AsRef<Path>>(
    target_dir: P,
    bpf_target_dir: Q,
) -> (PathBuf, Vec<u8>) {
    let pkg = get_package(METHODS_DIR);
    let guest_build_env = setup_guest_build_env(target_dir.as_ref());
    let target_dir_guest = target_dir.as_ref().join("riscv-guest");

    // Prepare cargo build arguments for the guest code
    let args = &[
        "build",
        "--release",
        "--target",
        guest_build_env.target_spec.to_str().unwrap(),
        "-Z",
        "build-std=core,alloc,std,proc_macro,panic_abort",
        "-Z",
        "build-std-features=compiler-builtins-mem",
        "--manifest-path",
        pkg.manifest_path.as_str(),
        "--target-dir",
        target_dir_guest.to_str().unwrap(),
    ];

    eprintln!("Building guest package: cargo {}", args.join(" "));

    let risc0_standard_lib: String = if let Ok(path) = env::var("RISC0_STANDARD_LIB") {
        path
    } else {
        guest_build_env.rust_lib_src.to_str().unwrap().into()
    };

    eprintln!("Using rust standard library root: {}", risc0_standard_lib);

    let mut cmd = Command::new("cargo");
    cmd.env("BPF_LIB_DIR", bpf_target_dir.as_ref().as_os_str())
        .env("CARGO_ENCODED_RUSTFLAGS", "-C\x1fpasses=loweratomic")
        .env("__CARGO_TESTS_ONLY_SRC_ROOT", &risc0_standard_lib)
        .args(args);

    // Spawn the cargo process and wait for completion
    let child = cmd.spawn().expect("Failed to spawn cargo build");
    let status = child.wait().expect("Failed to wait for cargo build");

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    // Extract the compiled guest method
    let mut methods = guest_methods(&pkg, target_dir);
    if methods.is_empty() {
        eprintln!("No methods found.");
        std::process::exit(1);
    }

    let method = methods.remove(0);
    (
        method.elf_path.clone(),
        method.make_method_id(GuestOptions::default().code_limit),
    )
}
