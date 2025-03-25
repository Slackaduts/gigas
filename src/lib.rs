use lazy_static::lazy_static;
use std::collections::HashMap;

// Define the types of operands
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum OperandType {
    Register8,   // 8-bit register (al, bl, etc.)
    Register16,  // 16-bit register (ax, bx, etc.)
    Register32,  // 32-bit register (eax, ebx, etc.)
    Register64,  // 64-bit register (rax, rbx, etc.)
    Memory,      // Memory reference [reg+offset]
    Immediate8,  // 8-bit immediate value
    Immediate16, // 16-bit immediate value
    Immediate32, // 32-bit immediate value
    Immediate64, // 64-bit immediate value
}

// Define the instruction format
#[derive(Debug, Clone)]
struct InstructionFormat {
    prefixes: Vec<u8>,
    opcode: Vec<u8>,
    has_modrm: bool,
    modrm_reg_field: Option<String>, // What goes in the reg field
    modrm_rm_field: Option<String>,  // What goes in the r/m field
    has_sib: bool,
    immediate_size: Option<usize>,
    displacement_size: Option<usize>,
    operand_order: Vec<String>, // Order of operands in encoding
}

// Register encoding table
lazy_static! {
    static ref REGISTER_ENCODING: HashMap<&'static str, u8> = {
        let mut m = HashMap::new();
        // 8-bit registers
        m.insert("al", 0);
        m.insert("cl", 1);
        m.insert("dl", 2);
        m.insert("bl", 3);
        m.insert("ah", 4);
        m.insert("ch", 5);
        m.insert("dh", 6);
        m.insert("bh", 7);

        // 16-bit registers
        m.insert("ax", 0);
        m.insert("cx", 1);
        m.insert("dx", 2);
        m.insert("bx", 3);
        m.insert("sp", 4);
        m.insert("bp", 5);
        m.insert("si", 6);
        m.insert("di", 7);

        // 32-bit registers
        m.insert("eax", 0);
        m.insert("ecx", 1);
        m.insert("edx", 2);
        m.insert("ebx", 3);
        m.insert("esp", 4);
        m.insert("ebp", 5);
        m.insert("esi", 6);
        m.insert("edi", 7);

        // 64-bit registers
        m.insert("rax", 0);
        m.insert("rcx", 1);
        m.insert("rdx", 2);
        m.insert("rbx", 3);
        m.insert("rsp", 4);
        m.insert("rbp", 5);
        m.insert("rsi", 6);
        m.insert("rdi", 7);

        // Additional registers in x86_64
        m.insert("r8", 8);
        m.insert("r9", 9);
        m.insert("r10", 10);
        m.insert("r11", 11);
        m.insert("r12", 12);
        m.insert("r13", 13);
        m.insert("r14", 14);
        m.insert("r15", 15);
        m
    };
}

// Instruction encoding lookup table
lazy_static! {
    static ref INSTRUCTION_ENCODING: HashMap<&'static str, HashMap<Vec<OperandType>, InstructionFormat>> = {
        let mut m = HashMap::new();

        // MOV instruction variants
        let mut mov_variants = HashMap::new();

        // mov r32, imm32
        mov_variants.insert(
            vec![OperandType::Register32, OperandType::Immediate32],
            InstructionFormat {
                prefixes: vec![],
                opcode: vec![0xB8], // Will add register code
                has_modrm: false,
                modrm_reg_field: None,
                modrm_rm_field: None,
                has_sib: false,
                immediate_size: Some(4),
                displacement_size: None,
                operand_order: vec!["opcode+reg".to_string(), "imm".to_string()],
            }
        );

        // mov r64, imm32 (sign-extended)
        mov_variants.insert(
            vec![OperandType::Register64, OperandType::Immediate32],
            InstructionFormat {
                prefixes: vec![0x48], // REX.W prefix
                opcode: vec![0xC7],
                has_modrm: true,
                modrm_reg_field: Some("0".to_string()), // Using 0 in reg field
                modrm_rm_field: Some("dst".to_string()),
                has_sib: false,
                immediate_size: Some(4),
                displacement_size: None,
                operand_order: vec!["dst".to_string(), "imm".to_string()],
            }
        );

        // mov r/m32, r32
        mov_variants.insert(
            vec![OperandType::Memory, OperandType::Register32],
            InstructionFormat {
                prefixes: vec![],
                opcode: vec![0x89],
                has_modrm: true,
                modrm_reg_field: Some("src".to_string()),
                modrm_rm_field: Some("dst".to_string()),
                has_sib: false, // Will be determined dynamically
                immediate_size: None,
                displacement_size: None, // Will be determined dynamically
                operand_order: vec!["dst".to_string(), "src".to_string()],
            }
        );

        // mov r32, r/m32
        mov_variants.insert(
            vec![OperandType::Register32, OperandType::Memory],
            InstructionFormat {
                prefixes: vec![],
                opcode: vec![0x8B],
                has_modrm: true,
                modrm_reg_field: Some("dst".to_string()),
                modrm_rm_field: Some("src".to_string()),
                has_sib: false,
                immediate_size: None,
                displacement_size: None,
                operand_order: vec!["dst".to_string(), "src".to_string()],
            }
        );

        m.insert("mov", mov_variants);

        // ADD instruction variants
        let mut add_variants = HashMap::new();

        // add r32, imm32
        add_variants.insert(
            vec![OperandType::Register32, OperandType::Immediate32],
            InstructionFormat {
                prefixes: vec![],
                opcode: vec![0x81],
                has_modrm: true,
                modrm_reg_field: Some("0".to_string()), // 0 for ADD
                modrm_rm_field: Some("dst".to_string()),
                has_sib: false,
                immediate_size: Some(4),
                displacement_size: None,
                operand_order: vec!["dst".to_string(), "imm".to_string()],
            }
        );

        // add r32, r32
        add_variants.insert(
            vec![OperandType::Register32, OperandType::Register32],
            InstructionFormat {
                prefixes: vec![],
                opcode: vec![0x01],
                has_modrm: true,
                modrm_reg_field: Some("src".to_string()),
                modrm_rm_field: Some("dst".to_string()),
                has_sib: false,
                immediate_size: None,
                displacement_size: None,
                operand_order: vec!["dst".to_string(), "src".to_string()],
            }
        );

        m.insert("add", add_variants);

        // More instructions can be added...

        m
    };
}

// Represents an operand in an assembly instruction
#[derive(Debug, Clone)]
enum Operand {
    Register(String),
    Immediate(i64),
    Memory {
        base_register: Option<String>,
        index_register: Option<String>,
        scale: Option<u8>,
        displacement: Option<i32>,
    },
}

impl Operand {
    fn get_type(&self) -> OperandType {
        match self {
            Operand::Register(reg) => {
                if reg.starts_with("r") && !reg.starts_with("r8") && !reg.starts_with("r9") {
                    OperandType::Register64
                } else if reg.starts_with("e") {
                    OperandType::Register32
                } else if reg.len() == 2 && !reg.ends_with("h") && !reg.ends_with("l") {
                    OperandType::Register16
                } else {
                    OperandType::Register8
                }
            }
            Operand::Immediate(value) => {
                if *value >= -128 && *value <= 127 {
                    OperandType::Immediate8
                } else if *value >= -32768 && *value <= 32767 {
                    OperandType::Immediate16
                } else if *value >= -(2i64.pow(31)) && *value <= 2i64.pow(31) - 1 {
                    OperandType::Immediate32
                } else {
                    OperandType::Immediate64
                }
            }
            Operand::Memory { .. } => OperandType::Memory,
        }
    }
}

// Main encoder function
pub fn encode_instruction(mnemonic: &str, operands: &[Operand]) -> Result<Vec<u8>, String> {
    // Get the instruction variants map
    let instruction_variants = INSTRUCTION_ENCODING
        .get(mnemonic)
        .ok_or_else(|| format!("Unknown instruction: {}", mnemonic))?;

    // Get operand types
    let operand_types: Vec<OperandType> = operands.iter().map(|op| op.get_type()).collect();

    // Find the matching format
    let format = instruction_variants.get(&operand_types).ok_or_else(|| {
        format!(
            "No encoding found for {} with operand types {:?}",
            mnemonic, operand_types
        )
    })?;

    // Start building the encoded instruction
    let mut encoded = Vec::new();

    // Add prefixes
    encoded.extend_from_slice(&format.prefixes);

    // Handle opcode (some opcodes are modified by register number)
    let mut opcode = format.opcode.clone();

    // Create operand map for easy lookup
    let mut operand_map: HashMap<String, &Operand> = HashMap::new();

    // Check if we need to add register to opcode
    for (i, order) in format.operand_order.iter().enumerate() {
        if i < operands.len() {
            operand_map.insert(order.clone(), &operands[i]);

            if order == "opcode+reg" {
                if let Operand::Register(reg) = &operands[i] {
                    if let Some(reg_num) = REGISTER_ENCODING.get(reg.as_str()) {
                        // For instructions like MOV r32, imm32 with opcode 0xB8+rd
                        opcode[0] += reg_num;
                    }
                }
            }
        }
    }

    // Add opcode
    encoded.extend_from_slice(&opcode);

    // Handle ModR/M byte if needed
    if format.has_modrm {
        let modrm = encode_modrm(
            &format.modrm_reg_field,
            &format.modrm_rm_field,
            &operand_map,
        )?;
        encoded.push(modrm);
    }

    // Handle SIB byte if needed
    // (simplified for this example)

    // Handle displacement
    if let Some(disp_size) = format.displacement_size {
        // For simplicity, we'll assume 32-bit displacement
        let displacement = 0u32; // Would come from memory operand
        let disp_bytes = displacement.to_le_bytes();
        encoded.extend_from_slice(&disp_bytes[0..disp_size]);
    }

    // Handle immediate value
    if let Some(imm_size) = format.immediate_size {
        if let Some(imm_op) = operand_map.get("imm") {
            if let Operand::Immediate(value) = imm_op {
                match imm_size {
                    1 => encoded.push(*value as u8),
                    2 => {
                        let bytes = (*value as u16).to_le_bytes();
                        encoded.extend_from_slice(&bytes);
                    }
                    4 => {
                        let bytes = (*value as u32).to_le_bytes();
                        encoded.extend_from_slice(&bytes);
                    }
                    8 => {
                        let bytes = (*value as u64).to_le_bytes();
                        encoded.extend_from_slice(&bytes);
                    }
                    _ => return Err(format!("Invalid immediate size: {}", imm_size)),
                }
            }
        }
    }

    Ok(encoded)
}

// Encode the ModR/M byte
fn encode_modrm(
    reg_field: &Option<String>,
    rm_field: &Option<String>,
    operand_map: &HashMap<String, &Operand>,
) -> Result<u8, String> {
    let mut modrm: u8 = 0;

    // Set mod field (bits 6-7)
    // For simplicity, we'll use direct register addressing (mod=11)
    let mod_bits = 0b11;
    modrm |= mod_bits << 6;

    // Set reg field (bits 3-5)
    if let Some(reg_key) = reg_field {
        if reg_key == "0" {
            // Special case where reg field is a constant
            modrm |= 0 << 3;
        } else if let Some(Operand::Register(reg_name)) = operand_map.get(reg_key) {
            if let Some(reg_num) = REGISTER_ENCODING.get(reg_name.as_str()) {
                modrm |= (*reg_num & 0x7) << 3;
            } else {
                return Err(format!("Unknown register: {}", reg_name));
            }
        }
    }

    // Set r/m field (bits 0-2)
    if let Some(rm_key) = rm_field {
        if let Some(Operand::Register(reg_name)) = operand_map.get(rm_key) {
            if let Some(reg_num) = REGISTER_ENCODING.get(reg_name.as_str()) {
                modrm |= *reg_num & 0x7;
            } else {
                return Err(format!("Unknown register: {}", reg_name));
            }
        }
        // Memory addressing is simplified for this example
    }

    Ok(modrm)
}

// Example usage
fn main() {
    // Example: mov eax, 42
    let instruction = "mov";
    let operands = vec![Operand::Register("eax".to_string()), Operand::Immediate(42)];

    match encode_instruction(instruction, &operands) {
        Ok(bytes) => {
            println!("Encoded instruction: ");
            for byte in bytes {
                print!("{:02X} ", byte);
            }
            println!();
        }
        Err(e) => println!("Error: {}", e),
    }
}
