from capstone import *

# Define the input hex code to disassemble
hex_code = "C0035FD6"  # Change this to your desired hex code

# Create a disassembler instance for ARM64 architecture
md_arm64 = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# Disassemble the ARM64 code
print("ARM64:")
for insn in md_arm64.disasm(bytes.fromhex(hex_code), 0):
    print(f"{insn.address:x}: {insn.mnemonic} {insn.op_str}")

# Create a disassembler instance for ARMv7 architecture
md_armv7 = Cs(CS_ARCH_ARM, CS_MODE_ARM)

# Disassemble the ARMv7 code
print("ARMv7:")
for insn in md_armv7.disasm(bytes.fromhex(hex_code), 0):
    print(f"{insn.address:x}: {insn.mnemonic} {insn.op_str}")