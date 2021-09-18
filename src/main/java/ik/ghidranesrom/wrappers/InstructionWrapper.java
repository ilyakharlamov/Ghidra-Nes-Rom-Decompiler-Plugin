package ik.ghidranesrom.wrappers;

import ghidra.program.model.listing.Instruction;

public class InstructionWrapper {
    private final Instruction instruction;

    InstructionWrapper(Instruction instruction) {
        this.instruction = instruction;
    }

    @Override
    public String toString() {
        return this.instruction.getAddress().toString();
    }
}
