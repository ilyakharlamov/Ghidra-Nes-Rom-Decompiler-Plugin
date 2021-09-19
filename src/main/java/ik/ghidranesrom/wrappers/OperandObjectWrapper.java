package ik.ghidranesrom.wrappers;

import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

public class OperandObjectWrapper {

    private final GenericAddress address;
    private final Program program;

    public OperandObjectWrapper(GenericAddress addr, Program program) {
        this.address = addr;
        this.program = program;
    }

    public CodeUnit get() {
        return program.getListing().getCodeUnitAt(address);
    }

    public String getLabel() {
        return program.getListing().getCodeUnitAt(address).getLabel();
    }
}
