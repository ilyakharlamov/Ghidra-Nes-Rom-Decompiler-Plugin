package ik.ghidranesrom.wrappers;

import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.listing.Instruction;

import java.util.Arrays;

public class InstructionWrapper {
    private final Instruction instruction;

    InstructionWrapper(Instruction instruction) {
        this.instruction = instruction;
    }

    @Override
    public String toString() {
        return this.instruction.getAddress().toString();
    }

    public Boolean isInput() {
        return (this.instruction.getMnemonicString().equals("LDA")
                || this.instruction.getMnemonicString().equals("LDX")
                || this.instruction.getMnemonicString()
                .equals("LDY")) && Arrays.stream(this.instruction.getInputObjects()).map(
                Object::getClass).filter(x -> x.equals(GenericAddress.class)).count() > 0;
    }

    public OperandObjectWrapper getSource() {
        for (Object obj : this.instruction.getInputObjects()) {
            if (obj instanceof GenericAddress) {
                return new OperandObjectWrapper((GenericAddress) obj, this.instruction.getProgram());
            }
        }
        throw new RuntimeException(String.format("No Generic address for LD* found: %s at ", this.instruction,
                this.instruction.getAddress()
        ));
    }

    public Boolean isBranch() {
        return instruction.getFlowType().isConditional();
    }
}

