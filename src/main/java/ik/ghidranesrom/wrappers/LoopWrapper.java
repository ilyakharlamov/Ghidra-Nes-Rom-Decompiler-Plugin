package ik.ghidranesrom.wrappers;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class LoopWrapper {
    private final Symbol symbol;

    LoopWrapper (Symbol symbol) {
        if (symbol.getReferences().length !=1) {
            throw new RuntimeException("Number of references is not 1");
        }
        this.symbol = symbol;
    }

    public String getName() {
        return this.symbol.getName();
    }

    public Iterable<InstructionWrapper> getInstructions() {
        AddressSet range = symbol.getProgram().getAddressFactory().getAddressSet(symbol.getAddress(), symbol.getReferences()[0].getFromAddress());
        InstructionIterator instructionIterator = symbol.getProgram().getListing().getInstructions(range, true);
        return StreamSupport.stream(instructionIterator.spliterator(), false).map(x->new InstructionWrapper(x)).collect(Collectors.toList());
    }

    public Address getAddress() {
        return this.symbol.getAddress();
    }

    public void renameTo(String s) {
        try {
            this.symbol.setName(s, SourceType.ANALYSIS);
        } catch (DuplicateNameException e) {
            e.printStackTrace();
        } catch (InvalidInputException e) {
            e.printStackTrace();
        }
    }
}
