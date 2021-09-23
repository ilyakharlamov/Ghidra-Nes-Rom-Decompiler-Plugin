package ik.ghidranesrom.wrappers;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;

import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class ProgramWrapper {
    private final Program program;

    public ProgramWrapper(Program program) {
        this.program = program;
    }

    public Stream<Symbol> getLabels() {
        return StreamSupport.stream(program.getSymbolTable().getAllSymbols(true).spliterator(), false)
                .filter(x -> x.getSymbolType().equals(SymbolType.LABEL));
    }

    public Iterable<LoopWrapper> getLoops() {
        return StreamSupport.stream(program.getSymbolTable().getAllSymbols(true).spliterator(), false)
                .filter(x -> x.getSymbolType().equals(SymbolType.LABEL))
                .filter(x -> x.getReferenceCount() == 1)
                .filter(x -> SymbolUtilities.getDynamicName(x.getProgram(), x.getAddress()).startsWith("LAB_"))
                .filter(x -> x.getReferences()[0].getFromAddress().compareTo(x.getAddress()) > 0)
                .map(LoopWrapper::new)
                .collect(Collectors.toList());
    }

    public Stream<Symbol> getFirstLabelAbove(Address address) {
        return StreamSupport.stream(program.getListing().getInstructions(address, false).spliterator(), false)
                .dropWhile(l -> !program.getSymbolTable().hasSymbol(l.getAddress()))
                .findFirst().stream()
                .flatMap(inst -> Arrays.stream(program.getSymbolTable().getSymbols(inst.getAddress())))
                ;

    }

    public Stream<Symbol> streamSymbolsAt(Address address) {
        return Arrays.stream(this.program.getSymbolTable().getSymbols(address));
    }
}
