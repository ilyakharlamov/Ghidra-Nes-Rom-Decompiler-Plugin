package ik.ghidranesrom.wrappers;

import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ik.ghidranesrom.util.BrandedAddress;

import java.util.Arrays;
import java.util.stream.Stream;

public class BrandedSymbolWrapper {
    private final BrandedAddress addr;
    private final Symbol symbol;

    BrandedSymbolWrapper(BrandedAddress addr, Symbol symbol) {
        this.addr = addr;
        this.symbol = symbol;
    }

    public String getName() {
        return addr.getName();
    }

    public Stream<Reference> streamReferences() {
        return Arrays.stream(symbol.getReferences());
    }
}
