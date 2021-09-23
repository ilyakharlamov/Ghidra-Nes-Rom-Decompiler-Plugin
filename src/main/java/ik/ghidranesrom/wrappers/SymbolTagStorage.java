package ik.ghidranesrom.wrappers;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

import java.util.Set;

public interface SymbolTagStorage {
    void add(Symbol symbol, String name);

    Iterable<String> getAll(Symbol symbol);

    Set<Address> keys();
}
