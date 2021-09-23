package ik.ghidranesrom.wrappers;

import com.google.common.collect.ImmutableSet;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

import java.util.Set;

public interface SymbolTagStorage {
    void add(Symbol symbol, String name);

    ImmutableSet<String> getAll(Symbol symbol);

    ImmutableSet<Address> keys();
}
