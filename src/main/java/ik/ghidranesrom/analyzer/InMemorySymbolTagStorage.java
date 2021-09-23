package ik.ghidranesrom.analyzer;

import com.google.common.collect.ImmutableSet;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ik.ghidranesrom.wrappers.SymbolTagStorage;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class InMemorySymbolTagStorage implements SymbolTagStorage {
    private Map<Address, ImmutableSet<String>> map;

    public InMemorySymbolTagStorage() {
        this.map = new HashMap<>();
    }

    @Override
    public void add(Symbol symbol, String name) {
        Msg.info(getClass().getSimpleName(), String.format("adding to symbol: %s tag: %s ...", symbol, name));
        ImmutableSet<String> existingValue = map.getOrDefault(symbol.getAddress(), ImmutableSet.of());
        Msg.info(getClass().getSimpleName(), String.format(
                "old value: %s",
                this.map.getOrDefault(symbol.getAddress(), ImmutableSet.of())
        ));
        this.map.put(
                symbol.getAddress(),
                ImmutableSet.<String>builder().addAll(existingValue).add(name).build()
        );
        Msg.info(getClass().getSimpleName(), String.format(
                "new value: %s",
                this.map.getOrDefault(symbol.getAddress(), ImmutableSet.of())
        ));
    }

    @Override
    public Iterable<String> getAll(Symbol symbol) {
        ImmutableSet<String> val = map.getOrDefault(symbol.getAddress(), ImmutableSet.of());
        Msg.info(getClass().getSimpleName(), String.format("getAll: for symbol %s val:%s, total keys:%s", symbol, val,
                ImmutableSet.copyOf(map.keySet())
        ));
        return val;
    }

    @Override
    public Set<Address> keys() {
        return this.map.keySet();
    }
}
