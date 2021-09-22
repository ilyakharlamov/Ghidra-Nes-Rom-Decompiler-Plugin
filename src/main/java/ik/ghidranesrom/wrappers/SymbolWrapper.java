package ik.ghidranesrom.wrappers;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ik.ghidranesrom.util.Constants;

import java.util.ArrayList;
import java.util.stream.Stream;

public class SymbolWrapper {
    private final Symbol symbol;
    private final ArrayList<String> tags;

    public SymbolWrapper(Symbol symbol) {
        this.symbol = symbol;
        this.tags = new ArrayList<String>();
    }

    public Stream<BrandedSymbolWrapper> streamBranded() {
        return Constants.brandedAddresses.stream().filter(b -> b.getAddr() == symbol.getAddress().getOffset())
                .map(b -> new BrandedSymbolWrapper(b, symbol));
    }


    public String getName() {
        return symbol.getName();
    }

    public void addTag(String name) {
        this.tags.add(name);
        renameFromTags();
    }

    private void renameFromTags() {
        ImmutableList.Builder<String> items = ImmutableList.<String>builder();
        if (isLoop()) {
            items.add("LOOP");
        } else {
            items.add("LAB");
        }
        items.addAll(tags);
        items.add(this.symbol.getAddress().toString());
        try {
            this.symbol.setName(
                    Joiner.on("_").join(items.build()).replaceAll("\\W+", "_"),
                    SourceType.ANALYSIS
            );
        } catch (DuplicateNameException e) {
            e.printStackTrace();
        } catch (InvalidInputException e) {
            e.printStackTrace();
        }
    }

    private boolean isLoop() {
        Symbol x = symbol;
        return x.getSymbolType().equals(SymbolType.LABEL) && x.getReferenceCount() == 1 &&
                x.getReferences()[0].getFromAddress().compareTo(x.getAddress()) > 0;

    }
}

