package ik.ghidranesrom.wrappers;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ik.ghidranesrom.util.Constants;

import java.util.stream.Stream;

public class SymbolWrapper {
    private final Symbol symbol;
    private final SymbolTagStorage symbolTagStorage;

    public SymbolWrapper(Symbol symbol, SymbolTagStorage symbolTagStorage) {
        this.symbol = symbol;
        this.symbolTagStorage = symbolTagStorage;
    }

    public Stream<BrandedSymbolWrapper> streamBranded() {
        return Constants.brandedAddresses.stream().filter(b -> b.getAddr() == symbol.getAddress().getOffset())
                .map(b -> new BrandedSymbolWrapper(b, symbol));
    }


    public String getName() {
        return symbol.getName();
    }

    public void addTag(String name) {
        addStorageTag(name);
    }

    private void addStorageTag(String name) {
        symbolTagStorage.add(symbol, name);
    }

    private Iterable<String> getStorageTags() {
        return symbolTagStorage.getAll(symbol);
    }

    public void renameFromTags() {
        ImmutableList.Builder<String> items = ImmutableList.<String>builder();
        items.addAll(getStorageTags());
        items.add(this.symbol.getAddress().toString());
        ImmutableList<String> tags = items.build();
        Msg.info(getClass().getSimpleName(), String.format("rename from tags:%s", tags));
        try {
            this.symbol.setName(
                    Joiner.on("_").join(tags).replaceAll("\\W+", "_"),
                    SourceType.ANALYSIS
            );
        } catch (DuplicateNameException e) {
            e.printStackTrace();
        } catch (InvalidInputException e) {
            e.printStackTrace();
        }
    }

    public boolean isLoop() {
        Symbol x = symbol;
        boolean isConditional = false;
        if (x.getSymbolType().equals(SymbolType.LABEL) && x.getReferenceCount() == 1 && x.getProgram().getListing()
                .getInstructionAt(x.getReferences()[0].getFromAddress()) != null) {
            Msg.info("isLoop", symbol);
            Instruction instr = x.getProgram().getListing()
                    .getInstructionAt(x.getReferences()[0].getFromAddress());
            Msg.info("instr", instr);
            Msg.info("flowType", instr.getFlowType());
            Msg.info("isConditional", instr.getFlowType().isConditional());
            if (instr.getFlowType().isConditional()) {
                isConditional = true;
            }
        }
        return x.getSymbolType().equals(SymbolType.LABEL) && x.getReferenceCount() == 1 &&
                x.getReferences()[0].getFromAddress().compareTo(x.getAddress()) > 0 && isConditional;

    }
}

