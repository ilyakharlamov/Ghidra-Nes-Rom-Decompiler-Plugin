package ik.ghidranesrom.wrappers;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ik.ghidranesrom.util.Constants;

import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SymbolWrapper {
    private final Symbol symbol;
    private final SymbolTagStorage symbolTagStorage;
    private ImmutableList<String> orderedLabels = ImmutableList.<String>builder().add("LOOP").build();

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
        Msg.debug(getClass().getSimpleName(), String.format("adding tag %s ...", name));
        addStorageTag(name);
    }

    private void addStorageTag(String name) {
        symbolTagStorage.add(symbol, name);
    }

    public void renameFromTags() {
        ImmutableList<String> tags = getOrderedStorageTags();
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

    private ImmutableList<String> getOrderedStorageTags() {
        ImmutableList.Builder<String> itemsBuilder = ImmutableList.<String>builder();
        ImmutableSet<String> storageTags= ImmutableSet.copyOf(symbolTagStorage.getAll(symbol));
        Msg.info("storageTags:", storageTags);
        itemsBuilder.addAll(orderedLabels.stream().filter(storageTags::contains).collect(Collectors.toList()));
        if (storageTags.contains("LOOP") && storageTags.contains("LAB")) {
            storageTags = ImmutableSet.copyOf(storageTags.stream().filter(x -> !"LAB".equals(x)).collect(Collectors.toSet()));
        }
        itemsBuilder.addAll(storageTags.stream().filter(x->!ImmutableSet.copyOf(orderedLabels).contains(x)).collect(Collectors.toList()));
        itemsBuilder.add(this.symbol.getAddress().toString());
        ImmutableList<String> tags = itemsBuilder.build();
        return tags;
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

