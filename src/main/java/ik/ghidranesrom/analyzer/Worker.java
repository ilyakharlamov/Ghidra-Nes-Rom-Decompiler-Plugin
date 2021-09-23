package ik.ghidranesrom.analyzer;

import ghidra.util.Msg;
import ik.ghidranesrom.wrappers.ProgramWrapper;
import ik.ghidranesrom.wrappers.SymbolTagStorage;
import ik.ghidranesrom.wrappers.SymbolWrapper;

import java.util.stream.Stream;

public class Worker {
    private final ProgramWrapper programWrapper;
    private final SymbolTagStorage symbolTagStorage;

    public Worker(ProgramWrapper programWrapper, SymbolTagStorage symbolTagStorage) {
        this.programWrapper = programWrapper;
        this.symbolTagStorage = symbolTagStorage;
    }

    public void analyzeBrandedLabels() {
        programWrapper.getLabels()
                .map(symbol -> new SymbolWrapper(symbol, symbolTagStorage))
                .flatMap(SymbolWrapper::streamBranded)
                .peek((symbolWrapper) -> {
                    Msg.info("branded", symbolWrapper.getName());
                })
                .forEach(brandedSymbolWrapper -> {
                    brandedSymbolWrapper.streamReferences().forEach(ref -> {
                        programWrapper.getFirstLabelAbove(ref.getFromAddress())
                                .map(x -> new SymbolWrapper(x, symbolTagStorage))
                                .forEach(l -> {
                                    if (l.getName().equals("reset")) {
                                        return;
                                    }
                                    if (l.getName().equals("irq")) {
                                        return;
                                    }
                                    if (l.getName().equals("vblank")) {
                                        return;
                                    }
                                    Msg.debug("label", l.getName());
                                    l.addTag("LAB");
                                    l.addTag(brandedSymbolWrapper.getName());
                                });
                    });
                });
    }

    public void analyzeLoops() {
        programWrapper.getLabels()
                .map(symbol -> new SymbolWrapper(symbol, symbolTagStorage))
                .filter(SymbolWrapper::isLoop).forEach(x -> x.addTag("LOOP"));
    }

    public void renameLabels() {
        symbolTagStorage.keys().stream()
                .flatMap(x -> programWrapper.streamSymbolsAt(x))
                .map(x -> new SymbolWrapper(x, symbolTagStorage))
                .forEach(SymbolWrapper::renameFromTags);

    }
}
