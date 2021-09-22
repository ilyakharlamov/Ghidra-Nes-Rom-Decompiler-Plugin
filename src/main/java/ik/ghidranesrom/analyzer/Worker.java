package ik.ghidranesrom.analyzer;

import ghidra.program.model.listing.Program;
import ik.ghidranesrom.wrappers.LoopWrapper;
import ik.ghidranesrom.wrappers.ProgramWrapper;
import ik.ghidranesrom.wrappers.SymbolWrapper;

public class Worker {
    private final ProgramWrapper programWrapper;

    public Worker(ProgramWrapper programWrapper) {
        this.programWrapper = programWrapper;
    }

    public void smartRenameLabels() {
        programWrapper.getLabels()
                .map(SymbolWrapper::new)
                .flatMap(SymbolWrapper::streamBranded)
                .forEach(brandedSymbolWrapper -> {
                    brandedSymbolWrapper.streamReferences().forEach(ref -> {
                        programWrapper.getFirstLabelAbove(ref.getFromAddress())
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
                                    l.addTag(brandedSymbolWrapper.getName());
                                });
                    });
                });
    }
}
