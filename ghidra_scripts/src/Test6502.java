//TODO test your ideas fast here
//@author Ilya Kharlamov
//@category _NEW_
//@keybinding
//@menupath Tools.NES
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.NumericUtilities;
import ik.ghidranesrom.analyzer.Worker;
import ik.ghidranesrom.wrappers.ProgramWrapper;

public class Test6502 extends GhidraScript {
    public void run() throws Exception {
        ProgramWrapper programWrapper = new ProgramWrapper(currentProgram);
        Worker analyzer = new Worker(programWrapper);
    }

    private void extracted(Instruction instr) throws MemoryAccessException {
        for (int i = 0; i < instr.getNumOperands(); i++) {
            printf("    operandRefType:%s\n", instr.getOperandRefType(i));
            printf("    mnemonic:%s\n", instr.getMnemonicString());
            printf("    bytes:%s\n", NumericUtilities.convertBytesToString(instr.getBytes()));
            printf("    opObject:%s\n", instr.getOpObjects(i));
            printf("    reftype:%s\n", instr.getOperandRefType(i));
        }
    }

    private void fix9d(Instruction instr) throws MemoryAccessException {
        if (instr.getByte(0) == (byte) 0x9d) {
            printf("ROTTEN instr: %s at %s\n", instr, instr.getAddress());
            for (Reference x : instr.getReferencesFrom()) {
                if (x.getSource().equals(SourceType.ANALYSIS)) {
                    printf("ROTTEN REFERENCE: %s\n", x);
                    instr.getProgram().getReferenceManager().delete(x);
                }
            }
            int addr_int = (instr.getByte(2) << 8) | instr.getByte(1);
            printf("myhex: 0x%08X\n", addr_int);
            Address addr = instr.getAddress().getAddressSpace().getAddress(addr_int);
            printf("myadr: %s\n", addr);
            println(NumericUtilities.convertBytesToString(new byte[]{instr.getByte(1), instr.getByte(2)}));
            instr.getProgram().getReferenceManager()
                    .setPrimary(instr.getProgram().getReferenceManager().addMemoryReference(
                            instr.getAddress(),
                            addr, RefType.DATA, SourceType.ANALYSIS, 0
                    ), true);
        }
    }
}
