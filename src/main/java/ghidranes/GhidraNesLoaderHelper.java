package ghidranes;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class GhidraNesLoaderHelper {
    private final Program program;
    private final TaskMonitor monitor;

    public GhidraNesLoaderHelper(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    static void makeSym(Program program, TaskMonitor monitor, MessageLog log, int address, int size, String name) {
        try {
            Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            MemoryBlock block = program.getMemory().createInitializedBlock(name, addr, size, (byte)0x00, monitor, false);
            block.setRead(true);
            block.setWrite(true);
            block.setExecute(false);
            program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
        } catch(Exception e) {
            log.appendException(e);
        }
    }

    static void makeSyms(Program program, TaskMonitor monitor, MessageLog log) {
        makeSym(program, monitor, log, 0x2000, 1, "PPUCTRL");
        makeSym(program, monitor, log, 0x2001, 1, "PPUMASK");
        makeSym(program, monitor, log, 0x2002, 1, "PPUSTATUS");
        makeSym(program, monitor, log, 0x2003, 1, "OAMADDR");
        makeSym(program, monitor, log, 0x2004, 1, "OAMDATA");
        makeSym(program, monitor, log, 0x2005, 1, "PPUSCROLL");
        makeSym(program, monitor, log, 0x2006, 1, "PPUADDR");
        makeSym(program, monitor, log, 0x2007, 1, "PPUDATA");
        makeSym(program, monitor, log, 0x4000, 4, "APU_SND_SQUARE1_REG");
        makeSym(program, monitor, log, 0x4004, 4, "APU_SND_SQUARE2_REG");
        makeSym(program, monitor, log, 0x4008, 4, "APU_SND_TRIANGLE_REG");
        makeSym(program, monitor, log, 0x400c, 2, "APU_NOISE_REG");
        makeSym(program, monitor, log, 0x4010, 4, "APU_DELTA_REG");
        makeSym(program, monitor, log, 0x4014, 1, "OAMDMA");
        makeSym(program, monitor, log, 0x4015, 1, "APU_MASTERCTRL_REG");
        makeSym(program, monitor, log, 0x4016, 1, "JOYPAD_PORT1");
        makeSym(program, monitor, log, 0x4017, 1, "JOYPAD_PORT2");
    }
}