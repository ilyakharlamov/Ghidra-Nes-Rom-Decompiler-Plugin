package ghidranes;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import static ghidranes.util.AddressSpaceUtil.getLittleEndianAddress;

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

    void makeSyms(MessageLog log) {
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
        makeSym(program, monitor, log, 0x400e, 1, "APU_NOISE_REG_FREQUENCY_2");
        makeSym(program, monitor, log, 0x400f, 1, "APU_NOISE_REG_FREQUENCY_AND_TIME_3");
        makeSym(program, monitor, log, 0x4010, 4, "APU_DELTA_REG");
        makeSym(program, monitor, log, 0x4014, 1, "OAMDMA");
        makeSym(program, monitor, log, 0x4015, 1, "APU_MASTERCTRL_REG");
        makeSym(program, monitor, log, 0x4016, 1, "JOYPAD_PORT1");
        makeSym(program, monitor, log, 0x4017, 1, "JOYPAD_PORT2");
    }

    void markAddresses() throws MemoryAccessException, InvalidInputException {
        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        SymbolTable symbolTable = program.getSymbolTable();
        Memory memory =  program.getMemory();

        Address nmiAddress = addressSpace.getAddress(0xFFFA);
        createPinnedLabel(symbolTable, nmiAddress, "NMI");
        symbolTable.addExternalEntryPoint(nmiAddress);

        Address resAddress = addressSpace.getAddress(0xFFFC);
        createPinnedLabel(symbolTable, resAddress, "RES");
        symbolTable.addExternalEntryPoint(resAddress);

        Address irqAddress = addressSpace.getAddress(0xFFFE);
        createPinnedLabel(symbolTable, irqAddress, "IRQ");
        symbolTable.addExternalEntryPoint(irqAddress);

        // RES should have the highest precedence, followed by NMI, followed by IRQ. We set them
        // as primary in reverse order because the last `.setPrimary()` call has precedence
        Address resTargetAddress = getLittleEndianAddress(addressSpace, memory, resAddress);
        Symbol resTargetSymbol = symbolTable.createLabel(resTargetAddress, "reset", SourceType.IMPORTED);
        symbolTable.addExternalEntryPoint(resTargetAddress);
        resTargetSymbol.setPrimary();

        Address nmiTargetAddress = getLittleEndianAddress(addressSpace, memory, nmiAddress);
        Symbol nmiTargetSymbol = symbolTable.createLabel(nmiTargetAddress, "vblank", SourceType.IMPORTED);
        symbolTable.addExternalEntryPoint(nmiTargetAddress);
        nmiTargetSymbol.setPrimary();

        Address irqTargetAddress = getLittleEndianAddress(addressSpace, memory, irqAddress);
        Symbol irqTargetSymbol = symbolTable.createLabel(irqTargetAddress, "irq", SourceType.IMPORTED);
        symbolTable.addExternalEntryPoint(irqTargetAddress);
        irqTargetSymbol.setPrimary();
    }

    public void smartRename() {
        System.out.format("IK smart rename\n");

    }

    private static void createPinnedLabel(final SymbolTable symbolTable, final Address address, final String label) throws InvalidInputException {
        Symbol nmiSymbol = symbolTable.createLabel(address, label, SourceType.IMPORTED);
        nmiSymbol.setPinned(true);
        nmiSymbol.setPrimary();
    }
}
