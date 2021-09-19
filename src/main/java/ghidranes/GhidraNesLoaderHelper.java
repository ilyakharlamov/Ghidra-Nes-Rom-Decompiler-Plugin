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
import ik.ghidranesrom.util.BrandedAddress;
import ik.ghidranesrom.util.Constants;

import static ghidranes.util.AddressSpaceUtil.getLittleEndianAddress;

public class GhidraNesLoaderHelper {
    private final Program program;
    private final TaskMonitor monitor;
    private final MessageLog log;

    public GhidraNesLoaderHelper(Program program, TaskMonitor monitor, MessageLog log) {
        this.program = program;
        this.monitor = monitor;
        this.log = log;
    }

    void makeSym(
            BrandedAddress brandedAddress
    ) {
        try {
            Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(brandedAddress.getAddr());
            MemoryBlock block = program.getMemory().createInitializedBlock(
                    brandedAddress.getName(),
                    addr,
                    brandedAddress.getSize(),
                    (byte) 0x00,
                    monitor,
                    false
            );
            block.setRead(true);
            block.setWrite(true);
            block.setExecute(false);
            program.getSymbolTable()
                    .createLabel(addr, brandedAddress.getName(), SourceType.IMPORTED);
        } catch (Exception e) {
            log.appendException(e);
        }
    }

    private static void createPinnedLabel(
            final SymbolTable symbolTable,
            final Address address,
            final String label
    ) throws InvalidInputException {
        Symbol nmiSymbol = symbolTable.createLabel(address, label, SourceType.IMPORTED);
        nmiSymbol.setPinned(true);
        nmiSymbol.setPrimary();
    }

    void makeSyms() {
        Constants.brandedAddresses.stream().forEach(this::makeSym);
    }

    void markAddresses() throws MemoryAccessException, InvalidInputException {
        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        SymbolTable symbolTable = program.getSymbolTable();
        Memory memory = program.getMemory();

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
        Symbol resTargetSymbol =
                symbolTable.createLabel(resTargetAddress, "reset", SourceType.IMPORTED);
        symbolTable.addExternalEntryPoint(resTargetAddress);
        resTargetSymbol.setPrimary();

        Address nmiTargetAddress = getLittleEndianAddress(addressSpace, memory, nmiAddress);
        Symbol nmiTargetSymbol =
                symbolTable.createLabel(nmiTargetAddress, "vblank", SourceType.IMPORTED);
        symbolTable.addExternalEntryPoint(nmiTargetAddress);
        nmiTargetSymbol.setPrimary();

        Address irqTargetAddress = getLittleEndianAddress(addressSpace, memory, irqAddress);
        Symbol irqTargetSymbol =
                symbolTable.createLabel(irqTargetAddress, "irq", SourceType.IMPORTED);
        symbolTable.addExternalEntryPoint(irqTargetAddress);
        irqTargetSymbol.setPrimary();
    }

    public void smartRename() {
        System.out.format("IK smart rename\n");

    }
}

