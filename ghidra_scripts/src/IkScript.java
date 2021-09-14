//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;

public class IkScript extends GhidraScript {

    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
// currentProgram
// currentAddress
// currentLocation
// currentSelection
// currentHighlight
        println(String.format("currentAddress: %s", currentAddress));
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator iter = symbolTable.getAllSymbols(true);
        for (Symbol symbol: iter) {
            println(String.format("symbol %s", symbol));
        }
    }

}
