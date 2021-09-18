//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.listing.*;

import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import ik.ghidranesrom.wrappers.InstructionWrapper;
import ik.ghidranesrom.wrappers.ProgramWrapper;
import ik.ghidranesrom.wrappers.LoopWrapper;

public class IkScript extends GhidraScript {

    public void run() throws Exception {
        println("==============================================================================================================");
        // Listing listing = currentProgram.getListing();
        // Memory memory = currentProgram.getMemory();
// currentProgram
// currentAddress
// currentLocation
// currentSelection
// currentHighlight
        println(String.format("currentAddresr: %s", currentAddress));
        ProgramWrapper wrapper = new ProgramWrapper(currentProgram);
        for(LoopWrapper loop: wrapper.getLoops()) {
            println(String.format("LABEL: %s", loop.getName()));
            loop.renameTo("LOOP_"+loop.getAddress().toString());
            for (InstructionWrapper instruction: loop.getInstructions()) {
                println(String.format("     INSTR: %s", instruction));
            }
        }
        println("END");
    }
}










