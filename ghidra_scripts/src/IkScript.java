//TODO test your ideas fast here
//@author Ilya Kharlamov
//@category _NEW_
//@keybinding 
//@menupath Tools.NES
//@toolbar 
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import java.util.Arrays;



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
        CodeUnit codeunit = currentProgram.getListing().getCodeUnitAt(currentAddress);
        println(String.format("currentAddress: %s", currentAddress));
        println(String.format("codeUnit: %s", codeunit));
        println(String.format("mnemonicRefs: %s", Arrays.toString(codeunit.getMnemonicReferences())));
        println(String.format("symbols: %s", Arrays.toString(codeunit.getSymbols())));

        Instruction instruction = currentProgram.getListing().getInstructionAt(currentAddress);
        println(String.format("getInputObjects: %s", Arrays.toString(instruction.getInputObjects())));

        for (Object obj : instruction.getInputObjects()) {
            printf("class:%s\n", obj.getClass());
        }
        /*ProgramWrapper programWrapper = new ProgramWrapper(currentProgram);
        for (LoopWrapper loop : programWrapper.getLoops()) {
            if (loop.getInstructions().size() != 2) {
                continue;
            }
        }*/
        println("END");
    }
}










