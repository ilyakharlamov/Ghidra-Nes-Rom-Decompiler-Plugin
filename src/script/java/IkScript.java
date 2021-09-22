//TODO test your ideas fast here
//@author Ilya Kharlamov
//@category _NEW_
//@keybinding 
//@menupath Tools.NES
//@toolbar 

import ghidra.app.script.GhidraScript;
import ik.ghidranesrom.analyzer.Worker;
import ik.ghidranesrom.wrappers.ProgramWrapper;

public class IkScript extends GhidraScript {

    public void run() throws Exception {
        println("==============================================================================================================");
// currentProgram
// currentAddress
// currentLocation
// currentSelection
// currentHighlight
        printf("currentSelection: %s\n", currentSelection);
        Worker worker = new Worker(new ProgramWrapper(currentProgram));
        worker.smartRenameLabels();
        //StreamSupport.stream(programWrapper.getLabels().spliterator(), false);
        println("END");
    }

}










