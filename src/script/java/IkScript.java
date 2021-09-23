//TODO test your ideas fast here
//@author Ilya Kharlamov
//@category _NEW_
//@keybinding 
//@menupath Tools.NES
//@toolbar 

import ghidra.app.script.GhidraScript;
import ik.ghidranesrom.analyzer.InMemorySymbolTagStorage;
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
        InMemorySymbolTagStorage symbolTagStorage = new InMemorySymbolTagStorage();
        Worker worker = new Worker(new ProgramWrapper(currentProgram), symbolTagStorage);
        worker.analyzeBrandedLabels();
        worker.analyzeLoops();
        //StreamSupport.stream(programWrapper.getLabels().spliterator(), false);


        // AutoAnalysisManager.
        //AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
        //ConsoleService consoleService = mgr.getAnalysisTool().getService(ConsoleService.class);
        //consoleService.print("FU");

        println("END");
    }

}













