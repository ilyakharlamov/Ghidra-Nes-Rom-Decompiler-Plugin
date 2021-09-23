/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ik.ghidranesrom.analyzer;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ik.ghidranesrom.wrappers.ProgramWrapper;


/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class GhidraNesAnalyzer extends AbstractAnalyzer {
    public static final String OPTION_NAME_GOES_HERE = "Option name goes here";
    private ConsoleService consoleService;

    public GhidraNesAnalyzer() {

        // TODO: Name the analyzer and give it a description.

        super("GhidraNesRom analyzer", "Rename labels", AnalyzerType.INSTRUCTION_ANALYZER);
        setSupportsOneTimeAnalysis(true);
    }

    @Override
    public boolean getDefaultEnablement(Program program) {

        // TODO: Return true if analyzer should be enabled by default

        return true;
    }

    @Override
    public boolean canAnalyze(Program program) {
        // TODO: Examine 'program' to determine of this analyzer should analyze it.
        return program.getLanguage().getProcessor().toString().startsWith("6502");
    }

    @Override
    public void registerOptions(Options options, Program program) {

        // TODO: If this analyzer has custom options, register them here

        options.registerOption(OPTION_NAME_GOES_HERE, false, null,
                "Option description goes here"
        );
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        println("added");
        AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
        ConsoleService consoleService = analysisManager.getAnalysisTool().getService(ConsoleService.class);
        // TODO: Perform analysis when things get added to the 'program'.  Return true if the
        // analysis succeeded.

        ProgramWrapper programWrapper = new ProgramWrapper(program);
        Worker analyzer = new Worker(programWrapper, new InMemorySymbolTagStorage());
        analyzer.analyzeBrandedLabels();
        analyzer.analyzeLoops();
        analyzer.renameLabels();
        return false;
    }

    @Override
    public void analysisEnded(Program program) {
        println("analysys ended");
    }

    private void println(String s) {
        Msg.info(this.getClass().getSimpleName(), s);
    }

    private void print(Program program, String s) {
        AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
        consoleService = analysisManager.getAnalysisTool().getService(ConsoleService.class);
        consoleService.print(s);
    }

    @Override
    protected void setPriority(AnalysisPriority priority) {
        super.setPriority(priority);
    }

    @Override
    protected void setDefaultEnablement(boolean b) {
        super.setDefaultEnablement(b);
    }

    @Override
    protected void setSupportsOneTimeAnalysis() {
        super.setSupportsOneTimeAnalysis();
    }

    @Override
    protected void setSupportsOneTimeAnalysis(boolean supportsOneTimeAnalysis) {
        super.setSupportsOneTimeAnalysis(supportsOneTimeAnalysis);
    }

    @Override
    protected void setPrototype() {
        super.setPrototype();
    }

    @Override
    public boolean removed(
            Program program,
            AddressSetView set,
            TaskMonitor monitor,
            MessageLog log
    ) throws CancelledException {
        return super.removed(program, set, monitor, log);
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        super.optionsChanged(options, program);
    }
}

