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
package ghidranes;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ik.ghidranesrom.wrappers.InstructionWrapper;
import ik.ghidranesrom.wrappers.LoopWrapper;
import ik.ghidranesrom.wrappers.ProgramWrapper;


/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class GhidraNesAnalyzer extends AbstractAnalyzer {

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
		// TODO: Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		ConsoleService consoleService = analysisManager.getAnalysisTool().getService(ConsoleService.class);
		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		consoleService.print("TEST set");

		ProgramWrapper wrapper = new ProgramWrapper(program);
		for(LoopWrapper loop: wrapper.getLoops()) {
			loop.renameTo("LOOP_"+loop.getAddress().toString());
			for (InstructionWrapper instruction: loop.getInstructions()) {
			}
		}
		return false;
	}

	@Override
	public void analysisEnded(Program program) {

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
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		return super.removed(program, set, monitor, log);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
	}
}
