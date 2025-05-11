import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class FindWritableExecutableAddresses extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        MemoryBlock textBlock = memory.getBlock(".text");
        if (textBlock == null) {
            printerr(".text section not found.");
            return;
        }

        Address textStart = textBlock.getStart();
        Address textEnd = textBlock.getEnd();

        FunctionManager fm = currentProgram.getFunctionManager();
        List<Function> functions = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            Address addr = f.getEntryPoint();
            if (textBlock.contains(addr)) {
                functions.add(f);
            }
        }

        functions.sort(Comparator.comparing(Function::getEntryPoint));
        List<String> freeRegionsJson = new ArrayList<>();

        for (int i = 0; i < functions.size() - 1; i++) {
            Function func1 = functions.get(i);
            Function func2 = functions.get(i + 1);

            Address func1End = func1.getBody().getMaxAddress();
            Instruction lastInstr = listing.getInstructionAt(func1End);
            int lastInstrLen = (lastInstr != null) ? lastInstr.getLength() : 1;
            Address gapStart = func1End.add(lastInstrLen);
            Address gapEnd = func2.getEntryPoint().subtract(1);

            if (gapStart.compareTo(gapEnd) >= 0 || !textBlock.contains(gapStart) || !textBlock.contains(gapEnd)) {
                continue;
            }

            List<AddressRange> usedRanges = new ArrayList<>();
            InstructionIterator instrIter = listing.getInstructions(new AddressSet(gapStart, gapEnd), true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                Address start = instr.getAddress();
                Address end = start.add(instr.getLength() - 1);
                usedRanges.add(new AddressRangeImpl(start, end));
            }

            usedRanges.sort(Comparator.comparing(AddressRange::getMinAddress));
            Address current = gapStart;

            for (AddressRange used : usedRanges) {
                Address usedStart = used.getMinAddress();
                Address usedEnd = used.getMaxAddress();

                if (current.compareTo(usedStart) < 0) {
                    Address freeEnd = usedStart.subtract(1);
                    int length = (int) freeEnd.subtract(current) + 1;
                    if (length > 0) {
                        String entry = String.format("{\"start\": \"%s\", \"length\": %d}", current.toString(), length);
                        freeRegionsJson.add(entry);
                    }
                }
                current = usedEnd.add(1);
            }

            if (current.compareTo(gapEnd) <= 0) {
                int length = (int) gapEnd.subtract(current) + 1;
                if (length > 0) {
                    String entry = String.format("{\"start\": \"%s\", \"length\": %d}", current.toString(), length);
                    freeRegionsJson.add(entry);
                }
            }
        }

        // Output to JSON file
        String outputPath = "C:\\\\Users\\\\celin\\\\Desktop\\\\usj\\\\FYP\\\\agentic_obfuscator_deobfuscator_system\\\\obfuscation_deobfuscation_flow\\\\src\\\\obfuscation_deobfuscation_flow\\\\crews\\\\binaryobfuscationcrew\\\\ghidra_output\\\\free_memory.json";
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputPath))) {
            writer.println("[");
            for (int i = 0; i < freeRegionsJson.size(); i++) {
                writer.print("  " + freeRegionsJson.get(i));
                if (i < freeRegionsJson.size() - 1) {
                    writer.println(",");
                } else {
                    writer.println();
                }
            }
            writer.println("]");
            println("Free regions exported to: " + outputPath);
        }
    }
}