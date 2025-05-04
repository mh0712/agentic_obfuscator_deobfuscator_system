import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class DetectConditionalBranches extends GhidraScript {

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        MemoryBlock textBlock = currentProgram.getMemory().getBlock(".text");

        if (textBlock == null) {
            println(".text section not found.");
            return;
        }

        Address start = textBlock.getStart();
        Address end = textBlock.getEnd();

        Instruction instr = listing.getInstructionAt(start);
        List<Map<String, Object>> output = new ArrayList<>();

        while (instr != null && instr.getMinAddress().compareTo(end) <= 0) {
            monitor.checkCanceled();

            // Skip instructions not in a valid function or from external/system functions
            Function func = currentProgram.getFunctionManager().getFunctionContaining(instr.getAddress());
            if (func == null || func.isExternal()) {
                instr = instr.getNext();
                continue;
            }

            String funcName = func.getName().toLowerCase();
            if (funcName.startsWith("_start") || funcName.startsWith("__") || funcName.startsWith("sub_") || funcName.startsWith("thunk_")) {
                instr = instr.getNext();
                continue;
            }

            String mnemonic = instr.getMnemonicString().toUpperCase();

            // Check if it's a conditional jump and if it involves arithmetic operations
            if (isConditionalJump(mnemonic)) {
                Instruction prev = instr.getPrevious();
                if (prev != null) {
                    String prevMnemonic = prev.getMnemonicString().toUpperCase();
                    // Filter CMP, TEST, and arithmetic operations
                    if (isArithmeticComparison(prev) || isArithmeticOperation(prevMnemonic)) {
                        Map<String, Object> branchInfo = new LinkedHashMap<>();
                        branchInfo.put("CMP_ADDRESS", prev.getAddress().toString());
                        branchInfo.put("CMP_INSTRUCTION", prev.toString().toUpperCase());
                        branchInfo.put("JUMP_ADDRESS", instr.getAddress().toString());
                        branchInfo.put("JUMP_INSTRUCTION", instr.toString().toUpperCase());

                        Address target = getJumpTarget(instr);
                        if (target != null) {
                            branchInfo.put("JUMP_TARGET", target.toString());
                        }

                        int availableBytes = getAvailableBytes(instr);
                        branchInfo.put("AVAILABLE_BYTES_FOR_OBFUSCATION", availableBytes);

                        output.add(branchInfo);
                    }
                }
            }

            instr = instr.getNext();
        }

        writeAsJson(output);
    }

    // Check if the instruction involves an arithmetic comparison (CMP or TEST)
    private boolean isArithmeticComparison(Instruction cmpInstr) {
        for (int i = 0; i < cmpInstr.getNumOperands(); i++) {
            Object[] opObjects = cmpInstr.getOpObjects(i);
            for (Object obj : opObjects) {
                // Check if the operand is an integer constant (use `Constant` or `Integer`)
                if (obj instanceof Integer) {
                    return true;
                }
                // You can also check for immediate values as integers
                else if (obj instanceof Address) {
                    return true;
                }
            }
        }
        return false;
    }

    // Check if the instruction involves an arithmetic operation (ADD, SUB, MUL, etc.)
    private boolean isArithmeticOperation(String mnemonic) {
        return mnemonic.matches("ADD|SUB|MUL|DIV|IMUL|IDIV|SAR|SHL|SHR");
    }

    private boolean isConditionalJump(String mnemonic) {
        return mnemonic.matches("J(E|NE|Z|NZ|G|L|GE|LE|A|B|AE|BE)");
    }

    private Address getJumpTarget(Instruction instr) {
        for (int i = 0; i < instr.getNumOperands(); i++) {
            Object[] opObjects = instr.getOpObjects(i);
            for (Object obj : opObjects) {
                if (obj instanceof Address) {
                    return (Address) obj;
                }
            }
        }
        return null;
    }

    private int getAvailableBytes(Instruction jumpInstr) {
        Address jumpEnd = jumpInstr.getMaxAddress().add(1);
        int count = 0;
        Address current = jumpEnd;
        Listing listing = currentProgram.getListing();
        MemoryBlock textBlock = currentProgram.getMemory().getBlock(".text");

        while (current.compareTo(textBlock.getEnd()) <= 0) {
            Instruction instrAt = listing.getInstructionAt(current);
            if (instrAt != null) {
                break;
            }
            count++;
            current = current.add(1);
        }

        return count;
    }

    private void writeAsJson(List<Map<String, Object>> output) {
        String outputPath = "C:\\\\Users\\\\celin\\\\Desktop\\\\usj\\\\FYP\\\\agentic_obfuscator_deobfuscator_system\\\\agentic_obfuscator_deobfuscator\\\\src\\\\obfuscation_deobfuscation_crew\\\\tools\\\\ghidra_output\\\\conditional_branches.json";

        try (FileWriter file = new FileWriter(outputPath)) {
            file.write("[\n");
            for (int i = 0; i < output.size(); i++) {
                Map<String, Object> entry = output.get(i);
                file.write("  {\n");
                int j = 0;
                for (Map.Entry<String, Object> kv : entry.entrySet()) {
                    file.write("    \"" + kv.getKey() + "\": \"" + kv.getValue() + "\"");
                    if (++j < entry.size()) file.write(",");
                    file.write("\n");
                }
                file.write(i < output.size() - 1 ? "  },\n" : "  }\n");
            }
            file.write("]\n");
            println("Saved output to: " + outputPath);
        } catch (IOException e) {
            printerr("Failed to write JSON output: " + e.getMessage());
        }
    }
}
