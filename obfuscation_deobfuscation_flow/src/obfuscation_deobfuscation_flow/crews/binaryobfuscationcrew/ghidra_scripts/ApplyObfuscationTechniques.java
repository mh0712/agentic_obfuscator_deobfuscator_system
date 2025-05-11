import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.assembler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class ApplyObfuscationTechniques extends GhidraScript {
    private Assembler asm;

    @Override
    public void run() throws Exception {
        asm = Assemblers.getAssembler(currentProgram);
        replaceArithmeticBranch();
        insertDeadCode();
    }

    private void replaceArithmeticBranch() throws Exception {
        String address = "0x00402178";
        String[] instructions = {
                "SETZ BL",
                "XOR EBX, 1",
                "MOVZX EBX, BL",
                "MOV ESI, 0x0040217f",
                "MOV EDI, 0x00402180",
                "CMP BL, 0",
                "CMOVZ ESI, EDI",
                "JMP ESI"
        };
        patchInstructions(address, instructions);
    }

    private void insertDeadCode() throws Exception {
        String address = "0x004037f9";
        String[] instructions = {
                "XOR EAX, EAX",
                "ADD EAX, 0"
        };
        patchInstructions(address, instructions);
    }

    private void patchInstructions(String address, String[] instructions) throws Exception {
        Address addr = toAddr(address);
        Listing listing = currentProgram.getListing();
        for (String instruction : instructions) {
            asm.assemble(addr, instruction);
            Instruction inserted = listing.getInstructionAt(addr);
            if (inserted == null) {
                printerr("Failed to fetch instruction at: " + addr);
                break;
            }
            println("Patched at " + addr + ": " + instruction);
            addr = addr.add(inserted.getLength());
        }
    }
}