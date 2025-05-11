```java
// Import necessary Ghidra classes
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.assembler.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.*;
import ghidra.program.model.listing.*;

public class ObfuscationScript extends GhidraScript {

    // Declare Assembler as a class member
    private Assembler asm;

    @Override
    public void run() throws Exception {
        // Initialize the Assembler inside the run method
        asm = Assemblers.getAssembler(currentProgram);

        // Apply obfuscation techniques
        insertDeadCode();
        replaceArithmeticBranch();

        println("Obfuscation techniques applied successfully.");
    }

    private void insertDeadCode() throws Exception {
        // Technique: Dead Code Insertion
        Address addr1 = toAddr("0x140001504");
        Address addr2 = toAddr("0x14000174B");

        // Assemble instructions for the first location
        asm.assemble(addr1, "NOP");
        asm.assemble(addr1.add(1), "XOR ECX, ECX");
        asm.assemble(addr1.add(3), "ADD ECX, 0");

        // Log the insertion success
        println("Inserted dead code at 0x140001504");

        // Assemble instructions for the second location
        asm.assemble(addr2, "MOV ECX, ECX");
        asm.assemble(addr2.add(2), "NOP");
        asm.assemble(addr2.add(3), "SUB ECX, 0");

        // Log the insertion success
        println("Inserted dead code at 0x14000174B");
    }

    private void replaceArithmeticBranch() throws Exception {
        // Technique: Arithmetic Branch Replacement
        Address replaceAddr = toAddr("0x140003478");

        // Assemble replacement instructions
        asm.assemble(replaceAddr, "SETZ BL");
        asm.assemble(replaceAddr.add(2), "XOR EBX, 1");

        // Log the replacement success
        println("Replaced arithmetic branch at 0x140003478");
    }
}
```

This script applies two obfuscation techniques: "Dead Code Insertion" and "Arithmetic Branch Replacement". It makes use of the Ghidra API's Assembler to insert and replace instructions at specified addresses. It also logs each successful application of a technique for user confirmation.