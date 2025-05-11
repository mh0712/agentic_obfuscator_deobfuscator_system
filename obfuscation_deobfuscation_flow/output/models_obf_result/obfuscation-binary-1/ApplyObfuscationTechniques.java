```java
// ApplyObfuscationTechniques.java
// Ghidra script applying various obfuscation techniques to the 'main' function

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Assembler;
import ghidra.program.model.lang.Assemblers;
import ghidra.program.model.listing.Instruction;

public class ApplyObfuscationTechniques extends GhidraScript {

    @Override
    protected void run() throws Exception {
        // Get a reference to the assembler for patching
        Assembler asm = Assemblers.getAssembler(currentProgram);
        
        // Apply Control Flow Flattening
        applyControlFlowFlattening(asm);

        // Apply Opaque Predicate Insertion
        applyOpaquePredicateInsertion(asm);

        // Apply Function Call Obfuscation (Demonstrative only - constrained by the provided restrictions)
        // applyFunctionCallObfuscation(asm);

        // Apply Indirect Branch Conversion (Demonstrative only - constrained by the provided restrictions)
        // applyIndirectBranchConversion(asm);
    }

    private void applyControlFlowFlattening(Assembler asm) throws Exception {
        println("Applying Control Flow Flattening...");

        // Insert dispatcher and initial state setup
        asm.assemble(toAddr("0x14000153f"), "MOV EAX, 0x0");
        createLabel(toAddr("0x140001543"), "dispatcher", true);
        asm.assemble(toAddr("0x140001543"), "CMP EAX, 0x0");
        asm.assemble(toAddr("0x140001546"), "JE 0x140001553");  // path1
        asm.assemble(toAddr("0x14000154b"), "CMP EAX, 0x1");
        asm.assemble(toAddr("0x14000154e"), "JE 0x140001556");  // path2
        asm.assemble(toAddr("0x140001553"), "CMP EAX, 0x2");
        asm.assemble(toAddr("0x140001556"), "JE 0x140001560");  // path3
        asm.assemble(toAddr("0x14000155b"), "JMP 0x140001586"); // end_dispatcher

        // Replace CALL instructions with dispatcher jumps
        asm.assemble(toAddr("0x140001547"), "MOV EAX, 0x1");
        asm.assemble(toAddr("0x140001549"), "JMP dispatcher");
        asm.assemble(toAddr("0x140001556"), "MOV EAX, 0x2");
        asm.assemble(toAddr("0x140001558"), "JMP dispatcher");
        asm.assemble(toAddr("0x140001560"), "MOV EAX, 0x3");
        asm.assemble(toAddr("0x140001562"), "JMP dispatcher");

        println("Control Flow Flattening applied successfully.");
    }

    private void applyOpaquePredicateInsertion(Assembler asm) throws Exception {
        println("Applying Opaque Predicate Insertion...");

        asm.assemble(toAddr("0x140001553"), "MOV EAX, EAX");
        createLabel(toAddr("0x140001557"), "always_true", true);
        asm.assemble(toAddr("0x140001557"), "CMP EAX, EAX");
        asm.assemble(toAddr("0x14000155a"), "JE always_true");

        println("Opaque Predicate Insertion applied successfully.");
    }

    /*
        The below functions are commented out as they require operations that are restricted 
        by the current scripting constraints, indicated by the instructions above. You can 
        uncomment and modify them according to your particular implementation scenario 
        beyond this scripting environment.

    private void applyFunctionCallObfuscation(Assembler asm) throws Exception {
        println("Applying Function Call Obfuscation...");
        // Placeholder for implementation
        println("Function Call Obfuscation applied successfully.");
    }

    private void applyIndirectBranchConversion(Assembler asm) throws Exception {
        println("Applying Indirect Branch Conversion...");
        // Placeholder for implementation
        println("Indirect Branch Conversion applied successfully.");
    }
    */
}
```

Save this script as `C:\Users\celin\ghidra_scripts\ApplyObfuscationTechniques.java`. 
This script will currently handle Control Flow Flattening and Opaque Predicate Insertion, 
while placeholders are left for the Function Call Obfuscation and Indirect Branch Conversion, 
due to restrictions given.