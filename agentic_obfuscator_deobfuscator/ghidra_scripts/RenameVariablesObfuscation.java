import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

import java.io.File;
import java.util.Random;

public class RenameVariablesObfuscation extends GhidraScript {

    // Function to generate a random obfuscated name
    private String generateObfuscatedName(String prefix, int length) {
        String characters = "abcdefghijklmnopqrstuvwxyz0123456789";
        Random rand = new Random();
        StringBuilder obfuscatedName = new StringBuilder(prefix);
        for (int i = 0; i < length; i++) {
            obfuscatedName.append(characters.charAt(rand.nextInt(characters.length())));
        }
        return obfuscatedName.toString();
    }

    @Override
    public void run() throws Exception {
        // Initialize count
        int count = 0;
        
        // Get function iterator from the current program's listing
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);

        // Iterate through all functions in the program
        while (funcs.hasNext() && !monitor.isCancelled()) {

            // Get the current function
            Function f = funcs.next();
            Variable[] vars = f.getLocalVariables(); // Get local variables for the function

            // Iterate through all variables in the current function
            for (int i = 0; i < vars.length; i++) {
                Variable v = vars[i];
                
                // Generate a random name for the variable (prefix 'var_' and length 8)
                String newName = generateObfuscatedName("var_", 8);
                
                // Ensure no name collision within the current function (local variables)
                while (isNameTaken(f, newName)) {
                    newName = generateObfuscatedName("var_", 8); // Regenerate if name exists
                }
                
                // Rename the variable if the current name is different
                if (!v.getName().equals(newName)) {
                    println(f.getName() + "::" + v.getName() + " -> " + newName);
                    v.setName(newName, SourceType.USER_DEFINED);
                    count++; // Increment the counter for renamed variables
                }
            }
        }

        // Print out how many variables were renamed
        println("Renamed " + count + " variables.");
        // Export the modified program
        exportModifiedProgram();
    
    }

    // Helper function to check if the new name is already taken by another variable in the function
    private boolean isNameTaken(Function f, String name) {
        Variable[] vars = f.getLocalVariables();
        for (Variable v : vars) {
            if (v.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }

private void exportModifiedProgram() {
    try {
        // Ask user where to save
        File outputFile = new File("C:\\Users\\celin\\Desktop\\usj\\FYP\\agentic_obfuscator_deobfuscator_system\\agentic_obfuscator_deobfuscator\\src\\obfuscation_deobfuscation_crew\\tools\\ghidra_output\\obfuscated_binary.exe");

	 if (outputFile.exists()) {
            outputFile.delete();
        }

        // Create a BinaryExporter
        BinaryExporter exporter = new BinaryExporter();

        // Get the entire memory range of the current program
        AddressSetView fullMemory = currentProgram.getMemory();

        // Export with full memory
        exporter.export(outputFile, currentProgram, fullMemory, monitor);

        println("Program successfully exported to: " + outputFile.getAbsolutePath());
    } catch (ExporterException e) {
        printerr("Export failed: " + e.getMessage());
    } catch (Exception e) {
        printerr("Unexpected error during export: " + e.getMessage());
    }
}
}
