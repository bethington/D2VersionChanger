//Export only named functions (human annotations) to JSON
//@category D2VersionChanger
//@menupath Tools.Export Names Only

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.io.*;
import java.util.*;

/**
 * Exports human-annotated function data (custom names, not FUN_*).
 *
 * Captures:
 * - Function name, address, RVA
 * - Return type
 * - Full signature/prototype
 * - Calling convention
 * - Parameters (name, type, storage)
 * - Local variables that have been renamed (not default names)
 * - Plate comment (function header comment)
 *
 * Output: F:/D2VersionChanger/data/ghidra_names/<program_name>.json
 *
 * Usage: Open binary in Ghidra, run this script via Script Manager
 */
public class ExportNamesOnly extends GhidraScript {

    @Override
    public void run() throws Exception {
        String programName = currentProgram.getName();

        // Output file path
        File outputDir = new File("F:/D2VersionChanger/data/ghidra_names");
        outputDir.mkdirs();
        File outputFile = new File(outputDir, programName + ".json");

        println("=".repeat(60));
        println("Exporting named functions from: " + programName);
        println("Output: " + outputFile.getAbsolutePath());
        println("=".repeat(60));

        FunctionManager funcManager = currentProgram.getFunctionManager();
        long imageBase = currentProgram.getImageBase().getOffset();
        String languageId = currentProgram.getLanguageID().toString();
        String compilerSpec = currentProgram.getCompilerSpec().getCompilerSpecID().toString();

        // Collect named functions
        List<String> entries = new ArrayList<>();
        int totalFuncs = 0;
        int namedFuncs = 0;
        int withComments = 0;
        int withParams = 0;

        FunctionIterator funcIter = funcManager.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) {
                println("Cancelled by user");
                return;
            }

            Function func = funcIter.next();
            totalFuncs++;

            String name = func.getName();

            // Skip auto-generated names
            if (name.startsWith("FUN_") ||
                name.startsWith("thunk_FUN_") ||
                name.startsWith("LAB_") ||
                name.equals("entry")) {
                continue;
            }

            namedFuncs++;

            long address = func.getEntryPoint().getOffset();
            long rva = address - imageBase;
            String signature = func.getSignature().getPrototypeString();
            String callingConv = func.getCallingConventionName();
            DataType returnType = func.getReturnType();
            String returnTypeName = returnType != null ? returnType.getName() : "undefined";

            // Get plate comment (function header)
            String plateComment = func.getComment();
            if (plateComment != null && !plateComment.isEmpty()) {
                withComments++;
            }

            // Get parameter info
            StringBuilder params = new StringBuilder("[");
            Parameter[] parameters = func.getParameters();
            if (parameters.length > 0) withParams++;

            for (int i = 0; i < parameters.length; i++) {
                if (i > 0) params.append(", ");
                Parameter p = parameters[i];
                params.append("{");
                params.append("\"name\": \"").append(escapeJson(p.getName())).append("\", ");
                params.append("\"type\": \"").append(escapeJson(p.getDataType().getName())).append("\", ");
                params.append("\"size\": ").append(p.getLength()).append(", ");
                params.append("\"storage\": \"").append(escapeJson(p.getVariableStorage().toString())).append("\"");
                params.append("}");
            }
            params.append("]");

            // Get local variables with custom names (not auto-generated)
            StringBuilder locals = new StringBuilder("[");
            Variable[] localVars = func.getLocalVariables();
            int localCount = 0;
            for (Variable v : localVars) {
                String varName = v.getName();
                // Skip auto-generated local names (local_XX, Stack[-0x...], etc)
                if (varName.startsWith("local_") ||
                    varName.startsWith("Stack[") ||
                    varName.startsWith("uStack") ||
                    varName.startsWith("iStack") ||
                    varName.startsWith("puStack") ||
                    varName.startsWith("piStack")) {
                    continue;
                }
                if (localCount > 0) locals.append(", ");
                locals.append("{");
                locals.append("\"name\": \"").append(escapeJson(varName)).append("\", ");
                locals.append("\"type\": \"").append(escapeJson(v.getDataType().getName())).append("\", ");
                locals.append("\"storage\": \"").append(escapeJson(v.getVariableStorage().toString())).append("\"");
                locals.append("}");
                localCount++;
            }
            locals.append("]");

            // Build JSON entry
            StringBuilder entry = new StringBuilder();
            entry.append("    \"").append(String.format("0x%08X", address)).append("\": {\n");
            entry.append("      \"name\": \"").append(escapeJson(name)).append("\",\n");
            entry.append("      \"rva\": \"").append(String.format("0x%X", rva)).append("\",\n");
            entry.append("      \"return_type\": \"").append(escapeJson(returnTypeName)).append("\",\n");
            entry.append("      \"signature\": \"").append(escapeJson(signature)).append("\",\n");
            entry.append("      \"calling_convention\": \"").append(escapeJson(callingConv)).append("\",\n");
            entry.append("      \"parameters\": ").append(params).append(",\n");
            entry.append("      \"locals\": ").append(locals).append(",\n");
            entry.append("      \"comment\": \"").append(escapeJson(plateComment != null ? plateComment : "")).append("\"\n");
            entry.append("    }");

            entries.add(entry.toString());

            // Progress every 100 functions
            if (namedFuncs % 100 == 0) {
                println("  Processed " + namedFuncs + " named functions...");
            }
        }

        // Write JSON file
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(outputFile), "UTF-8"))) {
            writer.println("{");
            writer.println("  \"program_name\": \"" + escapeJson(programName) + "\",");
            writer.println("  \"image_base\": \"" + String.format("0x%08X", imageBase) + "\",");
            writer.println("  \"language\": \"" + escapeJson(languageId) + "\",");
            writer.println("  \"compiler\": \"" + escapeJson(compilerSpec) + "\",");
            writer.println("  \"total_functions\": " + totalFuncs + ",");
            writer.println("  \"named_functions\": " + namedFuncs + ",");
            writer.println("  \"functions_with_comments\": " + withComments + ",");
            writer.println("  \"functions_with_params\": " + withParams + ",");
            writer.println("  \"functions\": {");

            for (int i = 0; i < entries.size(); i++) {
                writer.print(entries.get(i));
                if (i < entries.size() - 1) {
                    writer.println(",");
                } else {
                    writer.println();
                }
            }

            writer.println("  }");
            writer.println("}");
        }

        println("");
        println("=".repeat(60));
        println("Export complete!");
        println("  Total functions:    " + totalFuncs);
        println("  Named functions:    " + namedFuncs);
        println("  With comments:      " + withComments);
        println("  With parameters:    " + withParams);
        println("  Output: " + outputFile.getAbsolutePath());
        println("=".repeat(60));
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
