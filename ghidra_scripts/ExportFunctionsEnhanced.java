//Export all functions with extended data for comparison matching
//@category D2VersionChanger
//@menupath Tools.Export Functions Enhanced
//@description Exports all functions with callees, callers, strings, instructions, constants, CFG data for cross-version comparison. Output: data/enhanced/{GameType}/{Version}/{dll}.json

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.block.*;
import ghidra.program.model.scalar.*;
import java.io.*;
import java.util.*;
import java.security.MessageDigest;

public class ExportFunctionsEnhanced extends GhidraScript {

    private DecompInterface decompiler;
    private int maxInstructions = 15;  // First N instructions to capture
    private int maxStrings = 20;       // Max string refs per function
    private int maxCallees = 50;       // Max callees to list
    private int maxCallers = 50;       // Max callers to list
    private int maxConstants = 30;     // Max constants per function
    private int maxGlobals = 20;       // Max global refs per function

    @Override
    public void run() throws Exception {
        // Get program info
        String programName = currentProgram.getName();
        String programPath = currentProgram.getExecutablePath();

        println("=== Enhanced Function Export ===");
        println("Program: " + programName);
        println("Path: " + programPath);

        // Parse version from path: /F:/D2VersionChanger/VersionChanger/LoD/1.07/file.dll
        // Also check for PD2/binaries path pattern
        String[] pathParts = programPath.replace("\\", "/").split("/");
        String gameType = "Unknown";  // Classic or LoD
        String version = "Unknown";
        
        // Find VersionChanger in path to extract game type and version
        for (int i = 0; i < pathParts.length - 2; i++) {
            if (pathParts[i].equals("VersionChanger")) {
                if (i + 2 < pathParts.length) {
                    gameType = pathParts[i + 1];  // Classic or LoD
                    version = pathParts[i + 2];   // 1.00, 1.07, etc.
                }
                break;
            }
            // Also handle PD2 path: .../PD2/binaries/LoD/1.13c/...
            if (pathParts[i].equals("binaries")) {
                if (i + 2 < pathParts.length) {
                    gameType = pathParts[i + 1];
                    version = pathParts[i + 2];
                }
                break;
            }
        }

        println("Game Type: " + gameType);
        println("Version: " + version);

        // Output file path with version structure
        File outputDir = new File("F:/D2VersionChanger/data/enhanced/" + gameType + "/" + version);
        outputDir.mkdirs();
        File outputFile = new File(outputDir, programName + ".json");

        println("Output file: " + outputFile.getAbsolutePath());

        // Initialize decompiler for better analysis
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        FunctionManager funcManager = currentProgram.getFunctionManager();
        ReferenceManager refManager = currentProgram.getReferenceManager();
        long imageBase = currentProgram.getImageBase().getOffset();

        // Collect all functions
        List<String> functionEntries = new ArrayList<>();
        int totalFuncs = 0;
        int namedFuncs = 0;
        int processedFuncs = 0;

        // Count total for progress
        FunctionIterator countIter = funcManager.getFunctions(true);
        while (countIter.hasNext()) {
            countIter.next();
            totalFuncs++;
        }

        println("Total functions to process: " + totalFuncs);

        FunctionIterator funcIter = funcManager.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) {
                println("Export cancelled by user");
                break;
            }

            Function func = funcIter.next();
            processedFuncs++;

            // Progress update every 100 functions
            if (processedFuncs % 100 == 0) {
                monitor.setMessage("Processing " + processedFuncs + "/" + totalFuncs);
                println("Progress: " + processedFuncs + "/" + totalFuncs);
            }

            String name = func.getName();
            long address = func.getEntryPoint().getOffset();
            long rva = address - imageBase;

            // Check if it has a custom name
            boolean hasCustomName = !name.startsWith("FUN_") &&
                                   !name.startsWith("thunk_FUN_") &&
                                   !name.equals("entry");

            if (hasCustomName) {
                namedFuncs++;
            }

            // Get signature and calling convention
            String signature = func.getSignature().getPrototypeString();
            String callingConvention = func.getCallingConventionName();
            if (callingConvention == null || callingConvention.isEmpty()) {
                callingConvention = "unknown";
            }

            // Get function size (in bytes)
            long size = 0;
            AddressSetView body = func.getBody();
            if (body != null) {
                size = body.getNumAddresses();
            }

            // Get stack frame size
            int stackFrameSize = 0;
            try {
                StackFrame frame = func.getStackFrame();
                if (frame != null) {
                    stackFrameSize = frame.getFrameSize();
                }
            } catch (Exception e) {
                // Ignore
            }

            // Enhanced instruction analysis
            List<String> instructions = new ArrayList<>();
            List<String> mnemonics = new ArrayList<>();  // Just mnemonics for hashing
            Set<Long> constants = new TreeSet<>();       // Numeric constants used
            Set<String> globals = new LinkedHashSet<>(); // Global variable references
            int instructionCount = 0;
            int backwardJumps = 0;  // Loop indicator
            long prevAddr = 0;
            
            try {
                Listing listing = currentProgram.getListing();
                InstructionIterator instrIter = listing.getInstructions(body, true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    instructionCount++;
                    long instrAddr = instr.getAddress().getOffset();
                    String mnemonic = instr.getMnemonicString();
                    mnemonics.add(mnemonic);
                    
                    // Detect backward jumps (loops)
                    if (mnemonic.startsWith("J") || mnemonic.equals("LOOP")) {
                        Reference[] refs = instr.getReferencesFrom();
                        for (Reference ref : refs) {
                            if (ref.getReferenceType().isJump()) {
                                long targetAddr = ref.getToAddress().getOffset();
                                if (targetAddr < instrAddr && body.contains(ref.getToAddress())) {
                                    backwardJumps++;
                                }
                            }
                        }
                    }
                    
                    // Extract constants from operands
                    for (int op = 0; op < instr.getNumOperands(); op++) {
                        Object[] opObjs = instr.getOpObjects(op);
                        for (Object obj : opObjs) {
                            if (obj instanceof Scalar) {
                                long val = ((Scalar) obj).getValue();
                                // Filter out small values and likely addresses
                                if (val > 0xFF && val < 0x10000000L && constants.size() < maxConstants) {
                                    constants.add(val);
                                }
                            }
                        }
                    }
                    
                    // Track global/data references
                    Reference[] refs = instr.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isData() && globals.size() < maxGlobals) {
                            Address toAddr = ref.getToAddress();
                            // Check if it's a global (not stack, not code)
                            if (!body.contains(toAddr)) {
                                long refRva = toAddr.getOffset() - imageBase;
                                Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(toAddr);
                                String symName = (sym != null) ? sym.getName() : "";
                                globals.add(String.format("0x%X|%s", refRva, symName));
                            }
                        }
                    }
                    
                    if (instructions.size() < maxInstructions) {
                        long instrRva = instrAddr - imageBase;
                        String operands = formatOperands(instr);
                        instructions.add(String.format("0x%X|%s|%s", instrRva, mnemonic, operands));
                    }
                    
                    prevAddr = instrAddr;
                }
            } catch (Exception e) {
                // Ignore instruction parsing errors
            }
            
            // Compute mnemonic hash (position-independent)
            String mnemonicHash = "";
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                StringBuilder mnemonicSeq = new StringBuilder();
                for (String m : mnemonics) {
                    mnemonicSeq.append(m).append(";");
                }
                byte[] digest = md.digest(mnemonicSeq.toString().getBytes());
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) {
                    sb.append(String.format("%02x", b));
                }
                mnemonicHash = sb.toString();
            } catch (Exception e) {
                // Ignore hash errors
            }
            
            // Get basic block count (CFG complexity)
            int basicBlockCount = 0;
            try {
                BasicBlockModel bbModel = new BasicBlockModel(currentProgram);
                CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(body, monitor);
                while (blockIter.hasNext()) {
                    blockIter.next();
                    basicBlockCount++;
                }
            } catch (Exception e) {
                // Ignore block counting errors
            }

            // Get callees (functions this function calls)
            List<String> callees = new ArrayList<>();
            try {
                Set<Function> calledFuncs = func.getCalledFunctions(monitor);
                for (Function callee : calledFuncs) {
                    if (callees.size() >= maxCallees) break;
                    String calleeName = callee.getName();
                    long calleeAddr = callee.getEntryPoint().getOffset();
                    callees.add(String.format("%s|0x%X", calleeName, calleeAddr));
                }
            } catch (Exception e) {
                // Ignore callee errors
            }

            // Get callers (functions that call this function)
            List<String> callers = new ArrayList<>();
            try {
                Set<Function> callingFuncs = func.getCallingFunctions(monitor);
                for (Function caller : callingFuncs) {
                    if (callers.size() >= maxCallers) break;
                    String callerName = caller.getName();
                    long callerAddr = caller.getEntryPoint().getOffset();
                    callers.add(String.format("%s|0x%X", callerName, callerAddr));
                }
            } catch (Exception e) {
                // Ignore caller errors
            }

            // Get string references
            List<String> strings = new ArrayList<>();
            try {
                ReferenceIterator refIter = refManager.getReferenceIterator(func.getEntryPoint());
                AddressSet funcAddrs = new AddressSet(body);
                
                // Check all references FROM this function
                InstructionIterator instrIter = currentProgram.getListing().getInstructions(body, true);
                while (instrIter.hasNext() && strings.size() < maxStrings) {
                    Instruction instr = instrIter.next();
                    Reference[] refs = instr.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (strings.size() >= maxStrings) break;
                        Address toAddr = ref.getToAddress();
                        Data data = currentProgram.getListing().getDataAt(toAddr);
                        if (data != null && data.hasStringValue()) {
                            Object value = data.getValue();
                            if (value != null) {
                                String strVal = value.toString();
                                if (strVal.length() > 0 && strVal.length() < 200) {
                                    strings.add(strVal);
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore string reference errors
            }

            // Get parameter info
            List<String> parameters = new ArrayList<>();
            try {
                Parameter[] params = func.getParameters();
                for (Parameter param : params) {
                    String paramName = param.getName();
                    String paramType = param.getDataType().getDisplayName();
                    String storage = param.getVariableStorage().toString();
                    parameters.add(String.format("%s|%s|%s", paramName, paramType, storage));
                }
            } catch (Exception e) {
                // Ignore parameter errors
            }

            // Get local variable count
            int localVarCount = 0;
            try {
                Variable[] locals = func.getLocalVariables();
                localVarCount = locals.length;
            } catch (Exception e) {
                // Ignore
            }

            // Get return type
            String returnType = "void";
            try {
                returnType = func.getReturnType().getDisplayName();
            } catch (Exception e) {
                // Ignore
            }

            // Build JSON entry
            StringBuilder entry = new StringBuilder();
            entry.append("    {\n");
            entry.append("      \"address\": \"").append(String.format("0x%08X", address)).append("\",\n");
            entry.append("      \"rva\": \"").append(String.format("0x%X", rva)).append("\",\n");
            entry.append("      \"name\": \"").append(escapeJson(name)).append("\",\n");
            entry.append("      \"has_custom_name\": ").append(hasCustomName).append(",\n");
            entry.append("      \"signature\": \"").append(escapeJson(signature)).append("\",\n");
            entry.append("      \"calling_convention\": \"").append(escapeJson(callingConvention)).append("\",\n");
            entry.append("      \"return_type\": \"").append(escapeJson(returnType)).append("\",\n");
            entry.append("      \"size\": ").append(size).append(",\n");
            entry.append("      \"instruction_count\": ").append(instructionCount).append(",\n");
            entry.append("      \"local_var_count\": ").append(localVarCount).append(",\n");
            entry.append("      \"param_count\": ").append(parameters.size()).append(",\n");
            entry.append("      \"stack_frame_size\": ").append(stackFrameSize).append(",\n");
            entry.append("      \"basic_block_count\": ").append(basicBlockCount).append(",\n");
            entry.append("      \"loop_count\": ").append(backwardJumps).append(",\n");
            entry.append("      \"mnemonic_hash\": \"").append(mnemonicHash).append("\",\n");
            
            // Instructions array
            entry.append("      \"instructions\": [");
            for (int i = 0; i < instructions.size(); i++) {
                entry.append("\"").append(escapeJson(instructions.get(i))).append("\"");
                if (i < instructions.size() - 1) entry.append(", ");
            }
            entry.append("],\n");

            // Callees array
            entry.append("      \"callees\": [");
            for (int i = 0; i < callees.size(); i++) {
                entry.append("\"").append(escapeJson(callees.get(i))).append("\"");
                if (i < callees.size() - 1) entry.append(", ");
            }
            entry.append("],\n");

            // Callers array
            entry.append("      \"callers\": [");
            for (int i = 0; i < callers.size(); i++) {
                entry.append("\"").append(escapeJson(callers.get(i))).append("\"");
                if (i < callers.size() - 1) entry.append(", ");
            }
            entry.append("],\n");

            // Strings array
            entry.append("      \"strings\": [");
            for (int i = 0; i < strings.size(); i++) {
                entry.append("\"").append(escapeJson(strings.get(i))).append("\"");
                if (i < strings.size() - 1) entry.append(", ");
            }
            entry.append("],\n");

            // Parameters array
            entry.append("      \"parameters\": [");
            for (int i = 0; i < parameters.size(); i++) {
                entry.append("\"").append(escapeJson(parameters.get(i))).append("\"");
                if (i < parameters.size() - 1) entry.append(", ");
            }
            entry.append("],\n");
            
            // Constants array
            entry.append("      \"constants\": [");
            int constIdx = 0;
            for (Long c : constants) {
                entry.append(c);
                if (++constIdx < constants.size()) entry.append(", ");
            }
            entry.append("],\n");
            
            // Globals array (RVA|name)
            entry.append("      \"globals\": [");
            int globIdx = 0;
            for (String g : globals) {
                entry.append("\"").append(escapeJson(g)).append("\"");
                if (++globIdx < globals.size()) entry.append(", ");
            }
            entry.append("]\n");

            entry.append("    }");
            functionEntries.add(entry.toString());
        }

        // Cleanup decompiler
        decompiler.dispose();

        // Write JSON file
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            writer.println("{");
            writer.println("  \"program_name\": \"" + escapeJson(programName) + "\",");
            writer.println("  \"game_type\": \"" + escapeJson(gameType) + "\",");
            writer.println("  \"version\": \"" + escapeJson(version) + "\",");
            writer.println("  \"image_base\": \"" + String.format("0x%08X", imageBase) + "\",");
            writer.println("  \"total_functions\": " + processedFuncs + ",");
            writer.println("  \"named_functions\": " + namedFuncs + ",");
            writer.println("  \"export_version\": \"2.0\",");
            writer.println("  \"functions\": [");

            for (int i = 0; i < functionEntries.size(); i++) {
                writer.print(functionEntries.get(i));
                if (i < functionEntries.size() - 1) {
                    writer.println(",");
                } else {
                    writer.println();
                }
            }

            writer.println("  ]");
            writer.println("}");
        }

        println("=== Export Complete ===");
        println("Total functions: " + processedFuncs);
        println("Named functions: " + namedFuncs);
        println("Output: " + outputFile.getAbsolutePath());
    }

    private String formatOperands(Instruction instr) {
        StringBuilder sb = new StringBuilder();
        int numOperands = instr.getNumOperands();
        for (int i = 0; i < numOperands; i++) {
            if (i > 0) sb.append(", ");
            String opStr = instr.getDefaultOperandRepresentation(i);
            sb.append(opStr);
        }
        return sb.toString();
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
