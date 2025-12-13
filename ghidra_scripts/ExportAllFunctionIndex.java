//Export function index data for ALL programs in the current Ghidra project
//@category D2VersionChanger
//@menupath Tools.Export All Function Index
//@description Iterates through all programs in the project and exports function index data for each. Output: data/function_index/{GameType}/{Version}/{dll}.json

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.*;
import java.io.*;
import java.util.*;
import java.security.*;

/**
 * Batch export script that processes all programs in the current Ghidra project.
 * 
 * For each program found in the project, this script:
 * 1. Opens the program
 * 2. Computes function indexes (EXP/STR/API/MNE/CFG/PRO)
 * 3. Saves to data/function_index/{GameType}/{Version}/{programName}.json
 * 4. Closes the program to free memory
 * 
 * Expected project structure:
 *   /LoD/1.07/D2Client.dll
 *   /LoD/1.08/D2Client.dll
 *   /Classic/1.00/D2Client.dll
 *   etc.
 * 
 * The game type and version are derived from the folder path.
 */
public class ExportAllFunctionIndex extends GhidraScript {

    private int totalProcessed = 0;
    private int totalFailed = 0;
    private int totalFunctions = 0;
    private List<String> failedPrograms = new ArrayList<>();

    // Per-program state (reset for each program)
    private Program currentProg;
    private Map<String, Integer> stringRefCounts;
    private Map<Address, String> importMap;

    @Override
    public void run() throws Exception {
        println("=".repeat(70));
        println("BATCH FUNCTION INDEX EXPORT");
        println("=".repeat(70));
        
        // Get the project
        Project project = state.getProject();
        if (project == null) {
            printerr("No project is open!");
            return;
        }
        
        ProjectData projectData = project.getProjectData();
        println("Project: " + projectData.getProjectLocator().getName());
        
        // Get root folder
        DomainFolder rootFolder = projectData.getRootFolder();
        
        // Count total files first
        int totalFiles = countProgramFiles(rootFolder);
        println("Total program files found: " + totalFiles);
        println("");
        
        // Ask user for confirmation
        if (!askYesNo("Confirm Batch Export", 
                "This will export function index data for " + totalFiles + " programs.\n" +
                "This may take a while. Continue?")) {
            println("Export cancelled by user.");
            return;
        }
        
        long startTime = System.currentTimeMillis();
        
        // Process all folders recursively
        processFolder(rootFolder, "");
        
        long elapsed = (System.currentTimeMillis() - startTime) / 1000;
        
        // Summary
        println("");
        println("=".repeat(70));
        println("BATCH EXPORT COMPLETE");
        println("=".repeat(70));
        println("Successfully processed: " + totalProcessed + " programs");
        println("Total functions exported: " + totalFunctions);
        println("Failed: " + totalFailed);
        println("Elapsed time: " + elapsed + " seconds");
        
        if (!failedPrograms.isEmpty()) {
            println("");
            println("Failed programs:");
            for (String prog : failedPrograms) {
                println("  - " + prog);
            }
        }
    }
    
    private int countProgramFiles(DomainFolder folder) throws Exception {
        int count = 0;
        
        // Count files in this folder
        for (DomainFile file : folder.getFiles()) {
            String contentType = file.getContentType();
            if (contentType.equals("Program")) {
                count++;
            }
        }
        
        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            count += countProgramFiles(subfolder);
        }
        
        return count;
    }
    
    private void processFolder(DomainFolder folder, String path) throws Exception {
        String currentPath = path.isEmpty() ? folder.getName() : path + "/" + folder.getName();
        
        // Skip root folder name in path
        if (folder.getParent() == null) {
            currentPath = "";
        }
        
        // Process files in this folder
        for (DomainFile file : folder.getFiles()) {
            if (monitor.isCancelled()) {
                println("Export cancelled by user.");
                return;
            }
            
            String contentType = file.getContentType();
            if (!contentType.equals("Program")) {
                continue;
            }
            
            String filePath = currentPath.isEmpty() ? file.getName() : currentPath + "/" + file.getName();
            processProgram(file, filePath);
        }
        
        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            if (monitor.isCancelled()) {
                return;
            }
            processFolder(subfolder, currentPath);
        }
    }
    
    private void processProgram(DomainFile file, String projectPath) {
        currentProg = null;
        
        try {
            println("");
            println("-".repeat(50));
            println("Processing: " + projectPath);
            
            // Open the program (read-only is fine for export)
            currentProg = (Program) file.getDomainObject(this, false, false, monitor);
            
            if (currentProg == null) {
                throw new Exception("Failed to open program");
            }
            
            // Parse version from project path: LoD/1.07/D2Client.dll
            String[] pathParts = projectPath.split("/");
            String gameType = "Unknown";
            String version = "Unknown";
            String programName = file.getName();
            
            if (pathParts.length >= 3) {
                // Path format: GameType/Version/filename
                gameType = pathParts[0];
                version = pathParts[1];
            } else if (pathParts.length == 2) {
                // Path format: Version/filename (assume LoD)
                gameType = "LoD";
                version = pathParts[0];
            }
            
            println("  Game Type: " + gameType);
            println("  Version: " + version);
            
            // Create output directory
            File outputDir = new File("F:/D2VersionChanger/data/function_index/" + gameType + "/" + version);
            outputDir.mkdirs();
            File outputFile = new File(outputDir, programName + ".json");
            
            // Reset per-program state
            stringRefCounts = new HashMap<>();
            importMap = new HashMap<>();
            
            // Phase 1: Build import map and count string references
            monitor.setMessage("Analyzing " + programName + ": imports...");
            buildImportMap();
            
            monitor.setMessage("Analyzing " + programName + ": strings...");
            countStringReferences();
            
            // Phase 2: Process all functions
            monitor.setMessage("Processing " + programName + ": functions...");
            List<FunctionData> functions = processFunctions();
            
            // Phase 3: Write output
            monitor.setMessage("Writing " + programName + ": output...");
            writeOutput(outputFile, gameType, version, functions);
            
            // Stats
            int named = 0;
            for (FunctionData f : functions) {
                if (f.hasHumanName) named++;
            }
            
            println("  Functions: " + functions.size() + " (" + named + " named)");
            println("  Output: " + outputFile.getName());
            
            totalProcessed++;
            totalFunctions += functions.size();
            
        } catch (Exception e) {
            printerr("  ERROR: " + e.getMessage());
            failedPrograms.add(projectPath + " - " + e.getMessage());
            totalFailed++;
        } finally {
            // Always release the program to free memory
            if (currentProg != null) {
                currentProg.release(this);
                currentProg = null;
            }
        }
    }
    
    private void buildImportMap() throws Exception {
        SymbolTable symTable = currentProg.getSymbolTable();
        ReferenceManager refMgr = currentProg.getReferenceManager();
        
        // Get all external references
        SymbolIterator extSymbols = symTable.getExternalSymbols();
        while (extSymbols.hasNext()) {
            Symbol sym = extSymbols.next();
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                // Get references TO this external symbol
                ReferenceIterator refIter = refMgr.getReferencesTo(sym.getAddress());
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    importMap.put(ref.getFromAddress(), sym.getName());
                }
            }
        }
        
        // Also check import table directly
        for (Symbol sym : symTable.getAllSymbols(true)) {
            if (sym.isExternalEntryPoint() || sym.getName().startsWith("_imp_")) {
                importMap.put(sym.getAddress(), sym.getName().replace("_imp_", ""));
            }
        }
    }
    
    private void countStringReferences() throws Exception {
        // First pass: find all strings
        Listing listing = currentProg.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        
        Set<String> allStrings = new HashSet<>();
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String str = data.getDefaultValueRepresentation();
                if (str != null && str.length() >= 4) {
                    allStrings.add(str);
                }
            }
        }
        
        // Initialize counts
        for (String str : allStrings) {
            stringRefCounts.put(str, 0);
        }
        
        // Count references per string
        FunctionManager funcMgr = currentProg.getFunctionManager();
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            Set<String> funcStrings = getStringReferences(func);
            for (String str : funcStrings) {
                stringRefCounts.merge(str, 1, Integer::sum);
            }
        }
    }
    
    private Set<String> getStringReferences(Function func) {
        Set<String> strings = new HashSet<>();
        
        AddressSetView body = func.getBody();
        ReferenceManager refMgr = currentProg.getReferenceManager();
        Listing listing = currentProg.getListing();
        
        AddressIterator addrIter = body.getAddresses(true);
        while (addrIter.hasNext()) {
            Address addr = addrIter.next();
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                Data data = listing.getDataAt(toAddr);
                if (data != null && data.hasStringValue()) {
                    String str = data.getDefaultValueRepresentation();
                    if (str != null && str.length() >= 4) {
                        strings.add(str);
                    }
                }
            }
        }
        
        return strings;
    }
    
    private List<String> getApiCalls(Function func) {
        List<String> apis = new ArrayList<>();
        
        AddressSetView body = func.getBody();
        ReferenceManager refMgr = currentProg.getReferenceManager();
        
        AddressIterator addrIter = body.getAddresses(true);
        while (addrIter.hasNext()) {
            Address addr = addrIter.next();
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                if (ref.getReferenceType().isCall()) {
                    Address toAddr = ref.getToAddress();
                    String importName = importMap.get(toAddr);
                    if (importName != null) {
                        apis.add(importName);
                    } else {
                        Function calledFunc = currentProg.getFunctionManager().getFunctionAt(toAddr);
                        if (calledFunc != null && calledFunc.isThunk()) {
                            Function thunkedFunc = calledFunc.getThunkedFunction(false);
                            if (thunkedFunc != null && thunkedFunc.isExternal()) {
                                apis.add(thunkedFunc.getName());
                            }
                        }
                    }
                }
            }
        }
        
        return apis;
    }
    
    private String getMnemonicSequence(Function func) {
        StringBuilder mnemonics = new StringBuilder();
        
        Listing listing = currentProg.getListing();
        AddressSetView body = func.getBody();
        
        InstructionIterator instrIter = listing.getInstructions(body, true);
        while (instrIter.hasNext()) {
            Instruction instr = instrIter.next();
            mnemonics.append(instr.getMnemonicString());
            mnemonics.append(";");
        }
        
        return mnemonics.toString();
    }
    
    private byte[] getPrologueBytes(Function func, int maxBytes) {
        Address entry = func.getEntryPoint();
        Memory memory = currentProg.getMemory();
        
        int bytesToRead = Math.min(maxBytes, (int)func.getBody().getNumAddresses());
        byte[] bytes = new byte[bytesToRead];
        
        try {
            memory.getBytes(entry, bytes);
        } catch (Exception e) {
            return new byte[0];
        }
        
        return bytes;
    }
    
    private int getBasicBlockCount(Function func) {
        try {
            BasicBlockModel bbModel = new BasicBlockModel(currentProg);
            CodeBlockIterator blocks = bbModel.getCodeBlocksContaining(func.getBody(), monitor);
            int count = 0;
            while (blocks.hasNext()) {
                blocks.next();
                count++;
            }
            return count;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private List<FunctionData> processFunctions() throws Exception {
        List<FunctionData> functions = new ArrayList<>();
        
        FunctionManager funcMgr = currentProg.getFunctionManager();
        SymbolTable symTable = currentProg.getSymbolTable();
        long imageBase = currentProg.getImageBase().getOffset();
        
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        int total = funcMgr.getFunctionCount();
        int processed = 0;
        
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) {
                throw new Exception("Cancelled by user");
            }
            
            Function func = funcIter.next();
            processed++;
            
            if (processed % 500 == 0) {
                monitor.setMessage("Processing functions: " + processed + "/" + total);
            }
            
            FunctionData data = new FunctionData();
            
            // Basic info
            data.address = func.getEntryPoint().getOffset();
            data.rva = data.address - imageBase;
            data.size = (int) func.getBody().getNumAddresses();
            data.name = func.getName();
            
            // Check if name is human-assigned
            data.hasHumanName = !data.name.startsWith("FUN_") && 
                               !data.name.startsWith("thunk_FUN_") &&
                               !data.name.startsWith("LAB_") &&
                               !data.name.equals("entry");
            
            // Export ordinal
            data.exportOrdinal = -1;
            Symbol[] symbols = symTable.getSymbols(func.getEntryPoint());
            for (Symbol sym : symbols) {
                if (sym.isExternalEntryPoint()) {
                    data.exportOrdinal = getExportOrdinal(sym);
                    data.exportName = sym.getName();
                    break;
                }
            }
            
            // String references (only unique ones for index)
            Set<String> allStrings = getStringReferences(func);
            for (String str : allStrings) {
                Integer count = stringRefCounts.get(str);
                if (count != null && count == 1) {
                    data.uniqueStrings.add(str);
                }
            }
            data.stringRefs = allStrings;
            
            // API calls
            data.apiCalls = getApiCalls(func);
            
            // Mnemonic sequence
            data.mnemonicSeq = getMnemonicSequence(func);
            
            // Prologue bytes
            data.prologueBytes = getPrologueBytes(func, 16);
            
            // Basic block count
            data.basicBlockCount = getBasicBlockCount(func);
            
            // Signature and metadata
            data.signature = func.getSignature().getPrototypeString();
            data.callingConvention = func.getCallingConventionName();
            data.comment = func.getComment();
            
            // Parameters
            for (Parameter p : func.getParameters()) {
                ParamData pd = new ParamData();
                pd.name = p.getName();
                pd.type = p.getDataType().getName();
                pd.storage = p.getVariableStorage().toString();
                data.parameters.add(pd);
            }
            
            // Compute indexes
            computeIndexes(data);
            
            functions.add(data);
        }
        
        return functions;
    }
    
    private int getExportOrdinal(Symbol sym) {
        try {
            String name = sym.getName();
            if (name.startsWith("Ordinal_")) {
                return Integer.parseInt(name.substring(8));
            }
        } catch (Exception e) {
            // Ignore
        }
        return -1;
    }
    
    private void computeIndexes(FunctionData data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        
        // EXP index
        if (data.exportOrdinal >= 0) {
            data.expIndex = String.valueOf(data.exportOrdinal);
        }
        
        // STR index
        if (!data.uniqueStrings.isEmpty()) {
            List<String> sorted = new ArrayList<>(data.uniqueStrings);
            Collections.sort(sorted);
            String combined = String.join("|", sorted);
            data.strIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }
        
        // API index
        if (data.apiCalls.size() >= 2) {
            String combined = String.join("|", data.apiCalls);
            data.apiIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }
        
        // MNE index
        if (!data.mnemonicSeq.isEmpty()) {
            String combined = data.mnemonicSeq + "|" + data.size;
            data.mneIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }
        
        // CFG index
        if (data.basicBlockCount > 1) {
            String combined = data.basicBlockCount + "|" + data.size;
            data.cfgIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }
        
        // PRO index
        if (data.prologueBytes.length > 0) {
            md.update(data.prologueBytes);
            md.update(String.valueOf(data.size).getBytes("UTF-8"));
            data.proIndex = hashToHex(md.digest(), 16);
        }
        
        // Select best index
        if (data.expIndex != null) {
            data.bestIndex = "EXP:" + data.expIndex;
            data.bestMethod = "EXP";
        } else if (data.strIndex != null) {
            data.bestIndex = "STR:" + data.strIndex;
            data.bestMethod = "STR";
        } else if (data.apiIndex != null) {
            data.bestIndex = "API:" + data.apiIndex;
            data.bestMethod = "API";
        } else if (data.mneIndex != null) {
            data.bestIndex = "MNE:" + data.mneIndex;
            data.bestMethod = "MNE";
        } else if (data.cfgIndex != null) {
            data.bestIndex = "CFG:" + data.cfgIndex;
            data.bestMethod = "CFG";
        } else if (data.proIndex != null) {
            data.bestIndex = "PRO:" + data.proIndex;
            data.bestMethod = "PRO";
        } else {
            data.bestIndex = "ADDR:" + String.format("%08X", data.rva);
            data.bestMethod = "ADDR";
        }
        
        // Display name
        if (data.hasHumanName) {
            data.displayName = data.name;
        } else {
            data.displayName = data.bestMethod + "_" + 
                (data.bestIndex.length() > 20 ? 
                    data.bestIndex.substring(data.bestIndex.indexOf(':') + 1, Math.min(data.bestIndex.length(), 20)) : 
                    data.bestIndex.substring(data.bestIndex.indexOf(':') + 1));
        }
    }
    
    private String hashToHex(byte[] hash, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(hash.length, length); i++) {
            sb.append(String.format("%02x", hash[i]));
        }
        return sb.toString();
    }
    
    private void writeOutput(File outputFile, String gameType, String version, 
                            List<FunctionData> functions) throws Exception {
        long imageBase = currentProg.getImageBase().getOffset();
        
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(outputFile), "UTF-8"))) {
            
            writer.println("{");
            writer.println("  \"program_name\": \"" + escapeJson(currentProg.getName()) + "\",");
            writer.println("  \"game_type\": \"" + escapeJson(gameType) + "\",");
            writer.println("  \"version\": \"" + escapeJson(version) + "\",");
            writer.println("  \"image_base\": \"" + String.format("0x%08X", imageBase) + "\",");
            writer.println("  \"total_functions\": " + functions.size() + ",");
            writer.println("  \"export_timestamp\": \"" + new java.util.Date().toString() + "\",");
            writer.println("  \"functions\": [");
            
            for (int i = 0; i < functions.size(); i++) {
                FunctionData f = functions.get(i);
                
                writer.println("    {");
                writer.println("      \"address\": \"" + String.format("0x%08X", f.address) + "\",");
                writer.println("      \"rva\": \"" + String.format("0x%X", f.rva) + "\",");
                writer.println("      \"size\": " + f.size + ",");
                writer.println("      \"name\": \"" + escapeJson(f.name) + "\",");
                writer.println("      \"display_name\": \"" + escapeJson(f.displayName) + "\",");
                writer.println("      \"has_human_name\": " + f.hasHumanName + ",");
                
                writer.println("      \"index\": \"" + escapeJson(f.bestIndex) + "\",");
                writer.println("      \"index_method\": \"" + f.bestMethod + "\",");
                
                writer.println("      \"indexes\": {");
                writer.println("        \"EXP\": " + (f.expIndex != null ? "\"" + escapeJson(f.expIndex) + "\"" : "null") + ",");
                writer.println("        \"STR\": " + (f.strIndex != null ? "\"" + escapeJson(f.strIndex) + "\"" : "null") + ",");
                writer.println("        \"API\": " + (f.apiIndex != null ? "\"" + escapeJson(f.apiIndex) + "\"" : "null") + ",");
                writer.println("        \"MNE\": " + (f.mneIndex != null ? "\"" + escapeJson(f.mneIndex) + "\"" : "null") + ",");
                writer.println("        \"CFG\": " + (f.cfgIndex != null ? "\"" + escapeJson(f.cfgIndex) + "\"" : "null") + ",");
                writer.println("        \"PRO\": " + (f.proIndex != null ? "\"" + escapeJson(f.proIndex) + "\"" : "null") + "");
                writer.println("      },");
                
                if (f.hasHumanName) {
                    writer.println("      \"signature\": \"" + escapeJson(f.signature) + "\",");
                    writer.println("      \"calling_convention\": \"" + escapeJson(f.callingConvention) + "\",");
                    writer.println("      \"comment\": \"" + escapeJson(f.comment != null ? f.comment : "") + "\",");
                    
                    writer.print("      \"parameters\": [");
                    for (int j = 0; j < f.parameters.size(); j++) {
                        ParamData p = f.parameters.get(j);
                        if (j > 0) writer.print(", ");
                        writer.print("{\"name\": \"" + escapeJson(p.name) + "\", ");
                        writer.print("\"type\": \"" + escapeJson(p.type) + "\", ");
                        writer.print("\"storage\": \"" + escapeJson(p.storage) + "\"}");
                    }
                    writer.println("],");
                }
                
                writer.print("      \"string_refs\": [");
                int strCount = 0;
                for (String str : f.stringRefs) {
                    if (strCount > 0) writer.print(", ");
                    if (strCount >= 5) {
                        writer.print("\"...+" + (f.stringRefs.size() - 5) + " more\"");
                        break;
                    }
                    writer.print("\"" + escapeJson(truncate(str, 50)) + "\"");
                    strCount++;
                }
                writer.println("],");
                
                writer.print("      \"api_calls\": [");
                for (int j = 0; j < Math.min(f.apiCalls.size(), 10); j++) {
                    if (j > 0) writer.print(", ");
                    writer.print("\"" + escapeJson(f.apiCalls.get(j)) + "\"");
                }
                if (f.apiCalls.size() > 10) {
                    writer.print(", \"...+" + (f.apiCalls.size() - 10) + " more\"");
                }
                writer.println("],");
                
                writer.println("      \"basic_block_count\": " + f.basicBlockCount);
                
                writer.print("    }");
                if (i < functions.size() - 1) {
                    writer.println(",");
                } else {
                    writer.println();
                }
            }
            
            writer.println("  ]");
            writer.println("}");
        }
    }
    
    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
    
    private String truncate(String s, int maxLen) {
        if (s == null) return "";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "...";
    }
    
    // Data classes
    class FunctionData {
        long address;
        long rva;
        int size;
        String name;
        String displayName;
        boolean hasHumanName;
        
        int exportOrdinal = -1;
        String exportName;
        
        Set<String> stringRefs = new HashSet<>();
        Set<String> uniqueStrings = new HashSet<>();
        List<String> apiCalls = new ArrayList<>();
        String mnemonicSeq;
        byte[] prologueBytes;
        int basicBlockCount;
        
        String signature;
        String callingConvention;
        String comment;
        List<ParamData> parameters = new ArrayList<>();
        
        String expIndex;
        String strIndex;
        String apiIndex;
        String mneIndex;
        String cfgIndex;
        String proIndex;
        
        String bestIndex;
        String bestMethod;
    }
    
    class ParamData {
        String name;
        String type;
        String storage;
    }
}
