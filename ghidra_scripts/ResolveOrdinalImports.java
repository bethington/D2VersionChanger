//Resolve ordinal imports by looking up exports in the actual DLL from the same project folder.
//@author D2VersionChanger
//@category D2VersionChanger
//@keybinding
//@menupath Tools.D2.Resolve Ordinal Imports
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.framework.model.*;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/**
 * Resolves ordinal imports by finding the exporting DLL in the same project folder
 * and looking up the actual function names and signatures from its symbols.
 * 
 * For example, if D2Common.dll imports FOG.DLL::Ordinal_10042, this script will:
 * 1. Find Fog.dll in the same project folder as D2Common.dll
 * 2. Find the function at the entry point for ordinal 10042
 * 3. If that function has a proper name and signature, apply both
 * 4. Rename the import from Ordinal_10042 to the actual name with correct signature
 * 
 * This leverages the RE work done on the exporting DLLs.
 */
public class ResolveOrdinalImports extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get the current program's location in the project
        DomainFile currentFile = currentProgram.getDomainFile();
        DomainFolder currentFolder = currentFile.getParent();
        
        println("Current program: " + currentFile.getName());
        println("Project folder: " + currentFolder.getPathname());
        
        // Get all external libraries this program imports from
        ExternalManager extMgr = currentProgram.getExternalManager();
        String[] libNames = extMgr.getExternalLibraryNames();
        
        println("\nExternal libraries imported:");
        for (String lib : libNames) {
            println("  " + lib);
        }
        
        int totalRenamed = 0;
        int totalSkipped = 0;
        
        // Process each library
        for (String libName : libNames) {
            // Skip standard Windows DLLs
            String libUpper = libName.toUpperCase();
            if (libUpper.equals("KERNEL32.DLL") || libUpper.equals("USER32.DLL") ||
                libUpper.equals("ADVAPI32.DLL") || libUpper.equals("GDI32.DLL") ||
                libUpper.equals("NTDLL.DLL") || libUpper.equals("MSVCRT.DLL") ||
                libUpper.equals("WS2_32.DLL") || libUpper.equals("WINMM.DLL") ||
                libUpper.equals("SHELL32.DLL") || libUpper.equals("OLE32.DLL") ||
                libUpper.equals("OLEAUT32.DLL") || libUpper.equals("COMCTL32.DLL")) {
                continue;
            }
            
            // Count all imports from this library
            int importCount = 0;
            ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
            while (iter.hasNext()) {
                iter.next();
                importCount++;
            }
            
            if (importCount == 0) {
                continue;
            }
            
            println("\n" + libName + ": " + importCount + " external references to process");
            
            // Try to find this DLL in the same project folder
            DomainFile libFile = findLibraryInProject(currentFolder, libName);
            
            if (libFile == null) {
                println("  WARNING: Could not find " + libName + " in project folder");
                totalSkipped += importCount;
                continue;
            }
            
            println("  Found: " + libFile.getPathname());
            
            // Open the library and process exports with signatures
            Program libProgram = null;
            Object consumer = this;
            
            try {
                libProgram = (Program) libFile.getDomainObject(consumer, false, false, monitor);
                
                if (libProgram == null) {
                    println("  Could not open " + libFile.getName());
                    totalSkipped += importCount;
                    continue;
                }
                
                // Build ordinal -> address mapping from PE export directory
                Map<Integer, Address> ordinalToAddr = getOrdinalAddressMap(libProgram);
                
                // Also build name -> function mapping for direct lookups
                Map<String, Function> nameToFunc = new HashMap<>();
                FunctionManager libFuncMgr = libProgram.getFunctionManager();
                FunctionIterator allFuncs = libFuncMgr.getFunctions(true);
                while (allFuncs.hasNext()) {
                    Function f = allFuncs.next();
                    nameToFunc.put(f.getName(), f);
                }
                
                println("  Loaded " + ordinalToAddr.size() + " exports, " + nameToFunc.size() + " functions");
                
                SymbolTable libSymTable = libProgram.getSymbolTable();
                
                // Process ALL external locations
                iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation loc = iter.next();
                    String label = loc.getLabel();
                    
                    if (label == null) {
                        totalSkipped++;
                        continue;
                    }
                    
                    Function srcFunc = null;
                    String newName = null;
                    
                    if (label.startsWith("Ordinal_")) {
                        // Ordinal import - look up by ordinal number
                        try {
                            int ordinal = Integer.parseInt(label.substring(8));
                            Address funcAddr = ordinalToAddr.get(ordinal);
                            
                            if (funcAddr == null) {
                                println("    " + label + ": ordinal not in export table");
                                totalSkipped++;
                                continue;
                            }
                            
                            srcFunc = libFuncMgr.getFunctionAt(funcAddr);
                            if (srcFunc != null) {
                                newName = srcFunc.getName();
                            } else {
                                Symbol sym = libSymTable.getPrimarySymbol(funcAddr);
                                if (sym != null) {
                                    newName = sym.getName();
                                }
                            }
                            
                            if (newName == null || newName.startsWith("Ordinal_") || newName.startsWith("FUN_")) {
                                println("    " + label + ": no useful name at " + funcAddr);
                                totalSkipped++;
                                continue;
                            }
                            
                            // Rename the external location
                            loc.setName(loc.getParentNameSpace(), newName, SourceType.USER_DEFINED);
                            
                            // Update the address to point to the actual function in the DLL
                            loc.setAddress(funcAddr);
                            
                            println("    " + label + " -> " + newName + " @ " + funcAddr);
                            
                            // Apply signature if we have a function
                            if (srcFunc != null) {
                                applySignatureToExternal(loc, srcFunc, newName);
                                totalRenamed++;
                            } else {
                                totalRenamed++;  // Still count the rename
                            }
                            
                        } catch (NumberFormatException e) {
                            totalSkipped++;
                            continue;
                        }
                    } else {
                        // Already named - just look up the function by name for signature
                        srcFunc = nameToFunc.get(label);
                        
                        // Apply signature if we have a source function
                        if (srcFunc != null) {
                            applySignatureToExternal(loc, srcFunc, label);
                            totalRenamed++;
                        } else {
                            // println("    " + label + ": no source function found (skipping sig)");
                            totalSkipped++;
                        }
                    }
                }
                
            } finally {
                if (libProgram != null) {
                    libProgram.release(consumer);
                }
            }
        }
        
        println("\n========================================");
        println("Done! Updated " + totalRenamed + " imports, skipped " + totalSkipped);
        println("========================================");
    }
    
    /**
     * Find a library DLL in the same project folder (case-insensitive).
     */
    private DomainFile findLibraryInProject(DomainFolder folder, String libName) {
        // Try exact match first
        DomainFile file = folder.getFile(libName);
        if (file != null) {
            return file;
        }
        
        // Try case-insensitive match
        String libLower = libName.toLowerCase();
        // Remove .dll extension for matching
        String baseName = libLower.endsWith(".dll") ? libLower.substring(0, libLower.length() - 4) : libLower;
        
        try {
            DomainFile[] files = folder.getFiles();
            for (DomainFile f : files) {
                String fname = f.getName().toLowerCase();
                // Match with or without .dll extension
                if (fname.equals(libLower) || fname.equals(baseName) || 
                    fname.equals(baseName + ".dll")) {
                    return f;
                }
            }
        } catch (Exception e) {
            println("Error listing folder: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Build ordinal -> address mapping from PE export directory.
     * 
     * This reads the PE export directory to get ordinal-to-RVA mappings.
     */
    private Map<Integer, Address> getOrdinalAddressMap(Program libProgram) {
        Map<Integer, Address> exports = new HashMap<>();
        
        try {
            Memory memory = libProgram.getMemory();
            
            // Get the image base
            Address dosHeader = libProgram.getImageBase();
            
            // Read DOS header to find PE header
            int peOffset = memory.getInt(dosHeader.add(0x3C));  // e_lfanew
            Address peHeader = dosHeader.add(peOffset);
            
            // PE signature is at peHeader, optional header starts at +24
            Address optionalHeader = peHeader.add(24);
            
            // Check PE32 vs PE32+ by reading magic
            short magic = memory.getShort(optionalHeader);
            int exportDirOffset = (magic == 0x20b) ? 112 : 96;  // PE32+ : PE32
            
            // Read export directory RVA and size
            Address exportDirEntry = optionalHeader.add(exportDirOffset);
            int exportDirRVA = memory.getInt(exportDirEntry);
            int exportDirSize = memory.getInt(exportDirEntry.add(4));
            
            if (exportDirRVA == 0) {
                println("  No export directory found");
                return exports;
            }
            
            // Calculate export directory address
            Address exportDir = dosHeader.add(exportDirRVA);
            
            // Read export directory structure
            int ordinalBase = memory.getInt(exportDir.add(0x10));
            int numberOfFunctions = memory.getInt(exportDir.add(0x14));
            int addressOfFunctions = memory.getInt(exportDir.add(0x1C));
            
            println("  Export directory: ordinalBase=" + ordinalBase + 
                    ", numberOfFunctions=" + numberOfFunctions);
            
            // Read the export address table
            Address eatAddr = dosHeader.add(addressOfFunctions);
            
            for (int i = 0; i < numberOfFunctions && !monitor.isCancelled(); i++) {
                int funcRVA = memory.getInt(eatAddr.add(i * 4));
                
                if (funcRVA == 0) {
                    continue;  // Empty slot
                }
                
                // Check if it's a forwarder (RVA points within export directory)
                if (funcRVA >= exportDirRVA && funcRVA < exportDirRVA + exportDirSize) {
                    continue;  // Skip forwarders
                }
                
                int ordinal = ordinalBase + i;
                Address funcAddr = dosHeader.add(funcRVA);
                
                exports.put(ordinal, funcAddr);
            }
            
        } catch (Exception e) {
            println("  Error reading export directory: " + e.getMessage());
            e.printStackTrace();
        }
        
        return exports;
    }
    
    /**
     * Apply function signature from source to external location.
     */
    private void applySignatureToExternal(ExternalLocation loc, Function srcFunc, String label) {
        try {
            // Get or create the external function
            Function extFunc = loc.getFunction();
            
            if (extFunc == null) {
                try {
                    extFunc = loc.createFunction();
                } catch (Exception e) {
                    println("    " + label + ": could not create ext function: " + e.getMessage());
                }
            }
            
            if (extFunc != null) {
                // Copy return type
                DataType returnType = srcFunc.getReturnType();
                extFunc.setReturnType(returnType, SourceType.USER_DEFINED);
                
                // Copy calling convention first (before parameters)
                String callingConv = srcFunc.getCallingConventionName();
                if (callingConv != null && !callingConv.equals("unknown")) {
                    try {
                        extFunc.setCallingConvention(callingConv);
                    } catch (Exception e) {
                        // Calling convention might not be available
                    }
                }
                
                // Copy parameters
                Parameter[] srcParams = srcFunc.getParameters();
                if (srcParams.length > 0) {
                    ArrayList<ParameterImpl> newParams = new ArrayList<>();
                    for (Parameter p : srcParams) {
                        ParameterImpl newParam = new ParameterImpl(
                            p.getName(),
                            p.getDataType(),
                            currentProgram
                        );
                        newParams.add(newParam);
                    }
                    
                    extFunc.replaceParameters(newParams,
                        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true, SourceType.USER_DEFINED);
                }
                
                println("    " + label + " sig updated: " + srcFunc.getSignature().getPrototypeString());
            } else {
                // Try setting data type directly
                try {
                    FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(srcFunc, false);
                    loc.setDataType(funcDef);
                    println("    " + label + " sig via datatype: " + funcDef.getPrototypeString());
                } catch (Exception e) {
                    println("    " + label + ": could not apply signature");
                }
            }
        } catch (Exception e) {
            println("    " + label + " sig failed: " + e.getMessage());
        }
    }
}
