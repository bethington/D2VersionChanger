//Rename ordinal imports (e.g., Ordinal_10042) to their actual function names using a mapping file.
//@author D2VersionChanger
//@category D2VersionChanger
//@keybinding
//@menupath Tools.D2.Rename Ordinal Imports
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import generic.jar.ResourceFile;
import java.io.*;
import java.util.*;

/**
 * Renames ordinal imports to their proper function names.
 * 
 * Reads ordinal mappings from JSON files in data/ordinal_maps/{DLL}.json
 * Format: {"10042": "Fog_AllocMemory", "10216": "Fog_FreeMemory", ...}
 * 
 * This handles external function references like:
 *   FOG.DLL::Ordinal_10042 -> FOG.DLL::Fog_AllocMemory
 */
public class RenameOrdinalImports extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get the project root (parent of ghidra_scripts)
        ResourceFile scriptFile = getSourceFile();
        File scriptDir = new File(scriptFile.getAbsolutePath()).getParentFile();
        File projectRoot = scriptDir.getParentFile();
        File mapsDir = new File(projectRoot, "data/ordinal_maps");
        
        if (!mapsDir.exists()) {
            println("Creating ordinal maps directory: " + mapsDir.getAbsolutePath());
            mapsDir.mkdirs();
            println("\nPlease add ordinal mapping files to: " + mapsDir.getAbsolutePath());
            println("Format: {DLL}.json with content like:");
            println("  {\"10042\": \"Fog_AllocMemory\", \"10216\": \"Fog_FreeMemory\"}");
            return;
        }
        
        // Load all ordinal mappings
        Map<String, Map<Integer, String>> allMappings = new HashMap<>();
        File[] mapFiles = mapsDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".json"));
        
        if (mapFiles == null || mapFiles.length == 0) {
            println("No mapping files found in: " + mapsDir.getAbsolutePath());
            println("Create files like FOG.DLL.json, STORM.DLL.json, etc.");
            return;
        }
        
        for (File mapFile : mapFiles) {
            String dllName = mapFile.getName().replace(".json", "").toUpperCase();
            Map<Integer, String> mapping = loadMapping(mapFile);
            if (!mapping.isEmpty()) {
                allMappings.put(dllName, mapping);
                println("Loaded " + mapping.size() + " ordinal mappings for " + dllName);
            }
        }
        
        if (allMappings.isEmpty()) {
            println("No valid mappings loaded.");
            return;
        }
        
        // Find and rename ordinal imports
        ExternalManager extMgr = currentProgram.getExternalManager();
        int renamed = 0;
        int skipped = 0;
        
        // Iterate through all external locations
        for (String libName : extMgr.getExternalLibraryNames()) {
            String libUpper = libName.toUpperCase();
            Map<Integer, String> mapping = allMappings.get(libUpper);
            
            if (mapping == null) {
                continue;
            }
            
            ExternalLocationIterator extLocs = extMgr.getExternalLocations(libName);
            while (extLocs.hasNext()) {
                ExternalLocation extLoc = extLocs.next();
                String label = extLoc.getLabel();
                
                // Check if this is an ordinal reference
                if (label != null && label.startsWith("Ordinal_")) {
                    try {
                        int ordinal = Integer.parseInt(label.substring(8));
                        String newName = mapping.get(ordinal);
                        
                        if (newName != null) {
                            // Rename the external location
                            extLoc.setName(extLoc.getParentNameSpace(), newName, SourceType.USER_DEFINED);
                            println("  Renamed " + libName + "::" + label + " -> " + newName);
                            renamed++;
                        } else {
                            skipped++;
                        }
                    } catch (NumberFormatException e) {
                        // Not a valid ordinal number
                    }
                }
            }
        }
        
        println("\nDone! Renamed " + renamed + " ordinal imports, skipped " + skipped + " unmapped.");
    }
    
    /**
     * Load ordinal mapping from a JSON file.
     * Simple parser for {"ordinal": "name", ...} format.
     */
    private Map<Integer, String> loadMapping(File file) {
        Map<Integer, String> mapping = new HashMap<>();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            
            String json = sb.toString().trim();
            // Remove outer braces
            if (json.startsWith("{")) json = json.substring(1);
            if (json.endsWith("}")) json = json.substring(0, json.length() - 1);
            
            // Parse key-value pairs
            String[] pairs = json.split(",");
            for (String pair : pairs) {
                pair = pair.trim();
                if (pair.isEmpty()) continue;
                
                String[] kv = pair.split(":", 2);
                if (kv.length != 2) continue;
                
                // Clean up key and value
                String key = kv[0].trim().replace("\"", "");
                String value = kv[1].trim().replace("\"", "");
                
                try {
                    int ordinal = Integer.parseInt(key);
                    mapping.put(ordinal, value);
                } catch (NumberFormatException e) {
                    // Skip non-numeric keys
                }
            }
        } catch (IOException e) {
            println("Error reading " + file.getName() + ": " + e.getMessage());
        }
        
        return mapping;
    }
}
