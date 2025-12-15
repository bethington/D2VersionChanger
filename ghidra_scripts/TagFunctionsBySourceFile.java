//Tag functions based on source file path strings found in the binary
//@category D2VersionChanger
//@menupath Tools.Tag Functions by Source File
//@keybinding ctrl shift T
//@description Finds strings containing source file paths (*.cpp, *.c, *.h) and tags functions that reference them with the filename

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import java.util.*;
import java.util.regex.*;

/**
 * Tags functions based on source file path strings.
 *
 * Scans all defined strings in the binary looking for file paths like:
 *   "C:\projects\D2\head\Diablo2\Source\D2Common\Waypoint\Waypoint.cpp"
 *
 * Extracts the filename (e.g., "Waypoint.cpp") and tags all functions
 * that reference that string with the filename as a tag.
 *
 * This helps identify which source file a function originated from
 * based on debug/assert strings left in the binary.
 */
public class TagFunctionsBySourceFile extends GhidraScript {

    // Pattern to match file paths ending in source file extensions
    // Matches both forward and back slashes, handles quoted strings
    private static final Pattern PATH_PATTERN = Pattern.compile(
        ".*[/\\\\]([^/\\\\]+\\.(cpp|c|h|hpp|cxx|cc|inl))\"?$",
        Pattern.CASE_INSENSITIVE
    );

    // Statistics
    private int stringsFound = 0;
    private int functionsTagged = 0;
    private int tagsCreated = 0;
    private Map<String, Integer> tagCounts = new TreeMap<>();

    @Override
    public void run() throws Exception {
        println("=".repeat(70));
        println("TAG FUNCTIONS BY SOURCE FILE");
        println("=".repeat(70));
        println("Program: " + currentProgram.getName());
        println("");

        // Phase 1: Find all source file path strings
        println("Phase 1: Scanning for source file path strings...");
        Map<Address, String> sourceFileStrings = findSourceFileStrings();
        println("  Found " + sourceFileStrings.size() + " source file path strings");

        if (sourceFileStrings.isEmpty()) {
            println("\nNo source file path strings found. Nothing to tag.");
            return;
        }

        // Show what we found
        println("\nSource files found:");
        Set<String> uniqueFiles = new TreeSet<>(sourceFileStrings.values());
        for (String file : uniqueFiles) {
            println("  - " + file);
        }

        // Ask for confirmation
        if (!askYesNo("Confirm Tagging",
                "Found " + sourceFileStrings.size() + " source file strings.\n" +
                "This will create tags for " + uniqueFiles.size() + " unique source files.\n\n" +
                "Continue?")) {
            println("\nCancelled by user.");
            return;
        }

        // Phase 2: Tag functions that reference these strings
        println("\nPhase 2: Tagging functions...");
        tagFunctions(sourceFileStrings);

        // Summary
        println("\n" + "=".repeat(70));
        println("TAGGING COMPLETE");
        println("=".repeat(70));
        println("Source file strings found: " + stringsFound);
        println("Functions tagged: " + functionsTagged);
        println("Total tag applications: " + tagsCreated);
        println("\nTags created (by count):");
        for (Map.Entry<String, Integer> entry : tagCounts.entrySet()) {
            println("  " + entry.getKey() + ": " + entry.getValue() + " functions");
        }
    }

    /**
     * Scan all defined strings looking for source file paths.
     * Returns map of string address -> extracted filename
     */
    private Map<Address, String> findSourceFileStrings() throws Exception {
        Map<Address, String> results = new HashMap<>();

        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);

        while (dataIter.hasNext()) {
            if (monitor.isCancelled()) {
                throw new Exception("Cancelled by user");
            }

            Data data = dataIter.next();

            // Check if it's a string
            if (!data.hasStringValue()) {
                continue;
            }

            String value = data.getDefaultValueRepresentation();
            if (value == null || value.length() < 5) {
                continue;
            }

            // Remove surrounding quotes if present
            if (value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1);
            }

            // Check if it matches a source file path pattern
            String filename = extractFilename(value);
            if (filename != null) {
                results.put(data.getAddress(), filename);
                stringsFound++;
            }
        }

        return results;
    }

    /**
     * Extract the filename from a path string.
     * Returns null if not a valid source file path.
     */
    private String extractFilename(String path) {
        if (path == null) {
            return null;
        }

        // Try the regex pattern first
        Matcher matcher = PATH_PATTERN.matcher(path);
        if (matcher.matches()) {
            return matcher.group(1);
        }

        // Fallback: simple check for source file extensions at the end
        String lower = path.toLowerCase();
        if (lower.endsWith(".cpp") || lower.endsWith(".c") ||
            lower.endsWith(".h") || lower.endsWith(".hpp") ||
            lower.endsWith(".cxx") || lower.endsWith(".cc") ||
            lower.endsWith(".inl")) {

            // Extract filename from path
            int lastSlash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
            if (lastSlash >= 0 && lastSlash < path.length() - 1) {
                return path.substring(lastSlash + 1);
            } else if (lastSlash < 0) {
                // No path separator, might just be a filename
                return path;
            }
        }

        return null;
    }

    /**
     * Tag all functions that reference the source file strings.
     */
    private void tagFunctions(Map<Address, String> sourceFileStrings) throws Exception {
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        // Get or create the function tag manager
        FunctionTagManager tagMgr = funcMgr.getFunctionTagManager();

        int processed = 0;
        int total = sourceFileStrings.size();

        for (Map.Entry<Address, String> entry : sourceFileStrings.entrySet()) {
            if (monitor.isCancelled()) {
                throw new Exception("Cancelled by user");
            }

            Address stringAddr = entry.getKey();
            String tagName = entry.getValue();

            processed++;
            if (processed % 100 == 0) {
                monitor.setMessage("Processing: " + processed + "/" + total);
            }

            // Find all references to this string
            ReferenceIterator refIter = refMgr.getReferencesTo(stringAddr);

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();

                // Find the function containing this reference
                Function func = funcMgr.getFunctionContaining(fromAddr);
                if (func == null) {
                    continue;
                }

                // Check if function already has this tag
                boolean hasTag = false;
                for (FunctionTag existingTag : func.getTags()) {
                    if (existingTag.getName().equals(tagName)) {
                        hasTag = true;
                        break;
                    }
                }

                if (!hasTag) {
                    // Create tag if it doesn't exist, then add to function
                    FunctionTag tag = tagMgr.getFunctionTag(tagName);
                    if (tag == null) {
                        tag = tagMgr.createFunctionTag(tagName, "Source file: " + tagName);
                    }

                    func.addTag(tagName);
                    tagsCreated++;
                    tagCounts.merge(tagName, 1, Integer::sum);

                    // Count unique functions
                    functionsTagged++;
                }
            }
        }
    }
}
