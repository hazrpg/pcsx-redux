// Import a Redux MCP memory dump manifest (.json) and its companion binary (.bin) as an overlay block
//@author PCSX-Redux MCP
//@category Import

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ReduxOverlayImporter extends GhidraScript {

    @Override
    protected void run() throws Exception {
        File manifestFile = askFile("Select Redux Dump Manifest", "Choose a .json manifest file:");
        if (manifestFile == null || !manifestFile.exists()) {
            println("No manifest selected.");
            return;
        }

        String json = new String(Files.readAllBytes(manifestFile.toPath()), "UTF-8");

        String baseAddressStr = extractJsonString(json, "base_address");
        String filename       = extractJsonString(json, "filename");
        String tag            = extractJsonString(json, "tag");
        int    size           = extractJsonInt(json, "size");

        if (baseAddressStr == null || filename == null || size <= 0) {
            println("Manifest missing required fields (base_address, filename, size).");
            return;
        }

        long baseAddr = Long.parseLong(baseAddressStr.replace("0x", "").replace("0X", ""), 16);
        Address startAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(baseAddr);

        Path binPath = Paths.get(manifestFile.getParent(), filename);
        if (!Files.exists(binPath)) {
            println("Binary file not found: " + binPath.toString());
            return;
        }

        Memory memory = currentProgram.getMemory();

        String blockName = (tag != null && !tag.isEmpty()) ? sanitizeBlockName(tag) : "redux_overlay";
        blockName = ensureUniqueBlockName(memory, blockName);

        FileInputStream fis = new FileInputStream(binPath.toFile());
        MemoryBlock block = memory.createInitializedBlock(
            blockName,
            startAddr,
            fis,
            size,
            monitor,
            true   // overlay flag
        );
        fis.close();

        block.setRead(true);
        block.setWrite(true);
        block.setExecute(true);

        println(String.format("Imported '%s' as overlay block '%s' at %s (size=%d)",
            filename, blockName, startAddr.toString(), size));
    }

    private String extractJsonString(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start == -1) return null;
        start += search.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return null;
        return json.substring(start, end);
    }

    private int extractJsonInt(String json, String key) {
        String search = "\"" + key + "\":";
        int start = json.indexOf(search);
        if (start == -1) return -1;
        start += search.length();
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) end++;
        try {
            return Integer.parseInt(json.substring(start, end));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private String sanitizeBlockName(String tag) {
        return tag.replaceAll("[^a-zA-Z0-9_.-]", "_");
    }

    private String ensureUniqueBlockName(Memory memory, String name) {
        String candidate = name;
        int counter = 1;
        while (memory.getBlock(candidate) != null) {
            candidate = name + "_" + counter;
            counter++;
        }
        return candidate;
    }
}
