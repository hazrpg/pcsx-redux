/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "mcp-server.h"

#include <charconv>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>

#include "third_party/json.hpp"

namespace PCSX {

// Static member initialization
MCPServer::Config MCPServer::config_;
std::unordered_map<uint32_t, MCPServer::Breakpoint> MCPServer::breakpoints_;
std::unordered_map<std::string, MCPServer::Tool> MCPServer::tools_;

// Helper function to parse an address from JSON. Numbers are decimal; strings
// are hexadecimal, with an optional 0x prefix. This matches how the debugger
// and the Ghidra scripts display addresses.
static uint32_t parseAddress(const nlohmann::json& value) {
    if (value.is_number_unsigned()) {
        uint64_t v = value.get<uint64_t>();
        if (v > 0xFFFFFFFFull) throw std::runtime_error("Address out of range");
        return static_cast<uint32_t>(v);
    }
    if (value.is_number_integer()) {
        int64_t v = value.get<int64_t>();
        if (v < 0 || v > 0xFFFFFFFFll) throw std::runtime_error("Address out of range");
        return static_cast<uint32_t>(v);
    }
    if (value.is_number_float()) {
        double v = value.get<double>();
        if (v < 0.0 || v > 4294967295.0) throw std::runtime_error("Address out of range");
        return static_cast<uint32_t>(v);
    }
    if (!value.is_string()) {
        throw std::runtime_error("Address must be an integer or a hexadecimal string");
    }
    std::string str = value.get<std::string>();
    std::string_view sv = str;
    if (sv.size() > 2 && (sv.substr(0, 2) == "0x" || sv.substr(0, 2) == "0X")) {
        sv.remove_prefix(2);
    }
    if (sv.empty()) throw std::runtime_error("Empty address");
    uint32_t address = 0;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), address, 16);
    if (ec != std::errc() || ptr != sv.data() + sv.size()) {
        throw std::runtime_error("Invalid hexadecimal address: '" + str + "'");
    }
    return address;
}

// Helper to get required string parameter with validation
static std::string getRequiredString(const nlohmann::json& args, const std::string& key, const std::string& tool_name) {
    if (!args.contains(key)) {
        throw std::runtime_error("Missing required parameter '" + key + "' for tool '" + tool_name + "'");
    }
    if (!args.at(key).is_string()) {
        throw std::runtime_error("Parameter '" + key + "' must be a string for tool '" + tool_name + "'");
    }
    return args.at(key).get<std::string>();
}

// Helper to get required address parameter with validation
static uint32_t getRequiredAddress(const nlohmann::json& args, const std::string& key, const std::string& tool_name) {
    if (!args.contains(key)) {
        throw std::runtime_error("Missing required parameter '" + key + "' for tool '" + tool_name +
                                 "'. Provide as hex string (\"0x80010000\") or decimal number (2147549184)");
    }
    return parseAddress(args.at(key));
}

// Helper to get required number parameter with validation
static uint32_t getRequiredNumber(const nlohmann::json& args, const std::string& key, const std::string& tool_name) {
    if (!args.contains(key)) {
        throw std::runtime_error("Missing required parameter '" + key + "' for tool '" + tool_name + "'");
    }
    if (!args.at(key).is_number()) {
        throw std::runtime_error("Parameter '" + key + "' must be a number for tool '" + tool_name + "'");
    }
    return args.at(key).get<uint32_t>();
}

void MCPServer::RegisterToolsIfNeeded() {
    if (!tools_.empty()) return;

    const char* ADDR =
        R"({"type":["string","integer"],"description":"Guest address: hex string (0x80010000) or decimal integer"})";
    const char* LEN = R"({"type":"integer","minimum":1,"maximum":8388608,"description":"Number of bytes"})";
    const char* REGION = R"({"type":"string","enum":["ram","bios"],"description":"Memory region to read"})";
    const char* PATH = R"({"type":"string","description":"Host filesystem path"})";
    const char* OUTDIR = R"({"type":"string","description":"Directory under the configured MCP dump root"})";
    const char* TAG = R"({"type":"string","description":"Label used in the output filename"})";
    const char* REG = R"({"type":"string","description":"Hardware register name"})";
    const char* DEPTH = R"({"type":"integer","minimum":1,"maximum":64})";

    auto prop = [](const char* json) { return nlohmann::json::parse(json); };
    auto schema = [](nlohmann::json properties, nlohmann::json required = nlohmann::json::array()) {
        nlohmann::json s;
        s["type"] = "object";
        s["properties"] = std::move(properties);
        if (!required.empty()) s["required"] = std::move(required);
        return s.dump();
    };

    tools_["get_cpu_state"] = {"get_cpu_state", "Get current CPU state", schema({})};
    tools_["get_memory_map"] = {"get_memory_map", "Get the PSX memory map", schema({})};
    tools_["get_memory_range"] = {"get_memory_range", "Read a range of guest memory",
                                  schema({{"address", prop(ADDR)}, {"length", prop(LEN)}}, {"address", "length"})};
    tools_["hexdump"] = {"hexdump", "Hex dump of a memory region",
                         schema({{"address", prop(ADDR)}, {"length", prop(LEN)}}, {"address", "length"})};
    tools_["find_string"] = {
        "find_string", "Search for a string in a memory region",
        schema({{"pattern", prop(R"({"type":"string"})")}, {"region", prop(REGION)}}, {"pattern"})};
    tools_["search_bytes"] = {"search_bytes", "Search for a hexadecimal byte pattern in a memory region",
                              schema({{"pattern", prop(R"({"type":"string","description":"Hex bytes, e.g. 0a1b2c"})")},
                                      {"region", prop(REGION)}},
                                     {"pattern"})};
    tools_["get_gpu_state"] = {"get_gpu_state", "Get the GPU status register and parsed display mode", schema({})};
    tools_["list_hardware_registers"] = {"list_hardware_registers", "List known hardware register names", schema({})};
    tools_["read_hardware_register"] = {"read_hardware_register", "Read a hardware register",
                                        schema({{"register", prop(REG)}}, {"register"})};
    tools_["write_hardware_register"] = {
        "write_hardware_register", "Write a hardware register",
        schema({{"register", prop(REG)}, {"value", prop(R"({"type":["string","integer"]})")}}, {"register", "value"})};
    tools_["get_dma_state"] = {
        "get_dma_state", "Get a DMA channel's registers",
        schema({{"channel", prop(R"({"type":"integer","minimum":0,"maximum":6})")}}, {"channel"})};
    tools_["set_breakpoint"] = {"set_breakpoint", "Set an execution breakpoint",
                                schema({{"address", prop(ADDR)}}, {"address"})};
    tools_["get_breakpoints"] = {"get_breakpoints", "List active breakpoints", schema({})};
    tools_["clear_breakpoint"] = {"clear_breakpoint", "Clear an execution breakpoint",
                                  schema({{"address", prop(ADDR)}}, {"address"})};
    tools_["get_call_chain"] = {"get_call_chain", "Trace the call chain from the current instruction",
                                schema({{"max_depth", prop(DEPTH)}})};
    tools_["get_call_graph"] = {
        "get_call_graph", "Get the callers and callees of a function",
        schema({{"function", prop(R"({"type":"string","description":"Function name or 0x address"})")},
                {"depth", prop(DEPTH)}},
               {"function"})};
    tools_["get_emulator_state"] = {"get_emulator_state", "Get a comprehensive emulator snapshot", schema({})};
    tools_["is_game_loaded"] = {"is_game_loaded", "Check whether a game is loaded and running", schema({})};

    tools_["pause"] = {"pause", "Pause emulator execution", schema({})};
    tools_["resume"] = {"resume", "Resume emulator execution", schema({})};
    tools_["step_in"] = {"step_in", "Step into the next instruction", schema({})};
    tools_["step_over"] = {"step_over", "Step over the next instruction", schema({})};
    tools_["step_out"] = {"step_out", "Step out of the current function", schema({})};
    tools_["run_to_address"] = {"run_to_address", "Run until the given address is reached",
                                schema({{"address", prop(ADDR)}}, {"address"})};
    tools_["get_execution_state"] = {"get_execution_state", "Get the running/paused state", schema({})};
    tools_["how_to_use_mcp"] = {"how_to_use_mcp", "Get an AI-friendly usage guide", schema({})};

    tools_["dump_memory"] = {
        "dump_memory", "Dump a memory region to a .bin file and a .json manifest",
        schema({{"address", prop(ADDR)}, {"length", prop(LEN)}, {"tag", prop(TAG)}, {"output_dir", prop(OUTDIR)}},
               {"address", "length", "tag", "output_dir"})};
    tools_["snapshot_ram"] = {"snapshot_ram", "Dump the full 2 MB of main RAM",
                              schema({{"tag", prop(TAG)}, {"output_dir", prop(OUTDIR)}}, {"tag", "output_dir"})};
    tools_["vram_dump"] = {"vram_dump", "Write raw 16-bit VRAM to a file", schema({{"path", prop(PATH)}}, {"path"})};
    tools_["screenshot"] = {"screenshot", "Write the current framebuffer as a binary PPM",
                            schema({{"path", prop(PATH)}}, {"path"})};
    tools_["write_memory"] = {"write_memory", "Write 8, 16 or 32 bits to guest memory",
                              schema({{"address", prop(ADDR)},
                                      {"value", prop(R"({"type":"integer"})")},
                                      {"size", prop(R"({"type":"integer","enum":[8,16,32],"default":32})")}},
                                     {"address", "value"})};
    tools_["save_state"] = {"save_state", "Serialize the emulator state to a file",
                            schema({{"path", prop(PATH)}}, {"path"})};
    tools_["load_state"] = {"load_state", "Load a serialized emulator state from a file",
                            schema({{"path", prop(PATH)}}, {"path"})};
}

std::vector<MCPServer::Tool> MCPServer::ListTools() {
    RegisterToolsIfNeeded();
    std::vector<Tool> tool_list;
    for (const auto& pair : tools_) {
        tool_list.push_back(pair.second);
    }
    return tool_list;
}

MCPServer::ToolResult MCPServer::ExecuteTool(const std::string& tool_name, const std::string& arguments_json) {
    RegisterToolsIfNeeded();
    try {
        nlohmann::json args = nlohmann::json::parse(arguments_json);

        if (tool_name == "get_cpu_state") {
            return ToolGetCPUState();
        } else if (tool_name == "get_memory_map") {
            return ToolGetMemoryMap();
        } else if (tool_name == "get_memory_range") {
            uint32_t address = getRequiredAddress(args, "address", tool_name);
            uint32_t length = getRequiredAddress(args, "length", tool_name);
            return ToolGetMemoryRange(address, length);
        } else if (tool_name == "hexdump") {
            uint32_t address = getRequiredAddress(args, "address", tool_name);
            uint32_t length = args.value("length", 256);
            return ToolHexdump(address, length);
        } else if (tool_name == "find_string") {
            std::string pattern = getRequiredString(args, "pattern", tool_name);
            std::string region = args.value("region", "ram");
            return ToolFindString(pattern, region);
        } else if (tool_name == "search_bytes") {
            std::string pattern = getRequiredString(args, "pattern", tool_name);
            std::string region = args.value("region", "ram");
            return ToolSearchBytes(pattern, region);
        } else if (tool_name == "get_gpu_state") {
            return ToolGetGPUState();
        } else if (tool_name == "list_hardware_registers") {
            return ToolListHardwareRegisters();
        } else if (tool_name == "read_hardware_register") {
            std::string reg_name = getRequiredString(args, "register", tool_name);
            return ToolReadHardwareRegister(reg_name);
        } else if (tool_name == "write_hardware_register") {
            std::string reg_name = getRequiredString(args, "register", tool_name);
            uint32_t value = getRequiredAddress(args, "value", tool_name);
            return ToolWriteHardwareRegister(reg_name, value);
        } else if (tool_name == "get_dma_state") {
            uint32_t channel = getRequiredNumber(args, "channel", tool_name);
            return ToolGetDMAState(channel);
        } else if (tool_name == "set_breakpoint") {
            uint32_t address = getRequiredAddress(args, "address", tool_name);
            return ToolSetBreakpoint(address);
        } else if (tool_name == "get_breakpoints") {
            return ToolGetBreakpoints();
        } else if (tool_name == "clear_breakpoint") {
            uint32_t address = getRequiredAddress(args, "address", tool_name);
            return ToolClearBreakpoint(address);
        } else if (tool_name == "get_call_chain") {
            uint32_t max_depth = args.value("max_depth", 10);
            return ToolGetCallChain(max_depth);
        } else if (tool_name == "get_call_graph") {
            std::string function_name = getRequiredString(args, "function", tool_name);
            uint32_t depth = args.value("depth", 3);
            return ToolGetCallGraph(function_name, depth);
        } else if (tool_name == "get_emulator_state") {
            return ToolGetEmulatorState();
        } else if (tool_name == "is_game_loaded") {
            return ToolIsGameLoaded();
        } else if (tool_name == "pause") {
            return ToolPause();
        } else if (tool_name == "resume") {
            return ToolResume();
        } else if (tool_name == "step_in") {
            return ToolStepIn();
        } else if (tool_name == "step_over") {
            return ToolStepOver();
        } else if (tool_name == "step_out") {
            return ToolStepOut();
        } else if (tool_name == "run_to_address") {
            uint32_t address = getRequiredAddress(args, "address", tool_name);
            return ToolRunToAddress(address);
        } else if (tool_name == "get_execution_state") {
            return ToolGetExecutionState();
        } else if (tool_name == "how_to_use_mcp") {
            return ToolHowToUseMCP();
        } else if (tool_name == "dump_memory") {
            uint32_t address = getRequiredAddress(args, "address", tool_name);
            uint32_t length = getRequiredNumber(args, "length", tool_name);
            std::string tag = getRequiredString(args, "tag", tool_name);
            std::string output_dir = getRequiredString(args, "output_dir", tool_name);
            return ToolDumpMemory(address, length, tag, output_dir);
        } else if (tool_name == "snapshot_ram") {
            std::string tag = getRequiredString(args, "tag", tool_name);
            std::string output_dir = getRequiredString(args, "output_dir", tool_name);
            return ToolSnapshotRAM(tag, output_dir);
        } else if (tool_name == "vram_dump") {
            return ToolVRAMDump(getRequiredString(args, "path", tool_name));
        } else if (tool_name == "screenshot") {
            return ToolScreenshot(getRequiredString(args, "path", tool_name));
        } else if (tool_name == "write_memory") {
            uint32_t address = getRequiredAddress(args, "address", tool_name);
            uint32_t value = getRequiredNumber(args, "value", tool_name);
            uint32_t size = args.value("size", 32);
            return ToolWriteMemory(address, value, size);
        } else if (tool_name == "save_state") {
            return ToolSaveState(getRequiredString(args, "path", tool_name));
        } else if (tool_name == "load_state") {
            return ToolLoadState(getRequiredString(args, "path", tool_name));
        } else {
            return {false, "", "Unknown tool: " + tool_name};
        }
    } catch (const nlohmann::json::exception& e) {
        return {false, "", "JSON parse error for tool " + tool_name + ": " + e.what()};
    } catch (const std::exception& e) {
        return {false, "", "Error executing tool " + tool_name + ": " + e.what()};
    }
}

// Global emulator instance (needs to be set by the main emulator loop)
std::string MCPServer::HandleMCPRequest(const std::string& request_str) {
    // This runs on the emulator's libuv thread. Tool implementations must not
    // block or touch state from another thread.
    nlohmann::json request_json;
    try {
        request_json = nlohmann::json::parse(request_str);
    } catch (const nlohmann::json::exception& e) {
        nlohmann::json error = {{"jsonrpc", "2.0"},
                                {"id", nullptr},
                                {"error", {{"code", -32700}, {"message", "Parse error: " + std::string(e.what())}}}};
        return error.dump();
    }

    if (!request_json.is_object() || !request_json.contains("method") || !request_json["method"].is_string()) {
        nlohmann::json error = {
            {"jsonrpc", "2.0"}, {"id", nullptr}, {"error", {{"code", -32600}, {"message", "Invalid Request"}}}};
        return error.dump();
    }

    const std::string method = request_json["method"].get<std::string>();
    const nlohmann::json params = request_json.value("params", nlohmann::json::object());
    const bool isNotification = !request_json.contains("id");

    // JSON-RPC notifications never receive a response.
    if (isNotification && method.rfind("notifications/", 0) == 0) {
        return "";
    }

    nlohmann::json response;
    response["jsonrpc"] = "2.0";
    if (!isNotification) response["id"] = request_json["id"];

    try {
        if (method == "initialize") {
            static const std::set<std::string> supported = {"2024-11-05", "2025-03-26", "2025-06-18"};
            const std::string clientVersion = params.value("protocolVersion", "");
            const std::string version = supported.count(clientVersion) ? clientVersion : "2025-06-18";
            response["result"] = {
                {"protocolVersion", version},
                {"capabilities", {{"tools", {{"listChanged", false}}}}},
                {"serverInfo", {{"name", "PCSX-Redux MCP Server"}, {"version", "1.0.0"}}},
                {"instructions",
                 "Real-time access to the PCSX-Redux emulator: CPU, memory, breakpoints, execution control, GPU "
                 "status and memory dumps for reverse engineering."}};
        } else if (method == "ping") {
            response["result"] = nlohmann::json::object();
        } else if (method == "tools/list") {
            nlohmann::json tools_array = nlohmann::json::array();
            for (const auto& tool : ListTools()) {
                nlohmann::json inputSchema = nlohmann::json::parse(tool.schema.empty() ? "{}" : tool.schema);
                tools_array.push_back(
                    {{"name", tool.name}, {"description", tool.description}, {"inputSchema", inputSchema}});
            }
            response["result"] = {{"tools", tools_array}};
        } else if (method == "tools/call") {
            const std::string tool_name = params.at("name").get<std::string>();
            const nlohmann::json args_json = params.value("arguments", nlohmann::json::object());

            bool readOnly = false;
            if (g_emulator) {
                const auto& settings = g_emulator->settings.get<Emulator::SettingDebugSettings>();
                readOnly = settings.get<Emulator::DebugSettings::MCPServerReadOnly>();
            }
            if (readOnly && IsMutatingTool(tool_name)) {
                response["result"] = {
                    {"content",
                     nlohmann::json::array(
                         {{{"type", "text"}, {"text", "Tool '" + tool_name + "' is disabled in read-only mode."}}})},
                    {"isError", true}};
            } else {
                const ToolResult result = ExecuteTool(tool_name, args_json.dump());
                if (result.success) {
                    response["result"] = {
                        {"content", nlohmann::json::array({{{"type", "text"}, {"text", result.content}}})}};
                } else {
                    response["result"] = {
                        {"content", nlohmann::json::array({{{"type", "text"}, {"text", result.error}}})},
                        {"isError", true}};
                }
            }
        } else {
            response["error"] = {{"code", -32601}, {"message", "Method not found"}};
        }
    } catch (const nlohmann::json::exception& e) {
        response["error"] = {{"code", -32602}, {"message", "Invalid params: " + std::string(e.what())}};
    } catch (const std::exception& e) {
        response["error"] = {{"code", -32603}, {"message", "Internal error: " + std::string(e.what())}};
    }

    if (isNotification) return "";
    return response.dump();
}

bool MCPServer::IsMutatingTool(const std::string& tool_name) {
    static const std::set<std::string> mutating = {"write_memory",   "write_hardware_register",
                                                   "save_state",     "load_state",
                                                   "pause",          "resume",
                                                   "step_in",        "step_over",
                                                   "step_out",       "run_to_address",
                                                   "set_breakpoint", "clear_breakpoint",
                                                   "vram_dump",      "screenshot",
                                                   "dump_memory",    "snapshot_ram"};
    return mutating.count(tool_name) != 0;
}

}  // namespace PCSX
