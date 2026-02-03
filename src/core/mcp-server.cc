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

#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <stdexcept>
#include <chrono>

// For TCP sockets
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// Include nlohmann/json for JSON parsing and serialization
#include "third_party/json.hpp"

namespace PCSX {

// Static member initialization
std::atomic<bool> MCPServer::running_ = false;
std::atomic<bool> MCPServer::server_running_ = false;
std::thread MCPServer::server_thread_;
std::mutex MCPServer::server_mutex_;
MCPServer::Config MCPServer::config_;
std::unordered_map<uint32_t, MCPServer::Breakpoint> MCPServer::breakpoints_;
std::unordered_map<std::string, MCPServer::Tool> MCPServer::tools_;

// Helper function to send data over socket
static void SendData(int socket, const std::string& data) {
    // Add length prefix to the data (4 bytes, network byte order)
    uint32_t length = data.length();
    uint32_t net_length = htonl(length);
    send(socket, (char*)&net_length, sizeof(net_length), 0);
    send(socket, data.c_str(), length, 0);
}

// Helper function to receive data from socket
static std::string ReceiveData(int socket) {
    // Receive length prefix
    uint32_t net_length;
    int bytes_received = recv(socket, (char*)&net_length, sizeof(net_length), 0);
    if (bytes_received <= 0) {
        return ""; // Error or connection closed
    }
    uint32_t length = ntohl(net_length);

    std::string data(length, '\0');
    bytes_received = recv(socket, (char*)data.c_str(), length, 0);
    if (bytes_received <= 0) {
        return ""; // Error or connection closed
    }
    return data;
}


static void ClientHandler(int client_socket) {
    while (MCPServer::server_running_) {
        std::string request_str = ReceiveData(client_socket);
        if (request_str.empty()) {
            break; // Client disconnected or error
        }

        std::string response_str = MCPServer::HandleMCPRequest(request_str);
        SendData(client_socket, response_str);
    }
#ifdef _WIN32
    closesocket(client_socket);
#else
    close(client_socket);
#endif
}

static void ServerLoop() {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        std::cerr << "WSAStartup failed.\n";
        MCPServer::server_running_ = false;
        return;
    }
#endif

    int server_fd = -1;
    try {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == -1) {
            throw std::runtime_error("Failed to create socket");
        }

        // Allow immediate reuse of the port
        int optval = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

        sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = inet_addr(MCPServer::config_.host.c_str());
        address.sin_port = htons(MCPServer::config_.port);

        if (bind(server_fd, (sockaddr*)&address, sizeof(address)) < 0) {
            throw std::runtime_error("Failed to bind socket");
        }

        if (listen(server_fd, 5) < 0) {
            throw std::runtime_error("Failed to listen on socket");
        }

        std::cout << "MCP Server listening on " << MCPServer::config_.host << ":" << MCPServer::config_.port << std::endl;
        MCPServer::server_running_ = true;

        while (MCPServer::server_running_) {
            sockaddr_in client_address;
            socklen_t client_len = sizeof(client_address);
#ifdef _WIN32
            int client_socket = accept(server_fd, (sockaddr*)&client_address, &client_len);
#else
            int client_socket = accept(server_fd, (sockaddr*)&client_address, &client_len);
#endif
            if (client_socket < 0) {
                if (!MCPServer::server_running_) {
                    break; // Server stopped
                }
                std::cerr << "Failed to accept client connection\n";
                continue;
            }

            std::thread(ClientHandler, client_socket).detach();
        }

    } catch (const std::exception& e) {
        std::cerr << "MCP Server error: " << e.what() << std::endl;
    }

    if (server_fd != -1) {
#ifdef _WIN32
        closesocket(server_fd);
        WSACleanup();
#else
        close(server_fd);
#endif
    }
    MCPServer::server_running_ = false;
    MCPServer::running_ = false;
    std::cout << "MCP Server stopped." << std::endl;
}

bool MCPServer::Initialize(const Config& config) {
    if (running_) {
        std::cerr << "MCP Server already initialized.\n";
        return false;
    }
    config_ = config;
    running_ = true;

    // Register tools
    tools_["get_cpu_state"] = {"get_cpu_state", "Get current CPU state"};
    tools_["get_memory_map"] = {"get_memory_map", "Get the PSX memory map"};
    tools_["get_memory_range"] = {"get_memory_range", "Get a range of memory (address, length)"};
    tools_["hexdump"] = {"hexdump", "Get a hex dump of memory region"};
    tools_["find_string"] = {"find_string", "Search for strings in memory"};
    tools_["search_bytes"] = {"search_bytes", "Search for byte patterns in memory"};
    tools_["get_gpu_state"] = {"get_gpu_state", "Get current GPU state"};
    tools_["list_gpu_commands"] = {"list_gpu_commands", "List current GPU command queue"};
    tools_["list_hardware_registers"] = {"list_hardware_registers", "List all available hardware registers"};
    tools_["read_hardware_register"] = {"read_hardware_register", "Read a specific hardware register value"};
    tools_["write_hardware_register"] = {"write_hardware_register", "Write a value to a hardware register"};
    tools_["get_dma_state"] = {"get_dma_state", "Get current DMA channel states"};
    tools_["set_breakpoint"] = {"set_breakpoint", "Set a breakpoint at the given address"};
    tools_["get_breakpoints"] = {"get_breakpoints", "List all active breakpoints"};
    tools_["clear_breakpoint"] = {"clear_breakpoint", "Clear a breakpoint at the given address"};
    tools_["get_call_chain"] = {"get_call_chain", "Trace the call chain from the current instruction"};
    tools_["get_call_graph"] = {"get_call_graph", "Get function call graph for a specific function"};
    tools_["get_emulator_state"] = {"get_emulator_state", "Get comprehensive emulator state"};

    return true;
}

bool MCPServer::Start() {
    if (!running_ || server_running_) {
        std::cerr << "MCP Server not initialized or already running.\n";
        return false;
    }

    // Launch server thread
    server_thread_ = std::thread(ServerLoop);
    server_thread_.detach(); // Detach to run in background

    // Wait a bit for the server to start up
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return server_running_;
}

void MCPServer::Stop() {
    if (!running_) {
        return;
    }
    server_running_ = false; // Signal server to stop
    running_ = false;

    // TODO: Gracefully close the server socket to unblock accept()
    // For now, accept() might block until timeout or another connection.
    // A simple way is to connect to itself to unblock it.
    
    // std::cout << "Stopping MCP Server...\n";
    // if (server_thread_.joinable()) {
    //     server_thread_.join();
    // }
}

bool MCPServer::IsRunning() {
    return server_running_;
}

std::vector<MCPServer::Tool> MCPServer::ListTools() {
    std::vector<Tool> tool_list;
    for (const auto& pair : tools_) {
        tool_list.push_back(pair.second);
    }
    return tool_list;
}

MCPServer::ToolResult MCPServer::ExecuteTool(const std::string& tool_name, const std::string& arguments_json) {
    try {
        nlohmann::json args = nlohmann::json::parse(arguments_json);

        if (tool_name == "get_cpu_state") {
            return ToolGetCPUState();
        } else if (tool_name == "get_memory_map") {
            return ToolGetMemoryMap();
        } else if (tool_name == "get_memory_range") {
            uint32_t address = args.at("address").get<uint32_t>();
            uint32_t length = args.at("length").get<uint32_t>();
            return ToolGetMemoryRange(address, length);
        } else if (tool_name == "hexdump") {
            uint32_t address = args.at("address").get<uint32_t>();
            uint32_t length = args.value("length", 256);
            return ToolHexdump(address, length);
        } else if (tool_name == "find_string") {
            std::string pattern = args.at("pattern").get<std::string>();
            std::string region = args.value("region", "ram");
            return ToolFindString(pattern, region);
        } else if (tool_name == "search_bytes") {
            std::string pattern = args.at("pattern").get<std::string>();
            std::string region = args.value("region", "ram");
            return ToolSearchBytes(pattern, region);
        } else if (tool_name == "get_gpu_state") {
            return ToolGetGPUState();
        } else if (tool_name == "list_gpu_commands") {
            uint32_t limit = args.value("limit", 20);
            return ToolListGPUCommands(limit);
        } else if (tool_name == "list_hardware_registers") {
            return ToolListHardwareRegisters();
        } else if (tool_name == "read_hardware_register") {
            std::string reg_name = args.at("register").get<std::string>();
            return ToolReadHardwareRegister(reg_name);
        } else if (tool_name == "write_hardware_register") {
            std::string reg_name = args.at("register").get<std::string>();
            uint32_t value = args.at("value").get<uint32_t>();
            return ToolWriteHardwareRegister(reg_name, value);
        } else if (tool_name == "get_dma_state") {
            uint32_t channel = args.at("channel").get<uint32_t>();
            return ToolGetDMAState(channel);
        } else if (tool_name == "set_breakpoint") {
            uint32_t address = args.at("address").get<uint32_t>();
            return ToolSetBreakpoint(address);
        } else if (tool_name == "get_breakpoints") {
            return ToolGetBreakpoints();
        } else if (tool_name == "clear_breakpoint") {
            uint32_t address = args.at("address").get<uint32_t>();
            return ToolClearBreakpoint(address);
        } else if (tool_name == "get_call_chain") {
            uint32_t max_depth = args.value("max_depth", 10);
            return ToolGetCallChain(max_depth);
        } else if (tool_name == "get_call_graph") {
            std::string function_name = args.at("function").get<std::string>();
            uint32_t depth = args.value("depth", 3);
            return ToolGetCallGraph(function_name, depth);
        } else if (tool_name == "get_emulator_state") {
            return ToolGetEmulatorState();
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
extern PCSX::Emulator* g_emulator;

MCPServer::CPUState MCPServer::GetCPUState() {
    CPUState state = {};
    if (g_emulator && g_emulator->m_cpu) {
        state.pc = g_emulator->m_cpu->m_regs.pc;
        state.sp = g_emulator->m_cpu->m_regs.GPR.r[29]; // SP is R29
        state.gp = g_emulator->m_cpu->m_regs.GPR.r[28]; // GP is R28
        state.fp = g_emulator->m_cpu->m_regs.GPR.r[30]; // FP is R30 (or S8)
        state.ra = g_emulator->m_cpu->m_regs.GPR.r[31]; // RA is R31
        state.s0 = g_emulator->m_cpu->m_regs.GPR.r[16];
        state.s1 = g_emulator->m_cpu->m_regs.GPR.r[17];
        state.s2 = g_emulator->m_cpu->m_regs.GPR.r[18];

        state.instruction = g_emulator->m_cpu->m_regs.code;
        // Mock instruction decoding for now
        state.instruction_hex = "0x" + std::to_string(state.instruction);
        state.instruction_decoded = "MOCK_INSTRUCTION"; // TODO: Implement actual MIPS decoding
        state.breakdown = {0, 0, "", ""}; // TODO: Implement actual MIPS decoding
    }
    return state;
}

MCPServer::MemoryState MCPServer::GetMemoryState() {
    MemoryState state = {};
    // Mock memory regions for now
    state.regions["ram"] = {MemoryRegion::Type::RAM, 0x00100000, 0x001FFFFF, "1 MB"};
    state.regions["vram"] = {MemoryRegion::Type::VRAM, 0x1F800000, 0x1F9FFFFF, "2 MB"};
    state.regions["rom"] = {MemoryRegion::Type::ROM, 0x80000000, 0x803FFFFF, "4 MB"};
    state.regions["hardware"] = {MemoryRegion::Type::HW, 0x1F000000, 0x1F0000FF, "256 B"};

    // TODO: Populate actual memory contents if needed, e.g., for hexdump tools
    // This will be large, consider only fetching on demand or by range
    return state;
}

MCPServer::GPUState MCPServer::GetGPUState() {
    GPUState state = {};
    if (g_emulator && g_emulator->m_gpu) {
        // Mock values for now, as direct access to GPU state might be more complex
        state.gpu_read = 0; //g_emulator->m_gpu->GPUREAD;
        state.gpu_reg = 0; //g_emulator->m_gpu->GPUREG;
        state.gp1 = 0; //g_emulator->m_gpu->GP1;
        state.status = 0; //g_emulator->m_gpu->STATUS;
        state.dirty_flag = false; //g_emulator->m_gpu->dirty_flag;

        state.display_mode = {0, 0, 0, 0}; // TODO: Get actual display mode
    }
    return state;
}

MCPServer::HardwareState MCPServer::GetHardwareState() {
    HardwareState state = {};
    if (g_emulator && g_emulator->m_gpu && g_emulator->m_counters /* && g_emulator->m_hw for DMA */) { // m_hw for DMA
        // GPU
        state.gpu = {0,0,0,0}; // TODO: Populate with actual GPU register values

        // DMA
        for (int i = 0; i < 8; ++i) {
            // Mock DMA state for now
            state.dma[i] = {0, 0, false, 0, 0};
        }

        // Counters
        for (int i = 0; i < 4; ++i) {
            // Mock counter state for now
            state.counter[i] = {0, 0, false};
        }
    }
    return state;
}

std::vector<MCPServer::Breakpoint> MCPServer::GetBreakpoints() {
    std::vector<Breakpoint> list;
    for (const auto& pair : breakpoints_) {
        list.push_back(pair.second);
    }
    return list;
}

bool MCPServer::SetBreakpoint(uint32_t address, const std::string& condition) {
    // TODO: Integrate with PCSX-Redux's actual breakpoint mechanism
    // For now, just store them internally
    breakpoints_[address] = {address, condition, false, true};
    std::cout << "Set breakpoint at 0x" << std::hex << address << std::dec << " with condition: " << condition << std::endl;
    return true;
}

bool MCPServer::ClearBreakpoint(uint32_t address) {
    // TODO: Integrate with PCSX-Redux's actual breakpoint mechanism
    if (breakpoints_.count(address)) {
        breakpoints_.erase(address);
        std::cout << "Cleared breakpoint at 0x" << std::hex << address << std::dec << std::endl;
        return true;
    }
    return false;
}

std::vector<std::string> MCPServer::ListHardwareRegisters() {
    // TODO: Populate with actual hardware register names from PCSX-Redux
    return {"GPUREAD", "GPUREG", "GP1", "STATUS", "DMA0_CR", "DMA1_CR", "TIMER0_COUNT"};
}

uint32_t MCPServer::ReadHardwareRegister(const std::string& register_name) {
    // TODO: Implement actual hardware register read logic
    // This will depend on how PCSX-Redux exposes its hardware registers
    std::cout << "Reading hardware register: " << register_name << std::endl;
    return 0xDEADBEEF; // Mock value
}

bool MCPServer::WriteHardwareRegister(const std::string& register_name, uint32_t value) {
    // TODO: Implement actual hardware register write logic
    std::cout << "Writing 0x" << std::hex << value << std::dec << " to hardware register: " << register_name << std::endl;
    return true; // Mock success
}

MCPServer::HardwareState::DMAChannel MCPServer::GetDMAState(uint32_t channel) {
    // TODO: Implement actual DMA state retrieval
    if (channel >= 0 && channel < 8) {
        return {0, 0, false, 0, 0}; // Mock value
    }
    return {};
}

std::vector<std::string> MCPServer::GetCallChain(uint32_t max_depth) {
    // TODO: Implement call chain tracing using PCSX-Redux's internal callstack or debugger
    std::vector<std::string> chain;
    chain.push_back("0x80010000 - main (mock)");
    chain.push_back("0x80010100 - game_loop (mock)");
    return chain;
}

std::vector<std::string> MCPServer::GetCallGraph(const std::string& function_name, uint32_t depth) {
    // TODO: Implement call graph analysis. This is complex and might involve
    // static analysis of the emulated binary or dynamic analysis during execution.
    std::vector<std::string> graph;
    graph.push_back(function_name + " callers: [mock_caller_1, mock_caller_2]");
    graph.push_back(function_name + " callees: [mock_callee_1, mock_callee_2]");
    return graph;
}

std::string MCPServer::GetEmulatorState() {
    // This will return a JSON string of the entire emulator state
    nlohmann::json state_json;
    state_json["cpu_state"] = nlohmann::json::parse(SerializeState(GetCPUState()));
    state_json["memory_map"] = nlohmann::json::parse(SerializeState(GetMemoryState()));
    state_json["gpu_state"] = nlohmann::json::parse(SerializeState(GetGPUState()));
    state_json["hardware_state"] = nlohmann::json::parse(SerializeState(GetHardwareState()));
    state_json["breakpoints"] = nlohmann::json::array();
    for (const auto& bp : breakpoints_) {
        state_json["breakpoints"].push_back({
            {"address", bp.second.address},
            {"condition", bp.second.condition},
            {"hit", bp.second.hit},
            {"enabled", bp.second.enabled}
        });
    }
    return state_json.dump(2);
}

std::string MCPServer::HandleMCPRequest(const std::string& request_str) {
    nlohmann::json request_json;
    nlohmann::json response_json;

    try {
        request_json = nlohmann::json::parse(request_str);
        std::string method = request_json.at("method").get<std::string>();
        nlohmann::json params = request_json.value("params", nlohmann::json::object());

        response_json["jsonrpc"] = "2.0";
        response_json["id"] = request_json.value("id", nullptr);

        if (method == "mcp_list_tools") {
            nlohmann::json tools_array = nlohmann::json::array();
            for (const auto& tool : ListTools()) {
                tools_array.push_back({
                    {"name", tool.name},
                    {"description", tool.description}
                });
            }
            response_json["result"] = tools_array;
        } else if (method == "mcp_call_tool") {
            std::string tool_name = params.at("name").get<std::string>();
            nlohmann::json args_json = params.at("arguments");
            ToolResult result = ExecuteTool(tool_name, args_json.dump());
            if (result.success) {
                response_json["result"] = nlohmann::json::parse(result.content);
            } else {
                response_json["error"] = {
                    {"code", -32000},
                    {"message", result.error}
                };
            }
        } else {
            response_json["error"] = {
                {"code", -32601},
                {"message", "Method not found"}
            };
        }
    } catch (const nlohmann::json::exception& e) {
        response_json["jsonrpc"] = "2.0";
        response_json["error"] = {
            {"code", -32700},
            {"message", "Parse error: " + std::string(e.what())}
        };
    } catch (const std::exception& e) {
        response_json["jsonrpc"] = "2.0";
        response_json["error"] = {
            {"code", -32000},
            {"message", "Server error: " + std::string(e.what())}
        };
    }

    return response_json.dump();
}

MCPServer::ToolResult MCPServer::ToolGetCPUState() {
    return {true, SerializeState(GetCPUState()), ""};
}

MCPServer::ToolResult MCPServer::ToolGetMemoryMap() {
    return {true, SerializeState(GetMemoryState()), ""};
}

MCPServer::ToolResult MCPServer::ToolGetMemoryRange(uint32_t address, uint32_t length) {
    // TODO: Implement actual memory reading from emulator
    std::vector<uint8_t> data(length, 0xCC); // Mock data
    nlohmann::json result_json;
    result_json["address"] = address;
    result_json["length"] = length;
    result_json["data"] = data; // Will be base64 encoded by default in JSON
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolFindString(const std::string& pattern, const std::string& region) {
    // TODO: Implement actual string search
    nlohmann::json result_json;
    result_json["pattern"] = pattern;
    result_json["region"] = region;
    result_json["results"] = nlohmann::json::array();
    result_json["results"].push_back({{"address", 0x80000400}, {"content", "Mock String"}});
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolSearchBytes(const std::string& pattern, const std::string& region) {
    // TODO: Implement actual byte search
    nlohmann::json result_json;
    result_json["pattern"] = pattern;
    result_json["region"] = region;
    result_json["results"] = nlohmann::json::array();
    result_json["results"].push_back({{"address", 0x80000500}, {"length", 4}});
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolHexdump(uint32_t address, uint32_t length) {
    // TODO: Implement actual hexdump from emulator memory
    std::string hex_str;
    for (uint32_t i = 0; i < length; ++i) {
        hex_str += "CC "; // Mock hex
    }
    nlohmann::json result_json;
    result_json["address"] = address;
    result_json["length"] = length;
    result_json["hexdump"] = hex_str;
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolGetGPUState() {
    return {true, SerializeState(GetGPUState()), ""};
}

MCPServer::ToolResult MCPServer::ToolListGPUCommands(uint32_t limit) {
    // TODO: Implement actual GPU command listing
    nlohmann::json result_json;
    result_json["limit"] = limit;
    result_json["commands"] = nlohmann::json::array();
    result_json["commands"].push_back("Mock GPU Command 1");
    result_json["commands"].push_back("Mock GPU Command 2");
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolListHardwareRegisters() {
    nlohmann::json result_json = ListHardwareRegisters();
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolReadHardwareRegister(const std::string& register_name) {
    nlohmann::json result_json;
    result_json["register"] = register_name;
    result_json["value"] = ReadHardwareRegister(register_name);
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolWriteHardwareRegister(const std::string& register_name, uint32_t value) {
    nlohmann::json result_json;
    result_json["register"] = register_name;
    result_json["value"] = value;
    result_json["success"] = WriteHardwareRegister(register_name, value);
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolGetDMAState(uint32_t channel) {
    nlohmann::json result_json;
    HardwareState::DMAChannel dma_state = GetDMAState(channel);
    result_json["channel"] = channel;
    result_json["address"] = dma_state.address;
    result_json["value"] = dma_state.value;
    result_json["active"] = dma_state.active;
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolSetBreakpoint(uint32_t address) {
    nlohmann::json result_json;
    result_json["address"] = address;
    result_json["success"] = SetBreakpoint(address);
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolGetBreakpoints() {
    nlohmann::json result_json = nlohmann::json::array();
    for (const auto& bp : GetBreakpoints()) {
        result_json.push_back({
            {"address", bp.address},
            {"condition", bp.condition},
            {"hit", bp.hit},
            {"enabled", bp.enabled}
        });
    }
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolClearBreakpoint(uint32_t address) {
    nlohmann::json result_json;
    result_json["address"] = address;
    result_json["success"] = ClearBreakpoint(address);
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolGetCallChain(uint32_t max_depth) {
    nlohmann::json result_json = GetCallChain(max_depth);
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolGetCallGraph(const std::string& function_name, uint32_t depth) {
    nlohmann::json result_json = GetCallGraph(function_name, depth);
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolGetEmulatorState() {
    return {true, GetEmulatorState(), ""};
}

// Serialization helpers
std::string MCPServer::SerializeState(const CPUState& state) {
    nlohmann::json j;
    j["pc"] = state.pc;
    j["sp"] = state.sp;
    j["gp"] = state.gp;
    j["fp"] = state.fp;
    j["ra"] = state.ra;
    j["s0"] = state.s0;
    j["s1"] = state.s1;
    j["s2"] = state.s2;
    j["instruction"] = state.instruction;
    j["instruction_hex"] = state.instruction_hex;
    j["instruction_decoded"] = state.instruction_decoded;
    j["breakdown"]["opcode"] = state.breakdown.opcode;
    j["breakdown"]["target"] = state.breakdown.target;
    j["breakdown"]["translated"] = state.breakdown.translated;
    j["breakdown"]["operation"] = state.breakdown.operation;
    return j.dump();
}

std::string MCPServer::SerializeState(const MemoryState& state) {
    nlohmann::json j;
    for (const auto& pair : state.regions) {
        j["regions"][pair.first]["type"] = (int)pair.second.type;
        j["regions"][pair.first]["start"] = pair.second.start;
        j["regions"][pair.first]["end"] = pair.second.end;
        j["regions"][pair.first]["size"] = pair.second.size;
    }
    // Note: 'ram', 'vram', 'rom' vectors are not serialized by default as they can be very large.
    // Tools like get_memory_range or hexdump handle specific ranges.
    return j.dump();
}

std::string MCPServer::SerializeState(const GPUState& state) {
    nlohmann::json j;
    j["gpu_read"] = state.gpu_read;
    j["gpu_reg"] = state.gpu_reg;
    j["gp1"] = state.gp1;
    j["status"] = state.status;
    j["dirty_flag"] = state.dirty_flag;
    j["display_mode"]["mode"] = state.display_mode.mode;
    j["display_mode"]["width"] = state.display_mode.width;
    j["display_mode"]["height"] = state.display_mode.height;
    j["display_mode"]["refresh_rate"] = state.display_mode.refresh_rate;
    return j.dump();
}

std::string MCPServer::SerializeState(const HardwareState& state) {
    nlohmann::json j;
    j["gpu"]["gpu_read"] = state.gpu.gpu_read;
    j["gpu"]["gpu_reg"] = state.gpu.gpu_reg;
    j["gpu"]["gp1"] = state.gpu.gp1;
    j["gpu"]["status"] = state.gpu.status;
    for (int i = 0; i < 8; ++i) {
        j["dma"][i]["address"] = state.dma[i].address;
        j["dma"][i]["value"] = state.dma[i].value;
        j["dma"][i]["active"] = state.dma[i].active;
        j["dma"][i]["transfer_mode"] = state.dma[i].transfer_mode;
        j["dma"][i]["transfer_count"] = state.dma[i].transfer_count;
    }
    for (int i = 0; i < 4; ++i) {
        j["counter"][i]["value"] = state.counter[i].value;
        j["counter"][i]["mode"] = state.counter[i].mode;
        j["counter"][i]["enabled"] = state.counter[i].enabled;
    }
    return j.dump();
}

} // namespace PCSX
