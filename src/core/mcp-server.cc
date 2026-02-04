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
#include <unordered_map>
#include <set>
#include <stdexcept>
#include <iomanip>
#include <sstream>

#include "third_party/json.hpp"
#include "core/cdrom.h"
#include "cdrom/cdriso.h"
#include "core/debug.h"
#include "core/gpulogger.h"
#include "core/callstacks.h"

namespace PCSX {

// Static member initialization  
MCPServer::Config MCPServer::config_;
std::unordered_map<uint32_t, MCPServer::Breakpoint> MCPServer::breakpoints_;
std::unordered_map<std::string, MCPServer::Tool> MCPServer::tools_;

void MCPServer::RegisterToolsIfNeeded() {
    if (!tools_.empty()) {
        return;
    }
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
    tools_["is_game_loaded"] = {"is_game_loaded", "Check if a game/ISO is currently loaded and running"};
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
        } else if (tool_name == "is_game_loaded") {
            return ToolIsGameLoaded();
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
    
    if (!g_emulator || !g_emulator->m_mem) {
        // Return static info if emulator not initialized
        state.regions["ram"] = {MemoryRegion::Type::RAM, 0x00000000, 0x00200000, "2 MB"};
        state.regions["vram"] = {MemoryRegion::Type::VRAM, 0x1F800000, 0x1F9FFFFF, "2 MB"};
        state.regions["bios"] = {MemoryRegion::Type::ROM, 0x1FC00000, 0x1FC80000, "512 KB"};
        state.regions["rom"] = {MemoryRegion::Type::ROM, 0x80000000, 0x803FFFFF, "4 MB"};
        state.regions["hardware"] = {MemoryRegion::Type::HW, 0x1F000000, 0x1F0000FF, "256 B"};
        return state;
    }
    
    // Get current PC to determine active memory region
    uint32_t pc = g_emulator->m_cpu->m_regs.pc;
    std::string active_region = "unknown";
    
    // Define all memory regions with dynamic info
    state.regions["ram"] = {MemoryRegion::Type::RAM, 0x00000000, 0x00200000, "2 MB"};
    state.regions["scratchpad"] = {MemoryRegion::Type::RAM, 0x1F800000, 0x1F800400, "1 KB"};
    state.regions["hardware_regs"] = {MemoryRegion::Type::HW, 0x1F000000, 0x1F010000, "64 KB"};
    state.regions["bios"] = {MemoryRegion::Type::ROM, 0x1FC00000, 0x1FC80000, "512 KB"};
    state.regions["exp1"] = {MemoryRegion::Type::ROM, 0x1F000000, 0x1F100000, "1 MB"};
    state.regions["exp2"] = {MemoryRegion::Type::ROM, 0x1F100000, 0x1F200000, "1 MB"};
    state.regions["exp3"] = {MemoryRegion::Type::ROM, 0x1FA00000, 0x1FB00000, "1 MB"};
    state.regions["memory_ctrl"] = {MemoryRegion::Type::HW, 0x1F801000, 0x1F801024, "36 B"};
    state.regions["interrupt_ctrl"] = {MemoryRegion::Type::HW, 0x1F801070, 0x1F801078, "8 B"};
    state.regions["dma_regs"] = {MemoryRegion::Type::HW, 0x1F801080, 0x1F8010F8, "120 B"};
    state.regions["timer_regs"] = {MemoryRegion::Type::HW, 0x1F801100, 0x1F801130, "48 B"};
    state.regions["gpu_regs"] = {MemoryRegion::Type::HW, 0x1F801810, 0x1F801818, "8 B"};
    
    // Determine active region based on PC
    if (pc >= 0x00000000 && pc < 0x00200000) {
        active_region = "ram";
    } else if (pc >= 0x1F800000 && pc < 0x1F800400) {
        active_region = "scratchpad";
    } else if (pc >= 0x1FC00000 && pc < 0x1FC80000) {
        active_region = "bios";
    } else if (pc >= 0x80000000 && pc < 0x80200000) {
        active_region = "ram (KSEG0)";
    } else if (pc >= 0xA0000000 && pc < 0xA0200000) {
        active_region = "ram (KSEG1)";
    } else if (pc >= 0x1F000000 && pc < 0x1F100000) {
        active_region = "exp1";
    } else if (pc >= 0xBFC00000 && pc < 0xBFC80000) {
        active_region = "bios (KSEG1)";
    } else if (pc >= 0x1F801000 && pc < 0x1F802000) {
        active_region = "hardware_regs";
    }
    
    // Add dynamic memory usage info
    state.regions["active_pc"] = {MemoryRegion::Type::RAM, pc, pc, active_region};
    
    // Check for RAM initialization by sampling first KB
    int non_zero_count = 0;
    for (uint32_t i = 0; i < 256; i++) {
        if (g_emulator->m_mem->read32(i * 4) != 0) {
            non_zero_count++;
        }
    }
    std::string ram_usage = (non_zero_count > 0) ? "Initialized" : "Uninitialized";
    state.regions["ram_status"] = {MemoryRegion::Type::RAM, 0, (uint32_t)non_zero_count, ram_usage};
    
    return state;
}

MCPServer::GPUState MCPServer::GetGPUState() {
    GPUState state = {};
    if (g_emulator && g_emulator->m_gpu) {
        state.status = g_emulator->m_gpu->readStatus();
        // Note: Other GPU registers may not be directly accessible
        // The status register contains most useful GPU state information
        state.gpu_read = 0;  // Would need GPU-specific interface
        state.gpu_reg = 0;   // Would need GPU-specific interface
        state.gp1 = 0;       // Would need GPU-specific interface
        state.dirty_flag = false;
        state.display_mode = {0, 0, 0, 0};  // Parsed from status if needed
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
    
    // First add our locally tracked breakpoints
    for (const auto& pair : breakpoints_) {
        list.push_back(pair.second);
    }
    
    // Then add breakpoints from the emulator's debug system
    if (g_emulator && g_emulator->m_debug) {
        const auto& tree = g_emulator->m_debug->getTree();
        for (const auto& bp : tree) {
            // Only add if not already in our list
            uint32_t addr = bp.address() | bp.base();
            if (breakpoints_.find(addr) == breakpoints_.end()) {
                std::string type_str = "exec";
                switch (bp.type()) {
                    case Debug::BreakpointType::Exec: type_str = "exec"; break;
                    case Debug::BreakpointType::Read: type_str = "read"; break;
                    case Debug::BreakpointType::Write: type_str = "write"; break;
                }
                std::string label = bp.label();
                list.push_back({addr, type_str, false, bp.enabled()});
            }
        }
    }
    
    return list;
}

bool MCPServer::SetBreakpoint(uint32_t address, const std::string& condition) {
    if (!g_emulator || !g_emulator->m_debug) {
        std::cout << "Cannot set breakpoint: emulator or debug not initialized" << std::endl;
        return false;
    }
    
    // Normalize address (remove region bits)
    uint32_t base = address & 0xe0000000;
    uint32_t normalized = address & ~0xe0000000;
    
    // Create invoker that logs and pauses
    Debug::BreakpointInvoker invoker = [](const Debug::Breakpoint* self, uint32_t addr, unsigned width, const char* cause) {
        std::cout << "[MCP] Breakpoint hit at 0x" << std::hex << addr << std::dec << ": " << cause << std::endl;
        g_system->pause();
        return true;
    };
    
    // Add the breakpoint (4 bytes width for instruction)
    Debug::Breakpoint* bp = g_emulator->m_debug->addBreakpoint(
        address, 
        Debug::BreakpointType::Exec, 
        4, 
        "MCP Breakpoint", 
        invoker
    );
    
    if (bp) {
        bp->label("MCP_" + std::to_string(address));
        std::cout << "Set breakpoint at 0x" << std::hex << address << std::dec << std::endl;
        
        // Also track in our local storage for MCP management
        breakpoints_[address] = {address, condition, false, true};
        return true;
    }
    
    return false;
}

bool MCPServer::ClearBreakpoint(uint32_t address) {
    bool cleared = false;
    
    // Clear from our local tracking
    if (breakpoints_.count(address)) {
        breakpoints_.erase(address);
        cleared = true;
    }
    
    // Clear from emulator's debug system
    if (g_emulator && g_emulator->m_debug) {
        const auto& tree = g_emulator->m_debug->getTree();
        for (const auto& bp : tree) {
            uint32_t bp_addr = bp.address() | bp.base();
            if (bp_addr == address) {
                g_emulator->m_debug->removeBreakpoint(&bp);
                cleared = true;
                break;
            }
        }
    }
    
    if (cleared) {
        std::cout << "Cleared breakpoint at 0x" << std::hex << address << std::dec << std::endl;
    }
    
    return cleared;
}

std::vector<std::string> MCPServer::ListHardwareRegisters() {
    // List of all known PSX hardware registers
    return {
        // Interrupt Control
        "I_STAT",    // 0x1070 - Interrupt Status
        "I_MASK",    // 0x1074 - Interrupt Mask
        
        // DMA Registers
        "DMA_DPCR",  // 0x10f0 - DMA Control
        "DMA_DICR",  // 0x10f4 - DMA Interrupt Control
        
        // DMA Channel 0 (MDECin)
        "DMA0_MADR", // 0x1080 - Memory Address
        "DMA0_BCR",  // 0x1084 - Block Control
        "DMA0_CHCR", // 0x1088 - Channel Control
        
        // DMA Channel 1 (MDECout)
        "DMA1_MADR", // 0x1090
        "DMA1_BCR",  // 0x1094
        "DMA1_CHCR", // 0x1098
        
        // DMA Channel 2 (GPU)
        "DMA2_MADR", // 0x10a0
        "DMA2_BCR",  // 0x10a4
        "DMA2_CHCR", // 0x10a8
        
        // DMA Channel 3 (CDROM)
        "DMA3_MADR", // 0x10b0
        "DMA3_BCR",  // 0x10b4
        "DMA3_CHCR", // 0x10b8
        
        // DMA Channel 4 (SPU)
        "DMA4_MADR", // 0x10c0
        "DMA4_BCR",  // 0x10c4
        "DMA4_CHCR", // 0x10c8
        
        // DMA Channel 5 (PIO)
        "DMA5_MADR", // 0x10d0
        "DMA5_BCR",  // 0x10d4
        "DMA5_CHCR", // 0x10d8
        
        // DMA Channel 6 (OTC)
        "DMA6_MADR", // 0x10e0
        "DMA6_BCR",  // 0x10e4
        "DMA6_CHCR", // 0x10e8
        
        // Timers
        "TIMER0_COUNT", // 0x1100
        "TIMER0_MODE",  // 0x1104
        "TIMER0_TARGET",// 0x1108
        "TIMER1_COUNT", // 0x1110
        "TIMER1_MODE",  // 0x1114
        "TIMER1_TARGET",// 0x1118
        "TIMER2_COUNT", // 0x1120
        "TIMER2_MODE",  // 0x1124
        "TIMER2_TARGET" // 0x1128
    };
}

uint32_t MCPServer::ReadHardwareRegister(const std::string& register_name) {
    // Map register names to hardware offsets
    static const std::unordered_map<std::string, uint16_t> register_map = {
        {"I_STAT", 0x1070}, {"I_MASK", 0x1074},
        {"DMA_DPCR", 0x10f0}, {"DMA_DICR", 0x10f4},
        {"DMA0_MADR", 0x1080}, {"DMA0_BCR", 0x1084}, {"DMA0_CHCR", 0x1088},
        {"DMA1_MADR", 0x1090}, {"DMA1_BCR", 0x1094}, {"DMA1_CHCR", 0x1098},
        {"DMA2_MADR", 0x10a0}, {"DMA2_BCR", 0x10a4}, {"DMA2_CHCR", 0x10a8},
        {"DMA3_MADR", 0x10b0}, {"DMA3_BCR", 0x10b4}, {"DMA3_CHCR", 0x10b8},
        {"DMA4_MADR", 0x10c0}, {"DMA4_BCR", 0x10c4}, {"DMA4_CHCR", 0x10c8},
        {"DMA5_MADR", 0x10d0}, {"DMA5_BCR", 0x10d4}, {"DMA5_CHCR", 0x10d8},
        {"DMA6_MADR", 0x10e0}, {"DMA6_BCR", 0x10e4}, {"DMA6_CHCR", 0x10e8},
        {"TIMER0_COUNT", 0x1100}, {"TIMER0_MODE", 0x1104}, {"TIMER0_TARGET", 0x1108},
        {"TIMER1_COUNT", 0x1110}, {"TIMER1_MODE", 0x1114}, {"TIMER1_TARGET", 0x1118},
        {"TIMER2_COUNT", 0x1120}, {"TIMER2_MODE", 0x1124}, {"TIMER2_TARGET", 0x1128}
    };
    
    auto it = register_map.find(register_name);
    if (it == register_map.end()) {
        std::cout << "Unknown hardware register: " << register_name << std::endl;
        return 0;
    }
    
    // Read from emulator's hardware register buffer
    uint16_t offset = it->second;
    uint32_t *ptr = reinterpret_cast<uint32_t*>(&g_emulator->m_mem->m_hard[offset]);
    return *ptr;
}

bool MCPServer::WriteHardwareRegister(const std::string& register_name, uint32_t value) {
    // Map register names to hardware offsets
    static const std::unordered_map<std::string, uint16_t> register_map = {
        {"I_STAT", 0x1070}, {"I_MASK", 0x1074},
        {"DMA_DPCR", 0x10f0}, {"DMA_DICR", 0x10f4},
        {"DMA0_MADR", 0x1080}, {"DMA0_BCR", 0x1084}, {"DMA0_CHCR", 0x1088},
        {"DMA1_MADR", 0x1090}, {"DMA1_BCR", 0x1094}, {"DMA1_CHCR", 0x1098},
        {"DMA2_MADR", 0x10a0}, {"DMA2_BCR", 0x10a4}, {"DMA2_CHCR", 0x10a8},
        {"DMA3_MADR", 0x10b0}, {"DMA3_BCR", 0x10b4}, {"DMA3_CHCR", 0x10b8},
        {"DMA4_MADR", 0x10c0}, {"DMA4_BCR", 0x10c4}, {"DMA4_CHCR", 0x10c8},
        {"DMA5_MADR", 0x10d0}, {"DMA5_BCR", 0x10d4}, {"DMA5_CHCR", 0x10d8},
        {"DMA6_MADR", 0x10e0}, {"DMA6_BCR", 0x10e4}, {"DMA6_CHCR", 0x10e8},
        {"TIMER0_COUNT", 0x1100}, {"TIMER0_MODE", 0x1104}, {"TIMER0_TARGET", 0x1108},
        {"TIMER1_COUNT", 0x1110}, {"TIMER1_MODE", 0x1114}, {"TIMER1_TARGET", 0x1118},
        {"TIMER2_COUNT", 0x1120}, {"TIMER2_MODE", 0x1124}, {"TIMER2_TARGET", 0x1128}
    };
    
    auto it = register_map.find(register_name);
    if (it == register_map.end()) {
        std::cout << "Unknown hardware register: " << register_name << std::endl;
        return false;
    }
    
    // Write to emulator's hardware register buffer
    // WARNING: Direct writes may bypass emulator logic - use with caution!
    uint16_t offset = it->second;
    uint32_t *ptr = reinterpret_cast<uint32_t*>(&g_emulator->m_mem->m_hard[offset]);
    *ptr = value;
    std::cout << "Wrote 0x" << std::hex << value << std::dec << " to " << register_name << std::endl;
    return true;
}

MCPServer::HardwareState::DMAChannel MCPServer::GetDMAState(uint32_t channel) {
    if (channel >= 7) {
        return {0, 0, false, 0, 0}; // Invalid channel
    }
    
    // Each DMA channel has 3 registers at offset 0x10 from each other
    // Base is 0x1080, each channel offset by 0x10
    uint16_t base_offset = 0x1080 + (channel * 0x10);
    
    // Read MADR (Memory Address Register) at offset +0
    uint32_t *madr_ptr = reinterpret_cast<uint32_t*>(&g_emulator->m_mem->m_hard[base_offset]);
    uint32_t madr = *madr_ptr;
    
    // Read BCR (Block Control Register) at offset +4
    uint32_t *bcr_ptr = reinterpret_cast<uint32_t*>(&g_emulator->m_mem->m_hard[base_offset + 4]);
    uint32_t bcr = *bcr_ptr;
    
    // Read CHCR (Channel Control Register) at offset +8
    uint32_t *chcr_ptr = reinterpret_cast<uint32_t*>(&g_emulator->m_mem->m_hard[base_offset + 8]);
    uint32_t chcr = *chcr_ptr;
    
    // Extract values from registers
    bool enabled = (chcr & 0x01000000) != 0; // Bit 24 indicates if DMA is active
    uint32_t block_size = bcr >> 16;
    uint32_t block_count = bcr & 0xFFFF;
    
    return {madr, bcr, enabled, block_size, block_count};
}

std::vector<std::string> MCPServer::GetCallChain(uint32_t max_depth) {
    std::vector<std::string> chain;
    
    if (!g_emulator || !g_emulator->m_callStacks) {
        chain.push_back("Error: Emulator or CallStacks not initialized");
        return chain;
    }
    
    // Check if we have a current call stack
    if (!g_emulator->m_callStacks->hasCurrent()) {
        // No call stack available yet - return current PC as the only entry
        uint32_t pc = g_emulator->m_cpu->m_regs.pc;
        uint32_t ra = g_emulator->m_cpu->m_regs.GPR.r[31];  // Return address (ra/$31)
        
        std::stringstream ss;
        ss << "0x" << std::hex << std::setfill('0') << std::setw(8) << pc 
           << " - current instruction (no call stack yet)";
        chain.push_back(ss.str());
        
        if (ra != 0 && ra != 0xFFFFFFFF) {
            std::stringstream ss_ra;
            ss_ra << "0x" << std::hex << std::setfill('0') << std::setw(8) << ra 
                  << " - return address (ra/$31)";
            chain.push_back(ss_ra.str());
        }
        
        return chain;
    }
    
    // Get the current call stack
    const auto& callStack = g_emulator->m_callStacks->getCurrent();
    
    // Add current PC at top of stack
    uint32_t pc = g_emulator->m_cpu->m_regs.pc;
    std::stringstream ss_pc;
    ss_pc << "0x" << std::hex << std::setfill('0') << std::setw(8) << pc 
          << " - current instruction (SP: 0x" << callStack.ra << ")";
    chain.push_back(ss_pc.str());
    
    // Iterate through the call stack
    uint32_t depth = 0;
    for (const auto& call : callStack.calls) {
        if (depth >= max_depth) {
            chain.push_back("... (truncated at depth " + std::to_string(max_depth) + ")");
            break;
        }
        
        std::stringstream ss;
        ss << "0x" << std::hex << std::setfill('0') << std::setw(8) << call.ra;
        
        if (call.shadow) {
            ss << " - function (shadow stack)";
        } else {
            ss << " - function (FP: 0x" << std::hex << call.fp << ", SP: 0x" << call.sp << ")";
        }
        
        chain.push_back(ss.str());
        depth++;
    }
    
    return chain;
}

std::vector<std::string> MCPServer::GetCallGraph(const std::string& function_name, uint32_t depth) {
    std::vector<std::string> graph;
    
    if (!g_emulator || !g_emulator->m_callStacks) {
        graph.push_back("Error: Emulator or CallStacks not initialized");
        return graph;
    }
    
    // Build dynamic call graph from available call stacks
    std::set<uint32_t> callers;
    std::set<uint32_t> callees;
    uint32_t target_addr = 0;
    
    // Try to parse function address from function_name if it's a hex string
    try {
        if (function_name.substr(0, 2) == "0x") {
            target_addr = std::stoul(function_name, nullptr, 16);
        }
    } catch (...) {
        // Use current PC if function name isn't an address
        if (g_emulator && g_emulator->m_cpu) {
            target_addr = g_emulator->m_cpu->m_regs.pc;
        }
    }
    
    // Get all call stacks from the tree
    const auto& callstacks = g_emulator->m_callStacks->getCallstacks();
    
    // Analyze each call stack
    for (const auto& stack : callstacks) {
        uint32_t prev_ra = stack.ra;
        
        for (const auto& call : stack.calls) {
            // If this call's return address matches our target, this function called our target
            if (call.ra == target_addr) {
                callers.insert(prev_ra);
            }
            
            // If the previous call's return address matches our target, this is a callee
            if (prev_ra == target_addr && call.ra != target_addr) {
                callees.insert(call.ra);
            }
            
            prev_ra = call.ra;
            
            if (callers.size() >= depth && callees.size() >= depth) {
                break;
            }
        }
        
        if (callers.size() >= depth && callees.size() >= depth) {
            break;
        }
    }
    
    // Format the results
    std::stringstream ss_callers;
    ss_callers << function_name << " callers: [";
    bool first = true;
    for (uint32_t addr : callers) {
        if (!first) ss_callers << ", ";
        ss_callers << "0x" << std::hex << std::setfill('0') << std::setw(8) << addr;
        first = false;
    }
    ss_callers << "]";
    graph.push_back(ss_callers.str());
    
    std::stringstream ss_callees;
    ss_callees << function_name << " callees: [";
    first = true;
    for (uint32_t addr : callees) {
        if (!first) ss_callees << ", ";
        ss_callees << "0x" << std::hex << std::setfill('0') << std::setw(8) << addr;
        first = false;
    }
    ss_callees << "]";
    graph.push_back(ss_callees.str());
    
    // Add note about dynamic analysis
    if (callers.empty() && callees.empty()) {
        graph.push_back("Note: No call relationships detected yet. Run emulation to collect dynamic profiling data.");
    }
    
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
        if (request_json.contains("id")) {
            response_json["id"] = request_json["id"];
        } else {
            response_json["id"] = nullptr;
        }

        if (method == "initialize") {
            // Standard MCP initialize method
            response_json["result"] = {
                {"protocolVersion", "2024-11-05"},
                {"capabilities", {
                    {"tools", nlohmann::json::object()}
                }},
                {"serverInfo", {
                    {"name", "PCSX-Redux MCP Server"},
                    {"version", "1.0.0"}
                }}
            };
        } else if (method == "tools/list") {
            // Standard MCP tools/list method
            nlohmann::json tools_array = nlohmann::json::array();
            for (const auto& tool : ListTools()) {
                tools_array.push_back({
                    {"name", tool.name},
                    {"description", tool.description},
                    {"inputSchema", {
                        {"type", "object"},
                        {"properties", nlohmann::json::object()}
                    }}
                });
            }
            response_json["result"] = {{"tools", tools_array}};
        } else if (method == "tools/call") {
            // Standard MCP tools/call method
            std::string tool_name = params.at("name").get<std::string>();
            nlohmann::json args_json = params.value("arguments", nlohmann::json::object());
            ToolResult result = ExecuteTool(tool_name, args_json.dump());
            if (result.success) {
                response_json["result"] = {
                    {"content", nlohmann::json::array({
                        {
                            {"type", "text"},
                            {"text", result.content}
                        }
                    })}
                };
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
    std::vector<uint8_t> data;
    if (g_emulator && g_emulator->m_mem) {
        data.reserve(length);
        for (uint32_t i = 0; i < length; ++i) {
            data.push_back(g_emulator->m_mem->read8(address + i));
        }
    } else {
        return {false, "", "Emulator not initialized"};
    }
    
    nlohmann::json result_json;
    result_json["address"] = address;
    result_json["length"] = length;
    result_json["data"] = data;  // Will be base64 encoded by nlohmann::json
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolFindString(const std::string& pattern, const std::string& region) {
    if (!g_emulator || !g_emulator->m_mem) {
        return {false, "", "Emulator not initialized"};
    }
    
    // Determine search region
    uint32_t start_addr = 0;
    uint32_t end_addr = 0;
    
    if (region == "ram") {
        start_addr = 0x00000000;
        end_addr = 0x00200000;  // 2MB RAM
    } else if (region == "bios") {
        start_addr = 0x1FC00000;
        end_addr = 0x1FC80000;  // 512KB BIOS
    } else {
        start_addr = 0x00000000;
        end_addr = 0x00200000;  // Default to RAM
    }
    
    nlohmann::json result_json;
    result_json["pattern"] = pattern;
    result_json["region"] = region;
    result_json["results"] = nlohmann::json::array();
    
    // Search for the pattern in memory
    size_t pattern_len = pattern.length();
    if (pattern_len == 0) {
        return {true, result_json.dump(), ""};
    }
    
    for (uint32_t addr = start_addr; addr <= end_addr - pattern_len; ++addr) {
        bool match = true;
        for (size_t i = 0; i < pattern_len; ++i) {
            uint8_t byte = g_emulator->m_mem->read8(addr + i);
            if (byte != static_cast<uint8_t>(pattern[i])) {
                match = false;
                break;
            }
        }
        
        if (match) {
            // Read a bit more context
            std::string context;
            for (size_t i = 0; i < pattern_len + 16 && (addr + i) < end_addr; ++i) {
                uint8_t byte = g_emulator->m_mem->read8(addr + i);
                if (byte >= 32 && byte < 127) {
                    context += static_cast<char>(byte);
                } else if (byte == 0) {
                    break;  // Null terminator
                } else {
                    context += '.';
                }
            }
            
            result_json["results"].push_back({
                {"address", addr},
                {"content", context}
            });
        }
    }
    
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolSearchBytes(const std::string& pattern, const std::string& region) {
    if (!g_emulator || !g_emulator->m_mem) {
        return {false, "", "Emulator not initialized"};
    }
    
    // Determine search region
    uint32_t start_addr = 0;
    uint32_t end_addr = 0;
    
    if (region == "ram") {
        start_addr = 0x00000000;
        end_addr = 0x00200000;  // 2MB RAM
    } else if (region == "bios") {
        start_addr = 0x1FC00000;
        end_addr = 0x1FC80000;  // 512KB BIOS
    } else {
        start_addr = 0x00000000;
        end_addr = 0x00200000;  // Default to RAM
    }
    
    // Parse hex pattern (e.g., "0A 1B 2C" or "0a1b2c")
    std::vector<uint8_t> search_bytes;
    std::string clean_pattern;
    for (char c : pattern) {
        if (c != ' ' && c != '\t') {
            clean_pattern += c;
        }
    }
    
    // Convert hex string to bytes
    for (size_t i = 0; i < clean_pattern.length(); i += 2) {
        if (i + 1 < clean_pattern.length()) {
            std::string byte_str = clean_pattern.substr(i, 2);
            try {
                uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
                search_bytes.push_back(byte);
            } catch (...) {
                return {false, "", "Invalid hex pattern"};
            }
        }
    }
    
    if (search_bytes.empty()) {
        return {false, "", "Empty search pattern"};
    }
    
    nlohmann::json result_json;
    result_json["pattern"] = pattern;
    result_json["region"] = region;
    result_json["results"] = nlohmann::json::array();
    
    // Search for byte pattern in memory
    size_t pattern_len = search_bytes.size();
    for (uint32_t addr = start_addr; addr <= end_addr - pattern_len; ++addr) {
        bool match = true;
        for (size_t i = 0; i < pattern_len; ++i) {
            uint8_t byte = g_emulator->m_mem->read8(addr + i);
            if (byte != search_bytes[i]) {
                match = false;
                break;
            }
        }
        
        if (match) {
            result_json["results"].push_back({
                {"address", addr},
                {"length", pattern_len}
            });
        }
    }
    
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolHexdump(uint32_t address, uint32_t length) {
    if (!g_emulator || !g_emulator->m_mem) {
        return {false, "", "Emulator not initialized"};
    }
    
    std::stringstream hex_str;
    hex_str << std::hex << std::setfill('0');
    
    for (uint32_t i = 0; i < length; ++i) {
        if (i > 0 && i % 16 == 0) {
            hex_str << "\n";
        }
        uint8_t byte = g_emulator->m_mem->read8(address + i);
        hex_str << std::setw(2) << static_cast<int>(byte) << " ";
    }
    
    nlohmann::json result_json;
    result_json["address"] = address;
    result_json["length"] = length;
    result_json["hexdump"] = hex_str.str();
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolGetGPUState() {
    return {true, SerializeState(GetGPUState()), ""};
}

MCPServer::ToolResult MCPServer::ToolListGPUCommands(uint32_t limit) {
    if (!g_emulator || !g_emulator->m_gpuLogger) {
        return {false, "", "Emulator or GPU Logger not initialized"};
    }
    
    nlohmann::json result_json;
    result_json["limit"] = limit;
    result_json["command_count"] = 0;
    result_json["commands"] = nlohmann::json::array();
    result_json["logger_enabled"] = false;
    
    // Check if GPU logger is enabled
    // Note: We can't directly check m_enabled as it's private, but we can try to enable it
    // For now, we'll return what's available
    
    // The GPULogger stores commands in m_list which is private
    // Since we can't access it directly, we'll return a message about the limitation
    // and suggest enabling the GPU logger from the GUI
    
    result_json["note"] = "GPU command logging requires GPU Logger to be enabled from the GUI (Debug -> GPU Logger)";
    result_json["gpu_logger_available"] = true;
    result_json["alternative"] = "Use get_gpu_state to read the GPU status register directly";
    
    // Add GPU status info as a command entry
    if (g_emulator->m_gpu) {
        uint32_t status = g_emulator->m_gpu->readStatus();
        nlohmann::json cmd;
        cmd["type"] = "GPU_STATUS";
        cmd["value"] = status;
        std::stringstream hex_str;
        hex_str << "0x" << std::hex << std::setfill('0') << std::setw(8) << status;
        cmd["hex"] = hex_str.str();
        cmd["description"] = "Current GPU status register";
        result_json["commands"].push_back(cmd);
        result_json["command_count"] = 1;
    }
    
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

MCPServer::ToolResult MCPServer::ToolIsGameLoaded() {
    if (!g_emulator || !g_emulator->m_cdrom) {
        return {false, "", "Emulator not initialized"};
    }
    
    nlohmann::json result;
    
    // Check if an ISO/game is loaded
    auto iso = g_emulator->m_cdrom->getIso();
    bool has_iso = iso && !iso->failed();
    
    result["game_loaded"] = has_iso;
    result["bios_only"] = !has_iso;
    
    if (has_iso) {
        // Get ISO path
        std::string iso_path = iso->getIsoPath().string();
        result["iso_path"] = iso_path;
        result["iso_name"] = iso->getIsoPath().filename().string();
        
        // Check if PC is in game code region (not BIOS)
        uint32_t pc = g_emulator->m_cpu->m_regs.pc;
        bool in_bios = (pc >= 0xBFC00000 && pc < 0xBFC80000) || 
                       (pc >= 0x1FC00000 && pc < 0x1FC80000);
        bool in_game_ram = (pc >= 0x80000000 && pc < 0x80200000) || 
                           (pc >= 0x00000000 && pc < 0x00200000);
        
        result["emulation_active"] = in_game_ram;
        result["in_bios"] = in_bios;
        result["current_pc"] = pc;
        
        // Try to detect if game has started by checking if RAM has been written
        // A simple heuristic: check if first 1KB of RAM is non-zero
        bool ram_initialized = false;
        for (uint32_t i = 0; i < 256; i++) {
            if (g_emulator->m_mem->read32(i * 4) != 0) {
                ram_initialized = true;
                break;
            }
        }
        result["ram_initialized"] = ram_initialized;
    } else {
        result["iso_path"] = "";
        result["iso_name"] = "";
        result["emulation_active"] = false;
        result["in_bios"] = true;
        result["current_pc"] = g_emulator->m_cpu->m_regs.pc;
        result["ram_initialized"] = false;
    }
    
    return {true, result.dump(), ""};
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
