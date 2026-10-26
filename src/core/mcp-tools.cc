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

#include <bit>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "core/callstacks.h"
#include "core/cdrom.h"
#include "core/debug.h"
#include "core/disr3000a.h"
#include "core/sstate.h"
#include "mcp-server.h"
#include "third_party/json.hpp"

namespace PCSX {

bool MCPServer::ReadGuestMemory(uint32_t address, uint32_t length, std::vector<uint8_t>& out) {
    if (!g_emulator || !g_emulator->m_mem) return false;
    out.clear();
    if (length == 0) return true;

    // Map the KSEG mirrors back to physical addresses.
    uint32_t phys = address;
    if (phys >= 0x80000000 && phys < 0xC0000000) phys &= 0x1FFFFFFF;

    auto& mem = g_emulator->m_mem;
    const bool ramExpansion = g_emulator->settings.get<Emulator::Setting8MB>();
    const uint32_t ramSize = ramExpansion ? 0x00800000 : 0x00200000;

    const uint8_t* src = nullptr;
    uint32_t base = 0;
    uint32_t size = 0;
    if (phys < ramSize) {
        src = mem->m_wram;
        base = 0;
        size = ramSize;
    } else if (phys >= 0x1F800000 && phys < 0x1F800400) {
        src = mem->m_hard;
        base = 0x1F800000;
        size = 0x400;
    } else if (phys >= 0x1FC00000 && phys < 0x1FC80000) {
        src = mem->m_bios;
        base = 0x1FC00000;
        size = 0x80000;
    } else if (phys >= 0x1F000000 && phys < 0x1F800000) {
        src = mem->m_exp1;
        base = 0x1F000000;
        size = 0x800000;
    } else {
        return false;
    }

    const uint32_t offset = phys - base;
    if (offset >= size || length > size - offset) return false;
    out.assign(src + offset, src + offset + length);
    return true;
}

std::filesystem::path MCPServer::AllowedDumpRoot() {
    if (g_emulator) {
        const auto& settings = g_emulator->settings.get<Emulator::SettingDebugSettings>();
        const std::string& configured = settings.get<Emulator::DebugSettings::MCPServerDumpRoot>().value;
        if (!configured.empty()) return std::filesystem::weakly_canonical(configured);
    }
    const char* home = std::getenv("HOME");
#ifdef _WIN32
    if (!home) home = std::getenv("USERPROFILE");
#endif
    if (home && *home) return std::filesystem::weakly_canonical(home);
    return std::filesystem::current_path();
}

bool MCPServer::IsPathWithin(const std::filesystem::path& root, const std::filesystem::path& target) {
    const auto rel = std::filesystem::relative(target, root);
    if (rel.empty()) return false;
    auto it = rel.begin();
    return !(it != rel.end() && *it == "..");
}

bool MCPServer::ResolveHostPath(const std::string& path, std::filesystem::path& out, std::string& error) {
    const auto root = AllowedDumpRoot();
    std::filesystem::path p(path);
    if (p.is_relative()) p = root / p;
    std::error_code ec;
    out = std::filesystem::weakly_canonical(p, ec);
    if (ec) {
        error = "Invalid path: " + path;
        return false;
    }
    if (!IsPathWithin(root, out)) {
        error = "Path must be inside " + root.string();
        return false;
    }
    return true;
}

extern PCSX::Emulator* g_emulator;

MCPServer::CPUState MCPServer::GetCPUState() {
    CPUState state = {};
    if (g_emulator && g_emulator->m_cpu) {
        state.pc = g_emulator->m_cpu->m_regs.pc;
        state.sp = g_emulator->m_cpu->m_regs.GPR.r[29];  // SP is R29
        state.gp = g_emulator->m_cpu->m_regs.GPR.r[28];  // GP is R28
        state.fp = g_emulator->m_cpu->m_regs.GPR.r[30];  // FP is R30 (or S8)
        state.ra = g_emulator->m_cpu->m_regs.GPR.r[31];  // RA is R31
        state.s0 = g_emulator->m_cpu->m_regs.GPR.r[16];
        state.s1 = g_emulator->m_cpu->m_regs.GPR.r[17];
        state.s2 = g_emulator->m_cpu->m_regs.GPR.r[18];

        state.instruction = g_emulator->m_cpu->m_regs.code;

        // Format instruction as hex
        std::stringstream ss_inst;
        ss_inst << "0x" << std::hex << std::setfill('0') << std::setw(8) << state.instruction;
        state.instruction_hex = ss_inst.str();

        // Decode instruction using PCSX-Redux disassembler
        uint32_t nextCode = 0;  // Next instruction (we don't have it here, use 0)
        std::string disasm = Disasm::asString(state.instruction, nextCode, state.pc, nullptr, false);

        // Extract just the mnemonic part (after "PC CODE: ")
        // Format is: "80010000 12345678: ADD v0, v1, v2"
        size_t colonPos = disasm.find(':');
        if (colonPos != std::string::npos && colonPos + 2 < disasm.length()) {
            state.instruction_decoded = disasm.substr(colonPos + 2);
        } else {
            state.instruction_decoded = disasm;
        }

        // Parse instruction breakdown (opcode, function, etc.)
        // For now, use basic parsing - could be enhanced later
        uint32_t opcode = (state.instruction >> 26) & 0x3F;
        uint32_t funct = state.instruction & 0x3F;
        uint32_t rs = (state.instruction >> 21) & 0x1F;
        uint32_t rt = (state.instruction >> 16) & 0x1F;
        uint32_t rd = (state.instruction >> 11) & 0x1F;

        state.breakdown = {opcode, funct, Disasm::s_disRNameGPR[rs], Disasm::s_disRNameGPR[rt]};
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

namespace {
uint32_t readHardwareWord(const uint8_t* hard, uint16_t offset) {
    uint32_t value;
    std::memcpy(&value, hard + offset, sizeof(value));
    if constexpr (std::endian::native == std::endian::big) {
        value = ((value & 0x000000FFu) << 24) | ((value & 0x0000FF00u) << 8) | ((value & 0x00FF0000u) >> 8) |
                ((value & 0xFF000000u) >> 24);
    }
    return value;
}

template <unsigned N, typename Mem>
MCPServer::HardwareState::DMAChannel dmaChannel(Mem& mem) {
    MCPServer::HardwareState::DMAChannel channel{};
    channel.address = mem->template getMADR<N>();
    channel.value = mem->template getCHCR<N>();
    channel.active = mem->template isDMABusy<N>();
    channel.transfer_mode = (channel.value >> 9) & 0x7;
    channel.transfer_count = mem->template getBCR<N>();
    return channel;
}
}  // namespace

MCPServer::GPUState MCPServer::GetGPUState() {
    GPUState state = {};
    if (!g_emulator || !g_emulator->m_gpu) return state;
    state.status = g_emulator->m_gpu->readStatus();
    static constexpr uint32_t widths[4] = {256, 320, 512, 640};
    state.display_mode.width = widths[(state.status >> 17) & 3];
    state.display_mode.height = ((state.status >> 19) & 1) ? 480 : 240;
    state.display_mode.refresh_rate = ((state.status >> 20) & 1) ? 50 : 60;
    return state;
}

MCPServer::HardwareState MCPServer::GetHardwareState() {
    HardwareState state = {};
    if (!g_emulator || !g_emulator->m_mem) return state;
    auto& mem = g_emulator->m_mem;
    state.gpu.status = g_emulator->m_gpu ? g_emulator->m_gpu->readStatus() : 0;
    for (uint32_t i = 0; i < 7; ++i) state.dma[i] = GetDMAState(i);
    for (uint32_t i = 0; i < 4; ++i) {
        const uint16_t base = static_cast<uint16_t>(0x1100 + i * 0x10);
        state.counter[i].value = readHardwareWord(mem->m_hard, base);
        state.counter[i].mode = readHardwareWord(mem->m_hard, base + 4);
        state.counter[i].target = readHardwareWord(mem->m_hard, base + 8);
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
                    case Debug::BreakpointType::Exec:
                        type_str = "exec";
                        break;
                    case Debug::BreakpointType::Read:
                        type_str = "read";
                        break;
                    case Debug::BreakpointType::Write:
                        type_str = "write";
                        break;
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

    // Add the breakpoint using default invoker (like GUI does)
    // Use the overload with label for better identification
    std::stringstream ss_label;
    ss_label << "MCP_0x" << std::hex << std::setfill('0') << std::setw(8) << address;
    std::string label = ss_label.str();
    Debug::Breakpoint* bp = g_emulator->m_debug->addBreakpoint(address, Debug::BreakpointType::Exec, 4, "MCP", label
                                                               // Using default invoker which calls g_system->pause()
    );

    if (bp) {
        // Enable the breakpoint (should be enabled by default, but ensure it is)
        bp->enable();
        std::cout << "Set breakpoint at 0x" << std::hex << address << std::dec << " (normalized: 0x"
                  << (address & ~0xe0000000) << ")" << std::endl;

        // Track in our local storage for MCP management
        breakpoints_[address] = {address, condition, false, true};
        return true;
    }

    std::cout << "Failed to set breakpoint at 0x" << std::hex << address << std::dec << std::endl;
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
        "I_STAT",  // 0x1070 - Interrupt Status
        "I_MASK",  // 0x1074 - Interrupt Mask

        // DMA Registers
        "DMA_DPCR",  // 0x10f0 - DMA Control
        "DMA_DICR",  // 0x10f4 - DMA Interrupt Control

        // DMA Channel 0 (MDECin)
        "DMA0_MADR",  // 0x1080 - Memory Address
        "DMA0_BCR",   // 0x1084 - Block Control
        "DMA0_CHCR",  // 0x1088 - Channel Control

        // DMA Channel 1 (MDECout)
        "DMA1_MADR",  // 0x1090
        "DMA1_BCR",   // 0x1094
        "DMA1_CHCR",  // 0x1098

        // DMA Channel 2 (GPU)
        "DMA2_MADR",  // 0x10a0
        "DMA2_BCR",   // 0x10a4
        "DMA2_CHCR",  // 0x10a8

        // DMA Channel 3 (CDROM)
        "DMA3_MADR",  // 0x10b0
        "DMA3_BCR",   // 0x10b4
        "DMA3_CHCR",  // 0x10b8

        // DMA Channel 4 (SPU)
        "DMA4_MADR",  // 0x10c0
        "DMA4_BCR",   // 0x10c4
        "DMA4_CHCR",  // 0x10c8

        // DMA Channel 5 (PIO)
        "DMA5_MADR",  // 0x10d0
        "DMA5_BCR",   // 0x10d4
        "DMA5_CHCR",  // 0x10d8

        // DMA Channel 6 (OTC)
        "DMA6_MADR",  // 0x10e0
        "DMA6_BCR",   // 0x10e4
        "DMA6_CHCR",  // 0x10e8

        // Timers
        "TIMER0_COUNT",   // 0x1100
        "TIMER0_MODE",    // 0x1104
        "TIMER0_TARGET",  // 0x1108
        "TIMER1_COUNT",   // 0x1110
        "TIMER1_MODE",    // 0x1114
        "TIMER1_TARGET",  // 0x1118
        "TIMER2_COUNT",   // 0x1120
        "TIMER2_MODE",    // 0x1124
        "TIMER2_TARGET"   // 0x1128
    };
}

uint32_t MCPServer::ReadHardwareRegister(const std::string& register_name) {
    // Map register names to hardware offsets
    static const std::unordered_map<std::string, uint16_t> register_map = {
        {"I_STAT", 0x1070},       {"I_MASK", 0x1074},       {"DMA_DPCR", 0x10f0},      {"DMA_DICR", 0x10f4},
        {"DMA0_MADR", 0x1080},    {"DMA0_BCR", 0x1084},     {"DMA0_CHCR", 0x1088},     {"DMA1_MADR", 0x1090},
        {"DMA1_BCR", 0x1094},     {"DMA1_CHCR", 0x1098},    {"DMA2_MADR", 0x10a0},     {"DMA2_BCR", 0x10a4},
        {"DMA2_CHCR", 0x10a8},    {"DMA3_MADR", 0x10b0},    {"DMA3_BCR", 0x10b4},      {"DMA3_CHCR", 0x10b8},
        {"DMA4_MADR", 0x10c0},    {"DMA4_BCR", 0x10c4},     {"DMA4_CHCR", 0x10c8},     {"DMA5_MADR", 0x10d0},
        {"DMA5_BCR", 0x10d4},     {"DMA5_CHCR", 0x10d8},    {"DMA6_MADR", 0x10e0},     {"DMA6_BCR", 0x10e4},
        {"DMA6_CHCR", 0x10e8},    {"TIMER0_COUNT", 0x1100}, {"TIMER0_MODE", 0x1104},   {"TIMER0_TARGET", 0x1108},
        {"TIMER1_COUNT", 0x1110}, {"TIMER1_MODE", 0x1114},  {"TIMER1_TARGET", 0x1118}, {"TIMER2_COUNT", 0x1120},
        {"TIMER2_MODE", 0x1124},  {"TIMER2_TARGET", 0x1128}};

    auto it = register_map.find(register_name);
    if (it == register_map.end()) {
        std::cout << "Unknown hardware register: " << register_name << std::endl;
        return 0;
    }

    // Read from emulator's hardware register buffer
    uint16_t offset = it->second;
    uint32_t* ptr = reinterpret_cast<uint32_t*>(&g_emulator->m_mem->m_hard[offset]);
    return *ptr;
}

bool MCPServer::WriteHardwareRegister(const std::string& register_name, uint32_t value) {
    // Map register names to hardware offsets
    static const std::unordered_map<std::string, uint16_t> register_map = {
        {"I_STAT", 0x1070},       {"I_MASK", 0x1074},       {"DMA_DPCR", 0x10f0},      {"DMA_DICR", 0x10f4},
        {"DMA0_MADR", 0x1080},    {"DMA0_BCR", 0x1084},     {"DMA0_CHCR", 0x1088},     {"DMA1_MADR", 0x1090},
        {"DMA1_BCR", 0x1094},     {"DMA1_CHCR", 0x1098},    {"DMA2_MADR", 0x10a0},     {"DMA2_BCR", 0x10a4},
        {"DMA2_CHCR", 0x10a8},    {"DMA3_MADR", 0x10b0},    {"DMA3_BCR", 0x10b4},      {"DMA3_CHCR", 0x10b8},
        {"DMA4_MADR", 0x10c0},    {"DMA4_BCR", 0x10c4},     {"DMA4_CHCR", 0x10c8},     {"DMA5_MADR", 0x10d0},
        {"DMA5_BCR", 0x10d4},     {"DMA5_CHCR", 0x10d8},    {"DMA6_MADR", 0x10e0},     {"DMA6_BCR", 0x10e4},
        {"DMA6_CHCR", 0x10e8},    {"TIMER0_COUNT", 0x1100}, {"TIMER0_MODE", 0x1104},   {"TIMER0_TARGET", 0x1108},
        {"TIMER1_COUNT", 0x1110}, {"TIMER1_MODE", 0x1114},  {"TIMER1_TARGET", 0x1118}, {"TIMER2_COUNT", 0x1120},
        {"TIMER2_MODE", 0x1124},  {"TIMER2_TARGET", 0x1128}};

    auto it = register_map.find(register_name);
    if (it == register_map.end()) {
        std::cout << "Unknown hardware register: " << register_name << std::endl;
        return false;
    }

    // Write to emulator's hardware register buffer
    // WARNING: Direct writes may bypass emulator logic - use with caution!
    uint16_t offset = it->second;
    uint32_t* ptr = reinterpret_cast<uint32_t*>(&g_emulator->m_mem->m_hard[offset]);
    *ptr = value;
    std::cout << "Wrote 0x" << std::hex << value << std::dec << " to " << register_name << std::endl;
    return true;
}

MCPServer::HardwareState::DMAChannel MCPServer::GetDMAState(uint32_t channel) {
    if (!g_emulator || !g_emulator->m_mem) return {};
    auto& mem = g_emulator->m_mem;
    switch (channel) {
        case 0:
            return dmaChannel<0>(mem);
        case 1:
            return dmaChannel<1>(mem);
        case 2:
            return dmaChannel<2>(mem);
        case 3:
            return dmaChannel<3>(mem);
        case 4:
            return dmaChannel<4>(mem);
        case 5:
            return dmaChannel<5>(mem);
        case 6:
            return dmaChannel<6>(mem);
        default:
            return {};
    }
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
            ss_ra << "0x" << std::hex << std::setfill('0') << std::setw(8) << ra << " - return address (ra/$31)";
            chain.push_back(ss_ra.str());
        }

        return chain;
    }

    // Get the current call stack
    const auto& callStack = g_emulator->m_callStacks->getCurrent();

    // Add current PC at top of stack
    uint32_t pc = g_emulator->m_cpu->m_regs.pc;
    std::stringstream ss_pc;
    ss_pc << "0x" << std::hex << std::setfill('0') << std::setw(8) << pc << " - current instruction (SP: 0x"
          << callStack.ra << ")";
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
        state_json["breakpoints"].push_back({{"address", bp.second.address},
                                             {"condition", bp.second.condition},
                                             {"hit", bp.second.hit},
                                             {"enabled", bp.second.enabled}});
    }
    return state_json.dump(2);
}

MCPServer::ToolResult MCPServer::ToolGetCPUState() { return {true, SerializeState(GetCPUState()), ""}; }

MCPServer::ToolResult MCPServer::ToolGetMemoryMap() { return {true, SerializeState(GetMemoryState()), ""}; }

MCPServer::ToolResult MCPServer::ToolGetMemoryRange(uint32_t address, uint32_t length) {
    std::vector<uint8_t> data;
    if (!ReadGuestMemory(address, length, data)) {
        return {false, "", "Address range is not readable guest memory (RAM, scratchpad, BIOS or EXP1)"};
    }

    nlohmann::json result_json;
    result_json["address"] = address;
    result_json["length"] = length;
    result_json["data"] = data;
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolFindString(const std::string& pattern, const std::string& region) {
    uint32_t start_addr = 0;
    uint32_t end_addr = 0x00200000;
    if (region == "bios") {
        start_addr = 0x1FC00000;
        end_addr = 0x1FC80000;
    }

    std::vector<uint8_t> data;
    if (!ReadGuestMemory(start_addr, end_addr - start_addr, data)) {
        return {false, "", "Unable to read the requested memory region"};
    }

    nlohmann::json result_json;
    result_json["pattern"] = pattern;
    result_json["region"] = region;
    result_json["results"] = nlohmann::json::array();

    if (pattern.empty()) return {true, result_json.dump(), ""};

    for (size_t i = 0; i + pattern.size() <= data.size(); ++i) {
        if (std::memcmp(data.data() + i, pattern.data(), pattern.size()) != 0) continue;
        std::string context;
        for (size_t j = 0; j < pattern.size() + 16 && i + j < data.size(); ++j) {
            const uint8_t byte = data[i + j];
            if (byte >= 32 && byte < 127) {
                context += static_cast<char>(byte);
            } else if (byte == 0) {
                break;
            } else {
                context += '.';
            }
        }
        result_json["results"].push_back({{"address", start_addr + static_cast<uint32_t>(i)}, {"content", context}});
    }

    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolSearchBytes(const std::string& pattern, const std::string& region) {
    uint32_t start_addr = 0;
    uint32_t end_addr = 0x00200000;
    if (region == "bios") {
        start_addr = 0x1FC00000;
        end_addr = 0x1FC80000;
    }

    std::vector<uint8_t> needle;
    std::string clean;
    for (char c : pattern) {
        if (c != ' ' && c != '	') clean += c;
    }
    if (clean.size() % 2 != 0) return {false, "", "Hex pattern must contain an even number of digits"};
    for (size_t i = 0; i < clean.size(); i += 2) {
        uint8_t byte = 0;
        const auto [ptr, ec] = std::from_chars(clean.data() + i, clean.data() + i + 2, byte, 16);
        if (ec != std::errc() || ptr != clean.data() + i + 2) return {false, "", "Invalid hex pattern"};
        needle.push_back(byte);
    }
    if (needle.empty()) return {false, "", "Empty search pattern"};

    std::vector<uint8_t> data;
    if (!ReadGuestMemory(start_addr, end_addr - start_addr, data)) {
        return {false, "", "Unable to read the requested memory region"};
    }

    nlohmann::json result_json;
    result_json["pattern"] = pattern;
    result_json["region"] = region;
    result_json["results"] = nlohmann::json::array();
    for (size_t i = 0; i + needle.size() <= data.size(); ++i) {
        if (std::memcmp(data.data() + i, needle.data(), needle.size()) == 0) {
            result_json["results"].push_back(
                {{"address", start_addr + static_cast<uint32_t>(i)}, {"length", needle.size()}});
        }
    }
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolHexdump(uint32_t address, uint32_t length) {
    std::vector<uint8_t> data;
    if (!ReadGuestMemory(address, length, data)) {
        return {false, "", "Address range is not readable guest memory (RAM, scratchpad, BIOS or EXP1)"};
    }

    std::stringstream hex_str;
    hex_str << std::hex << std::setfill('0');
    for (uint32_t i = 0; i < length; ++i) {
        if (i > 0 && i % 16 == 0) hex_str << "\n";
        hex_str << std::setw(2) << static_cast<int>(data[i]) << " ";
    }

    nlohmann::json result_json;
    result_json["address"] = address;
    result_json["length"] = length;
    result_json["hexdump"] = hex_str.str();
    return {true, result_json.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolGetGPUState() { return {true, SerializeState(GetGPUState()), ""}; }

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
        result_json.push_back(
            {{"address", bp.address}, {"condition", bp.condition}, {"hit", bp.hit}, {"enabled", bp.enabled}});
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

MCPServer::ToolResult MCPServer::ToolGetEmulatorState() { return {true, GetEmulatorState(), ""}; }

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
        bool in_bios = (pc >= 0xBFC00000 && pc < 0xBFC80000) || (pc >= 0x1FC00000 && pc < 0x1FC80000);
        bool in_game_ram = (pc >= 0x80000000 && pc < 0x80200000) || (pc >= 0x00000000 && pc < 0x00200000);

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
        result["current_pc"] = static_cast<uint32_t>(g_emulator->m_cpu->m_regs.pc);
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
    j["status"] = state.status;
    j["display_mode"]["width"] = state.display_mode.width;
    j["display_mode"]["height"] = state.display_mode.height;
    j["display_mode"]["refresh_rate"] = state.display_mode.refresh_rate;
    return j.dump();
}

std::string MCPServer::SerializeState(const HardwareState& state) {
    nlohmann::json j;
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
        j["counter"][i]["target"] = state.counter[i].target;
    }
    return j.dump();
}

// Execution Control Tool Implementations

MCPServer::ToolResult MCPServer::ToolPause() {
    if (!g_emulator) {
        return {false, "", "Emulator not initialized"};
    }

    g_system->pause();

    nlohmann::json result;
    result["status"] = "paused";
    result["message"] = "Emulator execution paused";

    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolResume() {
    if (!g_emulator) {
        return {false, "", "Emulator not initialized"};
    }

    g_system->resume();

    nlohmann::json result;
    result["status"] = "running";
    result["message"] = "Emulator execution resumed";

    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolStepIn() {
    if (!g_emulator || !g_emulator->m_debug) {
        return {false, "", "Emulator or debug subsystem not initialized"};
    }

    g_emulator->m_debug->stepIn();

    // Get updated CPU state after step
    CPUState cpu_state = GetCPUState();

    nlohmann::json result;
    result["status"] = "stepped";
    result["message"] = "Stepped into next instruction";
    result["pc"] = cpu_state.pc;
    result["instruction"] = cpu_state.instruction_decoded;

    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolStepOver() {
    if (!g_emulator || !g_emulator->m_debug) {
        return {false, "", "Emulator or debug subsystem not initialized"};
    }

    g_emulator->m_debug->stepOver();

    // Get updated CPU state after step
    CPUState cpu_state = GetCPUState();

    nlohmann::json result;
    result["status"] = "stepped_over";
    result["message"] = "Stepped over next instruction";
    result["pc"] = cpu_state.pc;
    result["instruction"] = cpu_state.instruction_decoded;

    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolStepOut() {
    if (!g_emulator || !g_emulator->m_debug) {
        return {false, "", "Emulator or debug subsystem not initialized"};
    }

    g_emulator->m_debug->stepOut();

    // Get updated CPU state after step
    CPUState cpu_state = GetCPUState();

    nlohmann::json result;
    result["status"] = "stepped_out";
    result["message"] = "Stepped out of current function";
    result["pc"] = cpu_state.pc;
    result["instruction"] = cpu_state.instruction_decoded;

    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolRunToAddress(uint32_t address) {
    if (!g_emulator || !g_emulator->m_debug) {
        return {false, "", "Emulator or debug subsystem not initialized"};
    }

    // Set a temporary breakpoint at the target address
    auto* bp = g_emulator->m_debug->addBreakpoint(
        address, PCSX::Debug::BreakpointType::Exec, 1, "MCP run_to_address",
        [](PCSX::Debug::Breakpoint* self, uint32_t addr, unsigned width, const char* cause) {
            g_system->pause();
            // Remove the temporary breakpoint after hitting it
            g_emulator->m_debug->removeBreakpoint(self);
            return true;
        });

    if (!bp) {
        return {false, "", "Failed to set temporary breakpoint"};
    }

    // Resume execution
    g_system->resume();

    nlohmann::json result;
    result["status"] = "running_to_address";
    result["target_address"] = address;
    std::stringstream ss_msg;
    ss_msg << "Emulator running until address 0x" << std::hex << std::setfill('0') << std::setw(8) << address;
    result["message"] = ss_msg.str();

    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolGetExecutionState() {
    if (!g_emulator) {
        return {false, "", "Emulator not initialized"};
    }

    bool is_running = g_system->running();

    nlohmann::json result;
    result["running"] = is_running;
    result["status"] = is_running ? "running" : "paused";

    // Add current PC if paused
    if (!is_running && g_emulator->m_cpu) {
        result["pc"] = static_cast<uint32_t>(g_emulator->m_cpu->m_regs.pc);
        result["instruction"] = g_emulator->m_cpu->m_regs.code;
    }

    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolHowToUseMCP() {
    nlohmann::json guide;

    guide["title"] = "MCP Server Usage Guide for AI Assistants";
    guide["version"] = "1.0";
    guide["total_tools"] = 35;

    // Overview
    guide["overview"] = {
        {"description", "The PCSX-Redux MCP server provides 35 tools for analyzing PlayStation 1 games in real-time"},
        {"capabilities",
         nlohmann::json::array({"Execution control (pause, resume, step through code)", "Real MIPS R3000A disassembly",
                                "Memory inspection and search", "GPU and DMA monitoring", "Hardware register access",
                                "Breakpoint management", "Call chain and graph tracing",
                                "Dynamic memory extraction for Ghidra overlay import"})},
        {"addressing", "All addresses accept hex strings (\"0x80010000\") or decimal numbers (2147549184)"}};

    // Quick Start Workflow
    guide["quick_start"] = {{"step1",
                             {{"action", "Check if game is loaded"},
                              {"tool", "is_game_loaded"},
                              {"arguments", nlohmann::json::object()},
                              {"why", "Verify emulator state before analysis"}}},
                            {"step2",
                             {{"action", "Pause execution to inspect state"},
                              {"tool", "pause"},
                              {"arguments", nlohmann::json::object()},
                              {"why", "Freeze game to examine CPU/memory safely"}}},
                            {"step3",
                             {{"action", "Get current CPU state"},
                              {"tool", "get_cpu_state"},
                              {"arguments", nlohmann::json::object()},
                              {"why", "See PC, registers, and disassembled instruction"}}},
                            {"step4",
                             {{"action", "Examine memory layout"},
                              {"tool", "get_memory_map"},
                              {"arguments", nlohmann::json::object()},
                              {"why", "Understand RAM, BIOS, and hardware regions"}}}};

    // Common Analysis Patterns
    guide["analysis_patterns"] = {
        {"finding_game_code",
         {{"description", "Locate main game code and routines"},
          {"steps",
           nlohmann::json::array({"1. pause() - Stop execution",
                                  "2. get_cpu_state() - Check current PC (usually in 0x80000000-0x801FFFFF range)",
                                  "3. hexdump(pc_address, 256) - Read surrounding code",
                                  "4. step_in() repeatedly - Trace execution flow",
                                  "5. set_breakpoint(interesting_address) - Mark important locations"})}}},
        {"finding_variables",
         {{"description", "Locate game variables like health, score, position"},
          {"steps", nlohmann::json::array({"1. find_string(\"HP\") or search_bytes(\"pattern\") - Search RAM",
                                           "2. hexdump(found_address, 64) - Examine surrounding data",
                                           "3. Resume game and repeat search to find changing values",
                                           "4. set_breakpoint(address) on suspected variable access",
                                           "5. get_call_chain() when breakpoint hits - See what code accesses it"})}}},
        {"tracing_function",
         {{"description", "Understand what a function does"},
          {"steps",
           nlohmann::json::array(
               {"1. set_breakpoint(function_start_address)", "2. resume() - Let game run to breakpoint",
                "3. get_cpu_state() - Verify you're at function entry",
                "4. step_in() or step_over() - Trace through function",
                "5. Watch memory changes with hexdump() between steps", "6. step_out() - Return to caller"})}}},
        {"monitoring_gpu",
         {{"description", "Analyze rendering and graphics"},
          {"steps", nlohmann::json::array({"1. get_gpu_state() - Check GPU status register",
                                           "2. get_dma_state(2) - Check GPU DMA channel (channel 2)",
                                           "4. Correlate with CPU code using breakpoints"})}}},
        {"extracting_overlays",
         {{"description", "Capture dynamically loaded code for Ghidra analysis"},
          {"steps",
           nlohmann::json::array({"1. pause() - Halt at the moment the overlay is loaded",
                                  "2. get_cpu_state() - Verify PC is in RAM range (0x80000000-0x801FFFFF)",
                                  "3. dump_memory(address, length, tag, output_dir) - Capture the region",
                                  "4. Import the resulting .bin + .json into Ghidra with ReduxOverlayImporter",
                                  "5. snapshot_ram(tag, output_dir) - Alternatively dump full 2MB for diffing"})}}}};

    // Tool Categories with Best Practices
    guide["tool_categories"] = {
        {"execution_control",
         {{"tools", nlohmann::json::array({"pause", "resume", "step_in", "step_over", "step_out", "run_to_address",
                                           "get_execution_state"})},
          {"best_practice",
           "Always pause() before inspecting state. Use step_over() to skip library functions. Use run_to_address() "
           "for quick navigation."}}},
        {"cpu_memory",
         {{"tools", nlohmann::json::array({"get_cpu_state", "get_memory_map", "get_memory_range", "hexdump",
                                           "find_string", "search_bytes"})},
          {"best_practice",
           "get_cpu_state() shows real MIPS disassembly. Use hexdump() for small regions, get_memory_range() for bulk "
           "reads. Search RAM region for game data."}}},
        {"debugging",
         {{"tools", nlohmann::json::array(
                        {"set_breakpoint", "get_breakpoints", "clear_breakpoint", "get_call_chain", "get_call_graph"})},
          {"best_practice",
           "Set breakpoints on interesting addresses. Use get_call_chain() to understand execution context. Remember "
           "breakpoint addresses for later sessions."}}},
        {"hardware",
         {{"tools", nlohmann::json::array({"list_hardware_registers", "read_hardware_register",
                                           "write_hardware_register", "get_dma_state", "get_gpu_state"})},
          {"best_practice",
           "Monitor I_STAT for interrupts. Check DMA channels 2 (GPU) and 6 (OT). GPU status shows display mode and "
           "busy state."}}},
        {"state",
         {{"tools", nlohmann::json::array({"get_emulator_state", "is_game_loaded"})},
          {"best_practice",
           "Use get_emulator_state() for comprehensive snapshot. Check is_game_loaded() before starting analysis."}}},
        {"dynamic_extraction",
         {{"tools", nlohmann::json::array({"dump_memory", "snapshot_ram"})},
          {"best_practice",
           "Pause before dumping to get a consistent snapshot. Use descriptive tags (e.g. 'bg2_title_code'). Provide "
           "output_dir as the absolute path to your Ghidra project's extracted_overlays folder."}}}};

    // Important Addresses
    guide["memory_regions"] = {{"ram",
                                {{"range", "0x00000000 - 0x001FFFFF (KUSEG) or 0x80000000 - 0x801FFFFF (KSEG0)"},
                                 {"size", "2 MB"},
                                 {"usage", "Main game code and data. Most analysis happens here."}}},
                               {"scratchpad",
                                {{"range", "0x1F800000 - 0x1F8003FF"},
                                 {"size", "1 KB"},
                                 {"usage", "Fast CPU cache. Check for performance-critical code."}}},
                               {"hardware_regs",
                                {{"range", "0x1F801000 - 0x1F802FFF"},
                                 {"size", "8 KB"},
                                 {"usage", "Memory control, interrupts, DMA, timers, GPU, etc."}}},
                               {"bios",
                                {{"range", "0x1FC00000 - 0x1FC7FFFF (or 0xBFC00000 - 0xBFC7FFFF)"},
                                 {"size", "512 KB"},
                                 {"usage", "BIOS ROM. System initialization and kernel functions."}}}};

    // Tips and Tricks
    guide["tips"] = {
        {"tip1", "MIPS disassembly in get_cpu_state() shows actual instruction mnemonics (ADD, LW, BEQ, etc.)"},
        {"tip2", "Use hex addresses \"0x80010000\" - easier to read than decimal 2147549184"},
        {"tip3", "Stack pointer (sp) grows downward. Watch sp in get_cpu_state() to track function calls."},
        {"tip4", "Return address (ra) shows where function will return. Useful for understanding call flow."},
        {"tip5", "JAL (Jump And Link) and JALR are function calls. JR $ra is function return."},
        {"tip6", "Search for strings like game title or \"SCUS\" to find game-specific code."},
        {"tip7", "DMA channel 2 is GPU, channel 4 is SPU (audio), channel 6 is OT (ordering table)."},
        {"tip8", "If PC is in BIOS range (0xBFC00000), game hasn't loaded yet or crashed."},
        {"tip9", "Combine step_in() with get_cpu_state() to trace instruction-by-instruction."},
        {"tip10", "Use get_emulator_state() to get everything at once - CPU, GPU, DMA, memory map, breakpoints."},
        {"tip11",
         "dump_memory() writes a .bin + .json pair. Point output_dir at your Ghidra project's extracted_overlays/ "
         "folder for easy importing."}};

    // Error Handling
    guide["common_errors"] = {{"missing_parameter",
                               {{"error", "JSON parse error: key 'address' not found"},
                                {"cause", "Required parameter missing from tool call"},
                                {"fix", "Always provide required parameters. Example: {\"address\": \"0x80010000\"}"}}},
                              {"invalid_address",
                               {{"error", "Address out of range or invalid format"},
                                {"cause", "Address outside valid memory regions"},
                                {"fix", "Check get_memory_map() for valid ranges. Use hex strings for clarity."}}},
                              {"emulator_not_initialized",
                               {{"error", "Emulator not initialized"},
                                {"cause", "Emulator not fully started or crashed"},
                                {"fix", "Check is_game_loaded() first. Restart emulator if needed."}}}};

    // Advanced Techniques
    guide["advanced"] = {
        {"reverse_engineering",
         "Use set_breakpoint() + get_call_chain() to map function relationships. Build control flow graph manually."},
        {"performance_profiling",
         "Use timers (TIMER0-2 registers) to measure code execution time. Check DMA transfer counts."},
        {"save_state_analysis",
         "Pause at interesting moments, dump memory with hexdump(), compare across game states."},
        {"overlay_extraction",
         "Use dump_memory() or snapshot_ram() to pull dynamically loaded code out of RAM. Import into Ghidra with "
         "ReduxOverlayImporter."},
        {"cheat_finding",
         "Search for numeric values with search_bytes(), modify game state, trace what code reads them."}};

    // Example Complete Session
    guide["example_session"] = nlohmann::json::array(
        {"// 1. Verify game is loaded",
         "{\"tool\": \"is_game_loaded\"}",
         "",
         "// 2. Pause to inspect",
         "{\"tool\": \"pause\"}",
         "",
         "// 3. Get current state with MIPS disassembly",
         "{\"tool\": \"get_cpu_state\"}",
         "// Returns: {\"pc\": \"0x80010000\", \"instruction_decoded\": \"ADDIU sp, sp, -32\", ...}",
         "",
         "// 4. Set breakpoint on suspected function",
         "{\"tool\": \"set_breakpoint\", \"arguments\": {\"address\": \"0x80011000\"}}",
         "",
         "// 5. Resume and wait for breakpoint",
         "{\"tool\": \"resume\"}",
         "",
         "// 6. When hit, trace the function",
         "{\"tool\": \"get_call_chain\", \"arguments\": {\"max_depth\": 10}}",
         "",
         "// 7. Step through instruction by instruction",
         "{\"tool\": \"step_in\"}",
         "{\"tool\": \"get_cpu_state\"}",
         "",
         "// 8. Read memory around interesting address",
         "{\"tool\": \"hexdump\", \"arguments\": {\"address\": \"0x80050000\", \"length\": 256}}",
         "",
         "// 9. Search for game strings",
         "{\"tool\": \"find_string\", \"arguments\": {\"pattern\": \"PLAYER\", \"region\": \"ram\"}}",
         "",
         "// 10. Dump dynamically loaded code for Ghidra",
         "{\"tool\": \"dump_memory\", \"arguments\": {\"address\": \"0x80010000\", \"length\": 65536, \"tag\": "
         "\"bg2_title_code\", \"output_dir\": \"/path/to/ghidra_project/extracted_overlays\"}}",
         "",
         "// 11. Or snapshot the entire 2MB RAM for diffing",
         "{\"tool\": \"snapshot_ram\", \"arguments\": {\"tag\": \"bg2_ram_full\", \"output_dir\": "
         "\"/path/to/ghidra_project/extracted_overlays\"}}"});

    guide["security"] = {{"bind", "The /mcp endpoint listens on 127.0.0.1 through the web server."},
                         {"token", "Set MCPServerToken to require an Authorization: Bearer <token> header."},
                         {"read_only", "Set MCPServerReadOnly to refuse tools that modify emulator state."},
                         {"dump_root",
                          "MCPServerDumpRoot confines dump_memory, save_state, vram_dump, screenshot and load_state. "
                          "It defaults to the user's home directory."}};

    guide["remember"] =
        "You have full control over PS1 emulation. Pause, inspect, step, search, and analyze. Build understanding "
        "incrementally. Use breakpoints to mark discoveries.";

    return {true, guide.dump(2), ""};  // Pretty print with 2-space indent
}

// Helper: sanitize a tag or filename fragment so it is safe for filesystem use
static std::string sanitizeFilenameTag(const std::string& tag) {
    std::string result;
    result.reserve(tag.size());
    for (char c : tag) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.') {
            result += c;
        } else {
            result += '_';
        }
    }
    if (result.empty()) result = "dump";
    return result;
}

// Helper: generate ISO 8601-ish timestamp for filenames
static std::string getTimestampString() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t_now);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y%m%d_%H%M%S");
    return ss.str();
}

MCPServer::ToolResult MCPServer::ToolDumpMemory(uint32_t address, uint32_t length, const std::string& tag,
                                                const std::string& output_dir) {
    if (!g_emulator || !g_emulator->m_mem) {
        return {false, "", "Emulator not initialized"};
    }

    if (length == 0 || length > 0x00800000) {
        return {false, "", "Invalid dump length (must be > 0 and <= 8MB)"};
    }

    std::vector<uint8_t> buffer;
    if (!ReadGuestMemory(address, length, buffer)) {
        return {false, "", "Address range is not readable guest memory (RAM, scratchpad, BIOS or EXP1)"};
    }

    // Pause emulator to ensure a consistent snapshot
    g_system->pause();

    try {
        std::filesystem::path outDir;
        std::string pathError;
        if (!ResolveHostPath(output_dir, outDir, pathError)) {
            return {false, "", pathError};
        }
        std::filesystem::create_directories(outDir);

        std::string safeTag = sanitizeFilenameTag(tag);
        std::string ts = getTimestampString();

        std::string baseName = safeTag + "_" + ts;
        std::filesystem::path binPath = outDir / (baseName + ".bin");
        std::filesystem::path jsonPath = outDir / (baseName + ".json");

        // Read memory and write binary file
        std::ofstream binFile(binPath.string(), std::ios::binary);
        if (!binFile) {
            return {false, "", "Failed to open binary file for writing: " + binPath.string()};
        }

        binFile.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        binFile.close();

        uint32_t pc = g_emulator->m_cpu ? g_emulator->m_cpu->m_regs.pc : 0;

        // Build manifest
        nlohmann::json manifest;
        std::stringstream addrSS;
        addrSS << "0x" << std::hex << std::setfill('0') << std::setw(8) << address;
        manifest["base_address"] = addrSS.str();
        manifest["size"] = length;
        manifest["tag"] = tag;
        manifest["dumped_at_pc"] = pc;
        manifest["timestamp"] = ts;
        manifest["filename"] = baseName + ".bin";
        manifest["manifest_filename"] = baseName + ".json";
        manifest["note"] = "Import this .bin into Ghidra as an overlay block at the base_address.";

        std::ofstream jsonFile(jsonPath.string());
        if (!jsonFile) {
            return {false, "", "Failed to open manifest file for writing: " + jsonPath.string()};
        }
        jsonFile << manifest.dump(2);
        jsonFile.close();

        nlohmann::json result;
        result["status"] = "success";
        result["bin_path"] = binPath.string();
        result["json_path"] = jsonPath.string();
        result["base_address"] = addrSS.str();
        result["size"] = length;
        result["tag"] = tag;

        return {true, result.dump(2), ""};
    } catch (const std::filesystem::filesystem_error& e) {
        return {false, "", std::string("Filesystem error: ") + e.what()};
    } catch (const std::exception& e) {
        return {false, "", std::string("Error during dump: ") + e.what()};
    }
}

MCPServer::ToolResult MCPServer::ToolSnapshotRAM(const std::string& tag, const std::string& output_dir) {
    if (!g_emulator || !g_emulator->m_mem) {
        return {false, "", "Emulator not initialized"};
    }

    // Snapshot the full 2MB main WRAM region (0x00000000 - 0x001FFFFF in KUSEG, same bytes mirrored in KSEG0)
    // m_wram is 8MB but the active PSX RAM window is 2MB unless expansion is enabled. We'll dump the full m_wram
    // size actually used by the emulator, but cap at 2MB for standard PSX behaviour.
    uint32_t ramSize = 0x00200000;
    return ToolDumpMemory(0x00000000, ramSize, tag, output_dir);
}

MCPServer::ToolResult MCPServer::ToolVRAMDump(const std::string& path) {
    if (!g_emulator || !g_emulator->m_gpu) {
        return {false, "", "Emulator not initialized"};
    }
    g_system->pause();

    auto vram = g_emulator->m_gpu->getVRAM();
    std::filesystem::path outPath;
    std::string pathError;
    if (!ResolveHostPath(path, outPath, pathError)) return {false, "", pathError};
    if (outPath.has_parent_path()) {
        std::filesystem::create_directories(outPath.parent_path());
    }
    std::ofstream out(outPath, std::ios::binary);
    if (!out) {
        return {false, "", "Cannot open " + outPath.string()};
    }
    out.write(reinterpret_cast<const char*>(vram.data()), vram.size());
    out.close();

    nlohmann::json result;
    result["path"] = outPath.string();
    result["bytes"] = vram.size();
    result["width"] = 1024;
    result["height"] = 512;
    result["format"] = "bgr555le";
    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolScreenshot(const std::string& path) {
    if (!g_emulator || !g_emulator->m_gpu) {
        return {false, "", "Emulator not initialized"};
    }
    g_system->pause();

    auto shot = g_emulator->m_gpu->takeScreenShot();
    const uint8_t* src = reinterpret_cast<const uint8_t*>(shot.data.data());
    const size_t pixels = static_cast<size_t>(shot.width) * shot.height;
    std::vector<uint8_t> rgb(pixels * 3);

    if (shot.bpp == GPU::ScreenShot::BPP_24) {
        std::memcpy(rgb.data(), src, pixels * 3);
    } else {
        const uint16_t* p = reinterpret_cast<const uint16_t*>(src);
        for (size_t i = 0; i < pixels; i++) {
            uint16_t v = p[i];
            rgb[i * 3 + 0] = static_cast<uint8_t>((v & 0x1F) << 3);
            rgb[i * 3 + 1] = static_cast<uint8_t>(((v >> 5) & 0x1F) << 3);
            rgb[i * 3 + 2] = static_cast<uint8_t>(((v >> 10) & 0x1F) << 3);
        }
    }

    std::filesystem::path outPath;
    std::string pathError;
    if (!ResolveHostPath(path, outPath, pathError)) return {false, "", pathError};
    if (outPath.has_parent_path()) {
        std::filesystem::create_directories(outPath.parent_path());
    }
    std::ofstream out(outPath, std::ios::binary);
    if (!out) {
        return {false, "", "Cannot open " + outPath.string()};
    }
    out << "P6\n" << shot.width << " " << shot.height << "\n255\n";
    out.write(reinterpret_cast<const char*>(rgb.data()), rgb.size());
    out.close();

    nlohmann::json result;
    result["path"] = outPath.string();
    result["width"] = shot.width;
    result["height"] = shot.height;
    result["bpp"] = (shot.bpp == GPU::ScreenShot::BPP_24) ? 24 : 16;
    result["format"] = "ppm-p6";
    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolWriteMemory(uint32_t address, uint32_t value, uint32_t size) {
    if (!g_emulator || !g_emulator->m_mem) {
        return {false, "", "Emulator not initialized"};
    }
    switch (size) {
        case 8:
            g_emulator->m_mem->write8(address, value & 0xFF);
            break;
        case 16:
            g_emulator->m_mem->write16(address, value & 0xFFFF);
            break;
        case 32:
            g_emulator->m_mem->write32(address, value);
            break;
        default:
            return {false, "", "size must be 8, 16 or 32"};
    }

    std::stringstream addrSS;
    addrSS << "0x" << std::hex << std::setfill('0') << std::setw(8) << address;
    nlohmann::json result;
    result["address"] = addrSS.str();
    result["value"] = value;
    result["size"] = size;
    result["message"] = "memory written";
    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolSaveState(const std::string& path) {
    if (!g_emulator) {
        return {false, "", "Emulator not initialized"};
    }
    std::string data = SaveStates::save();

    std::filesystem::path outPath;
    std::string pathError;
    if (!ResolveHostPath(path, outPath, pathError)) return {false, "", pathError};
    if (outPath.has_parent_path()) {
        std::filesystem::create_directories(outPath.parent_path());
    }
    std::ofstream out(outPath, std::ios::binary);
    if (!out) {
        return {false, "", "Cannot open " + outPath.string()};
    }
    out.write(data.data(), data.size());
    out.close();

    nlohmann::json result;
    result["path"] = outPath.string();
    result["bytes"] = data.size();
    return {true, result.dump(), ""};
}

MCPServer::ToolResult MCPServer::ToolLoadState(const std::string& path) {
    if (!g_emulator) {
        return {false, "", "Emulator not initialized"};
    }
    std::filesystem::path inPath;
    std::string pathError;
    if (!ResolveHostPath(path, inPath, pathError)) return {false, "", pathError};
    std::ifstream in(inPath, std::ios::binary);
    if (!in) {
        return {false, "", "Cannot open " + inPath.string()};
    }
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    g_system->pause();
    bool ok = SaveStates::load(data);
    if (!ok) {
        return {false, "", "SaveStates::load rejected the file"};
    }

    nlohmann::json result;
    result["path"] = path;
    result["bytes"] = data.size();
    result["message"] = "state loaded, emulator paused";
    return {true, result.dump(), ""};
}

}  // namespace PCSX
