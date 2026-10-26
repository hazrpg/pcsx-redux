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

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "src/core/psxemulator.h" // Path relative to pcsx-redux/
#include "src/core/psxmem.h"    // Path relative to pcsx-redux/
#include "src/core/gpu.h"       // Path relative to pcsx-redux/
#include "src/core/psxhw.h"     // Path relative to pcsx-redux/

namespace PCSX {

/**
 * @brief MCP (Model Context Protocol) Server for PCSX-Redux
 *
 * This server provides real-time access to emulator state for AI analysis
 * and integration with tools like GhidrAssistMCP.
 */
class MCPServer {
  public:
    /**
     * @brief MCP Tool definition
     */
    struct Tool {
        std::string name;
        std::string description;
    };

    /**
     * @brief MCP Tool call result
     */
    struct ToolResult {
        bool success;
        std::string content;
        std::string error;
    };

    /**
     * @brief CPU State structure
     */
    struct CPUState {
        uint32_t pc;
        uint32_t sp;
        uint32_t gp;
        uint32_t fp;
        uint32_t ra;
        uint32_t s0;
        uint32_t s1;
        uint32_t s2;

        // Current instruction
        uint32_t instruction;
        std::string instruction_hex;
        std::string instruction_decoded;

        // Breakdown of instruction
        struct InstructionBreakdown {
            uint32_t opcode;
            uint32_t target;
            std::string translated;
            std::string operation;
        };
        InstructionBreakdown breakdown;
    };

    /**
     * @brief Memory Region State
     */
    struct MemoryRegion {
        enum class Type {
            RAM,
            VRAM,
            ROM,
            HW
        };

        Type type;
        uint32_t start;
        uint32_t end;
        std::string size;
    };

    /**
     * @brief Memory State
     */
    struct MemoryState {
        std::unordered_map<std::string, MemoryRegion> regions;
        std::vector<uint8_t> ram;
        std::vector<uint8_t> vram;
        std::vector<uint8_t> rom;
    };

    /**
     * @brief GPU State
     */
    struct GPUState {
        uint32_t gpu_read;
        uint32_t gpu_reg;
        uint32_t gp1;
        uint32_t status;
        bool dirty_flag;

        // Display mode
        struct DisplayMode {
            uint32_t mode;
            uint32_t width;
            uint32_t height;
            uint32_t refresh_rate;
        };
        DisplayMode display_mode;
    };

    /**
     * @brief Hardware State
     */
    struct HardwareState {
        // GPU registers
        struct GPURegister {
            uint32_t gpu_read;
            uint32_t gpu_reg;
            uint32_t gp1;
            uint32_t status;
        };
        GPURegister gpu;

        // DMA channels
        struct DMAChannel {
            uint32_t address;
            uint32_t value;
            bool active;
            uint32_t transfer_mode;
            uint32_t transfer_count;
        };
        DMAChannel dma[8];

        // Counters
        struct Counter {
            uint32_t value;
            uint32_t mode;
            bool enabled;
        };
        Counter counter[4];
    };

    /**
     * @brief Breakpoint state
     */
    struct Breakpoint {
        uint32_t address;
        std::string condition;
        bool hit;
        bool enabled;
    };

    /**
     * @brief MCP Server Configuration
     */
    struct Config {
        std::string host = "127.0.0.1";
        uint16_t port = 32769;
        bool auto_start = false;
        bool verbose = true;
    };

    /**
     * @brief Get all available tools
     */
    static std::vector<Tool> ListTools();

    /**
     * @brief Execute a tool
     */
    static ToolResult ExecuteTool(const std::string& tool_name, const std::string& arguments);

    /**
     * @brief Get CPU State
     */
    static CPUState GetCPUState();

    /**
     * @brief Get Memory State
     */
    static MemoryState GetMemoryState();

    /**
     * @brief Get GPU State
     */
    static GPUState GetGPUState();

    /**
     * @brief Get Hardware State
     */
    static HardwareState GetHardwareState();

    /**
     * @brief Get Breakpoints
     */
    static std::vector<Breakpoint> GetBreakpoints();

    /**
     * @brief Set a Breakpoint
     */
    static bool SetBreakpoint(uint32_t address, const std::string& condition = "");

    /**
     * @brief Clear a Breakpoint
     */
    static bool ClearBreakpoint(uint32_t address);

    /**
     * @brief Get list of hardware registers
     */
    static std::vector<std::string> ListHardwareRegisters();

    /**
     * @brief Read a hardware register
     */
    static uint32_t ReadHardwareRegister(const std::string& register_name);

    /**
     * @brief Write to a hardware register
     */
    static bool WriteHardwareRegister(const std::string& register_name, uint32_t value);

    /**
     * @brief Get DMA State
     */
    static HardwareState::DMAChannel GetDMAState(uint32_t channel);

    /**
     * @brief Get Call Chain
     */
    static std::vector<std::string> GetCallChain(uint32_t max_depth = 10);

    /**
     * @brief Get Call Graph for a function
     */
    static std::vector<std::string> GetCallGraph(const std::string& function_name, uint32_t depth = 3);

    /**
     * @brief Get Emulator State
     */
    static std::string GetEmulatorState();

    // MCP Protocol Handler
    static std::string HandleMCPRequest(const std::string& request);

    // Internal state
    static Config config_;

    // Breakpoints storage
    static std::unordered_map<uint32_t, Breakpoint> breakpoints_;

    // Tool registry
    static std::unordered_map<std::string, Tool> tools_;

  private:
    MCPServer() = default;
    ~MCPServer() = default;

    // Internal helper to register all tools
    static void RegisterToolsIfNeeded();

    // Tool implementations (these are private helper functions for ExecuteTool)
    static ToolResult ToolGetCPUState();
    static ToolResult ToolGetMemoryMap();
    static ToolResult ToolGetMemoryRange(uint32_t address, uint32_t length);
    static ToolResult ToolFindString(const std::string& pattern, const std::string& region);
    static ToolResult ToolSearchBytes(const std::string& pattern, const std::string& region);
    static ToolResult ToolHexdump(uint32_t address, uint32_t length);
    static ToolResult ToolGetGPUState();
    static ToolResult ToolListGPUCommands(uint32_t limit);
    static ToolResult ToolListHardwareRegisters();
    static ToolResult ToolReadHardwareRegister(const std::string& register_name);
    static ToolResult ToolWriteHardwareRegister(const std::string& register_name, uint32_t value);
    static ToolResult ToolGetDMAState(uint32_t channel);
    static ToolResult ToolSetBreakpoint(uint32_t address);
    static ToolResult ToolGetBreakpoints();
    static ToolResult ToolClearBreakpoint(uint32_t address);
    static ToolResult ToolGetCallChain(uint32_t max_depth);
    static ToolResult ToolGetCallGraph(const std::string& function_name, uint32_t depth);
    static ToolResult ToolDumpMemory(uint32_t address, uint32_t length, const std::string& tag, const std::string& output_dir);
    static ToolResult ToolSnapshotRAM(const std::string& tag, const std::string& output_dir);
    static ToolResult ToolVRAMDump(const std::string& path);
    static ToolResult ToolScreenshot(const std::string& path);
    static ToolResult ToolWriteMemory(uint32_t address, uint32_t value, uint32_t size);
    static ToolResult ToolSaveState(const std::string& path);
    static ToolResult ToolLoadState(const std::string& path);

    // Execution control tools
    static ToolResult ToolPause();
    static ToolResult ToolResume();
    static ToolResult ToolStepIn();
    static ToolResult ToolStepOver();
    static ToolResult ToolStepOut();
    static ToolResult ToolRunToAddress(uint32_t address);
    static ToolResult ToolGetExecutionState();
    static ToolResult ToolGetEmulatorState();
    static ToolResult ToolIsGameLoaded();
    static ToolResult ToolHowToUseMCP();

    // Utility functions
    static std::string SerializeState(const CPUState& state);
    static std::string SerializeState(const MemoryState& state);
    static std::string SerializeState(const GPUState& state);
    static std::string SerializeState(const HardwareState& state);
};

}  // namespace PCSX
