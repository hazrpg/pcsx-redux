/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "core/mcp-server.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "third_party/json.hpp"

namespace {

nlohmann::json rpc(const std::string& method, nlohmann::json params = nlohmann::json::object(), bool withId = true) {
    nlohmann::json request;
    request["jsonrpc"] = "2.0";
    if (withId) request["id"] = 1;
    request["method"] = method;
    request["params"] = std::move(params);
    const std::string raw = PCSX::MCPServer::HandleMCPRequest(request.dump());
    if (raw.empty()) return nlohmann::json();
    return nlohmann::json::parse(raw);
}

}  // namespace

TEST(MCPServer, InitializeEchoesKnownProtocolVersion) {
    const auto response = rpc("initialize", {{"protocolVersion", "2025-03-26"}});
    ASSERT_TRUE(response.contains("result"));
    EXPECT_EQ(response["result"]["protocolVersion"], "2025-03-26");
    EXPECT_EQ(response["result"]["serverInfo"]["name"], "PCSX-Redux MCP Server");
}

TEST(MCPServer, InitializeFallsBackToLatestForUnknownVersion) {
    const auto response = rpc("initialize", {{"protocolVersion", "1999-01-01"}});
    ASSERT_TRUE(response.contains("result"));
    EXPECT_EQ(response["result"]["protocolVersion"], "2025-06-18");
}

TEST(MCPServer, PingReturnsAnEmptyResult) {
    const auto response = rpc("ping");
    ASSERT_TRUE(response.contains("result"));
    EXPECT_TRUE(response["result"].is_object());
    EXPECT_TRUE(response["result"].empty());
}

TEST(MCPServer, ToolsListIncludesSchemas) {
    const auto response = rpc("tools/list");
    ASSERT_TRUE(response.contains("result"));
    bool sawDumpMemory = false;
    bool sawListGpuCommands = false;
    for (const auto& tool : response["result"]["tools"]) {
        const std::string name = tool["name"];
        EXPECT_TRUE(tool.contains("inputSchema"));
        if (name == "dump_memory") sawDumpMemory = true;
        if (name == "list_gpu_commands") sawListGpuCommands = true;
    }
    EXPECT_TRUE(sawDumpMemory);
    EXPECT_FALSE(sawListGpuCommands);
}

TEST(MCPServer, NotificationsGetNoResponse) {
    const auto response = rpc("notifications/initialized", nlohmann::json::object(), false);
    EXPECT_TRUE(response.is_null());
}

TEST(MCPServer, MalformedJsonIsAParseError) {
    const std::string raw = PCSX::MCPServer::HandleMCPRequest("{not json");
    const auto response = nlohmann::json::parse(raw);
    EXPECT_EQ(response["error"]["code"], -32700);
}

TEST(MCPServer, UnknownMethodIsMethodNotFound) {
    const auto response = rpc("does/not/exist");
    ASSERT_TRUE(response.contains("error"));
    EXPECT_EQ(response["error"]["code"], -32601);
}

TEST(MCPServer, UnknownToolIsReportedAsAToolError) {
    const auto response = rpc("tools/call", {{"name", "no_such_tool"}, {"arguments", nlohmann::json::object()}});
    ASSERT_TRUE(response.contains("result"));
    EXPECT_TRUE(response["result"]["isError"]);
}

TEST(MCPServer, MutatingToolsAreClassified) {
    EXPECT_TRUE(PCSX::MCPServer::IsMutatingTool("write_memory"));
    EXPECT_TRUE(PCSX::MCPServer::IsMutatingTool("dump_memory"));
    EXPECT_FALSE(PCSX::MCPServer::IsMutatingTool("get_cpu_state"));
    EXPECT_FALSE(PCSX::MCPServer::IsMutatingTool("hexdump"));
}
