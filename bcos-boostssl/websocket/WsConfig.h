/*
 *  Copyright (C) 2021 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @file WsConfig.h
 * @author: octopus
 * @date 2021-08-23
 */
#pragma once

#include <bcos-framework/libutilities/Log.h>
#include <boost/asio/ip/tcp.hpp>
#include <cstdint>
#include <memory>
#include <vector>

#include <bcos-boostssl/network/Common.h>
namespace bcos
{
namespace boostssl
{
namespace ws
{
struct EndPoint
{
    std::string host;
    uint16_t port;
};

using EndPoints = std::vector<EndPoint>;
using EndPointsPtr = std::shared_ptr<std::vector<EndPoint>>;
using EndPointsConstPtr = std::shared_ptr<const std::vector<EndPoint>>;

enum WsModel : uint16_t
{
    Client = 0x01,
    Server = 0x10,
    Mixed = Client | Server
};

class WsConfig
{
public:
    using Ptr = std::shared_ptr<WsConfig>;
    using ConstPtr = std::shared_ptr<const WsConfig>;

private:
    // ws work model, as server or as client or server & client
    WsModel m_model = WsModel::Mixed;

    // the listen ip when ws work as server
    std::string m_listenIP;
    // the listen port when ws work as server
    uint16_t m_listenPort;

    // list of connected server nodes when ws work as client
    EndPointsConstPtr m_connectedPeers;

    // time out for send message
    int32_t m_sendMsgTimeout{-1};
    // thread pool size
    uint32_t m_threadPoolSize{4};

    // time interval for reconnection
    uint32_t m_reconnectPeriod{10000};

    // time interval for heartbeat
    uint32_t m_heartbeatPeriod{10000};

public:
    static bool validIP(const std::string& _ip)
    {
        boost::system::error_code ec;
        boost::asio::ip::address::from_string(_ip, ec);
        if (ec)
        {
            return false;
        }
        return true;
    }
    static bool validPort(uint16_t _port) { return (_port <= 65535 && _port > 1024); }

public:
    void setModel(WsModel _model) { m_model = _model; }
    WsModel model() const { return m_model; }

    bool asClient() { return m_model & WsModel::Client; }
    bool asServer() const { return m_model & WsModel::Server; }

    void setListenIP(const std::string _listenIP) { m_listenIP = _listenIP; }
    std::string listenIP() const { return m_listenIP; }

    void setListenPort(uint16_t _listenPort) { m_listenPort = _listenPort; }
    uint16_t listenPort() const { return m_listenPort; }

    uint32_t reconnectPeriod() const { return m_reconnectPeriod; }
    void setReconnectPeriod(uint32_t _reconnectPeriod) { m_reconnectPeriod = _reconnectPeriod; }

    uint32_t heartbeatPeriod() const { return m_heartbeatPeriod; }
    void setHeartbeatPeriod(uint32_t _heartbeatPeriod) { m_heartbeatPeriod = _heartbeatPeriod; }

    int32_t sendMsgTimeout() const { return m_sendMsgTimeout; }
    void setSendMsgTimeout(int32_t _sendMsgTimeout) { m_sendMsgTimeout = _sendMsgTimeout; }

    uint32_t threadPoolSize() const { return m_threadPoolSize; }
    void setThreadPoolSize(uint32_t _threadPoolSize) { m_threadPoolSize = _threadPoolSize; }

    EndPointsConstPtr connectedPeers() { return m_connectedPeers; }
    void setConnectedPeers(EndPointsConstPtr _connectedPeers)
    {
        m_connectedPeers = _connectedPeers;
    }
};
}  // namespace ws
}  // namespace boostssl
}  // namespace bcos
