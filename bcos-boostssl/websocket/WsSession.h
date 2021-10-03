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
 *  m_limitations under the License.
 *
 * @file WsSession.h
 * @author: octopus
 * @date 2021-07-28
 */
#pragma once
#include <bcos-boostssl/httpserver/Common.h>
#include <bcos-boostssl/websocket/Common.h>
#include <bcos-boostssl/websocket/WsMessage.h>
#include <bcos-framework/libutilities/Common.h>
#include <bcos-framework/libutilities/ThreadPool.h>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <atomic>
#include <shared_mutex>
#include <unordered_map>

namespace bcos
{
namespace boostssl
{
class ThreadPool;
namespace ws
{
class WsService;

// The websocket session for connection
class WsSession : public std::enable_shared_from_this<WsSession>
{
public:
    using Ptr = std::shared_ptr<WsSession>;
    using Ptrs = std::vector<std::shared_ptr<WsSession>>;

public:
    WsSession(boost::beast::websocket::stream<boost::beast::tcp_stream>&& _wsStream);

    virtual ~WsSession()
    {
        disconnect();
        WEBSOCKET_SESSION(INFO) << LOG_KV("[DELOBJ][WSSESSION]", this);
    }

    void drop(uint32_t _reason);
    void disconnect();

public:
    void initWsStream(bool _client);
    // start WsSession as server
    void doRun();
    // start WsSession as client
    void doAccept(bcos::boostssl::http::HttpRequest _req);
    void onAccept(boost::beast::error_code _ec);
    // async read
    void onRead(boost::beast::error_code _ec, std::size_t);
    void asyncRead();
    // async write
    void onWrite(boost::beast::error_code _ec, std::size_t);
    void asyncWrite();

    void ping();
    void pong();

public:
    virtual bool isConnected() { return !m_isDrop && m_wsStream.next_layer().socket().is_open(); }
    /**
     * @brief: async send message
     * @param _msg: message
     * @param _options: options
     * @param _respCallback: callback
     * @return void:
     */
    virtual void asyncSendMessage(std::shared_ptr<WsMessage> _msg, Options _options = Options(-1),
        RespCallBack _respCallback = RespCallBack());

public:
    std::string endPoint() const { return m_endPoint; }
    void setEndPoint(const std::string& _endPoint) { m_endPoint = _endPoint; }

    std::string connectedEndPoint() const { return m_connectedEndPoint; }
    void setConnectedEndPoint(const std::string& _connectedEndPoint)
    {
        m_connectedEndPoint = _connectedEndPoint;
    }

    void setConnectHandler(WsConnectHandler _connectHandler) { m_connectHandler = _connectHandler; }
    WsConnectHandler connectHandler() { return m_connectHandler; }

    void setDisconnectHandler(WsDisconnectHandler _disconnectHandler)
    {
        m_disconnectHandler = _disconnectHandler;
    }
    WsDisconnectHandler disconnectHandler() { return m_disconnectHandler; }

    void setRecvMessageHandler(WsRecvMessageHandler _recvMessageHandler)
    {
        m_recvMessageHandler = _recvMessageHandler;
    }
    WsRecvMessageHandler recvMessageHandler() { return m_recvMessageHandler; }

    void setHandlshakeHandler(WsHandshakeHandler _handlshakeHandler)
    {
        m_handlshakeHandler = _handlshakeHandler;
    }
    WsHandshakeHandler handlshakeHandler() { return m_handlshakeHandler; }

    std::shared_ptr<WsMessageFactory> messageFactory() { return m_messageFactory; }
    void setMessageFactory(std::shared_ptr<WsMessageFactory> _messageFactory)
    {
        m_messageFactory = _messageFactory;
    }

    std::shared_ptr<bcos::ThreadPool> threadPool() const { return m_threadPool; }
    void setThreadPool(std::shared_ptr<bcos::ThreadPool> _threadPool)
    {
        m_threadPool = _threadPool;
    }

    void setVersion(uint16_t _version) { m_version.store(_version); }
    uint16_t version() const { return m_version.load(); }

    std::size_t queueSize()
    {
        std::shared_lock lock(x_queue);
        return m_queue.size();
    }

    bool client() { return m_client; }
    void setClient(bool _client) { m_client = _client; }

    struct CallBack
    {
        using Ptr = std::shared_ptr<CallBack>;
        RespCallBack respCallBack;
        std::shared_ptr<boost::asio::deadline_timer> timer;
    };
    void addRespCallback(const std::string& _seq, CallBack::Ptr _callback);
    CallBack::Ptr getAndRemoveRespCallback(const std::string& _seq);
    void onRespTimeout(const boost::system::error_code& _error, const std::string& _seq);

private:
    // server or client session
    bool m_client = false;

    // websocket protocol version
    std::atomic<uint16_t> m_version;

    // buffer used to read message
    boost::beast::flat_buffer m_buffer;
    //
    std::atomic_bool m_isDrop = false;
    // websocket stream
    boost::beast::websocket::stream<boost::beast::tcp_stream> m_wsStream;
    std::string m_endPoint;
    std::string m_connectedEndPoint;

    // callbacks
    mutable std::shared_mutex x_callback;
    std::unordered_map<std::string, CallBack::Ptr> m_callbacks;

    // callback handler
    WsConnectHandler m_connectHandler;
    WsDisconnectHandler m_disconnectHandler;
    WsRecvMessageHandler m_recvMessageHandler;
    WsHandshakeHandler m_handlshakeHandler;

    // message factory
    std::shared_ptr<WsMessageFactory> m_messageFactory;
    // thread pool
    std::shared_ptr<bcos::ThreadPool> m_threadPool;

    // send message queue
    mutable std::shared_mutex x_queue;
    std::vector<std::shared_ptr<bcos::bytes>> m_queue;
};

}  // namespace ws
}  // namespace boostssl
}  // namespace bcos