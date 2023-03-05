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
#include "bcos-boostssl/interfaces/MessageFace.h"
#include <bcos-boostssl/httpserver/Common.h>
#include <bcos-boostssl/websocket/Common.h>
#include <bcos-boostssl/websocket/WsMessage.h>
#include <bcos-boostssl/websocket/WsStream.h>
#include <bcos-utilities/Common.h>
#include <bcos-utilities/ThreadPool.h>
#include <bcos-utilities/Timer.h>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/thread/thread.hpp>
#include <atomic>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <unordered_map>

namespace bcos
{
namespace boostssl
{
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
    WsSession(std::string _moduleName = "DEFAULT");

    virtual ~WsSession() { WEBSOCKET_SESSION(INFO) << LOG_KV("[DELOBJ][WSSESSION]", this); }

    void drop(uint32_t _reason);

public:
    // start WsSession as client
    void startAsClient();
    // start WsSession as server
    void startAsServer(bcos::boostssl::http::HttpRequest _httpRequest);

    virtual void onMessage(bcos::boostssl::MessageFace::Ptr _message);


    virtual bool isConnected()
    {
        return !m_isDrop && m_wsStreamDelegate && m_wsStreamDelegate->open();
    }
    /**
     * @brief: async send message
     * @param _msg: message
     * @param _options: options
     * @param _respCallback: callback
     * @return void:
     */
    virtual void asyncSendMessage(std::shared_ptr<boostssl::MessageFace> _msg,
        Options _options = Options(), RespCallBack _respCallback = RespCallBack());


    std::string endPoint() const { return m_endPoint; }
    void setEndPoint(const std::string& _endPoint) { m_endPoint = _endPoint; }

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

    std::shared_ptr<MessageFaceFactory> messageFactory() { return m_messageFactory; }
    void setMessageFactory(std::shared_ptr<MessageFaceFactory> _messageFactory)
    {
        m_messageFactory = _messageFactory;
    }

    std::shared_ptr<boost::asio::io_context> ioc() const { return m_ioc; }
    void setIoc(std::shared_ptr<boost::asio::io_context> _ioc) { m_ioc = _ioc; }

    std::shared_ptr<bcos::ThreadPool> threadPool() const { return m_threadPool; }
    void setThreadPool(std::shared_ptr<bcos::ThreadPool> _threadPool)
    {
        m_threadPool = _threadPool;
    }

    void setVersion(uint16_t _version) { m_version.store(_version); }
    uint16_t version() const { return m_version.load(); }

    WsStreamDelegate::Ptr wsStreamDelegate() { return m_wsStreamDelegate; }
    void setWsStreamDelegate(WsStreamDelegate::Ptr _wsStreamDelegate)
    {
        m_wsStreamDelegate = _wsStreamDelegate;
    }

    boost::beast::flat_buffer& buffer() { return m_buffer; }
    void setBuffer(boost::beast::flat_buffer _buffer) { m_buffer = std::move(_buffer); }

    int32_t sendMsgTimeout() const { return m_sendMsgTimeout; }
    void setSendMsgTimeout(int32_t _sendMsgTimeout) { m_sendMsgTimeout = _sendMsgTimeout; }

    int32_t maxWriteMsgSize() const { return m_maxWriteMsgSize; }
    void setMaxWriteMsgSize(int32_t _maxWriteMsgSize) { m_maxWriteMsgSize = _maxWriteMsgSize; }

    std::string nodeId() { return m_nodeId; }
    void setNodeId(std::string _nodeId) { m_nodeId = _nodeId; }

    std::string moduleName() { return m_moduleName; }
    void setModuleName(std::string _moduleName) { m_moduleName = _moduleName; }

    bool needCheckRspPacket() { return m_needCheckRspPacket; }
    void setNeedCheckRspPacket(bool _needCheckRespPacket)
    {
        m_needCheckRspPacket = _needCheckRespPacket;
    }

    std::size_t writeQueueSize()
    {
        bcos::Guard lockGuard(x_writeQueue);
        return m_writeQueue.size();
    }

    std::size_t callbackQueueSize()
    {
        bcos::Guard lockGuard(x_callback);
        return m_callbacks.size();
    }

protected:
    struct CallBack
    {
        using Ptr = std::shared_ptr<CallBack>;
        RespCallBack respCallBack;
        std::shared_ptr<boost::asio::deadline_timer> timer;
    };
    virtual void addRespCallback(const std::string& _seq, CallBack::Ptr _callback);
    CallBack::Ptr getAndRemoveRespCallback(
        const std::string& _seq, std::shared_ptr<MessageFace> _message = nullptr);
    virtual void onRespTimeout(const boost::system::error_code& _error, const std::string& _seq);

    virtual void onWsAccept(boost::beast::error_code _ec);

    virtual void asyncRead();
    virtual void onRead(boost::system::error_code ec, std::size_t bytes_transferred);
    virtual void onReadPacket(boost::beast::flat_buffer& _buffer);

    virtual void asyncWrite(std::shared_ptr<EncodedMsg> _encodeMsg);
    virtual void send(const std::shared_ptr<EncodedMsg>& _encodedMsg);
    void write();
    void onWrite(boost::beast::error_code _ec, std::size_t _size);

protected:
    // flag for message that need to check respond packet like p2p message
    bool m_needCheckRspPacket = false;
    //
    std::atomic_bool m_isDrop = false;
    // websocket protocol version
    std::atomic<uint16_t> m_version = 0;
    std::string m_moduleName;

    // buffer used to read message
    boost::beast::flat_buffer m_buffer;

    std::string m_endPoint;
    std::string m_connectedEndPoint;
    std::string m_nodeId;

    //
    int32_t m_sendMsgTimeout = -1;
    //
    int32_t m_maxWriteMsgSize = -1;

    //
    WsStreamDelegate::Ptr m_wsStreamDelegate;
    // callbacks
    mutable bcos::Mutex x_callback;
    std::unordered_map<std::string, CallBack::Ptr> m_callbacks;

    // callback handler
    WsConnectHandler m_connectHandler;
    WsDisconnectHandler m_disconnectHandler;
    WsRecvMessageHandler m_recvMessageHandler;

    // message factory
    std::shared_ptr<MessageFaceFactory> m_messageFactory;
    // thread pool
    std::shared_ptr<bcos::ThreadPool> m_threadPool;
    // ioc
    std::shared_ptr<boost::asio::io_context> m_ioc;

    // send message queue
    mutable bcos::Mutex x_writeQueue;
    std::list<std::shared_ptr<EncodedMsg>> m_writeQueue;
    std::atomic_bool m_writing = {false};
};

class WsSessionFactory
{
public:
    using Ptr = std::shared_ptr<WsSessionFactory>;
    WsSessionFactory() = default;
    virtual ~WsSessionFactory() {}

public:
    virtual WsSession::Ptr createSession(std::string _moduleName)
    {
        auto session = std::make_shared<WsSession>(_moduleName);
        return session;
    }
};

}  // namespace ws
}  // namespace boostssl
}  // namespace bcos
