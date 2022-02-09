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
 * @file WsSession.cpp
 * @author: octopus
 * @date 2021-07-08
 */

#include <bcos-boostssl/websocket/WsError.h>
#include <bcos-boostssl/websocket/WsSession.h>
#include <bcos-utilities/BoostLog.h>
#include <bcos-utilities/Common.h>
#include <bcos-utilities/ThreadPool.h>
#include <boost/beast/websocket/rfc6455.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <boost/core/ignore_unused.hpp>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

using namespace bcos;
using namespace bcos::boostssl;
using namespace bcos::boostssl::ws;
using namespace bcos::boostssl::http;

void WsSession::drop(uint32_t _reason)
{
    if (m_isDrop)
    {
        WEBSOCKET_SESSION(INFO) << LOG_BADGE("drop")
                                << LOG_DESC("the session has already been dropped")
                                << LOG_KV("endpoint", m_endPoint) << LOG_KV("session", this);
        return;
    }

    m_isDrop = true;

    WEBSOCKET_SESSION(INFO) << LOG_BADGE("drop") << LOG_KV("reason", _reason)
                            << LOG_KV("endpoint", m_endPoint) << LOG_KV("session", this);

    auto self = std::weak_ptr<WsSession>(shared_from_this());
    // call callbacks
    {
        auto error = std::make_shared<Error>(
            WsError::SessionDisconnect, "the session has been disconnected");

        boost::shared_lock<boost::shared_mutex> lock(x_callback);
        for (auto& cbEntry : m_callbacks)
        {
            auto callback = cbEntry.second;
            if (callback->timer)
            {
                callback->timer->cancel();
            }

            WEBSOCKET_SESSION(TRACE)
                << LOG_DESC("the session has been disconnected") << LOG_KV("seq", cbEntry.first);

            m_threadPool->enqueue(
                [callback, error]() { callback->respCallBack(error, nullptr, nullptr); });
        }
    }

    // clear callbacks
    {
        boost::unique_lock<boost::shared_mutex> lock(x_callback);
        m_callbacks.clear();
    }

    if (m_wsStreamDelegate)
    {
        m_wsStreamDelegate->close();
    }

    m_threadPool->enqueue([self]() {
        auto session = self.lock();
        if (session)
        {
            session->disconnectHandler()(nullptr, session);
        }
    });
}

// start WsSession as client
void WsSession::startAsClient()
{
    if (m_connectHandler)
    {
        auto session = shared_from_this();
        m_connectHandler(nullptr, session);
    }

    // read message
    asyncRead();

    WEBSOCKET_SESSION(INFO) << LOG_BADGE("startAsClient")
                            << LOG_DESC("websocket handshake successfully")
                            << LOG_KV("endPoint", m_endPoint) << LOG_KV("session", this);
}

// start WsSession as server
void WsSession::startAsServer(HttpRequest _httpRequest)
{
    WEBSOCKET_SESSION(INFO) << LOG_BADGE("startAsServer") << LOG_DESC("start websocket handshake")
                            << LOG_KV("endPoint", m_endPoint) << LOG_KV("session", this);

    auto session = shared_from_this();
    m_wsStreamDelegate->asyncAccept(
        _httpRequest, std::bind(&WsSession::onWsAccept, shared_from_this(), std::placeholders::_1));
}

void WsSession::onWsAccept(boost::beast::error_code _ec)
{
    if (_ec)
    {
        WEBSOCKET_SESSION(WARNING) << LOG_BADGE("onWsAccept") << LOG_KV("error", _ec.message());
        return drop(WsError::AcceptError);
    }

    if (connectHandler())
    {
        connectHandler()(nullptr, shared_from_this());
    }

    asyncRead();

    WEBSOCKET_SESSION(INFO) << LOG_BADGE("onWsAccept")
                            << LOG_DESC("websocket handshake successfully")
                            << LOG_KV("endPoint", endPoint()) << LOG_KV("session", this);
}

void WsSession::onReadPacket(boost::beast::flat_buffer& _buffer)
{
    auto data = boost::asio::buffer_cast<byte*>(boost::beast::buffers_front(_buffer.data()));
    auto size = boost::asio::buffer_size(m_buffer.data());

    auto message = m_messageFactory->buildMessage();
    if (message->decode(data, size) < 0)
    {  // invalid packet, stop this session ?
        WEBSOCKET_SESSION(WARNING) << LOG_BADGE("onReadPacket") << LOG_DESC("decode packet error")
                                   << LOG_KV("endpoint", endPoint()) << LOG_KV("session", this);
        return drop(WsError::PacketError);
    }

    _buffer.consume(_buffer.size());

    auto session = shared_from_this();
    auto seq = std::string(message->seq()->begin(), message->seq()->end());
    auto self = std::weak_ptr<WsSession>(session);
    auto callback = getAndRemoveRespCallback(seq);

    // task enqueue
    m_threadPool->enqueue([message, self, callback]() {
        auto session = self.lock();
        if (!session)
        {
            return;
        }
        if (callback)
        {
            if (callback->timer)
            {
                callback->timer->cancel();
            }

            callback->respCallBack(nullptr, message, session);
        }
        else
        {
            session->recvMessageHandler()(message, session);
        }
    });
}

void WsSession::asyncRead()
{
    if (!isConnected())
    {
        WEBSOCKET_SESSION(TRACE) << LOG_BADGE("asyncRead")
                                 << LOG_DESC("session has been disconnected")
                                 << LOG_KV("endpoint", endPoint()) << LOG_KV("session", this);
        return;
    }
    try
    {
        m_wsStreamDelegate->asyncRead(m_buffer, std::bind(&WsSession::onRead, shared_from_this(),
                                                    std::placeholders::_1, std::placeholders::_2));
    }
    catch (const std::exception& _e)
    {
        WEBSOCKET_SESSION(WARNING)
            << LOG_BADGE("asyncRead") << LOG_DESC("exception") << LOG_KV("endpoint", endPoint())
            << LOG_KV("session", this) << LOG_KV("what", std::string(_e.what()));
        drop(WsError::ReadError);
    }
}

void WsSession::onRead(boost::system::error_code _ec, std::size_t)
{
    if (_ec)
    {
        WEBSOCKET_SESSION(WARNING) << LOG_BADGE("asyncRead") << LOG_KV("error", _ec.message())
                                   << LOG_KV("endpoint", endPoint()) << LOG_KV("session", this);

        return drop(WsError::ReadError);
    }

    onReadPacket(buffer());
    asyncRead();
}

void WsSession::onWritePacket()
{
    boost::unique_lock<boost::shared_mutex> lock(x_queue);
    // remove the front ele from the queue, it has been sent
    m_queue.erase(m_queue.begin());

    // send the next message if any
    if (!m_queue.empty())
    {
        asyncWrite();
    }
}

void WsSession::asyncWrite()
{
    if (!isConnected())
    {
        WEBSOCKET_SESSION(TRACE) << LOG_BADGE("asyncWrite")
                                 << LOG_DESC("session has been disconnected")
                                 << LOG_KV("endpoint", endPoint()) << LOG_KV("session", this);
        return;
    }

    try
    {
        auto session = shared_from_this();
        // Note: add one simple way to monitor message sending latency
        m_wsStreamDelegate->asyncWrite(
            *m_queue.front(), [session](boost::beast::error_code _ec, std::size_t) {
                if (_ec)
                {
                    WEBSOCKET_SESSION(WARNING)
                        << LOG_BADGE("asyncWrite") << LOG_KV("message", _ec.message())
                        << LOG_KV("endpoint", session->endPoint());
                    return session->drop(WsError::WriteError);
                }

                session->onWritePacket();
            });
    }
    catch (const std::exception& _e)
    {
        WEBSOCKET_SESSION(WARNING)
            << LOG_BADGE("asyncWrite") << LOG_DESC("async_write throw exception")
            << LOG_KV("session", this) << LOG_KV("endpoint", endPoint())
            << LOG_KV("what", std::string(_e.what()));
        drop(WsError::WriteError);
    }
}

void WsSession::onWrite(std::shared_ptr<bytes> _buffer)
{
    std::unique_lock<boost::shared_mutex> lock(x_queue);
    auto isEmpty = m_queue.empty();
    // data to be sent is always enqueue first
    m_queue.push_back(_buffer);

    // no writing, send it
    if (isEmpty)
    {
        // we are not currently writing, so send this immediately
        asyncWrite();
    }
}

/**
 * @brief: send message with callback
 * @param _msg: message to be send
 * @param _options: options
 * @param _respCallback: callback
 * @return void:
 */
void WsSession::asyncSendMessage(
    std::shared_ptr<WsMessage> _msg, Options _options, RespCallBack _respFunc)
{
    auto seq = std::string(_msg->seq()->begin(), _msg->seq()->end());
    // check if message size overflow
    if ((int64_t)_msg->data()->size() > (int64_t)maxWriteMsgSize())
    {
        auto error = std::make_shared<Error>(WsError::MessageOverflow, "Message size overflow");
        _respFunc(error, nullptr, nullptr);

        WEBSOCKET_SESSION(WARNING)
            << LOG_BADGE("asyncSendMessage") << LOG_DESC("send message size overflow")
            << LOG_KV("seq", seq) << LOG_KV("msgSize", _msg->data()->size())
            << LOG_KV("maxWriteMsgSize", maxWriteMsgSize());
        return;
    }

    auto buffer = std::make_shared<bytes>();
    _msg->encode(*buffer);

    if (_respFunc)
    {  // callback
        auto callback = std::make_shared<CallBack>();
        callback->respCallBack = _respFunc;
        auto timeout = _options.timeout > 0 ? _options.timeout : m_sendMsgTimeout;
        if (timeout > 0)
        {
            // create new timer to handle timeout
            auto timer = std::make_shared<boost::asio::deadline_timer>(
                *m_ioc, boost::posix_time::milliseconds(timeout));

            callback->timer = timer;
            auto self = std::weak_ptr<WsSession>(shared_from_this());
            timer->async_wait([self, seq](const boost::system::error_code& e) {
                auto session = self.lock();
                if (session)
                {
                    session->onRespTimeout(e, seq);
                }
            });
        }

        addRespCallback(seq, callback);
    }

    {
        boost::asio::post(*m_ioc,
            boost::beast::bind_front_handler(&WsSession::onWrite, shared_from_this(), buffer));
    }
}

void WsSession::addRespCallback(const std::string& _seq, CallBack::Ptr _callback)
{
    std::unique_lock<boost::shared_mutex> lock(x_callback);
    m_callbacks[_seq] = _callback;
}

WsSession::CallBack::Ptr WsSession::getAndRemoveRespCallback(const std::string& _seq, bool _remove)
{
    CallBack::Ptr callback = nullptr;
    {
        boost::unique_lock<boost::shared_mutex> lock(x_callback);
        auto it = m_callbacks.find(_seq);
        if (it != m_callbacks.end())
        {
            callback = it->second;
            if (_remove)
            {
                m_callbacks.erase(it);
            }
        }
    }

    return callback;
}

void WsSession::onRespTimeout(const boost::system::error_code& _error, const std::string& _seq)
{
    if (_error)
    {
        return;
    }

    auto callback = getAndRemoveRespCallback(_seq);
    if (!callback)
    {
        return;
    }

    WEBSOCKET_SESSION(WARNING) << LOG_BADGE("onRespTimeout") << LOG_KV("seq", _seq);

    auto error =
        std::make_shared<Error>(WsError::TimeOut, "waiting for message response timed out");
    m_threadPool->enqueue([callback, error]() { callback->respCallBack(error, nullptr, nullptr); });
}