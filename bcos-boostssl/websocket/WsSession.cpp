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
#include <bcos-framework/interfaces/protocol/CommonError.h>
#include <bcos-framework/libutilities/DataConvertUtility.h>
#include <bcos-framework/libutilities/Log.h>
#include <bcos-framework/libutilities/ThreadPool.h>
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

WsSession::WsSession(boost::beast::websocket::stream<boost::beast::tcp_stream>&& _wsStream)
  : m_wsStream(std::move(_wsStream))
{
    auto remoteEndPoint = m_wsStream.next_layer().socket().remote_endpoint();
    m_endPoint = remoteEndPoint.address().to_string() + ":" + std::to_string(remoteEndPoint.port());

    WEBSOCKET_SESSION(INFO) << LOG_KV("[NEWOBJ][WSSESSION]", this)
                            << LOG_KV("endPoint", m_endPoint);
}

void WsSession::drop(uint32_t _reason)
{
    WEBSOCKET_SESSION(INFO) << LOG_BADGE("drop") << LOG_KV("reason", _reason)
                            << LOG_KV("endpoint", m_endPoint) << LOG_KV("session", this);

    m_isDrop = true;
    auto self = std::weak_ptr<WsSession>(shared_from_this());
    m_threadPool->enqueue([self]() {
        auto session = self.lock();
        if (session)
        {
            session->disconnectHandler()(nullptr, session);
        }
    });
}

void WsSession::disconnect()
{
    try
    {
        boost::beast::error_code ec;
        m_wsStream.next_layer().socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    }
    catch (const std::exception& e)
    {
        WEBSOCKET_SESSION(WARNING) << LOG_BADGE("disconnect") << LOG_KV("e", e.what());
    }

    WEBSOCKET_SESSION(INFO) << LOG_BADGE("disconnect") << LOG_DESC("disconnect the session")
                            << LOG_KV("endpoint", m_endPoint) << LOG_KV("session", this);
}

void WsSession::ping()
{
    try
    {
        boost::system::error_code error;
        m_wsStream.ping(boost::beast::websocket::ping_data(), error);
    }
    catch (const std::exception& _e)
    {
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("ping") << LOG_KV("endpoint", endPoint())
                                 << LOG_KV("what", std::string(_e.what()));
        drop(WsError::PingError);
    }
}

void WsSession::pong()
{
    try
    {
        boost::system::error_code error;
        m_wsStream.ping(boost::beast::websocket::ping_data(), error);
    }
    catch (const std::exception& _e)
    {
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("pong") << LOG_KV("endpoint", endPoint())
                                 << LOG_KV("what", std::string(_e.what()));
        drop(WsError::PongError);
    }
}

void WsSession::initialize(bool _client)
{
    setClient(_client);

    auto self = std::weak_ptr<WsSession>(shared_from_this());
    auto endPoint = m_endPoint;
    // callback for ping/pong
    m_wsStream.control_callback([self, endPoint](auto&& _kind, auto&& _payload) {
        auto session = self.lock();
        if (!session)
        {
            return;
        }

        if (_kind == boost::beast::websocket::frame_type::ping)
        {  // ping message
            session->pong();
            WEBSOCKET_SESSION(INFO) << LOG_DESC("receive ping framework")
                                    << LOG_KV("endPoint", endPoint) << LOG_KV("payload", _payload);
        }
        else if (_kind == boost::beast::websocket::frame_type::pong)
        {  // pong message
            WEBSOCKET_SESSION(INFO) << LOG_DESC("receive pong framework")
                                    << LOG_KV("endPoint", endPoint) << LOG_KV("payload", _payload);
        }
    });

    if (client())
    {
        m_wsStream.set_option(boost::beast::websocket::stream_base::timeout::suggested(
            boost::beast::role_type::client));
    }
    else
    {
        m_wsStream.set_option(boost::beast::websocket::stream_base::timeout::suggested(
            boost::beast::role_type::server));
        m_wsStream.set_option(boost::beast::websocket::stream_base::decorator(
            [](boost::beast::websocket::response_type& res) {
                res.set(boost::beast::http::field::server,
                    std::string(BOOST_BEAST_VERSION_STRING) + " FISCO-BCOS 3.0");
            }));
    }
}

// start WsSession as client
void WsSession::doRun()
{
    initialize(true);
    asyncRead();
}

// start WsSession as server
void WsSession::doAccept(bcos::boostssl::http::HttpRequest _req)
{
    initialize(false);
    // accept the websocket handshake
    m_wsStream.async_accept(
        _req, boost::beast::bind_front_handler(&WsSession::onAccept, shared_from_this()));

    WEBSOCKET_SESSION(INFO) << LOG_BADGE("doAccept") << LOG_DESC("start websocket handshake")
                            << LOG_KV("endPoint", m_endPoint) << LOG_KV("session", this);
}

void WsSession::onAccept(boost::beast::error_code _ec)
{
    if (_ec)
    {
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("onAccept") << LOG_KV("error", _ec);
        return drop(WsError::AcceptError);
    }

    auto session = shared_from_this();
    if (m_connectHandler)
    {
        m_connectHandler(nullptr, session);
    }

    asyncRead();

    WEBSOCKET_SESSION(INFO) << LOG_BADGE("onAccept") << LOG_DESC("websocket handshake successfully")
                            << LOG_KV("endPoint", m_endPoint) << LOG_KV("session", this);
}

void WsSession::onRead(boost::beast::error_code _ec, std::size_t _size)
{
    if (_ec)
    {
        if (_ec.value() == boost::asio::error::eof)
        {
            WEBSOCKET_SESSION(INFO)
                << LOG_BADGE("onRead") << LOG_DESC(" the peer close the connection");
        }
        else
        {
            WEBSOCKET_SESSION(ERROR)
                << LOG_BADGE("onRead") << LOG_KV("error", _ec) << LOG_KV("message", _ec.message());
        }

        return drop(WsError::ReadError);
    }

    auto data = boost::asio::buffer_cast<bcos::byte*>(boost::beast::buffers_front(m_buffer.data()));
    auto size = boost::asio::buffer_size(m_buffer.data());

    auto message = m_messageFactory->buildMessage();
    auto decodeSize = message->decode(data, size);
    if (decodeSize < 0)
    {  // invalid packet, stop this session ?
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("onRead")
                                 << LOG_DESC("invalid packet for unable to decode this packet")
                                 << LOG_KV("endpoint", endPoint())
                                 << LOG_KV("data", *toHexString(data, data + size))
                                 << LOG_KV("size", _size);
        return drop(WsError::PacketError);
    }

    m_buffer.consume(m_buffer.size());

    auto session = shared_from_this();
    auto seq = std::string(message->seq()->begin(), message->seq()->end());
    auto self = std::weak_ptr<WsSession>(session);
    auto callback = getAndRemoveRespCallback(seq);

    // WEBSOCKET_SESSION(TRACE) << LOG_BADGE("onRead") << LOG_KV("seq", seq)
    //                          << LOG_KV("type", message->type())
    //                          << LOG_KV("status", message->status())
    //                          << LOG_KV("callback", (callback ? true : false))
    //                          << LOG_KV("size", _size)
    //                          << LOG_KV("data", *toHexString(data, data + size));

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

    asyncRead();
}

void WsSession::asyncRead()
{
    try
    {
        auto session = shared_from_this();
        // read the next message
        m_wsStream.async_read(m_buffer,
            std::bind(&WsSession::onRead, session, std::placeholders::_1, std::placeholders::_2));
    }
    catch (const std::exception& _e)
    {
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("asyncRead") << LOG_DESC("async_read error")
                                 << LOG_KV("endpoint", endPoint())
                                 << LOG_KV("what", std::string(_e.what()));
        drop(WsError::ReadError);
    }
}

void WsSession::onWrite(boost::beast::error_code _ec, std::size_t)
{
    if (_ec)
    {
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("onWrite") << LOG_KV("error", _ec)
                                 << LOG_KV("message", _ec.message());
        return drop(WsError::WriteError);
    }

    std::unique_lock lock(x_queue);
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
    try
    {
        auto session = shared_from_this();
        m_wsStream.binary(true);
        // we are not currently writing, so send this immediately
        m_wsStream.async_write(boost::asio::buffer(*m_queue.front()),
            std::bind(&WsSession::onWrite, session, std::placeholders::_1, std::placeholders::_2));
    }
    catch (const std::exception& _e)
    {
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("asyncWrite") << LOG_DESC("async_write error")
                                 << LOG_KV("endpoint", endPoint())
                                 << LOG_KV("what", std::string(_e.what()));
        drop(WsError::WriteError);
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
    auto buffer = std::make_shared<bcos::bytes>();
    _msg->encode(*buffer);

    if (_respFunc)
    {  // callback
        auto callback = std::make_shared<CallBack>();
        callback->respCallBack = _respFunc;
        if (_options.timeout > 0)
        {
            // create new timer to handle timeout
            auto timer = std::make_shared<boost::asio::deadline_timer>(
                m_wsStream.get_executor(), boost::posix_time::milliseconds(_options.timeout));

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


    std::unique_lock lock(x_queue);
    auto isEmpty = m_queue.empty();
    // data to be sent is always enqueue first
    m_queue.push_back(buffer);

    // no writing, send it
    if (isEmpty)
    {
        // we are not currently writing, so send this immediately
        asyncWrite();
    }
}

void WsSession::addRespCallback(const std::string& _seq, CallBack::Ptr _callback)
{
    std::unique_lock lock(x_callback);
    m_callbacks[_seq] = _callback;
}

WsSession::CallBack::Ptr WsSession::getAndRemoveRespCallback(const std::string& _seq)
{
    CallBack::Ptr callback = nullptr;
    std::shared_lock lock(x_callback);
    auto it = m_callbacks.find(_seq);
    if (it != m_callbacks.end())
    {
        callback = it->second;
        m_callbacks.erase(it);
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

    auto error = std::make_shared<Error>(bcos::protocol::CommonError::TIMEOUT, "timeout");
    m_threadPool->enqueue([callback, error]() { callback->respCallBack(error, nullptr, nullptr); });
}