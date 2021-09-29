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

#include <bcos-boostssl/websocket/WsMessageType.h>
#include <bcos-boostssl/websocket/WsSession.h>
#include <bcos-framework/interfaces/protocol/CommonError.h>
#include <bcos-framework/libutilities/DataConvertUtility.h>
#include <bcos-framework/libutilities/Log.h>
#include <bcos-framework/libutilities/ThreadPool.h>
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

void WsSession::drop()
{
    WEBSOCKET_SESSION(INFO) << LOG_BADGE("drop") << LOG_KV("endpoint", m_endPoint)
                            << LOG_KV("session", this);
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

    WEBSOCKET_SESSION(INFO) << LOG_BADGE("disconnect") << LOG_KV("endpoint", m_endPoint)
                            << LOG_KV("session", this);
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

        return drop();
    }

    auto data = boost::asio::buffer_cast<bcos::byte*>(boost::beast::buffers_front(m_buffer.data()));
    auto size = boost::asio::buffer_size(m_buffer.data());

    auto message = m_messageFactory->buildMessage();
    auto decodeSize = message->decode(data, size);
    if (decodeSize < 0)
    {  // invalid packet, stop this session ?
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("onRead") << LOG_DESC("invalid packet")
                                 << LOG_KV("endpoint", endPoint())
                                 << LOG_KV("data", *toHexString(data, data + size));
        return drop();
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
    //                          << LOG_KV("data size", _size)
    //                          << LOG_KV("data", *toHexString(data, data + size));

    if (!callback && !checkHandshakeDone())
    {
        WEBSOCKET_SESSION(ERROR)
            << LOG_BADGE("onRead")
            << LOG_DESC("session unable to handle message until handshake with server")
            << LOG_KV("version", version()) << LOG_KV("seq", seq) << LOG_KV("type", message->type())
            << LOG_KV("status", message->status()) << LOG_KV("data size", _size)
            << LOG_KV("data", *toHexString(data, data + size));
        return drop();
    }

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
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("asyncRead") << LOG_DESC("async_read with exception")
                                 << LOG_KV("endpoint", endPoint())
                                 << LOG_KV("what", std::string(_e.what()));
        disconnect();
    }
}

void WsSession::onWrite(boost::beast::error_code _ec, std::size_t)
{
    if (_ec)
    {
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("onWrite") << LOG_KV("error", _ec)
                                 << LOG_KV("message", _ec.message());
        return drop();
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
        WEBSOCKET_SESSION(ERROR) << LOG_BADGE("asyncWrite")
                                 << LOG_DESC("async_write with exception")
                                 << LOG_KV("endpoint", endPoint())
                                 << LOG_KV("what", std::string(_e.what()));
        disconnect();
    }
}

/**
 * @brief: start handshake with node
 * @return void:
 */
void WsSession::startHandshake()
{
    auto msg = m_messageFactory->buildMessage();
    msg->setType(WsMessageType::HANDESHAKE);
    auto session = shared_from_this();
    asyncSendMessage(msg, Options(-1),
        [session](bcos::Error::Ptr _error, std::shared_ptr<WsMessage> _msg,
            std::shared_ptr<WsSession> _session) {
            if (_error && _error->errorCode() != bcos::protocol::CommonError::SUCCESS)
            {
                WEBSOCKET_SESSION(ERROR)
                    << LOG_BADGE("startHandshake") << LOG_DESC("callback response error")
                    << LOG_KV("endpoint", _session ? _session->endPoint() : std::string(""))
                    << LOG_KV("errorCode", _error ? _error->errorCode() : -1)
                    << LOG_KV("errorMessage", _error ? _error->errorMessage() : std::string(""));
                session->drop();
                return;
            }

            std::string strHandshake = std::string(_msg->data()->begin(), _msg->data()->end());
            // TODO: how to deal with handshake
            /*
            auto node = std::make_shared<bcos::ws::NodeInfo>();
            std::string strNodeInfo = std::string(_msg->data()->begin(),
            _msg->data()->end()); if (!node->init(strNodeInfo))
            {
                session->drop();
                return;
            }

            session->setVersion(node->wsProtocolVersion());
            */
            WEBSOCKET_SESSION(INFO)
                << LOG_BADGE("startHandshake") << LOG_DESC("handshake with server successfully")
                << LOG_KV("endpoint", _session ? _session->endPoint() : std::string(""))
                << LOG_KV("protocolVersion", session->version())
                << LOG_KV("strHandshake", strHandshake);

            session->handlshakeHandler()(nullptr, session);
        });
}

bool WsSession::checkHandshakeDone()
{
    // TODO: how to deal with handshake
    return true;
    // auto version = m_version.load();
    // return version != WsProtocolVersion::None;
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
    auto size = m_queue.size();

    // WEBSOCKET_SESSION(DEBUG) << LOG_BADGE("asyncSendMessage") << LOG_KV("seq", seq)
    //                          << LOG_KV("timeout", _options.timeout) << LOG_KV("queue size",
    //                          size);

    // data to be sent is always enqueue first
    m_queue.push_back(buffer);

    // no writing, send it
    if (0 == size)
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