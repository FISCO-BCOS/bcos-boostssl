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
 * @file WsService.cpp
 * @author: octopus
 * @date 2021-07-28
 */
#include <bcos-boostssl/websocket/Common.h>
#include <bcos-boostssl/websocket/WsError.h>
#include <bcos-boostssl/websocket/WsService.h>
#include <bcos-boostssl/websocket/WsSession.h>
#include <bcos-framework/interfaces/crypto/KeyInterface.h>
#include <bcos-framework/interfaces/protocol/CommonError.h>
#include <bcos-framework/libutilities/Common.h>
#include <bcos-framework/libutilities/DataConvertUtility.h>
#include <bcos-framework/libutilities/Log.h>
#include <bcos-framework/libutilities/ThreadPool.h>
#include <json/json.h>
#include <boost/core/ignore_unused.hpp>
#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

using namespace bcos;
using namespace bcos::boostssl;
using namespace bcos::boostssl::ws;

WsService::WsService()
{
    WEBSOCKET_SERVICE(INFO) << LOG_KV("[NEWOBJ][WsService]", this);
}

WsService::~WsService()
{
    stop();
    WEBSOCKET_SERVICE(INFO) << LOG_KV("[DELOBJ][WsService]", this);
}

void WsService::start()
{
    if (m_running)
    {
        WEBSOCKET_SERVICE(INFO) << LOG_BADGE("start") << LOG_DESC("websocket service is running");
        return;
    }
    m_running = true;

    // start ioc thread
    startIocThread();

    // start as server
    if (m_config->asServer())
    {
        m_httpServer->start();
    }

    // start as client
    if (m_config->asClient())
    {
        if (m_config->connectedPeers() && !m_config->connectedPeers()->empty())
        {
            // TODO: block until connect to server successfully(at least one)???
            reconnect();
        }
    }

    // heartbeat
    heartbeat();

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("start")
                            << LOG_DESC("start websocket service successfully")
                            << LOG_KV("model", m_config->model());
}

void WsService::stop()
{
    if (!m_running)
    {
        WEBSOCKET_SERVICE(INFO) << LOG_BADGE("stop")
                                << LOG_DESC("websocket service has been stopped");
        return;
    }
    m_running = false;

    // stop ioc thread
    if (m_ioc && !m_ioc->stopped())
    {
        m_ioc->stop();
    }

    // cancel reconnect task
    if (m_reconnect)
    {
        m_reconnect->cancel();
    }

    // cancel heartbeat task
    if (m_heartbeat)
    {
        m_heartbeat->cancel();
    }

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("stop") << LOG_DESC("stop websocket service successfully");
}

void WsService::startIocThread()
{
    // TODO: if multi-thread needed???
    m_iocThread = std::make_shared<std::thread>([&] {
        while (m_running)
        {
            try
            {
                m_ioc->run();
            }
            catch (const std::exception& e)
            {
                WEBSOCKET_SERVICE(WARNING)
                    << LOG_BADGE("startIocThread") << LOG_DESC("Exception in IOC Thread:")
                    << boost::diagnostic_information(e);
            }

            m_ioc->reset();
        }

        WEBSOCKET_SERVICE(INFO) << LOG_BADGE("startIocThread") << "IOC thread exit";
    });
}

void WsService::heartbeat()
{
    auto ss = sessions();
    for (auto const& s : ss)
    {
        s->ping();
    }

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("heartbeat") << LOG_DESC("connected nodes")
                            << LOG_KV("count", ss.size());

    m_heartbeat = std::make_shared<boost::asio::deadline_timer>(boost::asio::make_strand(*m_ioc),
        boost::posix_time::milliseconds(m_config->heartbeatPeriod()));
    auto self = std::weak_ptr<WsService>(shared_from_this());
    m_heartbeat->async_wait([self](const boost::system::error_code&) {
        auto service = self.lock();
        if (!service)
        {
            return;
        }
        service->heartbeat();
    });
}

void WsService::reconnect()
{
    auto peers = m_config->connectedPeers();
    for (auto const& peer : *peers)
    {
        std::string connectedEndPoint = peer.host + ":" + std::to_string(peer.port);
        auto session = getSession(connectedEndPoint);
        if (session)
        {
            continue;
        }

        WEBSOCKET_SERVICE(DEBUG) << LOG_BADGE("reconnect") << LOG_DESC("try to connect to peer")
                                 << LOG_KV("connectedEndPoint", connectedEndPoint);

        std::string host = peer.host;
        uint16_t port = peer.port;
        auto self = std::weak_ptr<WsService>(shared_from_this());
        m_connector->connectToWsServer(host, port,
            [self, connectedEndPoint](boost::beast::error_code _ec,
                std::shared_ptr<boost::beast::websocket::stream<boost::beast::tcp_stream>>
                    _stream) {
                auto service = self.lock();
                if (!service)
                {
                    return;
                }

                if (_ec)
                {
                    return;
                }

                auto session = service->newSession(_stream);
                // reset connected endpoint
                session->setConnectedEndPoint(connectedEndPoint);
                session->doRun();
            });
    }

    m_reconnect = std::make_shared<boost::asio::deadline_timer>(boost::asio::make_strand(*m_ioc),
        boost::posix_time::milliseconds(m_config->reconnectPeriod()));
    auto self = std::weak_ptr<WsService>(shared_from_this());
    m_reconnect->async_wait([self](const boost::system::error_code&) {
        auto service = self.lock();
        if (!service)
        {
            return;
        }
        service->reconnect();
    });
}

bool WsService::registerMsgHandler(uint32_t _msgType, MsgHandler _msgHandler)
{
    auto it = m_msgType2Method.find(_msgType);
    if (it == m_msgType2Method.end())
    {
        m_msgType2Method[_msgType] = _msgHandler;
        return true;
    }
    return false;
}

std::shared_ptr<WsSession> WsService::newSession(
    std::shared_ptr<boost::beast::websocket::stream<boost::beast::tcp_stream>> _stream)
{
    auto remoteEndPoint = _stream->next_layer().socket().remote_endpoint();
    std::string endPoint =
        remoteEndPoint.address().to_string() + ":" + std::to_string(remoteEndPoint.port());

    auto wsSession = std::make_shared<WsSession>(std::move(*_stream));
    wsSession->setThreadPool(threadPool());
    wsSession->setMessageFactory(messageFactory());
    wsSession->setEndPoint(endPoint);
    wsSession->setConnectedEndPoint(endPoint);

    auto self = std::weak_ptr<WsService>(shared_from_this());

    wsSession->setConnectHandler(
        [self](bcos::Error::Ptr _error, std::shared_ptr<WsSession> _session) {
            auto wsService = self.lock();
            if (wsService)
            {
                wsService->onConnect(_error, _session);
            }
        });
    wsSession->setDisconnectHandler(
        [self](bcos::Error::Ptr _error, std::shared_ptr<ws::WsSession> _session) {
            auto wsService = self.lock();
            if (wsService)
            {
                wsService->onDisconnect(_error, _session);
            }
        });
    wsSession->setRecvMessageHandler(
        [self](std::shared_ptr<WsMessage> _msg, std::shared_ptr<WsSession> _session) {
            auto wsService = self.lock();
            if (wsService)
            {
                wsService->onRecvMessage(_msg, _session);
            }
        });

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("newSession") << LOG_DESC("start the session")
                            << LOG_KV("endPoint", endPoint)
                            << LOG_KV("client", wsSession->client());
    return wsSession;
}

void WsService::addSession(std::shared_ptr<WsSession> _session)
{
    auto connectedEndPoint = _session->connectedEndPoint();
    auto endpoint = _session->endPoint();
    bool ok = false;
    {
        std::unique_lock lock(x_mutex);
        auto it = m_sessions.find(connectedEndPoint);
        if (it == m_sessions.end())
        {
            m_sessions[connectedEndPoint] = _session;
            ok = true;
        }
    }

    // thread pool
    for (auto& conHandler : m_connectHandlers)
    {
        conHandler(_session);
    }

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("addSession") << LOG_DESC("add session to mapping")
                            << LOG_KV("connectedEndPoint", connectedEndPoint)
                            << LOG_KV("endPoint", endpoint) << LOG_KV("result", ok);
}

void WsService::removeSession(const std::string& _endPoint)
{
    {
        std::unique_lock lock(x_mutex);
        m_sessions.erase(_endPoint);
    }

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("removeSession") << LOG_KV("endpoint", _endPoint);
}

std::shared_ptr<WsSession> WsService::getSession(const std::string& _endPoint)
{
    std::shared_lock lock(x_mutex);
    auto it = m_sessions.find(_endPoint);
    if (it != m_sessions.end())
    {
        return it->second;
    }
    return nullptr;
}

WsSessions WsService::sessions()
{
    WsSessions sessions;
    {
        std::shared_lock lock(x_mutex);
        for (const auto& session : m_sessions)
        {
            if (session.second && session.second->isConnected())
            {
                sessions.push_back(session.second);
            }
        }
    }

    // WEBSOCKET_SERVICE(TRACE) << LOG_BADGE("sessions") << LOG_KV("size", sessions.size());
    return sessions;
}

/**
 * @brief: session connect
 * @param _error:
 * @param _session: session
 * @return void:
 */
void WsService::onConnect(Error::Ptr _error, std::shared_ptr<WsSession> _session)
{
    boost::ignore_unused(_error);
    std::string endpoint = "";
    std::string connectedEndPoint = "";
    if (_session)
    {
        endpoint = _session->endPoint();
        connectedEndPoint = _session->connectedEndPoint();
    }

    addSession(_session);

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("onConnect") << LOG_KV("endpoint", endpoint)
                            << LOG_KV("connectedEndPoint", connectedEndPoint);
}

/**
 * @brief: session disconnect
 * @param _error: the reason of disconnection
 * @param _session: session
 * @return void:
 */
void WsService::onDisconnect(Error::Ptr _error, std::shared_ptr<WsSession> _session)
{
    boost::ignore_unused(_error);
    std::string endpoint = "";
    std::string connectedEndPoint = "";
    if (_session)
    {
        endpoint = _session->endPoint();
        connectedEndPoint = _session->connectedEndPoint();
    }

    // clear the session
    removeSession(connectedEndPoint);

    for (auto& disHandler : m_disconnectHandlers)
    {
        disHandler(_session);
    }

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("onDisconnect") << LOG_KV("endpoint", endpoint)
                            << LOG_KV("connectedEndPoint", connectedEndPoint);
}

void WsService::onRecvMessage(std::shared_ptr<WsMessage> _msg, std::shared_ptr<WsSession> _session)
{
    auto seq = std::string(_msg->seq()->begin(), _msg->seq()->end());

    WEBSOCKET_SERVICE(TRACE) << LOG_BADGE("onRecvMessage")
                             << LOG_DESC("receive message from server")
                             << LOG_KV("type", _msg->type()) << LOG_KV("seq", seq)
                             << LOG_KV("endpoint", _session->endPoint())
                             << LOG_KV("data size", _msg->data()->size());

    auto it = m_msgType2Method.find(_msg->type());
    if (it != m_msgType2Method.end())
    {
        auto callback = it->second;
        callback(_msg, _session);
    }
    else
    {
        WEBSOCKET_SERVICE(ERROR) << LOG_BADGE("onRecvMessage")
                                 << LOG_DESC("unrecognized message type")
                                 << LOG_KV("type", _msg->type())
                                 << LOG_KV("endpoint", _session->endPoint()) << LOG_KV("seq", seq)
                                 << LOG_KV("data size", _msg->data()->size());
    }
}

void WsService::asyncSendMessageByEndPoint(const std::string& _endPoint,
    std::shared_ptr<WsMessage> _msg, Options _options, RespCallBack _respFunc)
{
    std::shared_ptr<WsSession> session = getSession(_endPoint);
    if (!session)
    {
        auto error = std::make_shared<Error>(
            WsError::EndPointNotExist, "there has no connection of the endpoint exist");
        _respFunc(error, nullptr, nullptr);
        return;
    }

    session->asyncSendMessage(_msg, _options, _respFunc);
}

void WsService::asyncSendMessage(
    std::shared_ptr<WsMessage> _msg, Options _options, RespCallBack _respFunc)
{
    auto seq = std::string(_msg->seq()->begin(), _msg->seq()->end());
    auto ss = sessions();
    class Retry : public std::enable_shared_from_this<Retry>
    {
    public:
        WsSessions ss;
        std::shared_ptr<WsMessage> msg;
        Options options;
        RespCallBack respFunc;

    public:
        void sendMessage()
        {
            if (ss.empty())
            {
                auto error = std::make_shared<Error>(
                    WsError::NoActiveCons, "there has no active connection available");
                respFunc(error, nullptr, nullptr);
                return;
            }

            auto seed = std::chrono::system_clock::now().time_since_epoch().count();
            std::default_random_engine e(seed);
            std::shuffle(ss.begin(), ss.end(), e);

            auto session = *ss.begin();
            ss.erase(ss.begin());

            auto self = shared_from_this();
            session->asyncSendMessage(msg, options,
                [self](bcos::Error::Ptr _error, std::shared_ptr<WsMessage> _msg,
                    std::shared_ptr<WsSession> _session) {
                    if (_error && _error->errorCode() != bcos::protocol::CommonError::SUCCESS)
                    {
                        WEBSOCKET_VERSION(WARNING)
                            << LOG_BADGE("asyncSendMessage") << LOG_DESC("callback error")
                            << LOG_KV("endpoint", _session->endPoint())
                            << LOG_KV("errorCode", _error ? _error->errorCode() : -1)
                            << LOG_KV("errorMessage",
                                   _error ? _error->errorMessage() : std::string(""));
                        return self->sendMessage();
                    }

                    self->respFunc(_error, _msg, _session);
                });
        }
    };

    std::size_t size = ss.size();
    auto retry = std::make_shared<Retry>();
    retry->ss = ss;
    retry->msg = _msg;
    retry->options = _options;
    retry->respFunc = _respFunc;
    retry->sendMessage();

    WEBSOCKET_VERSION(DEBUG) << LOG_BADGE("asyncSendMessage") << LOG_KV("seq", seq)
                             << LOG_KV("size", size);
}

void WsService::broadcastMessage(std::shared_ptr<WsMessage> _msg)
{
    broadcastMessage(sessions(), _msg);
}

void WsService::broadcastMessage(const WsSession::Ptrs& _ss, std::shared_ptr<WsMessage> _msg)
{
    for (auto& session : _ss)
    {
        if (session->isConnected())
        {
            session->asyncSendMessage(_msg);
        }
    }

    WEBSOCKET_VERSION(DEBUG) << LOG_BADGE("broadcastMessage");
}