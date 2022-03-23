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
#include <bcos-utilities/BoostLog.h>
#include <bcos-utilities/Common.h>
#include <bcos-utilities/ThreadPool.h>
#include <json/json.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

using namespace bcos;
using namespace std::chrono_literals;
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
            // Connect to peers and wait for at least one connection to be successfully established
            syncConnectToEndpoints(m_config->connectedPeers());
        }

        reconnect();
    }

    // heartbeat
    heartbeat();

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("start")
                            << LOG_DESC("start websocket service successfully")
                            << LOG_KV("model", m_config->model())
                            << LOG_KV("max msg size", m_config->maxMsgSize());
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

    stopIocThread();

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("stop") << LOG_DESC("stop websocket service successfully");
}

void WsService::startIocThread()
{
    std::size_t threads =
        m_iocThreadCount > 0 ? m_iocThreadCount : std::thread::hardware_concurrency();
    if (!threads)
    {
        threads = 4;
    }

    m_iocThreads = std::make_shared<std::vector<std::thread>>();
    m_iocThreads->reserve(threads);

    for (std::size_t i = 0; i < threads; i++)
    {
        m_iocThreads->emplace_back([&, i] {
            bcos::pthread_setThreadName("t_ws_ioc_" + std::to_string(i));
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

                if (m_running && m_ioc->stopped())
                {
                    m_ioc->restart();
                }
            }

            WEBSOCKET_SERVICE(INFO) << LOG_BADGE("startIocThread") << "IOC thread exit";
        });
    }

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("startIocThread")
                            << LOG_KV("ioc thread count", m_iocThreads->size());
}

void WsService::stopIocThread()
{
    // stop io threads
    if (m_iocThreads && !m_iocThreads->empty())
    {
        for (auto& t : *m_iocThreads)
        {
            if (t.get_id() != std::this_thread::get_id())
            {
                t.join();
            }
            else
            {
                t.detach();
            }
        }
    }
}

void WsService::heartbeat()
{
    // todo: 改下函数名
    auto ss = sessions();

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

std::string WsService::genConnectError(
    const std::string& _error, const std::string& _host, uint16_t port, bool end)
{
    std::string msg = _error;
    msg += ":/";
    msg += _host;
    msg += ":";
    msg += std::to_string(port);
    if (!end)
    {
        msg += ", ";
    }
    return msg;
}

void WsService::syncConnectToEndpoints(EndPointsPtr _peers)
{
    std::string errorMsg;
    std::size_t sucCount = 0;

    auto vPromise = asyncConnectToEndpoints(_peers);

    for (std::size_t i = 0; i < vPromise->size(); ++i)
    {
        auto fut = (*vPromise)[i]->get_future();

        auto status = fut.wait_for(std::chrono::milliseconds(m_waitConnectFinishTimeout));
        switch (status)
        {
        case std::future_status::deferred:
            break;
        case std::future_status::timeout:
            errorMsg += genConnectError("connection timeout", (*_peers)[i].host, (*_peers)[i].port,
                i == vPromise->size() - 1);
            break;
        case std::future_status::ready:

            try
            {
                auto result = fut.get();
                if (result.first)
                {
                    errorMsg += genConnectError(result.second.empty() ?
                                                    result.first.message() :
                                                    result.second + " " + result.first.message(),
                        (*_peers)[i].host, (*_peers)[i].port, i == vPromise->size() - 1);
                }
                else
                {
                    sucCount++;
                }
            }
            catch (std::exception& _e)
            {
                WEBSOCKET_SERVICE(WARNING)
                    << LOG_BADGE("syncConnectToEndpoints") << LOG_DESC("future get throw exception")
                    << LOG_KV("e", _e.what());
            }
            break;
        }
    }

    if (sucCount == 0)
    {
        stop();
        BOOST_THROW_EXCEPTION(std::runtime_error("[" + boost::to_lower_copy(errorMsg) + "]"));
        return;
    }
}

std::shared_ptr<
    std::vector<std::shared_ptr<std::promise<std::pair<boost::beast::error_code, std::string>>>>>
WsService::asyncConnectToEndpoints(EndPointsPtr _peers)
{
    auto vPromise = std::make_shared<std::vector<
        std::shared_ptr<std::promise<std::pair<boost::beast::error_code, std::string>>>>>();

    for (auto& peer : *_peers)
    {
        std::string connectedEndPoint = peer.host + ":" + std::to_string(peer.port);

        /*
        WEBSOCKET_SERVICE(DEBUG) << LOG_BADGE("asyncConnect")
                                 << LOG_DESC("try to connect to endpoint")
                                 << LOG_KV("host", peer.host) << LOG_KV("port", peer.port);
        */

        auto p = std::make_shared<std::promise<std::pair<boost::beast::error_code, std::string>>>();
        vPromise->push_back(p);

        std::string host = peer.host;
        uint16_t port = peer.port;

        auto self = std::weak_ptr<WsService>(shared_from_this());
        m_connector->connectToWsServer(host, port, m_config->disableSsl(),
            [p, self, connectedEndPoint](boost::beast::error_code _ec,
                const std::string& _extErrorMsg,
                std::shared_ptr<WsStreamDelegate> _wsStreamDelegate, std::shared_ptr<std::string> _endpointPublicKey) {
                auto service = self.lock();
                if (!service)
                {
                    return;
                }

                auto futResult = std::make_pair(_ec, _extErrorMsg);
                p->set_value(futResult);

                if (_ec)
                {
                    return;
                }

                auto session = service->newSession(_wsStreamDelegate, *_endpointPublicKey.get());
                session->setConnectedEndPoint(connectedEndPoint);
                session->startAsClient();
            });
    }

    return vPromise;
}

void WsService::reconnect()
{
    auto self = std::weak_ptr<WsService>(shared_from_this());
    m_reconnect = std::make_shared<boost::asio::deadline_timer>(boost::asio::make_strand(*m_ioc),
        boost::posix_time::milliseconds(m_config->reconnectPeriod()));

    m_reconnect->async_wait([self, this](const boost::system::error_code&) {
        auto service = self.lock();
        if (!service)
        {
            return;
        }

        auto connectedPeers = std::make_shared<std::vector<EndPoint>>();

        // select all disconnected nodes
        // todo: connectedPeers p2pservice去重后要更新该配置信息 ip + port, update方法
        auto peers = m_config->connectedPeers();
        for (auto& peer : *peers)
        {
            std::string connectedEndPoint = peer.host + ":" + std::to_string(peer.port);
            auto session = getSession(connectedEndPoint);
            if (session)
            {
                continue;
            }

            connectedPeers->push_back(peer);
        }

        if (!connectedPeers->empty())
        {
            asyncConnectToEndpoints(connectedPeers);
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

MsgHandler WsService::getMsgHandler(uint32_t _type)
{
    // todo: m_wsservice->registerMsgHandler 考虑对变量m_msgType2Method加锁
    if (m_msgType2Method.count(_type))
    {
        return m_msgType2Method[_type];
    }
    return nullptr;
}

void WsService::eraseMsgHandler(uint32_t _type)
{
    if (!m_msgType2Method.count(_type))
    {
        return;
    }
    m_msgType2Method.erase(_type);
}

NodeInfo WsService::nodeInfo()
{
    try
    {
        if (m_nodeInfo.nodeID.empty())
        {
            /// get certificate
            auto sslContext = m_ctx->native_handle();
            X509* cert = SSL_CTX_get0_certificate(sslContext);

            /// get issuer name
            const char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
            std::string issuerName(issuer);

            /// get subject name
            const char* subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            std::string subjectName(subject);

            /// get nodeID
            std::string nodeIDOut;
            auto sslContextPubHandler = m_connector->sslCertInfo()->sslContextPubHandler();
            if (sslContextPubHandler(cert, nodeIDOut))
            {
                m_nodeInfo.nodeID = boost::to_upper_copy(nodeIDOut);
                WEBSOCKET_SERVICE(INFO) << LOG_DESC("Get node information from cert")
                               << LOG_KV("nodeID", m_nodeInfo.nodeID);
            }

            /// fill in the node informations
            m_nodeInfo.agencyName = obtainCommonNameFromSubject(issuerName);
            m_nodeInfo.nodeName = obtainCommonNameFromSubject(subjectName);
            m_nodeInfo.nodeIPEndpoint = NodeIPEndpoint(m_listenHost, m_listenPort);
            /// free resources
            OPENSSL_free((void*)issuer);
            OPENSSL_free((void*)subject);
        }
    }
    catch (std::exception& e)
    {
        WEBSOCKET_SERVICE(ERROR) << LOG_DESC("Get node information from cert failed.")
                        << boost::diagnostic_information(e);
        return m_nodeInfo;
    }
    return m_nodeInfo;
}

std::string WsService::obtainCommonNameFromSubject(std::string const& subject)
{
    std::vector<std::string> fields;
    boost::split(fields, subject, boost::is_any_of("/"), boost::token_compress_on);
    for (auto field : fields)
    {
        std::size_t pos = field.find("CN");
        if (pos != std::string::npos)
        {
            std::vector<std::string> cn_fields;
            boost::split(cn_fields, field, boost::is_any_of("="), boost::token_compress_on);
            /// use the whole fields as the common name
            if (cn_fields.size() < 2)
            {
                return field;
            }
            /// return real common name
            return cn_fields[1];
        }
    }
    return subject;
}

std::shared_ptr<WsSession> WsService::newSession(
    std::shared_ptr<WsStreamDelegate> _wsStreamDelegate, std::string const& _publicKey)
{
    _wsStreamDelegate->setMaxReadMsgSize(m_config->maxMsgSize());

    std::string endPoint = _wsStreamDelegate->remoteEndpoint();
    auto wsSession = std::make_shared<WsSession>();
    wsSession->setWsStreamDelegate(_wsStreamDelegate);
    wsSession->setIoc(ioc());
    wsSession->setThreadPool(threadPool());
    wsSession->setMessageFactory(messageFactory());
    wsSession->setEndPoint(endPoint);
    wsSession->setConnectedEndPoint(endPoint);
    wsSession->setMaxWriteMsgSize(m_config->maxMsgSize());
    wsSession->setSendMsgTimeout(m_config->sendMsgTimeout());
    wsSession->setPublicKey(_publicKey);
    auto nodeID = wsSession->obtainNodeID(_publicKey);
    wsSession->setNodeID(nodeID);

    auto self = std::weak_ptr<WsService>(shared_from_this());
    wsSession->setConnectHandler([self](Error::Ptr _error, std::shared_ptr<WsSession> _session) {
        auto wsService = self.lock();
        if (wsService)
        {
            wsService->onConnect(_error, _session);
        }
    });
    wsSession->setDisconnectHandler(
        [self](Error::Ptr _error, std::shared_ptr<ws::WsSession> _session) {
            auto wsService = self.lock();
            if (wsService)
            {
                wsService->onDisconnect(_error, _session);
            }
        });
    wsSession->setRecvMessageHandler(
        [self](std::shared_ptr<boostssl::MessageFace> _msg, std::shared_ptr<WsSession> _session) {
            auto wsService = self.lock();
            if (wsService)
            {
                wsService->onRecvMessage(_msg, _session);
            }
        });

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("newSession") << LOG_DESC("start the session")
                            << LOG_KV("endPoint", endPoint);
    return wsSession;
}

void WsService::addSession(std::shared_ptr<WsSession> _session)
{
    auto connectedEndPoint = _session->connectedEndPoint();
    auto endpoint = _session->endPoint();
    bool ok = false;
    {
        boost::unique_lock<boost::shared_mutex> lock(x_mutex);
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
        boost::unique_lock<boost::shared_mutex> lock(x_mutex);
        m_sessions.erase(_endPoint);
    }

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("removeSession") << LOG_KV("endpoint", _endPoint);
}

std::shared_ptr<WsSession> WsService::getSession(const std::string& _endPoint)
{
    boost::shared_lock<boost::shared_mutex> lock(x_mutex);
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
        boost::shared_lock<boost::shared_mutex> lock(x_mutex);
        for (const auto& session : m_sessions)
        {
            if (session.second && session.second->isConnected())
            {
                sessions.push_back(session.second);
            }
        }
    }

    // WEBSOCKET_SERVICE(TRACE) << LOG_BADGE("sessions") << LOG_KV("size",
    // sessions.size());
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
    std::ignore = _error;
    std::string endpoint = "";
    std::string connectedEndPoint = "";
    if (_session)
    {
        endpoint = _session->endPoint();
        connectedEndPoint = _session->connectedEndPoint();
    }

    addSession(_session);

    WEBSOCKET_SERVICE(INFO) << LOG_BADGE("onConnect") << LOG_KV("endpoint", endpoint)
                            << LOG_KV("connectedEndPoint", connectedEndPoint)
                            << LOG_KV("refCount", _session.use_count());
}

/**
 * @brief: session disconnect
 * @param _error: the reason of disconnection
 * @param _session: session
 * @return void:
 */
void WsService::onDisconnect(Error::Ptr _error, std::shared_ptr<WsSession> _session)
{
    std::ignore = _error;
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
                            << LOG_KV("connectedEndPoint", connectedEndPoint)
                            << LOG_KV("refCount", _session ? _session.use_count() : -1);
}

void WsService::onRecvMessage(std::shared_ptr<boostssl::MessageFace> _msg, std::shared_ptr<WsSession> _session)
{
    auto seq = _msg->seq();

    WEBSOCKET_SERVICE(TRACE) << LOG_BADGE("onRecvMessage")
                             << LOG_DESC("receive message from server")
                             << LOG_KV("type", _msg->packetType()) << LOG_KV("seq", seq)
                             << LOG_KV("endpoint", _session->endPoint())
                             << LOG_KV("data size", _msg->payload()->size())
                             << LOG_KV("use_count", _session.use_count());

    auto it = m_msgType2Method.find(_msg->packetType());
    if (it != m_msgType2Method.end())
    {
        auto callback = it->second;
        callback(_msg, _session);
    }
    else
    {
        WEBSOCKET_SERVICE(WARNING)
            << LOG_BADGE("onRecvMessage") << LOG_DESC("unrecognized message type")
            << LOG_KV("type", _msg->packetType()) << LOG_KV("endpoint", _session->endPoint())
            << LOG_KV("seq", seq) << LOG_KV("data size", _msg->payload()->size())
            << LOG_KV("use_count", _session.use_count());
    }
}

void WsService::asyncSendMessageByEndPoint(const std::string& _endPoint,
    std::shared_ptr<boostssl::MessageFace> _msg, Options _options, RespCallBack _respFunc)
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
    std::shared_ptr<boostssl::MessageFace> _msg, Options _options, RespCallBack _respCallBack)
{
    auto seq = _msg->seq();
    return asyncSendMessage(sessions(), _msg, _options, _respCallBack);
}

void WsService::asyncSendMessage(const WsSessions& _ss, std::shared_ptr<boostssl::MessageFace> _msg,
    Options _options, RespCallBack _respFunc)
{
    class Retry : public std::enable_shared_from_this<Retry>
    {
    public:
        WsSessions ss;
        std::shared_ptr<boostssl::MessageFace> msg;
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
                [self, session](Error::Ptr _error, std::shared_ptr<boostssl::MessageFace> _msg,
                    std::shared_ptr<WsSession> _session) {
                    if (_error && _error->errorCode() != 0)
                    {
                        WEBSOCKET_SERVICE(WARNING)
                            << LOG_BADGE("asyncSendMessage") << LOG_DESC("callback error")
                            << LOG_KV("endpoint", session->endPoint())
                            << LOG_KV("errorCode", _error->errorCode())
                            << LOG_KV("errorMessage", _error->errorMessage());

                        if (notRetryAgain(_error->errorCode()))
                        {
                            return self->respFunc(_error, _msg, _session);
                        }

                        // resend message again
                        return self->sendMessage();
                    }

                    self->respFunc(_error, _msg, _session);
                });
        }
    };

    auto size = _ss.size();

    auto retry = std::make_shared<Retry>();
    retry->ss = _ss;
    retry->msg = _msg;
    retry->options = _options;
    retry->respFunc = _respFunc;
    retry->sendMessage();

    auto seq = _msg->seq();
    int32_t timeout = _options.timeout > 0 ? _options.timeout : m_config->sendMsgTimeout();

    WEBSOCKET_SERVICE(DEBUG) << LOG_BADGE("asyncSendMessage") << LOG_KV("seq", seq)
                             << LOG_KV("size", size) << LOG_KV("timeout", timeout);
}

void WsService::asyncSendMessage(const std::set<std::string>& _endPoints,
    std::shared_ptr<boostssl::MessageFace> _msg, Options _options, RespCallBack _respFunc)
{
    ws::WsSessions ss;
    for (const std::string& endPoint : _endPoints)
    {
        auto s = getSession(endPoint);
        if (s)
        {
            ss.push_back(s);
        }
        else
        {
            WEBSOCKET_SERVICE(DEBUG)
                << LOG_BADGE("asyncSendMessage")
                << LOG_DESC("there has no connection of the endpoint exist, skip")
                << LOG_KV("endPoint", endPoint);
        }
    }

    return asyncSendMessage(ss, _msg, _options, _respFunc);
}

void WsService::broadcastMessage(std::shared_ptr<boostssl::MessageFace> _msg)
{
    broadcastMessage(sessions(), _msg);
}

void WsService::broadcastMessage(const WsSession::Ptrs& _ss, std::shared_ptr<boostssl::MessageFace> _msg)
{
    for (auto& session : _ss)
    {
        if (session->isConnected())
        {
            session->asyncSendMessage(_msg);
        }
    }

    WEBSOCKET_SERVICE(DEBUG) << LOG_BADGE("broadcastMessage");
}