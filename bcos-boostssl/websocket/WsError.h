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
 * @file WsError.h
 * @author: octopus
 * @date 2021-10-02
 */
#pragma once
#include <memory>
#include <sstream>
#include <string>

namespace bcos
{
namespace boostssl
{
namespace ws
{
enum WsError
{
    AcceptError = -4000,
    ReadError = -4001,
    WriteError = -4002,
    PingError = -4003,
    PongError = -4004,
    PacketError = -4005,
    SessionDisconnect = -4006,
    UserDisconnect = -4007,
    TimeOut = -4008,
    NoActiveCons = -4009,
    EndPointNotExist = -4010,
    MessageOverflow = -4011,
    UndefinedException = -4012,
    MessageEncodeError = -4013
};

inline std::ostream& operator<<(std::ostream& _out, WsError const& error)
{
    switch (error)
    {
    case WsError::AcceptError:
        _out << "AcceptError";
        break;
    case WsError::ReadError:
        _out << "ReadError";
        break;
    case WsError::WriteError:
        _out << "WriteError";
        break;
    case WsError::PingError:
        _out << "PingError";
        break;
    case WsError::PongError:
        _out << "PongError";
        break;
    case WsError::PacketError:
        _out << "PacketError";
        break;
    case WsError::SessionDisconnect:
        _out << "SessionDisconnect";
        break;
    case WsError::UserDisconnect:
        _out << "UserDisconnect";
        break;
    case WsError::TimeOut:
        _out << "TimeOut";
        break;
    case WsError::NoActiveCons:
        _out << "NoActiveCons";
        break;
    case WsError::EndPointNotExist:
        _out << "EndPointNotExist";
        break;
    case WsError::MessageOverflow:
        _out << "MessageOverflow";
        break;
    case WsError::UndefinedException:
        _out << "UndefinedException";
        break;
    case WsError::MessageEncodeError:
        _out << "MessageEncodeError";
        break;
    default:
        _out << "Unkown";
        break;
    }
    return _out;
}


inline bool notRetryAgain(int _wsError)
{
    return (_wsError == boostssl::ws::WsError::MessageOverflow);
}

}  // namespace ws
}  // namespace boostssl
}  // namespace bcos