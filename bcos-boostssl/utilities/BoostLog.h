/**
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
 * @brief: define Log
 *
 * @file: Log.h
 * @author: yujiechen
 * @date 2021-02-24
 */
#pragma once

#include <boost/log/attributes/constant.hpp>
#include <boost/log/attributes/scoped_attribute.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/trivial.hpp>

#ifdef ERROR
#undef ERROR
#endif

// BCOS log format
#define LOG_BADGE(_NAME) "[" << (_NAME) << "]"
#define LOG_TYPE(_TYPE) (_TYPE) << "|"
#define LOG_DESC(_DESCRIPTION) (_DESCRIPTION)
#define LOG_KV(_K, _V) "," << (_K) << "=" << (_V)

namespace bcos
{
namespace boostssl
{
namespace utilities
{
extern std::string const FileLogger;
/// the file logger
extern boost::log::sources::severity_channel_logger_mt<boost::log::trivial::severity_level,
    std::string>
    FileLoggerHandler;

// the statFileLogger
extern std::string const StatFileLogger;
extern boost::log::sources::severity_channel_logger_mt<boost::log::trivial::severity_level,
    std::string>
    StatFileLoggerHandler;

enum LogLevel
{
    FATAL = boost::log::trivial::fatal,
    ERROR = boost::log::trivial::error,
    WARNING = boost::log::trivial::warning,
    INFO = boost::log::trivial::info,
    DEBUG = boost::log::trivial::debug,
    TRACE = boost::log::trivial::trace
};

extern LogLevel c_fileLogLevel;
extern LogLevel c_statLogLevel;

void setFileLogLevel(LogLevel const& _level);
void setStatLogLevel(LogLevel const& _level);

#if defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN32_)
#define BCOS_LOG(level)                                                                          \
    if (bcos::boostssl::utilities::LogLevel::level >= bcos::boostssl::utilities::c_fileLogLevel) \
    BOOST_LOG_SEV(bcos::boostssl::utilities::FileLoggerHandler,                                  \
        (boost::log::v2s_mt_nt6::trivial::severity_level)(bcos::boostssl::utilities::LogLevel::  \
                level))
#else
#define BCOS_LOG(level)                                                                           \
    if (bcos::boostssl::utilities::LogLevel::level >= bcos::boostssl::utilities::c_fileLogLevel)  \
    BOOST_LOG_SEV(bcos::boostssl::utilities::FileLoggerHandler,                                   \
        (boost::log::v2s_mt_posix::trivial::severity_level)(bcos::boostssl::utilities::LogLevel:: \
                level))
#endif
#define CompareLevel(level) \
    (bcos::boostssl::utilities::LogLevel::level >= bcos::boostssl::utilities::c_fileLogLevel)

}  // namespace utilities
}  // namespace boostssl
}  // namespace bcos
