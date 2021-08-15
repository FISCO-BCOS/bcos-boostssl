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
 * @file TimeUtility.cpp
 * @author: octopus
 * @date 2021-05-06
 */

#include <bcos-boostssl/utility/TimeUtility.h>
#include <sys/time.h>
#include <chrono>

using namespace boostssl;
using namespace boostssl::utility;

/// get utc time(ms)
uint64_t TimeUtility::utcTime()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// getSteadyTime(ms)
uint64_t TimeUtility::utcSteadyTime()
{
    // trans (ns) into (ms)
    return std::chrono::steady_clock::now().time_since_epoch().count() / 1000000;
}

/// get utc time(us)
uint64_t TimeUtility::utcTimeUs()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

uint64_t TimeUtility::utcSteadyTimeUs()
{
    return std::chrono::steady_clock::now().time_since_epoch().count() / 1000;
}
