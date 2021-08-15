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
 * @file ThreadPool.cpp
 * @author: octopus
 * @date 2021-06-11
 */

#include <bcos-boostssl/network/ThreadPool.h>

using namespace boostssl;
using namespace boostssl::utility;

ThreadPool::ThreadPool(const std::string& threadName, size_t size) : m_work(_ioService)
{
    _threadName = threadName;

    for (size_t i = 0; i < size; ++i)
    {
        _workers.create_thread([this, i] {
            setThreadName(_threadName + "_" + std::to_string(i));
            _ioService.run();
        });
    }
}

void ThreadPool::stop()
{
    _ioService.stop();
    if (!_workers.is_this_thread_in())
    {
        _workers.join_all();
    }
}

void ThreadPool::setThreadName(std::string const& _n)
{
#if defined(__GLIBC__)
    pthread_setname_np(pthread_self(), _n.c_str());
#elif defined(__APPLE__)
    pthread_setname_np(_n.c_str());
#endif
}
