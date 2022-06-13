#pragma once
#include <boost/asio.hpp>
#include <memory>
namespace bcos
{
namespace boostssl
{
namespace ws
{
class IOServicePool
{
public:
    using Ptr = std::shared_ptr<IOServicePool>;

    using IOService = boost::asio::io_context;
    using ExecutorType = boost::asio::io_context::executor_type;
    using Work = boost::asio::executor_work_guard<ExecutorType>;
    using WorkPtr = std::unique_ptr<Work>;

    // the constructor just launches some amount of threads
    IOServicePool(size_t _workerNum = std::thread::hardware_concurrency())
      : m_works(_workerNum), m_nextIOService(0)
    {
        // create the ioservices
        for (size_t i = 0; i < _workerNum; i++)
        {
            m_ioServices.emplace_back(std::make_shared<IOService>());
        }
    }

    IOServicePool(const IOServicePool&) = delete;
    IOServicePool& operator=(const IOServicePool&) = delete;

    void start()
    {
        for (size_t i = 0; i < m_ioServices.size(); ++i)
        {
            m_works[i] = std::unique_ptr<Work>(new Work(m_ioServices[i]->get_executor()));
        }

        // one io_context per thread
        for (size_t i = 0; i < m_ioServices.size(); ++i)
        {
            m_threads.emplace_back([this, i]() { (m_ioServices[i])->run(); });
        }
    }
    std::shared_ptr<IOService> getIOService()
    {
        auto selectedIoService = (m_nextIOService % m_ioServices.size());
        m_nextIOService++;
        return m_ioServices.at(selectedIoService);
    }

    void stop()
    {
        // Once the work object is destroyed, the service will stop.
        for (auto& work : m_works)
        {
            work.reset();
        }
        for (auto& t : m_threads)
        {
            t.join();
        }
    }

private:
    std::vector<std::shared_ptr<IOService>> m_ioServices;
    std::vector<WorkPtr> m_works;
    std::vector<std::thread> m_threads;
    size_t m_nextIOService;
};
}  // namespace ws
}  // namespace boostssl
}  // namespace bcos