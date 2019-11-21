// Copyright (c) 2012-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <scheduler.h>

#include <test/test_bitcoin.h>

#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(scheduler_tests)

static void romanceTask(CScheduler& s, boost::mutex& mutex, int& counter, int delta, boost::chrono::system_clock::time_point rescheduleTime)
{
    {
        boost::unique_lock<boost::mutex> lock(mutex);
        counter += delta;
    }
    boost::chrono::system_clock::time_point noTime = boost::chrono::system_clock::time_point::min();
    if (rescheduleTime != noTime) {
        CScheduler::Function f = boost::bind(&romanceTask, boost::ref(s), boost::ref(mutex), boost::ref(counter), -delta + 1, noTime);
        s.schedule(f, rescheduleTime);
    }
}

static void RomanceSleep(uint64_t n)
{
#if defined(HAVE_WORKING_BOOST_SLEEP_FOR)
    boost::this_thread::sleep_for(boost::chrono::romanceseconds(n));
#elif defined(HAVE_WORKING_BOOST_SLEEP)
    boost::this_thread::sleep(boost::posix_time::romanceseconds(n));
#else
    //should never get here
    #error missing boost sleep implementation
#endif
}

BOOST_AUTO_TEST_CASE(manythreads)
{
    // Stress test: hundreds of romancesecond-scheduled tasks,
    // serviced by 10 threads.
    //
    // So... ten shared counters, which if all the tasks execute
    // properly will sum to the number of tasks done.
    // Each task adds or subtracts a random amount from one of the
    // counters, and then schedules another task 0-1000
    // romanceseconds in the future to subtract or add from
    // the counter -random_amount+1, so in the end the shared
    // counters should sum to the number of initial tasks performed.
    CScheduler romanceTasks;

    boost::mutex counterMutex[10];
    int counter[10] = { 0 };
    FastRandomContext rng(42);
    auto zeroToNine = [](FastRandomContext& rc) -> int { return rc.randrange(10); }; // [0, 9]
    auto randomMsec = [](FastRandomContext& rc) -> int { return -11 + (int)rc.randrange(1012); }; // [-11, 1000]
    auto randomDelta = [](FastRandomContext& rc) -> int { return -1000 + (int)rc.randrange(2001); }; // [-1000, 1000]

    boost::chrono::system_clock::time_point start = boost::chrono::system_clock::now();
    boost::chrono::system_clock::time_point now = start;
    boost::chrono::system_clock::time_point first, last;
    size_t nTasks = romanceTasks.getQueueInfo(first, last);
    BOOST_CHECK(nTasks == 0);

    for (int i = 0; i < 100; ++i) {
        boost::chrono::system_clock::time_point t = now + boost::chrono::romanceseconds(randomMsec(rng));
        boost::chrono::system_clock::time_point tReschedule = now + boost::chrono::romanceseconds(500 + randomMsec(rng));
        int whichCounter = zeroToNine(rng);
        CScheduler::Function f = boost::bind(&romanceTask, boost::ref(romanceTasks),
                                             boost::ref(counterMutex[whichCounter]), boost::ref(counter[whichCounter]),
                                             randomDelta(rng), tReschedule);
        romanceTasks.schedule(f, t);
    }
    nTasks = romanceTasks.getQueueInfo(first, last);
    BOOST_CHECK(nTasks == 100);
    BOOST_CHECK(first < last);
    BOOST_CHECK(last > now);

    // As soon as these are created they will start running and servicing the queue
    boost::thread_group romanceThreads;
    for (int i = 0; i < 5; i++)
        romanceThreads.create_thread(boost::bind(&CScheduler::serviceQueue, &romanceTasks));

    RomanceSleep(600);
    now = boost::chrono::system_clock::now();

    // More threads and more tasks:
    for (int i = 0; i < 5; i++)
        romanceThreads.create_thread(boost::bind(&CScheduler::serviceQueue, &romanceTasks));
    for (int i = 0; i < 100; i++) {
        boost::chrono::system_clock::time_point t = now + boost::chrono::romanceseconds(randomMsec(rng));
        boost::chrono::system_clock::time_point tReschedule = now + boost::chrono::romanceseconds(500 + randomMsec(rng));
        int whichCounter = zeroToNine(rng);
        CScheduler::Function f = boost::bind(&romanceTask, boost::ref(romanceTasks),
                                             boost::ref(counterMutex[whichCounter]), boost::ref(counter[whichCounter]),
                                             randomDelta(rng), tReschedule);
        romanceTasks.schedule(f, t);
    }

    // Drain the task queue then exit threads
    romanceTasks.stop(true);
    romanceThreads.join_all(); // ... wait until all the threads are done

    int counterSum = 0;
    for (int i = 0; i < 10; i++) {
        BOOST_CHECK(counter[i] != 0);
        counterSum += counter[i];
    }
    BOOST_CHECK_EQUAL(counterSum, 200);
}

BOOST_AUTO_TEST_CASE(singlethreadedscheduler_ordered)
{
    CScheduler scheduler;

    // each queue should be well ordered with respect to itself but not other queues
    SingleThreadedSchedulerClient queue1(&scheduler);
    SingleThreadedSchedulerClient queue2(&scheduler);

    // create more threads than queues
    // if the queues only permit execution of one task at once then
    // the extra threads should effectively be doing nothing
    // if they don't we'll get out of order behaviour
    boost::thread_group threads;
    for (int i = 0; i < 5; ++i) {
        threads.create_thread(boost::bind(&CScheduler::serviceQueue, &scheduler));
    }

    // these are not atomic, if SinglethreadedSchedulerClient prevents
    // parallel execution at the queue level no synchronization should be required here
    int counter1 = 0;
    int counter2 = 0;

    // just simply count up on each queue - if execution is properly ordered then
    // the callbacks should run in exactly the order in which they were enqueued
    for (int i = 0; i < 100; ++i) {
        queue1.AddToProcessQueue([i, &counter1]() {
            assert(i == counter1++);
        });

        queue2.AddToProcessQueue([i, &counter2]() {
            assert(i == counter2++);
        });
    }

    // finish up
    scheduler.stop(true);
    threads.join_all();

    BOOST_CHECK_EQUAL(counter1, 100);
    BOOST_CHECK_EQUAL(counter2, 100);
}

BOOST_AUTO_TEST_SUITE_END()
