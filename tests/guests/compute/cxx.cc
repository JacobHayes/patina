// A small C++ program for compute points: a static object built before main and destroyed
// after it, two threads that add to a std::atomic and throw and catch an exception every 100
// steps, all in instrumented code. Prints "ctor ok", "total=... caught=... ok", "dtor ok".
#include <atomic>
#include <cstdio>
#include <stdexcept>
#include <thread>

static std::atomic<long> total;

struct Init {
	long seed;
	Init() : seed(0)
	{
		for (int i = 0; i < 1000; i++) seed += i % 7;
		std::printf("ctor %s\n", seed == 2997 ? "ok" : "BAD");
	}
	~Init() { std::printf("dtor %s\n", total.load() == 2 * 3000 ? "ok" : "BAD"); }
};
static Init init;

static long step(int i)
{
	if (i % 100 == 99) throw std::runtime_error("step");
	return 1;
}

static void work(long *caught)
{
	for (int i = 0; i < 3000; i++) {
		try {
			total.fetch_add(step(i));
		} catch (const std::runtime_error &) {
			++*caught;
			total.fetch_add(1);
		}
	}
}

int main()
{
	long c[2] = {0, 0};
	std::thread a(work, &c[0]), b(work, &c[1]);
	a.join();
	b.join();
	bool ok = total.load() == 6000 && c[0] + c[1] == 60;
	std::printf("total=%ld caught=%ld %s\n", total.load(), c[0] + c[1], ok ? "ok" : "BAD");
	return !ok;
}
