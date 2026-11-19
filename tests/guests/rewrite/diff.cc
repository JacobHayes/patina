// The rewriter's differential guest in C++: threads on a std::atomic, exceptions thrown and
// caught across frames, virtual calls, std::map and std::sort. Prints the same lines on every run.
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

struct Shape {
	virtual ~Shape() = default;
	virtual long area() const = 0;
};
struct Square : Shape {
	long s;
	explicit Square(long s) : s(s) {}
	long area() const override { return s * s; }
};
struct Rect : Shape {
	long w, h;
	Rect(long w, long h) : w(w), h(h) {}
	long area() const override { return w * h; }
};

static long step(int i)
{
	if (i % 97 == 0) throw std::runtime_error("step " + std::to_string(i));
	return i % 13;
}

int main()
{
	std::atomic<long> total{0};
	std::atomic<long> caught{0};
	std::vector<std::thread> ts;
	for (int t = 0; t < 4; t++)
		ts.emplace_back([&] {
			for (int i = 1; i < 20000; i++) {
				try {
					total += step(i);
				} catch (const std::exception &) {
					caught++;
				}
			}
		});
	for (auto &t : ts) t.join();
	std::vector<std::unique_ptr<Shape>> shapes;
	for (long i = 0; i < 1000; i++) {
		if (i % 2) shapes.push_back(std::make_unique<Square>(i));
		else shapes.push_back(std::make_unique<Rect>(i, i + 1));
	}
	long area = 0;
	for (auto &s : shapes) area += s->area();
	std::map<std::string, int> words;
	std::vector<int> v;
	for (int i = 0; i < 30000; i++) {
		words["w" + std::to_string(i % 101)] += i;
		v.push_back((i * 7919) % 10007);
	}
	std::sort(v.begin(), v.end());
	std::printf("total %ld caught %ld area %ld\n", total.load(), caught.load(), area);
	std::printf("words %zu w42 %d v %d..%d\n", words.size(), words["w42"], v.front(), v.back());
	return 0;
}
