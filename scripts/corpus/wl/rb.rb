# Ruby: a threaded TCP server, 4 client threads x 25 requests, fork + pipe, a Queue of workers, file I/O.
require 'socket'
srv = TCPServer.new('127.0.0.1', 41097)
acc = Thread.new { loop { c = srv.accept; Thread.new(c) { |s| while (l = s.gets); s.puts(l.upcase); end; s.close } } }
res = 4.times.map { |k| Thread.new { s = TCPSocket.new('127.0.0.1', 41097); n = 25.times.count { |i| s.puts("c#{k} m#{i}"); s.gets }; s.close; n } }.map(&:value)
puts "replies #{res.sum}"
r, w = IO.pipe
pid = fork { r.close; w.puts((1..1000).sum); w.close }
w.close; puts "child #{r.read.strip}"; Process.wait(pid); puts "child status #{$?.exitstatus}"
q = Queue.new; out = Queue.new
ws = 3.times.map { Thread.new { while (x = q.pop) != :done; out << x * x; end } }
10.times { |i| q << i }; 3.times { q << :done }; ws.each(&:join)
puts "squares #{Array.new(out.size) { out.pop }.sum}"
File.write('f.txt', "a\n" * 1000); puts "lines #{File.readlines('f.txt').size}"
