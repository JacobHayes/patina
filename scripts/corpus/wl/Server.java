// A com.sun.net.httpserver server on a 4-thread pool and java.net.http clients (100 requests, 8 at a time).
import com.sun.net.httpserver.*;
import java.net.*;
import java.net.http.*;
import java.util.*;
import java.util.concurrent.*;
public class Server {
  public static void main(String[] a) throws Exception {
    HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 41096), 64);
    s.createContext("/", ex -> { byte[] in = ex.getRequestBody().readAllBytes(); byte[] b = ("echo:" + ex.getRequestURI().getPath() + ":" + in.length).getBytes(); ex.sendResponseHeaders(200, b.length); ex.getResponseBody().write(b); ex.close(); });
    s.setExecutor(Executors.newFixedThreadPool(4)); s.start();
    HttpClient c = HttpClient.newBuilder().executor(Executors.newFixedThreadPool(4)).build();
    ExecutorService pool = Executors.newFixedThreadPool(8); List<Future<String>> fs = new ArrayList<>();
    for (int i = 0; i < 100; i++) { final int k = i; fs.add(pool.submit(() -> c.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:41096/r" + k)).POST(HttpRequest.BodyPublishers.ofString("x".repeat(k))).build(), HttpResponse.BodyHandlers.ofString()).body())); }
    String last = null; for (Future<String> f : fs) last = f.get();
    System.out.println("responses " + fs.size() + " " + last);
    long t = 0; for (int i = 0; i < 2_000_000; i++) t += Integer.bitCount(i * 31); System.out.println("jit " + t);
    pool.shutdown(); s.stop(0); System.exit(0);
  }
}
