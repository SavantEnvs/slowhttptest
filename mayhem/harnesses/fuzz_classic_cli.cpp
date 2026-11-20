// Classic slowhttptest command line: the real main() of src/slowhttptestmain.cc
// (compiled with -Dmain=slowhttptest_main) -> option bounds -> SlowHTTPTest
// ctor -> init() (URL/proxy parsing, request/header/random-extra buffer setup;
// the -x overflow upstream fixed in 67dc819 lived here) -> run_test().
// Input: NUL-separated argv words. URL parsing itself is fuzzed by fuzz_url.
//
// Each input's result depends only on that input, and nothing outside the
// harness's scratch dir is touched:
//  - The harness runs the input through main()'s own getopt optstring first.
//    If main() would reject the argv during option parsing (unknown option,
//    missing argument, non-option word), it gets the input's words verbatim and
//    returns before init(), with no file, socket or signal side effects.
//  - Otherwise main() gets the same option sequence, one option per word, with:
//    * -d/-e proxy values pinned to 127.0.0.1:1 (numeric, closed port: no DNS
//      lookup, no outside host) unless longer than main()'s 1024-byte proxy
//      buffer, which main() rejects before using;
//    * `-u http://127.0.0.1:1/ -l 1` appended (getopt: the last one wins), so
//      run_test() connects to a closed loopback port, sees "connection refused"
//      and returns at once instead of attacking a real host for minutes;
//    * `-o <scratch>/report` appended, so -g's .csv/.html reports go to a
//      private mkdtemp() dir under $TMPDIR and never to the cwd or an
//      input-chosen path; the harness removes them after each call.
//  - main() installs its own SIGINT handler and ignores SIGPIPE; the harness
//    restores the previous dispositions (libFuzzer's) after every call.
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

int slowhttptest_main(int argc, char** argv);

// Must match src/slowhttptestmain.cc main()'s getopt optstring.
static const char kOptstring[] =
    ":HBRXgha:b:c:d:e:f:i:j:k:l:m:n:o:p:r:s:t:u:v:w:x:y:z:1:";
static const size_t kProxyBuf = 1024;  // main(): char proxy[1024]
static std::string g_report_base;
static std::string g_scratch_dir;

static void remove_scratch_dir() { rmdir(g_scratch_dir.c_str()); }

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  // The tool prints its progress/report to stdout; keep libFuzzer's stderr.
  if (!std::freopen("/dev/null", "w", stdout)) return 0;
  const char* tmp = std::getenv("TMPDIR");
  std::string tmpl = std::string(tmp && *tmp ? tmp : "/tmp") +
                     "/slowhttptest-classic-cli-XXXXXX";
  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');
  if (!mkdtemp(buf.data())) {
    std::perror("fuzz_classic_cli: mkdtemp");
    std::abort();
  }
  g_scratch_dir = buf.data();
  g_report_base = g_scratch_dir + "/report";
  std::atexit(remove_scratch_dir);
  return 0;
}

static int run_main(std::vector<std::string>& words) {
  std::vector<char*> argv;
  for (auto& w : words) argv.push_back(&w[0]);
  argv.push_back(nullptr);
  optind = 0;  // glibc: full getopt re-initialisation for this argv
  return slowhttptest_main(static_cast<int>(words.size()), argv.data());
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (g_report_base.empty()) LLVMFuzzerInitialize(nullptr, nullptr);
  std::vector<std::string> words;
  words.emplace_back("slowhttptest");
  std::string cur;
  for (size_t i = 0; i < size; ++i) {
    if (data[i] == 0) { words.push_back(cur); cur.clear(); }
    else cur.push_back(static_cast<char>(data[i]));
  }
  if (!cur.empty()) words.push_back(cur);
  if (words.size() > 64) return -1;

  // Pre-parse a copy (getopt permutes its argv) with main()'s optstring.
  std::vector<std::string> copy = words;
  std::vector<char*> cargv;
  for (auto& w : copy) cargv.push_back(&w[0]);
  cargv.push_back(nullptr);
  std::vector<std::string> canon;
  canon.emplace_back("slowhttptest");
  bool rejected = false;
  optind = 0;
  opterr = 0;
  int o;
  while ((o = getopt(static_cast<int>(copy.size()), cargv.data(), kOptstring)) != -1) {
    if (o == '?' || o == ':') { rejected = true; break; }
    canon.push_back(std::string("-") + static_cast<char>(o));
    if (!optarg) continue;
    std::string arg = optarg;
    if ((o == 'd' || o == 'e') && arg.size() < kProxyBuf) arg = "127.0.0.1:1";
    canon.push_back(arg);
  }
  if (!rejected && optind < static_cast<int>(copy.size())) rejected = true;
  opterr = 1;

  struct sigaction old_int, old_pipe;
  sigaction(SIGINT, nullptr, &old_int);
  sigaction(SIGPIPE, nullptr, &old_pipe);
  if (rejected) {
    // main() returns from its option loop before init(): no side effects.
    run_main(words);
  } else {
    for (const char* w : {"-u", "http://127.0.0.1:1/", "-l", "1", "-o"})
      canon.emplace_back(w);
    canon.push_back(g_report_base);
    run_main(canon);
    unlink((g_report_base + ".csv").c_str());
    unlink((g_report_base + ".html").c_str());
  }
  sigaction(SIGINT, &old_int, nullptr);
  sigaction(SIGPIPE, &old_pipe, nullptr);
  std::fflush(stdout);
  return 0;
}
