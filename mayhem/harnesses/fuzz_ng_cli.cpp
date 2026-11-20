// slowhttptest-ng command line -> Config -> attack payloads.
// Input: NUL-separated argv words (argv[0] is supplied). parse_cli is the
// CLI's own entry point; on kRun the attack is built as main.cpp builds it and
// its first payloads (on_open/on_connect/on_timer) are produced, without the
// Engine (which opens sockets and _exit()s).
#include <getopt.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "attack_factory.hpp"
#include "slowhttp/cli.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::vector<std::string> words;
  words.emplace_back("slowhttptest-ng");
  std::string cur;
  for (size_t i = 0; i < size; ++i) {
    if (data[i] == 0) { words.push_back(cur); cur.clear(); }
    else cur.push_back(static_cast<char>(data[i]));
  }
  if (!cur.empty()) words.push_back(cur);
  if (words.size() > 64) return -1;
  std::vector<char*> argv;
  for (auto& w : words) argv.push_back(&w[0]);
  argv.push_back(nullptr);

  // parse_cli sets optind = 1 itself, which does not reset glibc's internal
  // scan pointer; a stale one would point into the previous input's argv
  // (freed). optind = 0 plus one getopt call on a dummy argv is glibc's full
  // reset, so each input starts from fresh getopt state.
  {
    static char a0[] = "x";
    char* dummy[] = {a0, nullptr};
    optind = 0;
    opterr = 0;
    (void)getopt(1, dummy, "");
    opterr = 1;
  }
  slowhttp::Config cfg;
  if (slowhttp::parse_cli(static_cast<int>(words.size()), argv.data(), cfg) !=
      slowhttp::CliResult::kRun)
    return 0;
  std::unique_ptr<slowhttp::Attack> attack = make_attack(cfg);
  if (!attack) return 0;
  int n = cfg.connections < 3 ? cfg.connections : 3;
  size_t total = 0;
  for (int id = 0; id < n; ++id) {
    attack->conn_options(id);
    attack->on_open(id);
    total += attack->on_connect(id).bytes.size();
    for (int t = 0; t < 4; ++t) total += attack->on_timer(id).bytes.size();
  }
  (void)attack->summary();
  (void)attack->status_note();
  (void)attack->verdict_caveat();
  for (int id = 0; id < n; ++id) attack->on_close(id);
  return total == static_cast<size_t>(-1) ? 1 : 0;
}
