// Server-controlled reply bytes -> each ng attack's on_readable() handler
// (status-line parsing in expect_continue, HTTP/2 GOAWAY frame walking,
// QUIC long-header classification, TLS alert reading, ...), plus the
// standalone http2::GoawayWatch and quic::classify readers.
// Input layout: byte0 = mode, byte1 = flags, then a stream of
// [chunk length byte][connection id byte][chunk bytes].
#include <cstddef>
#include <cstdint>
#include <string>

#include "attack_factory.hpp"
#include "slowhttp/http2.hpp"
#include "slowhttp/quic.hpp"

static constexpr int kConns = 4;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return -1;
  // Whole input through the stateless readers first.
  {
    slowhttp::http2::GoawayWatch w;
    w.feed(reinterpret_cast<const char*>(data), size);
    (void)slowhttp::quic::classify(reinterpret_cast<const char*>(data), size);
  }
  slowhttp::Config cfg;
  cfg.mode = static_cast<slowhttp::Mode>(data[0] % 9);
  cfg.http2 = data[1] & 1;
  cfg.quic_complete_hello = data[1] & 2;
  cfg.connections = kConns;
  cfg.target.host = (data[1] & 4) ? "127.0.0.1" : "example.test";
  if (cfg.mode == slowhttp::Mode::SlowTls || cfg.mode == slowhttp::Mode::SlowQuic) {
    cfg.target.scheme = "https";
    cfg.target.port = "443";
  }
  std::unique_ptr<slowhttp::Attack> attack = make_attack(cfg);
  if (!attack) return 0;
  for (int id = 0; id < kConns; ++id) {
    attack->on_open(id);
    attack->on_connect(id);
  }
  size_t i = 2;
  while (i + 2 <= size) {
    size_t len = data[i];
    int id = data[i + 1] % kConns;
    i += 2;
    if (len > size - i) len = size - i;
    slowhttp::Action a =
        attack->on_readable(id, reinterpret_cast<const char*>(data + i), len);
    i += len;
    if (a.kind == slowhttp::Action::Kind::Close ||
        a.kind == slowhttp::Action::Kind::Reconnect) {
      attack->on_close(id);
      attack->on_open(id);
      attack->on_connect(id);
    } else if (a.rearm) {
      attack->on_timer(id);
    }
  }
  (void)attack->summary();
  (void)attack->status_note();
  (void)attack->verdict_caveat();
  return 0;
}
