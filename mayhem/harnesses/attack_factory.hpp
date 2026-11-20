// Builds the Attack for cfg.mode exactly as ng/cli/main.cpp does (minus the
// Engine, whose run() does real I/O and leaves by _exit()).
#ifndef MAYHEM_ATTACK_FACTORY_HPP_
#define MAYHEM_ATTACK_FACTORY_HPP_
#include <memory>

#include "slowhttp/attacks/continuation.hpp"
#include "slowhttp/attacks/expect_continue.hpp"
#include "slowhttp/attacks/range.hpp"
#include "slowhttp/attacks/rapid_reset.hpp"
#include "slowhttp/attacks/slow_body.hpp"
#include "slowhttp/attacks/slow_headers.hpp"
#include "slowhttp/attacks/slow_quic.hpp"
#include "slowhttp/attacks/slow_read.hpp"
#include "slowhttp/attacks/slow_read_h2.hpp"
#include "slowhttp/attacks/slow_tls.hpp"
#include "slowhttp/config.hpp"

static inline std::unique_ptr<slowhttp::Attack> make_attack(const slowhttp::Config& cfg) {
  using namespace slowhttp;
  switch (cfg.mode) {
    case Mode::SlowHeaders: return std::unique_ptr<Attack>(new SlowHeaders(cfg));
    case Mode::SlowRead:
      if (cfg.http2) return std::unique_ptr<Attack>(new SlowReadH2(cfg));
      return std::unique_ptr<Attack>(new SlowRead(cfg));
    case Mode::SlowBody: return std::unique_ptr<Attack>(new SlowBody(cfg));
    case Mode::ExpectContinue: return std::unique_ptr<Attack>(new ExpectContinue(cfg));
    case Mode::SlowTls: return std::unique_ptr<Attack>(new SlowTls(cfg));
    case Mode::SlowQuic:
      return std::unique_ptr<Attack>(new SlowQuic(
          cfg, cfg.quic_complete_hello ? SlowQuic::Hello::Complete : SlowQuic::Hello::Partial));
    case Mode::Continuation: return std::unique_ptr<Attack>(new ContinuationFlood(cfg));
    case Mode::RapidReset: return std::unique_ptr<Attack>(new RapidReset(cfg));
    case Mode::Range: return std::unique_ptr<Attack>(new RangeAttack(cfg));
  }
  return nullptr;
}
#endif
