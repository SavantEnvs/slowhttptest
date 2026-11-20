// QUIC Initial packet builder (quic::initial_packet / client_hello /
// initial_keys / put_varint). Fuzzed connection IDs, packet number, crypto
// offset/data, datagram floor and SNI. A built packet must describe itself:
// its DCID/SCID length bytes must equal the IDs it carries (the silent
// truncation upstream fixed in 0f6ac31), and it must classify as Initial.
#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <cstdlib>
#include <string>

#include "slowhttp/quic.hpp"

using namespace slowhttp;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::string dcid = fdp.ConsumeRandomLengthString(400);
  std::string scid = fdp.ConsumeRandomLengthString(400);
  uint64_t pn = fdp.ConsumeIntegral<uint64_t>();
  uint64_t off = fdp.ConsumeIntegralInRange<uint64_t>(0, (1ull << 62) - 1);
  size_t floor = fdp.ConsumeIntegralInRange<size_t>(0, 2000);
  quic::HelloOptions ho;
  ho.host = fdp.ConsumeRandomLengthString(300);
  ho.scid = scid;
  ho.alpn = fdp.ConsumeRandomLengthString(64);
  bool use_hello = fdp.ConsumeBool();
  std::string crypto = use_hello ? quic::client_hello(ho) : fdp.ConsumeRemainingBytesAsString();

  std::string v;
  quic::put_varint(v, off);
  if (v.size() != quic::varint_size(off)) abort();

  quic::Keys k = quic::initial_keys(dcid, false);
  std::string p = quic::initial_packet(dcid, scid, k, pn, off, crypto, floor);
  if (p.empty()) return 0;
  if (p.size() < 7 + dcid.size()) abort();
  if (static_cast<unsigned char>(p[5]) != dcid.size()) abort();
  if (p.compare(6, dcid.size(), dcid) != 0) abort();
  if (static_cast<unsigned char>(p[6 + dcid.size()]) != scid.size()) abort();
  if (quic::classify(p.data(), p.size()) != quic::Reply::Initial) abort();
  return 0;
}
