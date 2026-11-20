// URL / proxy parsers of both trees: classic slowhttptest::Url::prepare and
// Proxy::prepare (src/slowurl.cc, fed from -u and -d/-e), and ng's
// slowhttp::parse_url (ng/src/config/cli.cpp, fed from -u).
#include <cstddef>
#include <cstdint>
#include <string>

#include "slowurl.h"
#include "slowhttp/cli.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string s(reinterpret_cast<const char*>(data), size);
  std::string cstr(s.c_str());  // the CLI hands these parsers C strings
  {
    slowhttptest::Url u;
    if (u.prepare(cstr.c_str())) {
      volatile size_t sink = u.getHost().size() + u.getPath().size() +
                             u.getPathLen() + u.getPort() + u.isSSL() +
                             u.isLiteralIPv6();
      (void)sink;
      (void)u.getData();
      (void)u.getPortStr();
    }
  }
  {
    slowhttptest::Proxy p;
    if (p.prepare(cstr.c_str())) {
      volatile size_t sink = p.getHost().size() + p.getPort();
      (void)sink;
      (void)p.getPortStr();
    }
  }
  {
    slowhttp::Target t;
    std::string err;
    if (slowhttp::parse_url(s, t, err)) {
      (void)t.host_header();
      (void)t.authority();
    }
  }
  return 0;
}
