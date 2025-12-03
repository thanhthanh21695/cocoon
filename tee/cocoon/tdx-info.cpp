#include "tdx.h"
#include "utils.h"
#include "td/actor/coro.h"
#include "td/net/Pipe.h"
#include "td/utils/OptionParser.h"

td::actor::Task<td::Unit> check_task(td::actor::Task<td::Unit> t) {
  auto r = (co_await std::move(t).wrap());
  if (r.is_error()) {
    LOG(ERROR) << r.error();
    std::_Exit(1);
  }
  std::_Exit(0);
  co_return td::Unit();
}

td::actor::Task<td::Unit> run(td::CSlice host, td::int32 port, bool fake_tdx) {
  auto tdx = fake_tdx ? tdx::TdxInterface::create_fake() : tdx::TdxInterface::create();
  td::IPAddress ip_address;
  co_await ip_address.init_host_port(host, port);
  auto cert = tdx::generate_cert_and_key(nullptr);
  auto socket = co_await td::SocketFd::open(ip_address);
  auto [pipe, info] = co_await cocoon::wrap_tls_client("Inspect", td::make_socket_pipe(std::move(socket)), cert,
                                                       tdx::Policy::make(tdx));
  LOG(INFO) << "Connection established";
  LOG(INFO) << info;
  co_return td::Unit();
}
int main(int argc, char **argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));

  td::OptionParser option_parser;
  bool fake_tdx = false;

  option_parser.add_checked_option('f', "fake-tdx", "port", [&]() {
    fake_tdx = true;
    return td::Status::OK();
  });

  option_parser.add_option('h', "help", "Show this help message", [&]() {
    LOG(PLAIN) << option_parser;
    std::_Exit(0);
  });

  option_parser.set_description(
      "Connect to a TLS server and print TDX attestation information\nUsage: tdx-info <host> <port>\n");

  auto r_args = option_parser.run(argc, argv, 2);
  if (r_args.is_error()) {
    LOG(ERROR) << r_args.error();
    LOG(ERROR) << option_parser;
    return 1;
  }
  auto args = r_args.move_as_ok();
  auto host = td::CSlice(args[0]);
  auto port = td::to_integer<td::int32>(td::CSlice(args[1]));
  // Start scheduler
  td::actor::Scheduler sched{{1}};

  sched.run_in_context([&] {
    // Create proxy actors for each configured port
    check_task(run(host, port, fake_tdx)).start().detach("check_task");
  });

  LOG(INFO) << "Proxies started";
  sched.start();
  while (sched.run(10)) {
    // empty
  }

  return 0;
}
