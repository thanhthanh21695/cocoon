#include "td/utils/tests.h"
#include "tdactor/td/actor/actor.h"
#include "td/net/SslCtx.h"
#include "td/net/SslStream.h"
#include "td/net/TcpListener.h"

#include "cocoon/FwdProxy.h"
#include "cocoon/RevProxy.h"
#include "cocoon/ProxyConfig.h"
#include "cocoon/pow.h"
#include "cocoon/utils.h"
#include "td/actor/coro_utils.h"
#include "td/net/Pipe.h"
#include "td/utils/benchmark.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/UInt.h"

#include <cocoon/tdx.h>

// Let's simplify attestation api
void start_ping_connection(td::BufferedFd<td::SocketFd> fd, bool expect_quote_info = false) {
  struct Connection : td::actor::Actor {
   public:
    explicit Connection(td::BufferedFd<td::SocketFd> fd, bool expect_quote_info)
        : sfd_(make_socket_pipe(std::move(fd)))
        , want_quote_info_(expect_quote_info)
        , want_send_hello_(!expect_quote_info) {
      CHECK(sfd_);
    }

   private:
    td::SocketPipe sfd_;
    td::actor::ActorId<Connection> self_;
    bool want_quote_info_{false};
    bool want_send_hello_{false};

    void start_up() override {
      sfd_.subscribe();
      loop();
    }

    void loop() override {
      auto status = do_loop();
      if (status.is_error()) {
        LOG(ERROR) << status;
        stop();
      }
    }
    td::Status do_loop() {
      TRY_STATUS(sfd_.flush_read());

      if (want_quote_info_) {
        TRY_RESULT(attestation_opt, cocoon::framed_tl_read<tdx::AttestationData>(sfd_.input_buffer()));
        if (!attestation_opt) {
          return td::Status::OK();
        }
        LOG(INFO) << "Ping: Received attestation data:\n" << attestation_opt.value();
        want_quote_info_ = false;
        want_send_hello_ = true;
      }
      if (want_send_hello_) {
        sfd_.output_buffer().append(td::BufferSlice("Hello world"));
        want_send_hello_ = false;
      }

      auto got = sfd_.input_buffer().read_as_buffer_slice(sfd_.input_buffer().size());
      if (!got.empty()) {
        LOG(INFO) << "Ping: got: " << got.as_slice();
        stop();
      }

      TRY_STATUS(sfd_.flush_write());
      return td::Status::OK();
    }
  };
  td::actor::create_actor<Connection>("ping_connection", std::move(fd), expect_quote_info).release();
}

void start_echo_connection(td::SocketFd fd, bool expect_quote_info = false) {
  struct Connection : td::actor::Actor {
    explicit Connection(td::BufferedFd<td::SocketFd> fd, bool expect_quote_info)
        : sfd_(make_socket_pipe(std::move(fd))), expect_quote_info_(expect_quote_info) {
    }

   private:
    td::SocketPipe sfd_;
    bool expect_quote_info_{false};

    void start_up() override {
      sfd_.subscribe();
    }

    void loop() override {
      auto status = do_loop();
      if (status.is_error()) {
        LOG(ERROR) << status;
        stop();
      }
    }
    td::Status do_loop() {
      TRY_STATUS(sfd_.flush_read());

      if (expect_quote_info_) {
        TRY_RESULT(attestation_opt, cocoon::framed_tl_read<tdx::AttestationData>(sfd_.input_buffer()));
        if (!attestation_opt) {
          return td::Status::OK();
        }
        LOG(INFO) << "Echo: Received attestation data";
        expect_quote_info_ = false;
      }
      cocoon::proxy_sockets(sfd_, sfd_);

      TRY_STATUS(sfd_.flush_write());
      return td::Status::OK();
    }
  };
  td::actor::create_actor<Connection>("echo_connection", td::BufferedFd<td::SocketFd>(std::move(fd)), expect_quote_info)
      .release();
}

void start_echo_server(td::int32 port, bool expect_quote_info = false) {
  struct Callback : td::TcpListener::Callback {
    bool expect_quote_info_;
    explicit Callback(bool expect_quote_info) : expect_quote_info_(expect_quote_info) {
    }
    virtual void accept(td::SocketFd fd) {
      start_echo_connection(std::move(fd), expect_quote_info_);
    }
  };
  td::actor::create_actor<td::TcpInfiniteListener>("Listener", port, std::make_unique<Callback>(expect_quote_info))
      .release();
}

// Custom verify callback that prints certificate information
template <typename T>
class DelayedAction : public td::actor::Actor {
 public:
  DelayedAction(T promise) : promise_(std::move(promise)) {
  }
  void set_timer(td::Timestamp t) {
    alarm_timestamp() = t;
  }
  void alarm() override {
    promise_();
    stop();
  }

  static void create(T promise, td::Timestamp t) {
    auto A = td::actor::create_actor<DelayedAction>("delayed", std::move(promise));
    td::actor::send_closure(A, &DelayedAction::set_timer, t);
    A.release();
  }

 private:
  T promise_;
};

template <typename T>
void delay_action(T promise, td::Timestamp timeout) {
  DelayedAction<T>::create(std::move(promise), timeout);
}

class TdxMakeQuoteBench final : public td::Benchmark {
 public:
  std::string get_description() const final {
    return "Tdx quote generation (usually done just once per run)";
  }

  void run(int n) final {
    auto tdx = tdx::TdxInterface::create();
    CHECK(tdx);
    for (int i = 0; i < n; i++) {
      tdx->make_quote(td::UInt512{}).ensure();
    }
  }

 private:
  tdx::Quote quote_;
};
class TdxValidateBench final : public td::Benchmark {
 public:
  TdxValidateBench(tdx::Quote quote) : quote_(std::move(quote)) {
  }
  std::string get_description() const final {
    return "Tdx validation";
  }

  void run(int n) final {
    auto tdx = tdx::TdxInterface::create();
    CHECK(tdx);
    for (int i = 0; i < n; i++) {
      tdx->validate_quote(quote_).ensure();
    }
  }

 private:
  tdx::Quote quote_;
};

#define TD_TDX_ATTESTATION 0
#if TD_TDX_ATTESTATION
TEST(TDX, Base) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(INFO));
  auto tdx = tdx::TdxInterface::create();
  CHECK(tdx);

  bool is_guest = false;
  tdx::Quote quote;
  tdx::UserClaims user_claims;
  auto r_quota = tdx->make_quote(user_claims.to_hash());
  if (r_quota.is_ok()) {
    is_guest = true;
    quote = r_quota.move_as_ok();
    auto attestation_data = tdx->get_data(quote).move_as_ok().as_tdx();
    CHECK(attestation_data.reportdata == user_claims.to_hash());
    LOG(INFO) << "Got quote: " << attestation_data;
  } else {
    LOG(ERROR) << "Failed to generate attestation: " << r_quota.error();
    LOG(ERROR) << "Using pregenerated quote";
    quote = tdx::Quote{td::read_file_str("../cocoon/test/quote.dat").move_as_ok()};
  }
  auto attestation_data = tdx->validate_quote(quote).move_as_ok().as_tdx();
  CHECK(!is_guest || attestation_data.reportdata == user_claims.to_hash());
  LOG(INFO) << attestation_data;

  if (is_guest) {
    td::bench(TdxMakeQuoteBench());
  }
  td::bench(TdxValidateBench(quote));
}
#endif

td::actor::Task<td::Unit> ensure_task(td::actor::Task<td::Unit> t) {
  (co_await std::move(t).wrap()).ensure();
  co_return td::Unit();
}

td::actor::Task<td::Unit> base_test() {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(INFO));

  // Test that generated example config is parseable
  LOG(INFO) << "Testing example config parseability...";
  {
    auto example_json = cocoon::generate_example_config();
    auto json_value = td::json_decode(example_json).move_as_ok();
    auto parsed_config = cocoon::parse_config_from_json(json_value).move_as_ok();

    LOG(INFO) << "Example config parsed successfully with " << parsed_config.policies.size() << " policies and "
              << parsed_config.ports.size() << " ports";
  }

  // Test AttestationData::image_hash()
  LOG(INFO) << "Testing AttestationData::image_hash()...";
  {
    tdx::TdxAttestationData tdx_data1;
    std::memset(tdx_data1.mr_td.raw, 0x12, sizeof(tdx_data1.mr_td.raw));
    std::memset(tdx_data1.mr_config_id.raw, 0x34, sizeof(tdx_data1.mr_config_id.raw));
    std::memset(tdx_data1.mr_owner.raw, 0xAA, sizeof(tdx_data1.mr_owner.raw));
    std::memset(tdx_data1.mr_owner_config.raw, 0xBB, sizeof(tdx_data1.mr_owner_config.raw));
    for (size_t i = 0; i < 4; i++) {
      std::memset(tdx_data1.rtmr[i].raw, static_cast<int>('a' + i), sizeof(tdx_data1.rtmr[i].raw));
    }
    tdx_data1.reportdata = td::UInt512{};  // Zero reportdata

    tdx::AttestationData attestation1(tdx_data1);
    auto hash1 = attestation1.image_hash();

    // Same measurements but different reportdata
    tdx::TdxAttestationData tdx_data2 = tdx_data1;
    std::memset(tdx_data2.reportdata.raw, 0xFF, sizeof(tdx_data2.reportdata.raw));  // Different reportdata

    tdx::AttestationData attestation2(tdx_data2);
    auto hash2 = attestation2.image_hash();

    // Hashes should be identical (reportdata is excluded)
    CHECK(hash1 == hash2);
    LOG(INFO) << "Image hash (same for different reportdata): " << td::hex_encode(hash1.as_slice());

    // Different measurements should produce different hash
    tdx::TdxAttestationData tdx_data3 = tdx_data1;
    std::memset(tdx_data3.mr_td.raw, 0x99, sizeof(tdx_data3.mr_td.raw));  // Different mr_td

    tdx::AttestationData attestation3(tdx_data3);
    auto hash3 = attestation3.image_hash();

    CHECK(hash1 != hash3);
    LOG(INFO) << "Image hash test PASSED";
  }

  auto fwd_proxy_port = 9116;
  auto rev_proxy_port = 9117;
  auto http_server_port = 9118;
  td::IPAddress http_server_ip_address;
  http_server_ip_address.init_host_port("localhost", http_server_port).ensure();

  tdx::TdxInterfaceRef fwd_tdx = tdx::TdxInterface::create_fake();
  tdx::TdxInterfaceRef rev_tdx = tdx::TdxInterface::create_fake();

  auto fwd_cert_and_key = tdx::generate_cert_and_key(fwd_tdx.get());
  auto rev_cert_and_key = tdx::generate_cert_and_key(rev_tdx.get());

  cocoon::FwdProxy::Config fwd_config;
  fwd_config.policies_["username"] = tdx::Policy::make(fwd_tdx);
  fwd_config.port_ = fwd_proxy_port;
  fwd_config.cert_and_key_ = td::SharedValue<tdx::CertAndKey>(fwd_cert_and_key);
  fwd_config.allow_policy_from_username_ = true;
  fwd_config.serialize_info = true;  // Test AttestationData serialization

  cocoon::RevProxy::Config rev_config;
  rev_config.src_port_ = rev_proxy_port;
  rev_config.dst_ = http_server_ip_address;
  rev_config.policy_ = tdx::Policy::make(rev_tdx);
  rev_config.cert_and_key_ = td::SharedValue<tdx::CertAndKey>(rev_cert_and_key);
  rev_config.serialize_info = true;  // Test AttestationData serialization
  rev_config.pow_difficulty = 20;

  co_await td::actor::coro_sleep(td::Timestamp::in(1));

  td::actor::create_actor<cocoon::FwdProxy>("FwdProxyServer", fwd_config).release();
  td::actor::create_actor<cocoon::RevProxy>("RevProxyServer", rev_config).release();

  start_echo_server(http_server_port, true);  // Expect attestation data from RevProxy

  td::IPAddress fwd_proxy_ip_address;
  fwd_proxy_ip_address.init_host_port("localhost", fwd_proxy_port).ensure();
  auto socket_fd = td::SocketFd::open(fwd_proxy_ip_address).move_as_ok();

  td::IPAddress rev_proxy_ip_address;
  rev_proxy_ip_address.init_host_port("localhost", rev_proxy_port).ensure();

  auto buff_socket_fd = co_await cocoon::socks5(std::move(socket_fd), rev_proxy_ip_address, "username", "password");
  start_ping_connection(std::move(buff_socket_fd), true);  // Expect attestation data from FwdProxy

  co_return td::Unit();
}

TEST(Cocoon, Base) {
  int threads_n = 2;
  td::actor::Scheduler sched({threads_n});
  sched.run_in_context([&] { ensure_task(base_test()).start().detach_silent(); });
  while (sched.run(10)) {
    // empty
  }
}
