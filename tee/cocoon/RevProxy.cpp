//
// Created by Arseny Smirnov  on 16.07.2025.
//
#include "cocoon/RevProxy.h"
#include "cocoon/pow.h"

#include "td/net/SslStream.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/optional.h"
#include "td/utils/format.h"
#include "tdx.h"
#include "utils.h"
#include "td/net/Pipe.h"
#include "td/net/utils.h"
#include "td/utils/CancellationToken.h"

namespace cocoon {
namespace {
struct AcceptAndProxy : td::TaskActor<ProxyState> {
  AcceptAndProxy(td::SocketFd socket, std::shared_ptr<const RevProxy::Config> config)
      : socket_(std::move(socket)), config_(std::move(config)) {
  }

  td::actor::Task<Action> task_loop_once() override {
    state_.init_source(socket_);
    state_.destination_ = config_->dst_;
    state_.update_state("Connecting");

    auto desc = state_.short_desc();

    td::SocketPipe client_pipe = td::make_socket_pipe(std::move(socket_));

    // Verify PoW from incoming client (always enabled)
    state_.update_state("Pow");
    client_pipe = co_await pow::verify_pow_server(std::move(client_pipe), config_->pow_difficulty);

    state_.update_state("TlsHandshake");
    auto [tls_socket, info] =
        co_await wrap_tls_server("-Rev-" + desc, std::move(client_pipe), config_->cert_and_key_.load(), config_->policy_);
    state_.set_attestation(info);

    auto dst_pipe = make_socket_pipe(co_await td::SocketFd::open(config_->dst_));

    if (config_->serialize_info) {
      co_await framed_tl_write(dst_pipe.output_buffer(), info);
    }

    state_.update_state("Proxying");
    co_await proxy("-Rev-" + desc, std::move(tls_socket), std::move(dst_pipe));
    co_return Action::Finish;
  }

  td::actor::Task<ProxyState> finish(td::Status status) override {
    state_.finish(std::move(status));
    co_return std::move(state_);
  }

 private:
  td::SocketFd socket_;
  std::shared_ptr<const RevProxy::Config> config_;
  ProxyState state_;
};
}  // namespace

void RevProxy::start_up() {
  struct Callback : public td::TcpListener::Callback {
    std::shared_ptr<const Config> config_;
    explicit Callback(std::shared_ptr<const Config> config) : config_(std::move(config)) {
    }
    void accept(td::SocketFd fd) override {
      td::actor::spawn_task_actor<AcceptAndProxy>("Rev", std::move(fd), config_).detach_silent();
    }
  };
  listener_ = td::actor::create_actor<td::TcpInfiniteListener>("Listener", config_->src_port_,
                                                               std::make_unique<Callback>(config_));
}
}  // namespace cocoon
