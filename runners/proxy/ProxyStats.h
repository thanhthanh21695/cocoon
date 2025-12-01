#pragma once

#include "runners/helpers/AmortCounter.h"

namespace cocoon {

struct ProxyStats {
  AmortCounterList requests_received;
  AmortCounterList requests_failed;
  AmortCounterList requests_success;
  AmortCounterList requests_rejected;
  AmortCounterList total_requests_time;
  AmortCounterList request_bytes_received;
  AmortCounterList answer_bytes_sent;
  AmortCounterList total_adjusted_tokens_used;
  AmortCounterList prompt_adjusted_tokens_used;
  AmortCounterList cached_adjusted_tokens_used;
  AmortCounterList completion_adjusted_tokens_used;
  AmortCounterList reasoning_adjusted_tokens_used;

  const std::string &header() {
    return AmortCounterList::header();
  }
};

}  // namespace cocoon
