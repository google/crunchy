// Copyright 2017 The CrunchyCrypt Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef CRUNCHY_INTERNAL_COMMON_POOL_H_
#define CRUNCHY_INTERNAL_COMMON_POOL_H_

#include <functional>
#include <memory>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/memory/memory.h"
#include "absl/synchronization/mutex.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

template <typename T>
using pool_unique_ptr = std::unique_ptr<T, std::function<void(T*)>>;

// Pool<T> contains a mutex-protected object pool, producing pool_unique_ptr<T>
// objects which are unique_ptr's that use a custom deleter.
//
// To implement a Pool for a particular object, override the Clone method, as a
// map from GetSeedValue() of type T* to a copy of type T*. e.g.
// class StringPool : public Pool<std::string> {
//  public:
//   using Pool<std::string>::Pool;
//
//   std::unique_ptr<std::string> Clone() override { return
//   absl::make_unique<std::string>(seed_value_); }
// };
// The deleter passed in the Pool constructor will be used to delete *all* T
// instances provduced by the Clone() method.
//
// StringPool::get() can be called concurrently as:
// pool_unique_ptr<std::string> ptr = pool.get();
//
// On destruction, ptr is automagically returned to the pool. While alive, ptr
// is independent of other objects of type pool_unique_ptr<std::string> produced from
// StringPool.get().
//
//
// All public methods are thread-safe.
template <class T>
class Pool {
 public:
  explicit Pool(pool_unique_ptr<T> seed_value)
      : seed_value_(std::move(seed_value)) {}

  // Returns an object from the pool or constructs a new object if the pool is
  // empty.
  pool_unique_ptr<T> get() {
    absl::MutexLock l(&mutex_);
    T* value;
    if (pool_.empty()) {
      value = Clone();
    } else {
      value = pool_.back();
      pool_.pop_back();
    }
    return pool_unique_ptr<T>(value, PoolPtrDeleter(this));
  }

  virtual ~Pool() {
    for (auto value : pool_) {
      seed_value_.reset(value);
    }
  }

 protected:
  virtual T* Clone() = 0;

  T* GetSeedValue() { return seed_value_.get(); }

 private:
  friend class PoolPtrDeleter;
  class PoolPtrDeleter {
   public:
    explicit PoolPtrDeleter(Pool* pool) : pool_(pool) {}
    void operator()(T* value) { return pool_->Return(value); }

   private:
    Pool* pool_;
  };

  void Return(T* value) {
    CRUNCHY_CHECK(value);
    absl::MutexLock l(&mutex_);
    pool_.push_back(value);
  }

  absl::Mutex mutex_;
  pool_unique_ptr<T> seed_value_;
  std::vector<T*> pool_ GUARDED_BY(mutex_);
};

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_COMMON_POOL_H_
