#ifndef _LOCKEDVECTOR_HPP_
#define _LOCKEDVECTOR_HPP_

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

using namespace std;

template <typename T> class LockedVector {
public:
private:
  std::recursive_mutex lock_;
  vector<T> vector_;

protected:
public:
  void push(T element);
  T pop();
  bool empty();
  void clear();
  void set(vector<T> setvector);
  vector<T> getToVector();

private:
protected:
};

template <typename T> void LockedVector<T>::push(T element) {
  lock_guard<std::recursive_mutex> guard(lock_);
  vector_.push_back(element);
}

template <typename T> T LockedVector<T>::pop() {
  lock_guard<std::recursive_mutex> guard(lock_);
  T return_value;
  if (!vector_.empty()) {
    return_value = vector_.front();
    vector_.pop_front();
  }

  return return_value;
}

template <typename T> bool LockedVector<T>::empty() {
  lock_guard<std::recursive_mutex> guard(lock_);
  return vector_.empty();
}

template <typename T> void LockedVector<T>::clear() {
  lock_guard<std::recursive_mutex> guard(lock_);
  vector_.clear();
}

template <typename T> void LockedVector<T>::set(vector<T> setvector) {
  lock_guard<std::recursive_mutex> guard(lock_);
  vector_.insert(vector_.end(), setvector.begin(), setvector.end());
}

template <typename T> vector<T> LockedVector<T>::getToVector() {
  lock_guard<std::recursive_mutex> guard(lock_);
  vector<T> v;
  for (auto a : vector_) {
    v.push_back(a);
  }

  return v;
}

#endif /* _LOCKEDVECTOR_HPP_ */
