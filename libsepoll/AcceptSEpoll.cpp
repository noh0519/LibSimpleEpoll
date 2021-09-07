template <typename T1, typename T2> //
class AcceptSEpoll {
public:
  AcceptSEpoll();
  ~AcceptSEpoll();

private:
  T1 recv_obj;
  T2 send_obj;

protected:
};