# controllerNet
- SensorDB에서 json 데이터 수신&파싱 하여 AP&Client 데이터 생성 및 컨트롤러에 전송까지 완료
- Aria 미구현으로 데이터 암복호화 불가, 컨트롤러와 연동시 컨트롤러의 함수 수정 요함

**packet.cpp**
```
void Packet::encryptData(const string &shared_key) {
  // 기존 코드 주석 처리 또는 삭제
}

optional<Packet> Packet::decryptData(const string &shared_key) {
  // 기존 코드 주석 처리 또는 삭제

  Packet decrypt_packet;
  decrypt_packet.insert(data_.data(), data_.size());

  return make_optional(decrypt_packet);
}
```
