import 'signed_pre_key_record.dart';

abstract mixin class SignedPreKeyStore {
  Future<SignedPreKeyRecord?> loadSignedPreKey(
      int signedPreKeyId); // Will return null instead of throwing InvalidKeyIdException;

  Future<List<SignedPreKeyRecord>> loadSignedPreKeys();

  Future<void> storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record);

  Future<bool> containsSignedPreKey(int signedPreKeyId);

  Future<void> removeSignedPreKey(int signedPreKeyId);
}
