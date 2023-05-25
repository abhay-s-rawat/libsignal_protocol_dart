import 'pre_key_record.dart';

abstract mixin class PreKeyStore {
  Future<PreKeyRecord?> loadPreKey(
      int preKeyId); // Will return null instead of throwing InvalidKeyIdException;

  Future<void> storePreKey(int preKeyId, PreKeyRecord record);

  Future<bool> containsPreKey(int preKeyId);

  Future<void> removePreKey(int preKeyId);
}
