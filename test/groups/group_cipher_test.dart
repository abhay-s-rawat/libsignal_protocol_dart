import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/src/duplicate_message_exception.dart';
import 'package:libsignal_protocol_dart/src/eq.dart';
import 'package:libsignal_protocol_dart/src/groups/group_cipher.dart';
import 'package:libsignal_protocol_dart/src/groups/group_session_builder.dart';
import 'package:libsignal_protocol_dart/src/groups/sender_key_name.dart';
import 'package:libsignal_protocol_dart/src/groups/state/in_memory_sender_key_store.dart';
import 'package:libsignal_protocol_dart/src/invalid_message_exception.dart';
import 'package:libsignal_protocol_dart/src/no_session_exception.dart';
import 'package:libsignal_protocol_dart/src/protocol/sender_key_distribution_message_wrapper.dart';
import 'package:libsignal_protocol_dart/src/signal_protocol_address.dart';
import 'package:libsignal_protocol_dart/src/util/key_helper.dart';
import 'package:test/test.dart';

void main() {
  const senderAddress = SignalProtocolAddress('+14150001111', 1);
  const groupSender =
      SenderKeyName('nihilist history reading group', senderAddress);

  const integerMax = 0x7fffffff;

  int randomInt() {
    final secureRandom = Random.secure();
    return secureRandom.nextInt(integerMax);
  }

  test('testNoSession', () async {
    final aliceStore = InMemorySenderKeyStore();
    final bobStore = InMemorySenderKeyStore();

    final aliceSessionBuilder = GroupSessionBuilder(aliceStore);
    // ignore: unused_local_variable
    final bobSessionBuilder = GroupSessionBuilder(bobStore);

    final aliceGroupCipher = GroupCipher(aliceStore, groupSender);
    final bobGroupCipher = GroupCipher(bobStore, groupSender);

    final sentAliceDistributionMessage =
        await aliceSessionBuilder.create(groupSender);

    assert(sentAliceDistributionMessage != null);
    if (sentAliceDistributionMessage == null) return;

    // ignore: unused_local_variable
    final receivedAliceDistributionMessage =
        SenderKeyDistributionMessageWrapper.fromSerialized(
            sentAliceDistributionMessage.serialize());

//    bobSessionBuilder.process(groupSender, receivedAliceDistributionMessage);

    final ciphertextFromAlice = await aliceGroupCipher
        .encrypt(Uint8List.fromList(utf8.encode('smert ze smert')));

    assert(ciphertextFromAlice != null);
    if (ciphertextFromAlice == null) return;

    try {
      // ignore: unused_local_variable
      final plaintextFromAlice =
          await bobGroupCipher.decrypt(ciphertextFromAlice);
      throw AssertionError('Should be no session!');
    } on NoSessionException {
      // good
    }
  });

  test('testBasicEncryptDecrypt', () async {
    final aliceStore = InMemorySenderKeyStore();
    final bobStore = InMemorySenderKeyStore();

    final aliceSessionBuilder = GroupSessionBuilder(aliceStore);
    final bobSessionBuilder = GroupSessionBuilder(bobStore);

    final aliceGroupCipher = GroupCipher(aliceStore, groupSender);
    final bobGroupCipher = GroupCipher(bobStore, groupSender);

    final sentAliceDistributionMessage =
        await aliceSessionBuilder.create(groupSender);

    assert(sentAliceDistributionMessage != null);
    if (sentAliceDistributionMessage == null) return;

    final receivedAliceDistributionMessage =
        SenderKeyDistributionMessageWrapper.fromSerialized(
            sentAliceDistributionMessage.serialize());
    await bobSessionBuilder.process(
        groupSender, receivedAliceDistributionMessage);

    final ciphertextFromAlice = await aliceGroupCipher
        .encrypt(Uint8List.fromList(utf8.encode('smert ze smert')));

    assert(ciphertextFromAlice != null);
    if (ciphertextFromAlice == null) return;

    final plaintextFromAlice =
        await bobGroupCipher.decrypt(ciphertextFromAlice);

    assert(plaintextFromAlice != null);
    if (plaintextFromAlice == null) return;

    assert(utf8.decode(plaintextFromAlice) == 'smert ze smert');
  });

  test('testLargeMessages', () async {
    final aliceStore = InMemorySenderKeyStore();
    final bobStore = InMemorySenderKeyStore();

    final aliceSessionBuilder = GroupSessionBuilder(aliceStore);
    final bobSessionBuilder = GroupSessionBuilder(bobStore);

    final aliceGroupCipher = GroupCipher(aliceStore, groupSender);
    final bobGroupCipher = GroupCipher(bobStore, groupSender);

    final sentAliceDistributionMessage =
        await aliceSessionBuilder.create(groupSender);

    assert(sentAliceDistributionMessage != null);
    if (sentAliceDistributionMessage == null) return;

    final receivedAliceDistributionMessage =
        SenderKeyDistributionMessageWrapper.fromSerialized(
            sentAliceDistributionMessage.serialize());
    await bobSessionBuilder.process(
        groupSender, receivedAliceDistributionMessage);

    final plaintext = generateRandomBytes(1024 * 1024);

    final ciphertextFromAlice = await aliceGroupCipher.encrypt(plaintext);

    assert(ciphertextFromAlice != null);
    if (ciphertextFromAlice == null) return;

    final plaintextFromAlice =
        await bobGroupCipher.decrypt(ciphertextFromAlice);

    assert(eq(plaintextFromAlice, plaintext));
  });

  test('testBasicRatchet', () async {
    final aliceStore = InMemorySenderKeyStore();
    final bobStore = InMemorySenderKeyStore();

    final aliceSessionBuilder = GroupSessionBuilder(aliceStore);
    final bobSessionBuilder = GroupSessionBuilder(bobStore);

    const aliceName = groupSender;

    final aliceGroupCipher = GroupCipher(aliceStore, aliceName);
    final bobGroupCipher = GroupCipher(bobStore, aliceName);

    final sentAliceDistributionMessage =
        await aliceSessionBuilder.create(aliceName);

    assert(sentAliceDistributionMessage != null);
    if (sentAliceDistributionMessage == null) return;

    final receivedAliceDistributionMessage =
        SenderKeyDistributionMessageWrapper.fromSerialized(
            sentAliceDistributionMessage.serialize());

    await bobSessionBuilder.process(
        aliceName, receivedAliceDistributionMessage);

    final ciphertextFromAlice = await aliceGroupCipher
        .encrypt(Uint8List.fromList(utf8.encode('smert ze smert')));

    assert(ciphertextFromAlice != null);
    if (ciphertextFromAlice == null) return;

    final ciphertextFromAlice2 = await aliceGroupCipher
        .encrypt(Uint8List.fromList(utf8.encode('smert ze smert2')));

    assert(ciphertextFromAlice2 != null);
    if (ciphertextFromAlice2 == null) return;

    final ciphertextFromAlice3 = await aliceGroupCipher
        .encrypt(Uint8List.fromList(utf8.encode('smert ze smert3')));

    assert(ciphertextFromAlice3 != null);
    if (ciphertextFromAlice3 == null) return;

    final plaintextFromAlice =
        await bobGroupCipher.decrypt(ciphertextFromAlice);

    assert(plaintextFromAlice != null);
    if (plaintextFromAlice == null) return;

    try {
      await bobGroupCipher.decrypt(ciphertextFromAlice);
      throw AssertionError('Should have ratcheted forward!');
    } on DuplicateMessageException {
      // good
    }

    final plaintextFromAlice2 =
        await bobGroupCipher.decrypt(ciphertextFromAlice2);

    assert(plaintextFromAlice2 != null);
    if (plaintextFromAlice2 == null) return;

    final plaintextFromAlice3 =
        await bobGroupCipher.decrypt(ciphertextFromAlice3);

    assert(plaintextFromAlice3 != null);
    if (plaintextFromAlice3 == null) return;

    assert(utf8.decode(plaintextFromAlice) == 'smert ze smert');
    assert(utf8.decode(plaintextFromAlice2) == 'smert ze smert2');
    assert(utf8.decode(plaintextFromAlice3) == 'smert ze smert3');
  });

  test('testLateJoin', () async {
    final aliceStore = InMemorySenderKeyStore();
    final bobStore = InMemorySenderKeyStore();

    final aliceSessionBuilder = GroupSessionBuilder(aliceStore);

    const aliceName = groupSender;

    final aliceGroupCipher = GroupCipher(aliceStore, aliceName);

    // ignore: unused_local_variable
    final aliceDistributionMessage =
        await aliceSessionBuilder.create(aliceName);
    // Send off to some people.

    for (var i = 0; i < 100; i++) {
      await aliceGroupCipher.encrypt(Uint8List.fromList(
          utf8.encode('up the punks up the punks up the punks')));
    }

    // Now Bob Joins.
    final bobSessionBuilder = GroupSessionBuilder(bobStore);
    final bobGroupCipher = GroupCipher(bobStore, aliceName);

    final distributionMessageToBob =
        await aliceSessionBuilder.create(aliceName);

    assert(distributionMessageToBob != null);
    if (distributionMessageToBob == null) return;

    await bobSessionBuilder.process(
        aliceName,
        SenderKeyDistributionMessageWrapper.fromSerialized(
            distributionMessageToBob.serialize()));

    final ciphertext = await aliceGroupCipher
        .encrypt(Uint8List.fromList(utf8.encode('welcome to the group')));

    assert(ciphertext != null);
    if (ciphertext == null) return;

    final plaintext = await bobGroupCipher.decrypt(ciphertext);

    assert(plaintext != null);
    if (plaintext == null) return;

    assert(utf8.decode(plaintext) == 'welcome to the group');
  });

  test('testOutOfOrder', () async {
    final aliceStore = InMemorySenderKeyStore();
    final bobStore = InMemorySenderKeyStore();

    final aliceSessionBuilder = GroupSessionBuilder(aliceStore);
    final bobSessionBuilder = GroupSessionBuilder(bobStore);

    const aliceName = groupSender;

    final aliceGroupCipher = GroupCipher(aliceStore, aliceName);
    final bobGroupCipher = GroupCipher(bobStore, aliceName);

    final sentAliceDistributionMessage =
        await aliceSessionBuilder.create(aliceName);

    assert(sentAliceDistributionMessage != null);
    if (sentAliceDistributionMessage == null) return;

    // ignore: unused_local_variable
    final receivedAliceDistributionMessage =
        SenderKeyDistributionMessageWrapper.fromSerialized(
            sentAliceDistributionMessage.serialize());

    final aliceDistributionMessage =
        await aliceSessionBuilder.create(aliceName);

    assert(aliceDistributionMessage != null);
    if (aliceDistributionMessage == null) return;

    await bobSessionBuilder.process(aliceName, aliceDistributionMessage);

    final ciphertexts = <Uint8List>[];

    for (var i = 0; i < 100; i++) {
      final temp = await aliceGroupCipher
          .encrypt(Uint8List.fromList(utf8.encode('up the punks')));
      if (temp != null) {
        ciphertexts.add(temp);
      }
    }

    while (ciphertexts.isNotEmpty) {
      final index = randomInt() % ciphertexts.length;
      final ciphertext = ciphertexts.removeAt(index);
      final plaintext = await bobGroupCipher.decrypt(ciphertext);

      assert(utf8.decode(plaintext as Uint8List) == 'up the punks');
    }
  });

  test('testEncryptNoSession', () async {
    final aliceStore = InMemorySenderKeyStore();
    final aliceGroupCipher = GroupCipher(
        aliceStore,
        const SenderKeyName(
            'coolio groupio', SignalProtocolAddress('+10002223333', 1)));
    try {
      await aliceGroupCipher
          .encrypt(Uint8List.fromList(utf8.encode('up the punks')));
      throw AssertionError('Should have failed!');
    } on NoSessionException {
      // good
    }
  });

  test('testTooFarInFuture', () async {
    final aliceStore = InMemorySenderKeyStore();
    final bobStore = InMemorySenderKeyStore();

    final aliceSessionBuilder = GroupSessionBuilder(aliceStore);
    final bobSessionBuilder = GroupSessionBuilder(bobStore);

    const aliceName = groupSender;

    final aliceGroupCipher = GroupCipher(aliceStore, aliceName);
    final bobGroupCipher = GroupCipher(bobStore, aliceName);

    final aliceDistributionMessage =
        await aliceSessionBuilder.create(aliceName);

    assert(aliceDistributionMessage != null);
    if (aliceDistributionMessage == null) return;

    await bobSessionBuilder.process(aliceName, aliceDistributionMessage);

    for (var i = 0; i < 2001; i++) {
      await aliceGroupCipher
          .encrypt(Uint8List.fromList(utf8.encode('up the punks')));
    }

    final tooFarCiphertext = await aliceGroupCipher
        .encrypt(Uint8List.fromList(utf8.encode('notta gonna worka')));

    assert(tooFarCiphertext != null);
    if (tooFarCiphertext == null) return;

    try {
      await bobGroupCipher.decrypt(tooFarCiphertext);
      throw AssertionError('Should have failed!');
    } on InvalidMessageException {
      // good
    }
  });

  test('testMessageKeyLimit', () async {
    final aliceStore = InMemorySenderKeyStore();
    final bobStore = InMemorySenderKeyStore();

    final aliceSessionBuilder = GroupSessionBuilder(aliceStore);
    final bobSessionBuilder = GroupSessionBuilder(bobStore);

    const aliceName = groupSender;

    final aliceGroupCipher = GroupCipher(aliceStore, aliceName);
    final bobGroupCipher = GroupCipher(bobStore, aliceName);

    final aliceDistributionMessage =
        await aliceSessionBuilder.create(aliceName);

    assert(aliceDistributionMessage != null);
    if (aliceDistributionMessage == null) return;

    await bobSessionBuilder.process(aliceName, aliceDistributionMessage);

    final inflight = <Uint8List>[];

    for (var i = 0; i < 2010; i++) {
      final temp = await aliceGroupCipher
          .encrypt(Uint8List.fromList(utf8.encode('up the punks')));
      if (temp != null) {
        inflight.add(temp);
      }
    }

    await bobGroupCipher.decrypt(inflight[1000]);
    await bobGroupCipher.decrypt(inflight[inflight.length - 1]);

    try {
      await bobGroupCipher.decrypt(inflight[0]);
      throw AssertionError('Should have failed!');
    } on DuplicateMessageException {
      // good
    }
  });
}
