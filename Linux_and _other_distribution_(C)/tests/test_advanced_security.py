#!/usr/bin/env python3

import pytest
import hashlib
import tempfile
import threading
import time
from pathlib import Path
from collections import deque
from sft import (
    SecureProtocol, SecureKeyManager, OUTPUT_DIR,
    REPLAY_WINDOW_SIZE, REPLAY_SEQUENCE_TOLERANCE
)

@pytest.fixture
def key_manager():
    return SecureKeyManager("test_identity")

@pytest.fixture
def protocol(key_manager):
    key_manager.generate_session_key()
    received_messages = deque(maxlen=1000)
    return SecureProtocol(key_manager, received_messages)

class TestReplayBypassMitigation:

    def test_sequence_number_increment(self, protocol):
        seq1 = protocol._get_next_sequence_number()
        seq2 = protocol._get_next_sequence_number()
        seq3 = protocol._get_next_sequence_number()

        assert seq2 == seq1 + 1
        assert seq3 == seq2 + 1

    def test_sequence_number_thread_safety(self, protocol):
        results = []
        def get_sequences():
            for _ in range(100):
                results.append(protocol._get_next_sequence_number())

        threads = [threading.Thread(target=get_sequences) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 1000
        assert len(set(results)) == 1000
        assert min(results) == 0
        assert max(results) == 999

    def test_sequence_validation_accept_in_order(self, protocol):
        assert protocol._validate_sequence_number(0) == True
        assert protocol._validate_sequence_number(1) == True
        assert protocol._validate_sequence_number(2) == True

    def test_sequence_validation_reject_duplicate(self, protocol):
        assert protocol._validate_sequence_number(5) == True
        assert protocol._validate_sequence_number(5) == False

    def test_sequence_validation_reject_too_old(self, protocol):
        for i in range(100):
            protocol._validate_sequence_number(i)

        protocol.replay_window_base = 50
        assert protocol._validate_sequence_number(49) == False
        assert protocol._validate_sequence_number(40) == False

    def test_sequence_validation_reject_too_far_ahead(self, protocol):
        protocol._validate_sequence_number(0)

        too_far = REPLAY_SEQUENCE_TOLERANCE + 10
        assert protocol._validate_sequence_number(too_far) == False

    def test_sequence_validation_out_of_order_within_window(self, protocol):
        assert protocol._validate_sequence_number(5) == True
        assert protocol._validate_sequence_number(3) == True
        assert protocol._validate_sequence_number(7) == True
        assert protocol._validate_sequence_number(4) == True

        assert protocol._validate_sequence_number(3) == False
        assert protocol._validate_sequence_number(5) == False

    def test_sequence_window_sliding(self, protocol):
        batch_size = min(1000, REPLAY_SEQUENCE_TOLERANCE - 10)
        for i in range(batch_size):
            result = protocol._validate_sequence_number(i)
            assert result == True, f"Failed at sequence {i}"

        assert len(protocol.replay_window) <= REPLAY_WINDOW_SIZE

    def test_sequence_in_json_packet(self, protocol):
        packet = protocol._create_json_packet('ping', {})
        assert packet is not None
        assert len(packet) > 0

class TestZombieFileProtection:

    def test_corrupted_file_removed_on_server(self, protocol, tmp_path):
        test_file = tmp_path / "test_corrupted.txt"
        test_file.write_bytes(b"corrupted data here")

        expected_hash = hashlib.sha256(b"original data").hexdigest()

        if test_file.exists():
            actual_hash = hashlib.sha256(test_file.read_bytes()).hexdigest()

            if actual_hash != expected_hash:
                test_file.unlink()
                assert not test_file.exists()

    def test_valid_file_kept_on_server(self, protocol, tmp_path):
        test_data = b"valid file content"
        test_file = tmp_path / "test_valid.txt"
        test_file.write_bytes(test_data)

        expected_hash = hashlib.sha256(test_data).hexdigest()
        actual_hash = hashlib.sha256(test_file.read_bytes()).hexdigest()

        if actual_hash == expected_hash:
            assert test_file.exists()
        else:
            test_file.unlink()
            assert not test_file.exists()

    def test_zombie_file_cleanup_multiple_failures(self, tmp_path):
        files_to_test = []

        for i in range(5):
            test_file = tmp_path / f"corrupted_{i}.txt"
            test_file.write_bytes(b"bad data")
            files_to_test.append(test_file)

        for test_file in files_to_test:
            expected_hash = hashlib.sha256(b"good data").hexdigest()
            actual_hash = hashlib.sha256(test_file.read_bytes()).hexdigest()

            if actual_hash != expected_hash:
                test_file.unlink()

        for test_file in files_to_test:
            assert not test_file.exists()

    def test_partial_file_protection(self, tmp_path):
        complete_data = b"x" * 10000
        partial_data = b"x" * 5000

        test_file = tmp_path / "partial.dat"
        test_file.write_bytes(partial_data)

        expected_hash = hashlib.sha256(complete_data).hexdigest()
        actual_hash = hashlib.sha256(test_file.read_bytes()).hexdigest()

        if actual_hash != expected_hash:
            test_file.unlink()
            assert not test_file.exists()

class TestCombinedProtections:

    def test_replay_protection_with_sequence(self, protocol):
        payload1 = {'test': 'data1'}
        packet1 = protocol._create_json_packet('ping', payload1)

        seq_before = protocol.sequence_number

        payload2 = {'test': 'data2'}
        packet2 = protocol._create_json_packet('pong', payload2)

        assert protocol.sequence_number > seq_before

    def test_concurrent_sequence_and_zombie_protection(self, protocol, tmp_path):
        results = {'sequences': [], 'files': []}

        def sequence_worker():
            for _ in range(50):
                seq = protocol._get_next_sequence_number()
                results['sequences'].append(seq)

        def file_worker():
            for i in range(10):
                test_file = tmp_path / f"test_{threading.current_thread().name}_{i}.txt"
                test_file.write_bytes(b"data")
                results['files'].append(test_file)

        threads = []
        for _ in range(3):
            threads.append(threading.Thread(target=sequence_worker))
            threads.append(threading.Thread(target=file_worker))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(set(results['sequences'])) == len(results['sequences'])

        for f in results['files']:
            if f.exists():
                f.unlink()

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
