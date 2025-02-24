import bencodepy
import hashlib
import requests
import urllib.parse
import socket
import struct
import threading
import os
import sys

class TorrentFile:
    def __init__(self, announce, info_hash, piece_hashes, piece_length, length, name):
        self.announce = announce
        self.info_hash = info_hash
        self.piece_hashes = piece_hashes
        self.piece_length = piece_length
        self.length = length
        self.name = name

    @classmethod
    def open(cls, path):
        with open(path, 'rb') as f:
            data = bencodepy.decode(f.read())
        
        info = data[b'info']
        info_hash = hashlib.sha1(bencodepy.encode(info)).digest()
        piece_hashes = [info[b'pieces'][i:i+20] for i in range(0, len(info[b'pieces']), 20)]
        
        return cls(
            announce=data[b'announce'].decode(),
            info_hash=info_hash,
            piece_hashes=piece_hashes,
            piece_length=info[b'piece length'],
            length=info[b'length'],
            name=info[b'name'].decode()
        )

class Tracker:
    @staticmethod
    def get_peers(torrent, peer_id, port):
        params = {
            'info_hash': torrent.info_hash,
            'peer_id': peer_id,
            'port': port,
            'uploaded': '0',
            'downloaded': '0',
            'compact': '1',
            'left': str(torrent.length)
        }
        url = torrent.announce + '?' + urllib.parse.urlencode(params)
        response = requests.get(url)
        response_data = bencodepy.decode(response.content)
        return response_data[b'peers']

class Peer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    @staticmethod
    def unmarshal(peers_bin):
        peers = []
        for i in range(0, len(peers_bin), 6):
            ip = socket.inet_ntoa(peers_bin[i:i+4])
            port = struct.unpack('!H', peers_bin[i+4:i+6])[0]
            peers.append(Peer(ip, port))
        return peers

class Handshake:
    def __init__(self, info_hash, peer_id):
        self.pstr = b"BitTorrent protocol"
        self.info_hash = info_hash
        self.peer_id = peer_id

    def serialize(self):
        return struct.pack('!B', len(self.pstr)) + self.pstr + b'\x00' * 8 + self.info_hash + self.peer_id

    @staticmethod
    def read(conn):
        data = conn.recv(68)
        if len(data) < 68:
            return None
        return Handshake(data[28:48], data[48:68])

class Client:
    def __init__(self, peer, peer_id, info_hash):
        self.peer = peer
        self.peer_id = peer_id
        self.info_hash = info_hash
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((peer.ip, peer.port))
        self.handshake()

    def handshake(self):
        hs = Handshake(self.info_hash, self.peer_id)
        self.conn.send(hs.serialize())
        response = Handshake.read(self.conn)
        if response.info_hash != self.info_hash:
            raise Exception("Invalid handshake")

    def send_unchoke(self):
        self.conn.send(struct.pack('!IB', 1, 1))

    def send_interested(self):
        self.conn.send(struct.pack('!IB', 1, 2))

    def request_piece(self, index, begin, length):
        msg = struct.pack('!IBIII', 13, 6, index, begin, length)
        self.conn.send(msg)
        return self.read_piece(length)

    def read_piece(self, length):
        data = b''
        while len(data) < length:
            packet = self.conn.recv(length - len(data))
            if not packet:
                break
            data += packet
        return data

def download_torrent(torrent, output_path):
    peer_id = b'-PY0001-' + os.urandom(12)
    peers_bin = Tracker.get_peers(torrent, peer_id, 6881)
    peers = Peer.unmarshal(peers_bin)

    work_queue = []
    for index, piece_hash in enumerate(torrent.piece_hashes):
        work_queue.append((index, piece_hash))

    results = []
    threads = []
    for peer in peers:
        t = threading.Thread(target=download_worker, args=(torrent, peer, peer_id, work_queue, results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    with open(output_path, 'wb') as f:
        for result in sorted(results, key=lambda x: x[0]):
            f.write(result[1])

def download_worker(torrent, peer, peer_id, work_queue, results):
    client = Client(peer, peer_id, torrent.info_hash)
    client.send_unchoke()
    client.send_interested()

    while work_queue:
        index, piece_hash = work_queue.pop(0)
        piece_data = client.request_piece(index, 0, torrent.piece_length)
        if hashlib.sha1(piece_data).digest() == piece_hash:
            results.append((index, piece_data))
        else:
            work_queue.append((index, piece_hash))

def main():
    if len(sys.argv) < 3:
        print("Usage: python torrent_client.py <torrent_file> <output_file>")
        return

    torrent_file = sys.argv[1]
    output_file = sys.argv[2]

    torrent = TorrentFile.open(torrent_file)
    download_torrent(torrent, output_file)

if __name__ == "__main__":
    main()
