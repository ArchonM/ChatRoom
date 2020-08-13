#!/usr/bin/env python

import socket
import threading
import sys
import binascii
import argparse
import curses
from datetime import datetime
from Crypto import Random
import binascii
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto import Random

DEFAULT_PORT = 39482

DH_SIZE = 2048

# Length (in bytes) of each variable for public transport
LEN_PRIME = 1024
LEN_GEN = 16
LEN_PK = 1024

# Total public transport message size (in bytes)
DH_MSG_SIZE = LEN_PRIME + LEN_GEN + LEN_PK


class Message:

    def __init__(self, key, plaintext=None, ciphertext=None):
        """
        Initialize a new message object from a key and either plaintext
        or cipher-text.
        :param key: shared key to use for encryption/decryption
        :param plaintext: plaintext message
        :param ciphertext: encrypted message
        """
        self.key = key
        # If plaintext is specified, generate its encrypted counterpart
        if plaintext:
            self.plaintext = plaintext
            self.ciphertext, self.iv = self.encrypt()
        # If instead cipher-text is specified, decrypt it
        elif ciphertext:
            self.ciphertext = ciphertext
            self.plaintext, self.iv = self.decrypt()
        # Otherwise declaration is invalid
        else:
            raise InvalidMessage("Either plaintext or cipher-text must be declared")

    def encrypt(self):
        """
        Encrypt a plaintext message.
        :return: the encrypted message and its corresponding initialization vector
        """
        # Generate a randomized initialization vector
        iv = Random.new().read(AES.block_size)
        # Create a new AES object in Cipher Block Chaining mode
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # Add a buffer so that the plaintext is a multiple of 16 characters in length
        pt_len = len(self.plaintext)
        buffer_size = AES.block_size - pt_len % AES.block_size
        return cipher.encrypt(self.plaintext + " " * buffer_size), iv

    def decrypt(self):
        """
        Decrypt a cipher-text message.
        :return: the decrypted message and its corresponding initialization vector
        """
        # Grab the initialization vector from the front of the cipher-text
        iv = self.ciphertext[:AES.block_size]
        # Create a new AES object in Cipher Block Chaining mode
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.decrypt(self.ciphertext)[AES.block_size:].rstrip().decode("utf-8"), iv

    def pack(self):
        """
        Package the message as an encrypted bytes object.
        :return: encrypted bytes
        """
        return self.iv + self.ciphertext


class InvalidMessage(Exception):

    def __init__(self, msg):
        self.msg = msg

class DH:

    def __init__(self, p, g, pk):
        """
        Initialize a new DH object for key exchange between client and server.
        :param p: a prime number from the multiplicative group of integers modulo n
        :param g: primitive root modulo
        :param pk: public key generated from p, g, and a private key
        """
        self.p = p
        self.g = g
        self.pk = pk

    @staticmethod
    def gen_private_key():
        """
        Generate a random private key.
        :return: a random integer of length DH_SIZE
        """
        return DH.b2i(Random.new().read(DH_SIZE))

    @staticmethod
    def gen_public_key(g, private, p):
        """
        Generate a public key from g, p, and a private key.
        :param g: primitive root modulo
        :param private: private key
        :param p: prime number
        :return: public key as an integer
        """
        return pow(g, private, p)

    @staticmethod
    def get_shared_key(public, private, p):
        """
        Calculate a shared key from a foreign public key, a local private
        key, and a shared prime.
        :param public: public key as an integer
        :param private: private key as an integer
        :param p: prime number
        :return: shared key as a 256-bit bytes object
        """
        s = pow(public, private, p)
        s_hex = hex(s)[2:]
        # Make the length of s_hex a multiple of 2
        if len(s_hex) % 2 != 0:
            s_hex = '0' + s_hex
        # Convert hex to bytes
        s_bytes = binascii.unhexlify(s_hex)
        # Hash and return the hex result
        return sha256(s_bytes).digest()

    @staticmethod
    def b2i(bts):
        """
        Convert a bytes object to an integer.
        :param bts: bytes to convert
        :return: integer
        """
        return int(binascii.hexlify(bts), 16)

    @staticmethod
    def package(i, length):
        """
        Package an integer as a bytes object of length "length".
        :param i: integer to be package
        :param length: desired length of the bytes object
        :return: bytes representation of the integer
        """
        # Convert i to hex and remove '0x' from the left
        i_hex = hex(i)[2:]
        # Make the length of i_hex a multiple of 2
        if len(i_hex) % 2 != 0:
            i_hex = '0' + i_hex
        # Convert hex string into bytes
        i_bytes = binascii.unhexlify(i_hex)
        # Check to make sure bytes to not exceed the max length
        len_i = len(i_bytes)
        if len_i > length:
            raise InvalidDH("Length Exceeds Maximum of {}".format(length))
        # Generate padding for the remaining space on the left
        i_padding = bytes(length - len_i)
        return i_padding + i_bytes

    @staticmethod
    def unpack(dh_message):
        """
        Unpack a bytes object into its component p, g, and pk values.
        :param dh_message: received bytes object
        :return: p: shared prime, g: primitive root modulo, pk: public key
        """
        # Separate message into components
        p_bytes = dh_message[:LEN_PRIME]
        g_bytes = dh_message[LEN_PRIME:LEN_PRIME+LEN_GEN]
        pk_bytes = dh_message[-1 * LEN_PK:]
        # Convert bytes to integers
        p = DH.b2i(p_bytes)
        g = DH.b2i(g_bytes)
        pk = DH.b2i(pk_bytes)
        return p, g, pk

    def __bytes__(self):
        """
        Convert DH message to bytes.
        :return: packaged DH message as bytes
        +-------+-----------+------------+
        | Prime | Generator | Public Key |
        |  1024 |    16     |    1024    |
        +-------+-----------+------------+
        """
        prm = self.package(self.p, LEN_PRIME)
        gen = self.package(self.g, LEN_GEN)
        pbk = self.package(self.pk, LEN_PK)
        return prm + gen + pbk


class InvalidDH(Exception):

    def __init__(self, message):
        self.message = message

class KEYS:

    BACKSPACE = [curses.KEY_BACKSPACE, curses.KEY_DC, 127]
    ENTER = [curses.KEY_ENTER, 10, 13]


class CLI:

    def __init__(self):
        """
        Initialize the command-line interface.
        """
        self.stdscr = curses.initscr()
        self.client = None
        self.max_y, self.max_x = self.stdscr.getmaxyx()
        self.chat_container = curses.newwin(self.max_y - 2, self.max_x, 1, 0)
        self.chat_win = self.chat_container.subwin(self.max_y - 3, self.max_x - 4, 2, 2)
        self.prompt_win = curses.newwin(1, self.max_x, self.max_y - 1, 0)
        self.setup()

    def init_client(self, client):
        """
        Update the client variable once connected.
        :param client: client object to add
        """
        self.client = client

    def uninit_client(self):
        """
        Remove client once disconnected from the server.
        """
        self.add_msg("Connection Lost")
        self.client = None

    def setup(self):
        """
        Perform basic command-line interface setup.
        """
        curses.curs_set(1)
        curses.noecho()
        curses.cbreak()
        # Keypad disabled until scrolling properly implemented
        # self.stdscr.keypad(True)
        self.stdscr.clear()
        self.stdscr.addstr("SecureChat v{}".format(__version__))
        self.chat_container.box()
        self.chat_win.addstr("Welcome to SecureChat!")
        self.chat_win.scrollok(True)
        self.chat_win.setscrreg(0, self.max_y - 5)
        self.prompt_win.addstr("> ")
        self.refresh_all()

    def refresh_chat(self):
        """
        Refresh only the chat box.
        """
        self.chat_container.noutrefresh()
        self.chat_win.noutrefresh()
        curses.doupdate()

    def refresh_prompt(self):
        """
        Refresh only the input prompt.
        """
        self.prompt_win.noutrefresh()
        curses.doupdate()

    def refresh_all(self):
        """
        Refresh everything in the interface.
        """
        self.stdscr.noutrefresh()
        self.chat_container.noutrefresh()
        self.chat_win.noutrefresh()
        self.prompt_win.noutrefresh()
        curses.doupdate()

    def add_msg(self, msg):
        """
        Add a message to the chat box.
        :param msg: message to add
        """
        self.chat_win.addch('\n')
        self.chat_win.addstr("[{}] {}".format(
            datetime.strftime(datetime.now(), "%H:%M"), msg)
        )
        self.refresh_all()

    def submit(self, msg):
        """
        Send a message to the server and add it to the chat box.
        :param msg: message to send
        """
        if len(msg) == 0:
            return
        self.prompt_win.clear()
        self.prompt_win.addstr("> ")
        self.refresh_prompt()
        if not self.client:
            self.add_msg("Error: Not Connected to Server")
            self.refresh_prompt()
            return
        self.add_msg("You: " + msg)
        self.client.send(msg)

    def main(self):
        """
        Main input loop.
        """
        inp = ""
        while True:
            # Get input character
            c = self.stdscr.getch()
            # Enter submits the message
            if c in KEYS.ENTER:
                self.submit(inp)
                inp = ""
            # Delete last character
            elif c in KEYS.BACKSPACE:
                inp = inp[:-1]
                self.prompt_win.clear()
                self.prompt_win.addstr("> " + inp)
                self.refresh_prompt()
            # Scrolling (disabled for now, see stdscr.keypad in setup)
            elif c == curses.KEY_UP:
                self.chat_win.scroll(-1)
                self.refresh_all()
            elif c == curses.KEY_DOWN:
                self.chat_win.scroll(1)
                self.refresh_all()
            # Add input to message if it doesn't exceed max length
            # I will disable the message limit when I get scrolling working properly
            elif len(inp) + 3 < self.max_x:
                k = chr(c)
                inp += k
                self.prompt_win.addstr(k)
                self.refresh_prompt()

    def clean_exit(self):
        """
        Exit cleanly from the interface and reset the command line.
        """
        if self.client:
            if self.client.key:
                self.client.send("!exit")
            self.client.cli = None
        self.stdscr.keypad(False)
        curses.echo()
        curses.nocbreak()
        curses.endwin()

class Client:

    def __init__(self, interface, server_address, port=DEFAULT_PORT):
        """
        Initialize
        """
        self.cli = interface
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cli.add_msg("Connecting to {}...".format(server_address))
        try:
            self.connection.connect((server_address, port))
        except KeyboardInterrupt:
            self.cli.clean_exit()
            sys.exit()
        self.cli.add_msg("Connected!")
        self.key = None

    def dh(self):
        """
        Perform Diffie-Hellman Key Exchange with the server.
        """
        self.cli.add_msg("Establishing Encryption Key...")
        dh_message = self.connection.recv(DH_MSG_SIZE)
        # Unpack p, g, and server_key from the server's dh message
        p, g, server_key = DH.unpack(dh_message)
        # Generate a randomized private key
        private_key = DH.gen_private_key()
        # Send the server a public key which used the previously
        # Generated private key and both g and p
        public_key = DH.gen_public_key(g, private_key, p)
        self.connection.sendall(DH.package(public_key, LEN_PK))
        # Calculate shared key
        shared_key = DH.get_shared_key(server_key, private_key, p)
        # print("Shared Key: {}".format(shared_key))
        self.cli.add_msg("Encryption Key: {}".format(binascii.hexlify(shared_key).decode("utf-8")))
        return shared_key

    def send(self, content):
        """
        Send a message to the server.
        """
        if not self.key:
            self.cli.add_msg("Error: Key Not Established")
            return
        msg = Message(key=self.key, plaintext=content)
        self.connection.sendall(msg.pack())

    def start(self):
        """
        Start the client
        """
        try:
            self.key = self.dh()
        except ConnectionError:
            self.cli.add_msg("Unable to Connect")
            return
        while True:
            try:
                # Wait for data from server
                data = self.connection.recv(1024)
                # Disconnect from server if no data received
                if not data:
                    self.connection.close()
                    self.cli.uninit_client()
                    break
                # Parse data as cipher-text message
                msg = Message(key=self.key, ciphertext=data)
                if not self.cli:
                    break
                # Add message to the command-line interface
                self.cli.add_msg(msg.plaintext)
            # Disconnect client if unable to read from connection
            except OSError:
                self.connection.close()
                self.cli.uninit_client()
                break


if __name__ == '__main__':
    # Get host and port arguments from the command-line
    aparser = argparse.ArgumentParser()
    aparser.add_argument("host", help="IP address of the chat server")
    aparser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Port number the chat server is running on")
    args = aparser.parse_args()
    # Initialize Command-Line Interface
    interface = CLI()
    try:
        c = Client(interface, args.host, port=args.port)
    except ConnectionRefusedError:
        interface.clean_exit()
        print("Connection Refused")
        sys.exit()
    except OSError:
        interface.clean_exit()
        print("Connection Failed")
        sys.exit()
    # Add the client object to the interface
    interface.init_client(c)
    # Start the client
    client_thread = threading.Thread(target=c.start)
    client_thread.start()
    # Start the main input loop
    try:
        interface.main()
    except KeyboardInterrupt:
        interface.clean_exit()
