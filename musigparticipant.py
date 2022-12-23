import sys
import os
import json
from binascii import hexlify, unhexlify
from typing import Tuple, Callable
from ms3a import MS3A, MS3A_STATE_NONCES_EXCHANGED, MS3A_STATE_FULLY_SIGNED, DETERMINISTIC_TEST
from twisted.protocols import basic
from twisted.internet import reactor, protocol, task, endpoints
from bitcointx.core.key import CKey, CPubKey
from bitcointx.core import (CTxOut, CMutableTransaction,
            CMutableTxInWitness, CMutableOutPoint, CMutableTxIn)
from bitcointx.wallet import P2TRCoinAddress, CCoinAddress
from bitcointx.core.script import CScriptWitness
from jmbitcoin import human_readable_transaction

port_base = 61529
hostname = "localhost"

class MS3AMessage(object):
    """ Encapsulates the messages passed over the wire
    to and from other onion peers
    """
    def __init__(self, index: int, vals: Tuple[str], msgtype: int):
        print("Constructing a message, vals is: ", vals)
        self.text = str(index) + ":" + ",".join(vals)
        self.msgtype = msgtype

    def encode(self) -> bytes:
        self.encoded = json.dumps({"type": self.msgtype,
                        "line": self.text}).encode("utf-8")
        return self.encoded

    def get_vals(self):
        valstring = self.text.split(":")[1]
        return valstring.split(",")

    def get_counterparty_index(self) -> int:
        return int(self.text.split(":")[0])

    @classmethod
    def from_string_decode(cls, msg: bytes) -> 'MS3AMessage':
        """ Build a custom message from a json-ified string.
        """
        try:
            msg_obj = json.loads(msg)
            text = msg_obj["line"]
            msgtype = msg_obj["type"]
            assert isinstance(msgtype, int)
            assert isinstance(text, str)
            index, valstring = text.split(":")
            vals = valstring.split(",")
        except:
            print("Error decoding message")
            raise
        return cls(index, vals, msgtype)

class MS3AManager(object):
    """ Simple message syntax:
    json of two keys 'type', 'line'. Type is as per `msg_callbacks` above.
    Line is of this syntax:
    counterparty_index:val,val,..
    The `val`s are keys, sigs etc. All hex encoded.
    The index must be an integer, then colon, then comma separated `val`s.
    """
    def __init__(self, privkey: CKey, n: int, myindex: int):
        # create a private key and public key, then
        # be ready to receive messages.
        self.privkey = privkey
        self.n = n
        self.myindex = myindex
        assert myindex < n
        # the signing state is encapsulated here:
        self.ms3a = MS3A(self.privkey, n, myindex)
        # boolean lets us kick off process only once
        self.kicked_off = False
        # managing outbound connections:
        self.factories = {}
        self.funding_received = False
        self.able_to_send = False
        self.key_sent = False
        for i in range(self.n):
            if i == self.myindex:
                continue
            port_to_use = port_base + i
            self.connect(i, port_to_use)        

    def check_for_kickoff(self):
        """ Intended to be a polling loop.
        """
        if self.kicked_off:
            return
        try:
            with open("musigfile" + str(self.myindex) + ".txt", "r") as f:
                lines = f.readlines()
                if len(lines) > 0:
                    print("We saw a line in the file: ", lines[0])
                    # the 'kicked off' state for each participant means
                    # that they have sent their key exchange message.
                    for i in range(self.n):
                        if i == self.myindex:
                            continue
                        self.send_key_exchange_message(i)
                    self.kicked_off = True
        except OSError:
            # ignore non-existence
            pass

    def check_for_funding(self):
        """ Intended to be a polling loop.
        """
        if self.funding_received:
            return
        try:
            with open("fundingfile" + str(self.myindex) + ".txt", "r") as f:
                lines = f.readlines()
                if len(lines) > 0:
                    print("We saw a line in the file: ", lines[0])
                    # txid:n of the utxo being spent are the first two.
                    # then, value and script refer to the same utxo, and
                    # allow us to create a CTxOut for it.
                    # lastly, we need value, address for the recipient, from
                    # which we create the transaction output (another CTxOut)
                    hextxid, strindex, strvalue, inaddress, strvalout, address = lines[0].strip().split(",")
                    for i in range(self.n):
                        self.send_funding_message(i, hextxid,
                                        int(strindex), int(strvalue), inaddress,
                                        int(strvalout), address)
                    self.funding_received = True
        except OSError:
            # ignore non-existence
            pass

    def send_key_exchange_message(self, index):
        msg = MS3AMessage(self.myindex, (hexlify(self.ms3a.basepubkey).decode(),), 1)
        res = self.factories[index].send(msg)
        if not res:
            print("Failed to send to {}, message was: {}".format(index, msg.text))

    def send_commitment_exchange_message(self, index):
        self.ms3a.get_ms3a_msg_1()
        msg = MS3AMessage(self.myindex,
                          (hexlify(self.ms3a.HRs[self.myindex]).decode(),
                           hexlify(self.ms3a.HTs[self.myindex]).decode()), 3)
        res = self.factories[index].send(msg)
        if not res:
            print("Failed to send to {}, message was: {}".format(index, msg.text))

    def send_nonce_exchange_message(self, index):
        msg = MS3AMessage(self.myindex,
                          (hexlify(self.ms3a.Rs[self.myindex]).decode(),
                           hexlify(self.ms3a.Ts[self.myindex]).decode()), 4)
        res = self.factories[index].send(msg)
        if not res:
            print("Failed to send to {}, message was: {}".format(index, msg.text))

    def send_funding_message(self, index: int, hextxid: str, spending_index: int,
                             value: int, inaddress: str, valueout: int,
                             addrout: str):
        msg = MS3AMessage(self.myindex, (hextxid,
                                         str(spending_index),
                                         str(value),
                                         inaddress,
                                         str(valueout),
                                         addrout), 2)
        if index == self.myindex:
            self.receive_funding_notification(msg)
        else:
            res = self.factories[index].send(msg)
            if not res:
                print("Failed to send to {}, message was: {}".format(index, msg.text))

    def send_partials_exchange_message(self, index):
        msg = MS3AMessage(self.myindex,
                          (hexlify(self.ms3a.fullpartials[self.myindex]).decode(),), 5)
        res = self.factories[index].send(msg)
        if not res:
            print("Failed to send to {}, message was: {}".format(index, msg.text))        
            
    def register_connection(self):
        self.able_to_send = True
        print("register connection")

    def register_disconnection(self):
        self.able_to_send = False
        print("register disconnection")

    def connect(self, index: int, port: int) -> None:
        if index in self.factories:
            return
        self.factories[index] = MS3AClientFactory(self.receive_message,
        self.register_connection, self.register_disconnection)
        print("{} is making a tcp connection to {}, {}".format(
            self.myindex, index, port))       
        self.tcp_connector = reactor.connectTCP(hostname, port,
                                                self.factories[index])

    def receive_message(self, message: MS3AMessage):
        """ This sends the message to the right callback,
        dependent on the message type. Note that this code,
        being only for toy/test cases, doesn't bother to
        pay attention to network source, just trusts the
        counterparty to be sending a consistent index to
        update the right set of keys, nonces, sigs etc.
        """
        msgtype = message.msgtype
        if msgtype in msg_callbacks.keys():
            msg_callbacks[msgtype](message)
            return
    
    def receive_key_exchange(self, msg: MS3AMessage):
        index = msg.get_counterparty_index()
        assert index != self.myindex
        try:
            pub = CPubKey(unhexlify(msg.get_vals()[0]))
        except:
            print("Failed key exchange message: ", msg)
            return
        if self.ms3a.set_base_pubkey(pub, index):
            # key exchange is complete; start by sending msg1
            print("Key exchange complete")
            print("Address to fund is: ", self.ms3a.get_musig_address())
        if not self.key_sent:
            for i in range(self.n):
                if i == self.myindex:
                    continue
                self.send_key_exchange_message(i)
            self.key_sent = True

    def receive_commitments(self, msg: MS3AMessage):
        """ This is the receipt of message 1
        """
        index = msg.get_counterparty_index()
        assert index != self.myindex
        try:
            commR = unhexlify(msg.get_vals()[0])
        except:
            print("Failed commitment exchange message: ", msg)
            return
        try:
            commT = unhexlify(msg.get_vals()[1])
        except:
            print("Failed commitment exchange message: ", msg)
            return
        if self.ms3a.receive_ms3a_msg_1(commR, commT, index):
            # commitment exchange is complete; send msg2
            for i in range(self.n):
                if i == self.myindex:
                    continue
                self.send_nonce_exchange_message(i)

    def receive_nonces(self, msg: MS3AMessage):
        """ This is the receipt of message 2
        """
        index = msg.get_counterparty_index()
        assert index != self.myindex
        try:
            R = CPubKey(unhexlify(msg.get_vals()[0]))
        except:
            print("Failed nonce exchange message: ", msg)
            return
        try:
            T = CPubKey(unhexlify(msg.get_vals()[1]))
        except:
            print("Failed nonce exchange message: ", msg)
            return
        if not self.ms3a.receive_ms3a_msg_2(R, T, index):
            print("Run was aborted due to invalid commitment opening.")
        elif self.ms3a.state >= MS3A_STATE_NONCES_EXCHANGED:
            # we now have at least our own partial; send it
            for i in range(self.n):
                if i == self.myindex:
                    continue
                self.send_partials_exchange_message(i)

    def receive_funding_notification(self, msg: MS3AMessage):
        """ This spending information could come from any participant.
        Handling this might take care, but for now:
        Just only allow this to happen once.
        """
        if self.ms3a.tx:
            print("Attempting to set the spending transaction twice!")
            return
        txid = unhexlify(msg.get_vals()[0])
        outindex = int(msg.get_vals()[1])
        spent_val = int(msg.get_vals()[2])
        spent_script = P2TRCoinAddress(msg.get_vals()[3]).to_scriptPubKey()
        spending_out = CTxOut(spent_val, spent_script)
        outpoint = CMutableOutPoint(txid[::-1], outindex)
        vin = [CMutableTxIn(prevout=outpoint, nSequence=0xffffffff)]
        outsPK = CCoinAddress(msg.get_vals()[5]).to_scriptPubKey()
        receiving_val = int(msg.get_vals()[4])
        vout = [CTxOut(receiving_val, outsPK)]
        tx2 = CMutableTransaction(vin, vout, nVersion=2)
        self.ms3a.set_transaction_message(tx2, 0, spending_out)
        for i in range(self.n):
            if i == self.myindex:
                continue
            self.send_commitment_exchange_message(i)        

    def receive_partial(self, msg: MS3AMessage):
        """ This is the receipt of message 3
        """
        index = msg.get_counterparty_index()
        assert index != self.myindex
        partial_sig = unhexlify(msg.get_vals()[0])
        self.ms3a.receive_ms3a_msg_3(partial_sig, index)
        if self.ms3a.state == MS3A_STATE_FULLY_SIGNED and self.kicked_off:
            print("We have a full transaction signature: ")
            print(hexlify(self.ms3a.full_signature))
            print("Attempting to broadcast.")
            self.broadcast_spend()

    def broadcast_spend(self):
        
        # Key path signing only requires one witness element: the signature,
        # inserted manually here.
        self.ms3a.tx.wit.vtxinwit[0] = CMutableTxInWitness(
            CScriptWitness([self.ms3a.full_signature]))
        print(hexlify(self.ms3a.tx.serialize()))
        print(human_readable_transaction(self.ms3a.tx))        

class MS3AProtocol(basic.LineReceiver):
    # TODO: line limit length
    MAX_LENGTH = 40000

    def connectionMade(self):
        print("a connection was made")
        self.factory.register_connection(self)
        basic.LineReceiver.connectionMade(self)

    def connectionLost(self, reason):
        self.factory.register_disconnection(self)
        basic.LineReceiver.connectionLost(self, reason)

    def lineReceived(self, line: bytes) -> None:
        try:
            msg = MS3AMessage.from_string_decode(line)
        except:
            print("Received invalid message: {}, "
                      "dropping connection.".format(line))
            self.transport.loseConnection()
            return
        self.factory.receive_message(msg, self)

    def message(self, message: MS3AMessage) -> None:
        self.sendLine(message.encode())

class MS3AFactory(protocol.ServerFactory):
    """ This factory allows us to start up instances
    of the LineReceiver protocol that are instantiated
    towards us.
    """
    protocol = MS3AProtocol

    def __init__(self, client: 'MS3AManager'):
        self.client = client

    def receive_message(self, message: MS3AMessage,
                        p: MS3AProtocol) -> None:
        self.client.receive_message(message)

    def register_connection(self, p: MS3AProtocol) -> None:
        print("registering connection in server factory")

    def register_disconnection(self, p: MS3AProtocol) -> None:
        print("registering disconnection in server factory")

    def send(self, message: MS3AMessage, destination: str) -> bool:
        if destination not in self.peers:
            print("sending message {}, destination {} was not in peers {}".format(
                message.encode(), destination, self.peers))
            return False
        proto = self.peers[destination]
        proto.message(message)
        return True

class MS3AClientFactory(protocol.ReconnectingClientFactory):
    """ We define a distinct protocol factory for outbound connections.
    """
    protocol = MS3AProtocol

    def __init__(self, message_receive_callback: Callable,
                 connection_callback: Callable,
                 disconnection_callback: Callable):
        self.proto_client = None
        # callback takes MS3AMessage as arg and returns None
        self.message_receive_callback = message_receive_callback
        # connection callback, no args, returns None
        self.connection_callback = connection_callback
        # disconnection the same
        self.disconnection_callback = disconnection_callback        

    def clientConnectionLost(self, connector, reason):
        print('MS3A client connection lost: ' + str(reason))

    def clientConnectionFailed(self, connector, reason):
        print('MS3A client connection failed: ' + str(reason))
        if reactor.running:
            print('Attempting to reconnect...')
            protocol.ReconnectingClientFactory.clientConnectionFailed(self,
                                                            connector, reason)        
    
    def register_connection(self, p: MS3AProtocol) -> None:
        print("registering connection in client factory")
        self.proto_client = p
        self.connection_callback()

    def register_disconnection(self, p: MS3AProtocol) -> None:
        self.proto_client = None
        self.disconnection_callback()

    def send(self, msg: MS3AMessage) -> bool:
        # we may be sending at the time the counterparty
        # disconnected
        if not self.proto_client:
            print("Could not send, connection not active.")
            return False
        self.proto_client.message(msg)
        return True

    def receive_message(self, message: MS3AMessage,
                        p: MS3AProtocol) -> None:
        self.message_receive_callback(message)
    

myindex = int(sys.argv[1])
# generate our public key randomly:
if DETERMINISTIC_TEST:
    oursecret = bytes([myindex+1]*32)
else:
    oursecret = os.urandom(32)
ncounterparties = int(sys.argv[2])
x = MS3AManager(CKey.from_secret_bytes(oursecret), ncounterparties, myindex)
my_port = port_base + myindex
msg_callbacks = {1: x.receive_key_exchange,
        2: x.receive_funding_notification,
        3: x.receive_commitments,
        4: x.receive_nonces,
        5: x.receive_partial}
kickoff_loop = task.LoopingCall(x.check_for_kickoff)
kickoff_loop.start(2.0)
funding_info_loop = task.LoopingCall(x.check_for_funding)
funding_info_loop.start(2.0)
endpoints.serverFromString(reactor,
    "tcp:"+str(my_port)).listen(MS3AFactory(x))
reactor.run()

