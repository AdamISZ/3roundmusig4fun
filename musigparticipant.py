import sys
import os
import json
from binascii import hexlify, unhexlify
from typing import Tuple, Callable
from optparse import OptionParser, OptionValueError
from configparser import NoOptionError
from ms3a import (MS3A, AdaptorizedMS3A, MS3A_STATE_NONCES_EXCHANGED,
                  MS3A_STATE_FULLY_SIGNED, DETERMINISTIC_TEST, GROUPN)
from twisted.protocols import basic
from twisted.internet import reactor, protocol, task, endpoints
from twisted.application.internet import ClientService
from twisted.internet.endpoints import TCP4ClientEndpoint
from txtorcon.socks import (TorSocksEndpoint, HostUnreachableError,
                            SocksError, GeneralServerFailureError)
from bitcointx.core.key import CKey, CPubKey
from bitcointx.core import (CTxOut, CMutableTransaction,
            CMutableTxInWitness, CMutableOutPoint, CMutableTxIn)
from bitcointx.wallet import P2TRCoinAddress, CCoinAddress
from bitcointx.core.script import CScriptWitness
from jmbitcoin import human_readable_transaction, select_chain_params
from jmbase import JMHiddenService
from bip340schnorr import bytes_from_int, int_from_bytes
port_base = 61529
hostname = "localhost"
ONION_VIRTUAL_PORT = 5321
# How many seconds to wait before treating an onion
# as unreachable
CONNECT_TO_ONION_TIMEOUT = 60

class MS3AMessage(object):
    """ Encapsulates the messages passed over the wire
    to and from other onion peers
    Simple message syntax:
    json of three keys 'context', 'type', 'line'.
    Type is as per `msg_callbacks` in MS3AManager.
    Context is an integer allowing to differentiate multiple
    communications for the signing of different transactions, at once.
    Line is of this syntax:
    counterparty_index:val,val,..
    The `val`s are keys, sigs etc. All hex encoded.
    The index must be an integer, then colon, then comma separated `val`s.
    """
    def __init__(self, signing_context: int, index: int,
                 vals: Tuple[str], msgtype: int):
        self.signing_context = signing_context
        self.text = str(index) + ":" + ",".join(vals)
        self.msgtype = msgtype

    def encode(self) -> bytes:
        self.encoded = json.dumps({"context": self.signing_context,
                                   "type": self.msgtype,
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
            signing_context = msg_obj["context"]
            text = msg_obj["line"]
            msgtype = msg_obj["type"]
            assert isinstance(msgtype, int)
            assert isinstance(text, str)
            index, valstring = text.split(":")
            vals = valstring.split(",")
        except:
            print("Error decoding message")
            raise
        return cls(signing_context, index, vals, msgtype)

class MS3AParticipant(object):
    """ Representing 1 party in N x (N of N MuSig) operations,
    this object:
    - owns the secret keys, of which there are N
    - owns the single adaptor secret
    - owns a final destination address for this participant
    - owns N MS3AManager objects which manage
    a single signing context with the other participants
    - manages the network interaction between this
    participant and the other participants; all reachable
    network destinations must be passed as onion hostnames in
    the first argument to the constructor.
    """
    def __init__(self, onions: Tuple[str], privkeys: Tuple[CKey],
                 destination_addr: str, n: int, myindex: int,
                 scindex_max: int, ouradaptor: bytes=b""):
        self.myindex = myindex
        self.n = n
        self.signing_contexts = []
        self.scindex_max = scindex_max
        self.destination_addresses = [None] * self.n
        # the destination addresses are at *our* index,
        # while our funding is at index + 1 % n. We set
        # ours now, but wait for key exchange to set the others.
        self.destination_addresses[myindex] = destination_addr

        # these manage instantiation of network communication
        # protocols, see MS3AProtocol
        self.factories = {}
        for k in range(scindex_max):
            self.signing_contexts.append(MS3AManager(
                privkeys[k], self.destination_addresses[k],
                n, myindex, k,
                ouradaptor=ouradaptor,
                send_callback=self.send,
                adaptor_safety_callback=self.check_adaptor_consistency))

        # For our use case, all signing contexts will
        # use an adaptor, and it will be the same one
        self.set_adaptor_secret(ouradaptor)

        for i in range(n):
            if i == self.myindex:
                continue
            self.connect(i, onions[i])
        self.connected_counter = 0

    def onion_hostname_callback(self, hostname):
        """ Just informational; allows bootstrapping,
        by printing the hostname.
        """
        print("We are starting a hidden service at: ", hostname)

    def set_adaptor_secret(self, secret:bytes):
        for s in self.signing_contexts:
            s.ms3a.set_adaptor_secret(secret)

    def check_adaptor_consistency(self) -> int:
        """ This should be called *before* sending
        partial signatures, in order to ensure safety
        of receipt of adaptor secrets on full signatures.
        There are three return values:
        1 : all adaptors are received and are consistent
        -1: there is an inconsistency in the received adaptors
        0: not all adaptors are yet received
        """
        for i in range(self.n):
            if i == self.myindex:
                continue
            ts_for_i = [s.ms3a.Ts[i] for s in self.signing_contexts]
            if None in ts_for_i:
                return 0
            first = ts_for_i[0]
            if not all(elem == first for elem in ts_for_i):
                print("Mismatch on adaptors at index {}, aborting: {}".format(
                    i, ts_for_i))
                return -1
        return 1

    def start_key_exchange(self):
        # current simple model: index 0 is always coordinator
        if not self.myindex == 0:
            return
        for i in range(0, self.scindex_max):
            self.signing_contexts[i].start_key_exchange()

    def register_connection(self):
        """ This code is naively optimistic; if we registered
        all the connections, we assume they're all up.
        """
        self.connected_counter += 1
        print("We have connected to", self.connected_counter, "participants.")
        if self.connected_counter == self.n - 1:
            self.start_key_exchange()

    def register_disconnection(self):
        self.connected_counter -= 1
        pass

    def connect(self, index: int, onion: str) -> None:
        # allows a bootstrap, where connect is a no-op:
        if onion == "":
            return
        if index in self.factories:
            return
        self.factories[index] = MS3AClientFactory(self.receive_message,
        self.register_connection, self.register_disconnection)
        torEndpoint = TCP4ClientEndpoint(reactor, "localhost",
                                         9050,
                                         timeout=CONNECT_TO_ONION_TIMEOUT)
        onionEndpoint = TorSocksEndpoint(torEndpoint, onion,
                                         ONION_VIRTUAL_PORT)
        self.reconnecting_service = ClientService(onionEndpoint, self.factories[index])
        print("Now trying to connect to : " + onion + str(ONION_VIRTUAL_PORT))
        self.reconnecting_service.startService()

    def send(self, counterparty_index: int, msg: MS3AMessage):
        res = self.factories[counterparty_index].send(msg)
        if not res:
            #print("Failed to send to {}, message was: {}".format(
            #    counterparty_index, msg.text))
            # keep trying in case connection drops happen:
            reactor.callLater(4.0, self.send, counterparty_index, msg)

    def receive_message(self, message: MS3AMessage):
        """ This sends the message to the right callback,
        dependent on the message type. Note that this code,
        being only for toy/test cases, doesn't bother to
        pay attention to network source, just trusts the
        counterparty to be sending a consistent index to
        update the right set of keys, nonces, sigs etc.
        """
        # Just ignore all messages that don't specify our
        # signing context
        if message.signing_context not in range(self.scindex_max):
            print("Invalid signing context index: ", message)
            return
        self.signing_contexts[message.signing_context].receive_message(
            message)

class MS3AManager(object):

    def __init__(self, privkey: CKey, destn_addr, n: int, myindex: int, scindex: int,
                 send_callback: Callable, adaptor_safety_callback: Callable,
                 ouradaptor: bytes=b""):
        # create a private key and public key, then
        # be ready to receive messages.
        self.privkey = privkey
        # the destination address may, at this point, be either
        # an address, or None (if we have to wait for key exchange to get it)
        self.destn_addr = destn_addr
        # number of counterparties
        self.n = n
        self.myindex = myindex
        assert myindex < n
        self.scindex = scindex
        # the signing state is encapsulated here:
        if ouradaptor == b"":
            self.ms3a = MS3A(self.privkey, n, myindex)
        else:
            self.ms3a = AdaptorizedMS3A(self.privkey, ouradaptor, n, myindex)
        self.msg_callbacks = {1: self.receive_key_exchange,
                              2: self.receive_funding_notification,
                              3: self.receive_commitments,
                              4: self.receive_nonces,
                              5: self.receive_partial,
                              6: self.receive_signature_adaptor,
                              7: self.receive_nonce_exchange_complete} # 7 is actually after 4
        self.adaptor_safety_callback = adaptor_safety_callback
        # boolean lets us kick off process only once
        self.kicked_off = False
        self.send_callback = send_callback
        self.funding_received = False
        self.able_to_send = False
        self.key_sent = False
        self.nonce_calc_complete = {}
        self.sig_adaptors = [None] * n

    def start_key_exchange(self):
        """ Arbitrarily, index 0 acts as coordinator,
        always. The process starts (after a delay) with
        this participant sending initial key exchange
        messages.
        """
        if not self.myindex == 0:
            return
        for i in range(1, self.n):
            self.send_key_exchange_message(i)

    def check_for_funding(self):
        """ Intended to be a polling loop.
        """
        if self.funding_received:
            return
        try:
            with open("fundingfile" + str(self.myindex) + str(self.scindex) + ".txt", "r") as f:
                lines = f.readlines()
                if len(lines) > 0:
                    print("We saw a line in the file: ", lines[0])
                    # txid:n of the utxo being spent are the first two.
                    # the third is the value in satoshis being spent.
                    # meanwhile, the txfee is hardcoded to 5K sats and the
                    # destination address (1 to 1) is already defined.
                    hextxid, strindex, strvalue= lines[0].strip().split(",")
                    for i in range(self.n):
                        self.send_funding_message(i, hextxid,
                                        int(strindex), int(strvalue))
                    self.funding_received = True
        except OSError:
            # ignore non-existence
            pass

    def create_ms3a_message(self, data: Tuple[str], msgtype: int) -> MS3AMessage:
        return MS3AMessage(self.scindex, self.myindex, data, msgtype)

    def send(self, counterparty_index: int, msg: MS3AMessage):
        self.send_callback(counterparty_index, msg)

    def send_key_exchange_message(self, index):
        if self.destn_addr is None:
            destmsg = ""
        else:
            destmsg = str(self.destn_addr)
        msg = self.create_ms3a_message((hexlify(self.ms3a.basepubkey).decode(),
                                        destmsg), 1)
        self.send(index, msg)

    def send_commitment_exchange_message(self, index):
        self.ms3a.get_ms3a_msg_1()
        msg = self.create_ms3a_message((hexlify(
            self.ms3a.HRs[self.myindex]).decode(),
            hexlify(self.ms3a.HTs[self.myindex]).decode()), 3)
        self.send(index, msg)

    def send_nonce_exchange_message(self, index):
        msg = self.create_ms3a_message((hexlify(
            self.ms3a.Rs[self.myindex]).decode(),
            hexlify(self.ms3a.Ts[self.myindex]).decode()), 4)
        self.nonce_calc_complete[self.myindex] = True
        self.send(index, msg)

    def send_funding_message(self, index: int, hextxid: str, spending_index: int,
                             value: int):
        msg = self.create_ms3a_message((hextxid,
                                       str(spending_index),
                                       str(value)), 2)
        if index == self.myindex:
            self.receive_funding_notification(msg)
        else:
            self.send(index, msg)

    def send_nonce_exchange_complete(self, index):
        msg = self.create_ms3a_message(("NONCE_EXCHANGE_COMPLETE",), 7)
        self.send(index, msg)

    def send_partials_exchange_message(self, index):
        msg = self.create_ms3a_message((hexlify(
            self.ms3a.fullpartials[self.myindex]).decode(),), 5)
        self.send(index, msg)

    def send_signature_adaptor_message(self, index: int) -> None:
        msg = self.create_ms3a_message((hexlify(
            self.ms3a.get_signature_adaptor()).decode(),), 6)
        self.send(index, msg)

    def receive_message(self, message: MS3AMessage):
        """ This sends the message to the right callback,
        dependent on the message type. Note that this code,
        being only for toy/test cases, doesn't bother to
        pay attention to network source, just trusts the
        counterparty to be sending a consistent index to
        update the right set of keys, nonces, sigs etc.
        """
        # Just ignore all messages that don't specify our
        # signing context
        if message.signing_context != self.scindex:
            return
        msgtype = message.msgtype
        if msgtype in self.msg_callbacks.keys():
            self.msg_callbacks[msgtype](message)
            return
    
    def receive_key_exchange(self, msg: MS3AMessage) -> None:
        index = msg.get_counterparty_index()
        if self.ms3a.keys[index]:
            # TODO clean up so they don't send repeats;
            # currently the instigator (index 0) can send
            # repeats, depending on context.
            print("Already received key; ignoring repeat.")
            return
        assert index != self.myindex
        try:
            pub = CPubKey(unhexlify(msg.get_vals()[0]))
        except:
            print("Failed key exchange message: ", msg)
            return
        # Set the destination if the right counterparty
        if self.scindex == index:
            assert msg.get_vals()[1] != ""
            self.destn_addr = msg.get_vals()[1]
        if not self.ms3a.musig_address and self.ms3a.set_base_pubkey(pub, index):
            # key exchange is complete; start by sending msg1
            print("Key exchange complete")
            if self.scindex == (self.myindex + 1) % self.n:
                print("You are index {}. You should fund the musig address"
                      " for signing session {}, which is: {}".format(self.myindex,
                    (self.myindex + 1) % self.n, self.ms3a.get_musig_address()))
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
            for i in range(self.n):
                if i == self.myindex:
                    continue
                self.send_nonce_exchange_complete(i)

    def receive_nonce_exchange_complete(self, msg: MS3AMessage):
        if not msg.get_vals()[0] == "NONCE_EXCHANGE_COMPLETE":
            print("invalid nonce exchange complete message")
            return
        i = msg.get_counterparty_index()
        if i in self.nonce_calc_complete:
            print("Received duplicate notification of nonce "
                  "exchange complete from", i)
            return
        self.nonce_calc_complete[i] = True
        if all(self.nonce_calc_complete.values()):
            # Once everyone has nonces, we can all verify each
            # others' adaptors, which is why we wait to send them
            # until we know everyone is finished with MuSig steps 1,2.
            for j in range(self.n):
                if j == self.myindex:
                    continue
                self.send_signature_adaptor_message(j)

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
        spent_script = self.ms3a.musig_address.to_scriptPubKey()
        spending_out = CTxOut(spent_val, spent_script)
        outpoint = CMutableOutPoint(txid[::-1], outindex)
        vin = [CMutableTxIn(prevout=outpoint, nSequence=0xffffffff)]
        outsPK = CCoinAddress(self.destn_addr).to_scriptPubKey()
        receiving_val = spent_val - 5000
        vout = [CTxOut(receiving_val, outsPK)]
        tx2 = CMutableTransaction(vin, vout, nVersion=2)
        self.ms3a.set_transaction_message(tx2, 0, spending_out)
        for i in range(self.n):
            if i == self.myindex:
                continue
            self.send_commitment_exchange_message(i)        


    def receive_partial(self, msg: MS3AMessage):
        """ This is the receipt of message 3 in the
        interaction, constituting completion.
        At this point we will be able to broadcast
        transactions if necessary and also receive
        any secret data promised.
        """
        index = msg.get_counterparty_index()
        assert index != self.myindex
        partial_sig = unhexlify(msg.get_vals()[0])
        self.ms3a.receive_ms3a_msg_3(partial_sig, index)
        if self.ms3a.state == MS3A_STATE_FULLY_SIGNED:
            print("We have a full transaction signature: ")
            print(hexlify(self.ms3a.full_signature))
            adaptor_secrets = []
            for i in range(self.n):
                if i == self.myindex:
                    continue
                if not self.ms3a.Ts[i] or self.ms3a.Ts[i] == bytes([0]):
                    continue
                adaptor_secrets.append(self.ms3a.reveal_adaptor_secret(
                    self.sig_adaptors[i], i))
                print("After signing we got the secret value: {} "
                      "for index {} corresponding to point: {}".format(
                          hexlify(adaptor_secrets[-1]), i, self.ms3a.Ts[i]))
            if len(adaptor_secrets) > 0:
                self.aggregated_adaptor_secret = bytes_from_int(sum(
                    [int_from_bytes(x) for x in adaptor_secrets]) % GROUPN)
                print("We got an aggregated adaptor secret of: ",
                      hexlify(self.aggregated_adaptor_secret))
            if self.myindex == self.scindex:
                # we set the destination address to our own, for our own
                # index in the list of signing sessions, so we want to
                # broadcast this one:
                print("Attempting to broadcast spend into my address!")
                self.broadcast_spend()

    def check_send_partials(self):
        """ Will send partial signatures ("full partials"),
        only when we have received a signature adaptor message
        from all counterparties.
        """
        # We only care about *others'* sig adaptors, not our own (null or not):
        sig_adaptors_to_check = self.sig_adaptors[:myindex] + self.sig_adaptors[myindex+1:]
        if all(sig_adaptors_to_check):
            x = self.adaptor_safety_callback()
            if x == -1:
                print("Not sending partial signatures; adaptors "
                      "in different signing contexts don't match.")
                return
            if x == 0:
                # we may still be waiting for funding to occur in the
                # other signing sessions, so that we need to wait until
                # we can check that all the T values match:
                reactor.callLater(1.0, self.check_send_partials)
                return
            assert x == 1
            # Having received all makes us safe to send, since
            # any secrets we need, we will now know:
            print("We have received all sig adaptor messages, "
                  "now sending out partials.")
            for i in range(self.n):
                if i == self.myindex:
                    continue
                self.send_partials_exchange_message(i)
        else:
            print("Not all sig adaptors yet received, continuing.")

    def receive_signature_adaptor(self, msg: MS3AMessage):
        index = msg.get_counterparty_index()
        assert index != self.myindex
        sig_adaptor = unhexlify(msg.get_vals()[0])
        # ignore nulls
        if sig_adaptor == bytes([0]):
            # Just flag message received so we can trigger
            # the next step when all are sent.
            self.sig_adaptors[index] = True
            self.check_send_partials()
            return
        if self.ms3a.state < MS3A_STATE_NONCES_EXCHANGED:
            print("Error: we received an adaptor but nonces "
                  "haven't been exchanged.")
        res = self.ms3a.verify_adaptor(sig_adaptor, index)
        if not res:
            print("Adaptor didn't verify at index ", index)
            raise
        else:
            print("Adaptor at index {} verified correctly: {}".format(
                index, hexlify(sig_adaptor)))
            self.sig_adaptors[index] = sig_adaptor
        self.check_send_partials()
        
    def broadcast_spend(self):
        # Key path signing only requires one witness element: the signature,
        # inserted manually here.
        # For now this is left as a manual print, for user to copy-paste
        # into actual broadcast.
        print("But currently you have to broadcast it manually:")
        self.ms3a.tx.wit.vtxinwit[0] = CMutableTxInWitness(
            CScriptWitness([self.ms3a.full_signature]))
        print(hexlify(self.ms3a.tx.serialize()))
        print(human_readable_transaction(self.ms3a.tx))        

class MS3AProtocol(basic.LineReceiver):
    # TODO: line limit length
    MAX_LENGTH = 40000

    def connectionMade(self):
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

    def __init__(self, client: 'MS3AParticipant'):
        self.client = client

    def receive_message(self, message: MS3AMessage,
                        p: MS3AProtocol) -> None:
        self.client.receive_message(message)

    def register_connection(self, p: MS3AProtocol) -> None:
        pass

    def register_disconnection(self, p: MS3AProtocol) -> None:
        pass

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
        pass
        #print('MS3A client connection lost: ' + str(reason))

    def clientConnectionFailed(self, connector, reason):
        #print('MS3A client connection failed: ' + str(reason))
        if reactor.running:
            protocol.ReconnectingClientFactory.clientConnectionFailed(self,
                                                            connector, reason)        
    
    def register_connection(self, p: MS3AProtocol) -> None:
        self.proto_client = p
        self.connection_callback()

    def register_disconnection(self, p: MS3AProtocol) -> None:
        self.proto_client = None
        self.disconnection_callback()

    def send(self, msg: MS3AMessage) -> bool:
        # we may be sending at the time the counterparty
        # disconnected
        if not self.proto_client:
            return False
        self.proto_client.message(msg)
        return True

    def receive_message(self, message: MS3AMessage,
                        p: MS3AProtocol) -> None:
        self.message_receive_callback(message)

parser = OptionParser(
        usage='usage: %prog [my index] [number of participants] [receiving address]',
        description=
        'Runs N-party adaptor based coin swap'
        ' an attempt to break the link between them. Sending to multiple '
        ' addresses is highly recommended for privacy. This tumbler can'
        ' be configured to ask for more address mid-run, giving the user'
        ' a chance to click `Generate New Deposit Address` on whatever service'
        ' they are using.')
parser.add_option('--bootstrap',
    action='store_true',
    dest='bootstrap',
    default=False,
    help=('If set to true, program just prints out .onion address'
           'to share with counterparties'))
parser.add_option('--deterministic',
    action='store_true',
    dest='deterministic',
    default=False,
    help=('If set to true, uses unsafe secret keys that'
          ' are fixed small integers.'))
parser.add_option('--network',
                  type='string',
                  dest='network',
                  default='regtest',
                  help=('Set to either signet or regtest'))

(options, args) = parser.parse_args()

myindex = int(args[0])

ncounterparties = int(args[1])

# TODO address check but maybe not jmclient version
my_destination = args[2]

# this is also referred to in ms3a.py; bit messy
if options.deterministic:
    DETERMINISTIC_TEST = options.deterministic

if DETERMINISTIC_TEST:
    oursecrets = [bytes([myindex+1+q]*32) for q in range(ncounterparties)]
else:
    oursecrets = [os.urandom(32) for _ in range(ncounterparties)]

if DETERMINISTIC_TEST:
    ouradaptor = bytes([myindex+47]*32)
else:
    ouradaptor = os.urandom(32)

# Sets these strings all to "", to bootstrap: your onion hostname will be printed (just *.onion, no port).
# Then, after exchanging these strings with your counterparties, run without `--bootstrap` option
if options.bootstrap:
    onions = ["", "", ""]
else:
    onions = ["6xapwqugm5i63625hqif45joly33h7nf63c6ecwr6feshybnkwiiutqd.onion", "uqiedohr7vorc6ssarerso4ruw2nu5ug5qjgvcgvvw3czvraccqj2aqd.onion", "ouhdwwzqz5u6tskbb62l4eed4uay3kkbvshyzxe2676lerhd56ryi6id.onion"]

assert len(onions) == ncounterparties, "you must provide exactly one onion address per counterparty"

if options.network != "regtest":
    print("Setting network to: ", options.network)
    select_chain_params("bitcoin/" + options.network)

x = MS3AParticipant(onions, [CKey.from_secret_bytes(s) for s in oursecrets],
                    my_destination, ncounterparties, myindex, ncounterparties,
                    ouradaptor=ouradaptor)

# The spending transaction will be processed from a file:
for sc in x.signing_contexts:
    task.LoopingCall(sc.check_for_funding).start(2.0)

hs = JMHiddenService(MS3AFactory(x), print,
                                      print,
                                      x.onion_hostname_callback,
                                      "localhost",
                                      9051,
                                      "127.0.0.1",
                                      8080,
                                      virtual_port=ONION_VIRTUAL_PORT,
                                      shutdown_callback=print,
                                      hidden_service_dir="hidserv" + str(myindex))
# this call will start bringing up the HS; when it's finished,
# it will fire the `onion_hostname_callback`.
hs.start_tor()

reactor.run()

