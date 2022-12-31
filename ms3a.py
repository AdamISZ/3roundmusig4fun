import bitcointx as btc
btc.allow_secp256k1_experimental_modules()
btc.select_chain_params("bitcoin/regtest")
import jmbitcoin
import os
import sys
from hashlib import sha256
from typing import Tuple, List
from bitcointx.wallet import CCoinKey
from bitcointx.core import CTxOut, CMutableTransaction
from bitcointx.core.script import SignatureHashSchnorr
from bitcointx.core.key import CPubKey
from bitcointx.wallet import P2TRCoinAddress
from binascii import hexlify, unhexlify
# This is the reference code that accompanies BIP340:
from bip340schnorr import (schnorr_verify, int_from_bytes,
                          bytes_from_int, tagged_hash)
from bip340schnorr import n as GROUPN

# set to true so the nonces are fixed and all the bytes are repeatable
DETERMINISTIC_TEST = False

# basic musig algorithm:
# see https://eprint.iacr.org/2018/068.pdf Section 3
# note that this is the "3-ROUND" version of MuSig, and not MuSig2.

# additionally, facility to include adaptors such that one counterparty
# can verify that a secret will be revealed by a fully valid Schnorr signature,
# is included here, but is optional.

# note about states: states should represent forward progress (hence >=
# is a valid check, below). Between 'nonces exchanged' and 'fully signed'
# there are many possible intermediate states, including
# adaptor sharing and partial sig sharing, but they aren't
# in a fixed order, so not here for now:
MS3A_ABORTED, MS3A_STATE_UNINITIALIZED, MS3A_STATE_KEYAGG_COMPLETE, \
MS3A_STATE_COMMS_EXCHANGED, MS3A_STATE_NONCES_EXCHANGED, \
MS3A_STATE_FULLY_SIGNED = range(6)

""" Before we begin, a note on x-only:

Two principles are applied here:
1. "JIT x-only": we need to do arithmetic on points here, and x-only keys
   are not actual curve points. This is the reason to keep keys in so-called
   "compressed" form (i.e. keeping the sign byte 02/03), until they need to
   be exposed inside a BIP340 signature.
2. Sign flip on drop into x-only: in case a key does need to be sign-flipped
   according to point 1. above, *we must also flip all the corresponding secret
   keys*. The word "all" matters, in that sentence: here we are building keys
   as aggregates of separately/privately held keys, so everyone in the protocol
   has to understand that they must flip their private keys, in synchrony.

For a full debate/discussion see https://github.com/jonasnick/bips/issues/32
"""


def its_not_ok_to_be_odd_in_bip340(point: CPubKey,
                    scalars: List[bytes]) -> Tuple[bytes, bool]:
    """ Pass a point in compressed form (CPubKey object),
    (note, not XOnlyPubKey), and pass a list of corresponding
    scalars (private keys as bytes) - flip the sign of
    the latters, if the former has odd y coord.
    The updated scalars are returned and should be used to reset.
    """
    sign_flipped = False
    newscalars = []
    if bytes(point)[0] == 3:
        for scalar in scalars:
            xi = int_from_bytes(scalar)
            xie = GROUPN - xi
            newscalars.append(bytes_from_int(xie))
        sign_flipped = True
    else:
        newscalars = scalars
    return newscalars, sign_flipped

def flip_pubkey_sign(point: CPubKey) -> CPubKey:
    """ In case we needed to flip signs of any input keys to the algorithm,
    in order to get a valid x-only signing event, we may also need to flip
    signs of public keys that do not belong to us, in order to do verification
    of the data sent to us by counterparties.
    (NB: Flipping "sign" (in finite field treat x>n/2 as "negative"),
    # is the same as flipping y-coord parity because group order is odd)
    """
    signbyte = bytes(point)[0]
    if signbyte == 3:
        nsb = b"\x02"
    else:
        assert signbyte == 2
        nsb = b"\x03"
    # python note: indexing into bytes returns int,
    # but *slicing* into bytes returns bytes.
    return CPubKey(nsb + bytes(point)[1:])

def bip340_signing_hash(Rbytes, Pbytes, sighash):
    """ BIP340 compatible Fiat-Shamir
    """
    return tagged_hash("BIP0340/challenge", Rbytes + Pbytes + sighash)

class MS3A(object):
    """ Represents signing process for an individual user in a musig signing
    event over a bitcoin transaction, using taproot.
    """
    def __init__(self, privkey: btc.core.key.CKey,
                n: int, myindex: int, hashfn = sha256):

        self.state = MS3A_STATE_UNINITIALIZED

        # number of participants
        self.n = n

        # my index position in the list
        # (TODO: deterministic ordering is easiest)
        self.myindex = myindex

        # the transaction we are going to sign after
        # funding.
        self.spending_tx = None
        # the input index we're signing from
        self.spending_index = None
        # the CTxOut to be spent at that index:
        self.spending_out = None
        # the sighash for our signing of the tx:
        self.sighash = None
        # the address negotiated from the pubkey set
        self.musig_address = None

        # adaptor secret `t`, for this index, may or may not be used:
        self.adaptor_secret = None

        self.privkey = privkey

        # k value for this index
        self.nonce = None

        self.basepubkey = self.privkey.pub

        # all the pubkeys used in musig negotiation
        self.keys = [None] * self.n
        
        self.keys[self.myindex] = self.basepubkey

        # commitment hashes of the participants' Rs:
        self.HRs = [None] * self.n
        # commitment hashes of participants' adaptor points if applicable:
        self.HTs = [None] * self.n
        self.Rs = [None] * self.n
        self.Ts = [None] * self.n
        # see https://eprint.iacr.org/2018/068.pdf as per above,
        # the aggregated pubkey is sigma(H(L||P_i)P_i), where L is
        # the concatenation of all the keys.
        self.agg_P = None
        # in 3-round musig, aggregate R is just sigma(R_i).
        self.agg_R = None
        # aggregate privkey is *our* privkey with aggregate pubkey hash multiplier:
        self.agg_privkey = None
        # "full" partials are the partial sigs including the corresponding
        # adaptor secret, so s_i = k_i (+t_i) + \
        #                          H(aggR (+T) || aggP || message)H(L||P_i)x_i
        # (note that the `T` here would be the full `T`, not just T_i)
        # (note that if there is no adaptor in use then the `t,T` values don't exist)
        self.fullpartials = [None] * self.n
        self.hashfn = hashfn
        self.keysetstr = b""

        # sign flip tracking (see `gacc` etc in MuSig BIP for analogous)
        # we need to know if we flipped *all* the signs of the nonces,
        # and if we flipped *all* the signs of the key shares
        self.nonce_sign_flipped = False
        self.key_sign_flipped = False

        # the spending transaction which will be signed.
        self.tx = None

    def set_base_pubkey(self, key: CPubKey, index: int):
        """ Populate the key at index index;
        return True if the set is complete, and False if not.
        """
        self.keys[index] = key
        if all(self.keys):
            if not self.agg_P:
                self.get_agg_P()
            return True
        return False

    def set_transaction_message(self, tx: CMutableTransaction, spending_index: int,
                                spending_out: CTxOut):
        self.tx = tx
        self.spending_index = spending_index
        # example: cto1 = CTxOut(10000000,
        #  P2TRCoinAddress.from_xonly_pubkey(k.xonly_pub).to_scriptPubKey())
        self.spending_out = spending_out
        # given the full transaction message context, we can already calculate
        # our sighash:
        self.sighash = SignatureHashSchnorr(self.tx, self.spending_index,
                                            [self.spending_out])

    def set_my_nonce(self):
        # Sets R and HR values for this context's index;
        # note this could be done in constructor for simplicity,
        # but might be useful to be able to do it later, in some cases.
        if DETERMINISTIC_TEST:
            self.basenonce = bytes([self.myindex+4]*32)
        else:
            self.basenonce = os.urandom(32)
        self.Rs[self.myindex] = CCoinKey.from_secret_bytes(self.basenonce).pub
        self.HRs[self.myindex] = self.hashfn(self.Rs[self.myindex]).digest()

    def set_adaptor_secret(self, secret_bytes):
        self.adaptor_secret = secret_bytes
        self.Ts[self.myindex] = CCoinKey.from_secret_bytes(self.adaptor_secret).pub
        self.HTs[self.myindex] = self.hashfn(self.Ts[self.myindex]).digest()

    def get_ms3a_msg_1(self) -> Tuple[bytes, bytes]:
        # Message 1 sends H(R_i), H(T_i) for this index i:
        if not self.Rs[self.myindex]:
            self.set_my_nonce()
        if not self.adaptor_secret:
            self.Ts[self.myindex] = bytes([0])
            self.HTs[self.myindex] = self.hashfn(self.Ts[self.myindex]).digest()

        return (self.hashfn(bytes(self.Rs[self.myindex])).digest(),
                self.hashfn(bytes(self.Ts[self.myindex])).digest())

    def receive_ms3a_msg_1(self, HR, HT, i) -> bool:
        self.HRs[i] = HR
        self.HTs[i] = HT
        if all(self.HRs) and all(self.HTs):
            return True
        return False

    def get_ms3a_msg_2(self) -> Tuple[bytes, bytes]:
        return (self.Rs[self.myindex], self.Ts[self.myindex])

    def verify_ms3a_msg_2(self, i: int, R: CPubKey,
                          T: bytes) -> bool:
        # Note we receive `T` as bytes, since optionally it can be a
        # null message consisting of a single zero byte, which is not a valid
        # CPubKey
        tempHR, tempHT = [self.hashfn(bytes(x)).digest() for x in [R, T]]
        return (tempHR == self.HRs[i] and tempHT == self.HTs[i])

    def receive_ms3a_msg_2(self, R, T, i) -> bool:
        if self.verify_ms3a_msg_2(i, R, T):
            self.Rs[i] = R
            self.Ts[i] = T
        else:
            # The R, T values can only be accepted if they match the pre-existing
            # hashes that were sent, for the same index.
            print("Aborting because received step 2 message was invalid for index: {}".format(i))
            print("Here are current R values: ")
            print(self.Rs)
            self.state = MS3A_ABORTED
            return False
        if all(self.Rs):
            self.state = MS3A_STATE_NONCES_EXCHANGED
            self.get_agg_R()
            # we can populate our own partial sig immediately:
            self.get_partial_signature()
        return True

    def get_ms3a_msg_3(self) -> bytes:
        # State can have advanced if we already received the others'
        # msg3, meaning we're already fully signed:
        assert self.state >= MS3A_STATE_NONCES_EXCHANGED
        return self.fullpartials[self.myindex]

    def receive_ms3a_msg_3(self, partial_sig: bytes, index: int) -> bool:
        if not self.verify_partial_sig(partial_sig, index):
            print("Partial sig verify failed at index {}".format(index))
            self.state = MS3A_ABORTED
            return False
        self.fullpartials[index] = partial_sig
        if all(self.fullpartials):
            if not self.get_full_signature_from_partials():
                self.state = MS3A_ABORTED
                return False
            self.state = MS3A_STATE_FULLY_SIGNED
        return True

    def get_full_signature_from_partials(self) -> bool:
        """ Combines all (validated) partial signatures
        by simple addition, to get the full signature on the
        multisig key. Checks validity of the aggregate signature
        and returns True if it validates, False otherwise.
        """
        sigs_int = [int_from_bytes(x) for x in self.fullpartials]
        res = 0
        for s in sigs_int:
            res = (res + s) % GROUPN
        fullsig = bytes_from_int(res)
        self.full_signature = bytes(
            btc.core.key.XOnlyPubKey(self.agg_R)) + fullsig
        if not schnorr_verify(self.sighash,
            bytes(btc.core.key.XOnlyPubKey(self.agg_P)),
            self.full_signature):
            print("Failed to verify the aggregated signature")
            return False
        return True

    def get_agg_R(self):
        """ Sets aggregate nonce using compressed points
        """
        self.agg_R = jmbitcoin.add_pubkeys(self.Rs)
        self.reset_base_nonce_with_aggR()

    def reset_base_nonce_with_aggR(self, include_t: bool =False):
        """deduces whether the base nonce sign, for this
        participant, needs to be flipped, depending on the aggregate
        nonce's parity.
        """
        scalarlist = [self.basenonce]
        if include_t:
            scalarlist.append(self.adaptor_secret)
        newscalarlist, x = its_not_ok_to_be_odd_in_bip340(
            self.agg_R, scalarlist)
        self.basenonce = newscalarlist[0]
        print("In reset base nonce, self.basenonce set to: ", self.basenonce)
        if include_t:
            self.adaptor_secret = newscalarlist[1]
        self.nonce_sign_flipped = x

    def set_keyset_str(self):
        """ Sets "L" as per algorithm document,
        i.e. the concatenation of the compressed serializations
        of all of the public keys used by the participants in the
        multisig.
        Notice that these are the original keys committed to, not
        (possibly) sign-flipped variants.
        """
        self.keysetstr = b""
        for k in self.keys:
            self.keysetstr += bytes(k)

    def get_partial_signature(self, include_t: bool = True) -> bytes:
        """ Returns partial signature in the form:
        s_i = k_i (+t_i) + H(R (+T),P,m)H(L||P_i)x_i for this participant,
        and can only be calculated after the first two rounds are completed
        by all participants, so we know the full (and sign flipped)
        aggregate nonce.
        Note that: returning a signature *adaptor* is functionally identical
        to returning a partial, without including the secret t_i, in cases where
        the secret t_i *is* defined.
        """
        # Must only be attempted once the first two rounds are completed
        # by all the participants.
        assert self.state == MS3A_STATE_NONCES_EXCHANGED
        # We calculate using actual arithmetic rather than using `schnorr_sign`,
        # because that algo doesn't account for musig nor adaptors.
        # NOTE: the complete insecurity of doing this is one reason this cannot
        # be used in prod. (One!).
        agg_priv_int = int_from_bytes(self.agg_privkey)
        my_nonce_int = int_from_bytes(self.basenonce)
        # x-only forms of keys are required for consensus:
        xonlyaggR = btc.core.key.XOnlyPubKey(self.agg_R)
        xonlyaggP = btc.core.key.XOnlyPubKey(self.agg_P)
        e = int_from_bytes(bip340_signing_hash(bytes(xonlyaggR),
                            bytes(xonlyaggP), self.sighash)) % GROUPN
        # s = k + ex, or k + t + ex where needed:
        sig = (my_nonce_int + e * agg_priv_int) % GROUPN
        if self.adaptor_secret and include_t:
            adaptor_int = int_from_bytes(self.adaptor_secret)
            sig = (sig + adaptor_int) % GROUPN
        if not include_t:
            # We don't set the partial signature, if we're returning
            # an adaptor (the only reason to set include_t = False)
            return sig
        self.fullpartials[self.myindex] = bytes_from_int(sig)
        return sig

    def verify_partial_sig(self, partial_sig: bytes, index: int,
                           include_t: bool = True):
        """ Given a partial sig s_i = k_i + H(..)x_agg_i , check if it
        Schnorr verifies (so that sigma(s_i) will verify with same sighash).
        Note we must flip signs of locally stored R partials, and P partials,
        if and only if (for each, separately), we have flipped the sign of
        the corresponding aggregate key.
        We also include the T value corresponding to index index, if it is set,
        into sG =?= R + T + eP (with e hashing the aggR including all Ts).
        """
        LHS = jmbitcoin.privkey_to_pubkey(partial_sig + b"\x01") # LHS=sG
        R = self.Rs[index]
        T = self.Ts[index]
        if self.nonce_sign_flipped:
            R = flip_pubkey_sign(R)
            if T != bytes([0]) and include_t:
                T = flip_pubkey_sign(T)
        # x-only forms of keys are required for consensus:
        xonlyaggR = btc.core.key.XOnlyPubKey(self.agg_R)
        xonlyaggP = btc.core.key.XOnlyPubKey(self.agg_P)        
        e = bip340_signing_hash(bytes(xonlyaggR), bytes(xonlyaggP), self.sighash)
        P = self.get_agg_P_i(index)
        if self.key_sign_flipped:
            P = flip_pubkey_sign(P)
        eP = jmbitcoin.multiply(e, P, return_serialized=False)
        RT = R
        if T != bytes([0]) and include_t:
            RT = jmbitcoin.add_pubkeys([RT, T])
        return LHS == jmbitcoin.add_pubkeys([RT, eP])

    def verify_adaptor(self, signature_adaptor: bytes,
                       adaptor_point: bytes, keyindex: int):
        """ Note that this is far from a fully-general
        'verify that this adaptor, for this message and key, is valid
        and implies revelation once the signature is revealed'. Here,
        we have set up the m, P, T and R values in advance, and are only
        checking that this s' works for this context.
        """
        assert self.Ts[keyindex] != bytes([0])
        assert self.state >= MS3A_STATE_NONCES_EXCHANGED
        return self.verify_partial_sig(signature_adaptor,
                                       keyindex, include_t=False)

    def get_agg_P_i(self, i: int) -> CPubKey:
        """ Sets the aggregate pubkey component for index i.
        additionally, sets the 'aggregate privkey' for *this* index,
        using the same hash coefficient (if we are working on our index).
        See `get_agg_P` for important note about sign-flipping this key.
        """
        mult = self.hashfn(self.keysetstr + bytes(self.keys[i])).digest()
        intmult = int_from_bytes(mult)
        if self.myindex == i and not self.agg_privkey:
            my_priv_int = int_from_bytes(self.privkey.secret_bytes)
            self.agg_privkey = bytes_from_int(my_priv_int * intmult % GROUPN)
        return jmbitcoin.multiply(mult, self.keys[i], return_serialized=False)

    def get_musig_address(self) -> P2TRCoinAddress:
        assert self.state >= MS3A_STATE_KEYAGG_COMPLETE
        self.musig_address = P2TRCoinAddress.from_xonly_output_pubkey(
            btc.core.key.XOnlyPubKey(self.agg_P))
        return self.musig_address

    def get_agg_P(self) -> Tuple[CPubKey, P2TRCoinAddress]:
        """ Returns the aggregated public key and taproot address
        for the provided set of participant pubkeys.
        In addition, we set here *our* aggregated private key, i.e.
        the private key H(L||P_i)x_i where x_i is our base private key,
        and L is the whole keyset and P_i is our pubkey.
        Note that that aggregate private key may have its sign flipped,
        if the aggregate key is odd parity.
        """
        xvals = []
        for i in range(self.n):
            xvals.append(self.get_agg_P_i(i))
        self.agg_P = jmbitcoin.add_pubkeys(xvals)
        agg_privkeylist, x = its_not_ok_to_be_odd_in_bip340(
            self.agg_P, [self.agg_privkey])
        self.agg_privkey = agg_privkeylist[0]
        self.key_sign_flipped = x
        self.state = MS3A_STATE_KEYAGG_COMPLETE
        # we now have an address:
        self.get_musig_address()
        return self.agg_P, self.musig_address

class AdaptorizedMS3A(MS3A):
    """ Include adaptor in MS3A process control.
    Includes ability to derive a "signature adaptor", once
    nonces are exchanged (i.e. first two rounds complete).
    Note that passing of adaptor *points* is *always* included
    in MS3A first two rounds; if they are not needed, they are set
    to 1-byte 0 strings, and then ignored in signing steps.
    """
    def __init__(self, privkey: btc.core.key.CKey,
                 adaptor_secret: bytes,
                n: int, myindex: int, hashfn = sha256):
        super().__init__(privkey, n, myindex, hashfn)
        """ Note that an adaptor secret is a required argument;
        if there isn't one, just create a MS3A object instead.
        """
        assert len(adaptor_secret) == 32
        self.adaptor_secret = adaptor_secret
        # sets T and the hash of T as commitment:
        self.set_adaptor_secret(self.adaptor_secret)

    def get_agg_R(self):
        """ In adaptor-including signing, we must include
        any and all non-empty T values into the aggregated nonce.
        """
        real_Ts = [CPubKey(x) for x in self.Ts if x != bytes([0])]
        self.agg_R = jmbitcoin.add_pubkeys(self.Rs + real_Ts)
        self.reset_base_nonce_with_aggR(include_t=True)

    def get_signature_adaptor(self) -> bytes:
        """ see note on raw arithmetic in MS3A.get_partial_signature.
        Also, note that this can only occur after full nonce exchange
        (i.e. messages 1 and 2), since only then do we know the correct
        signs for the x-only flips.
        """
        assert self.state >= MS3A_STATE_NONCES_EXCHANGED
        return self.get_partial_signature(include_t=False)

def test_musig_with_n_keys(n, deterministic):
    # 1. Keys and MuSig context objects created.
    # 2. Print taproot address for funding.
    # 3. User funds and enters the outpoint with the funds.
    # 4. Simulate passing messages 1,2,3.
    # 5. All participants have full signature by adding partials.
    # 6. Construct tx, insert signature and print.
    # (7. Can broadcast externally).
    global DETERMINISTIC_TEST
    DETERMINISTIC_TEST = deterministic
    startkeys = [CCoinKey.from_secret_bytes(
        bytes([i]*32)) for i in range(1, n+1)]
    startkeyspub = [x.pub for x in startkeys]
    scs = []
    for i in range(n):
        scs.append(MS3A(startkeys[i],
                        startkeyspub, n, i))
    for i, sc in enumerate(scs):
        sc.set_my_nonce()

    # maybe just auto-create this on MS3A object creation?:
    zaggP, zmusigaddr = scs[0].get_agg_P()
    for i in range(1, n):
        aggP, musigaddr = scs[i].get_agg_P()
        if not zaggP == aggP and zmusigaddr == musigaddr:
            print("Failed to agree on multisig address")
            exit(1)
    print(zaggP, zmusigaddr)

    # sanity check for testing (not possible in real world interaction):
    # does sum(agg_privkey)*G =?= +/- aggpubkey?
    totes = 0
    for i in range(n):
        totes = (totes + int_from_bytes(scs[i].agg_privkey)) % GROUPN
    te = jmbitcoin.privkey_to_pubkey(bytes_from_int(totes) + b"\x01")
    if not btc.core.key.XOnlyPubKey(te) == btc.core.key.XOnlyPubKey(zaggP):
        print("Failed to get equal pubkeys: {}, {}".format(te, zaggP))
        exit(1)
    else:
        print("We were able to correctly replicate the aggregate "
              "public key: ", te)
    # TODO: user choose amount
    txidn = input("The multisig address is : {} ; "
                  "please fund it with 0.04 and then "
                 "enter the txid:n here:".format(musigaddr))
    txid, stroutindex = txidn.split(":")
    outindex = int(stroutindex)
    txid = unhexlify(txid)
    outpoint = btc.core.CMutableOutPoint(txid[::-1], outindex)
    vin = [btc.core.CMutableTxIn(prevout=outpoint, nSequence=0xffffffff)]
    outsPK = musigaddr.to_scriptPubKey()
    vout = [btc.core.CMutableTxOut(3990000, outsPK)]
    tx2 = btc.core.CMutableTransaction(vin, vout, nVersion=2)
    # the output we're spending is same spk but 4M not 3.99M:
    for i in range(n):
        scs[i].set_transaction_message(tx2, 0,
            btc.core.CMutableTxOut(4000000, outsPK))
    scs[0].set_adaptor_secret(b"\x03"*32)

    # Simulate passing the three messages between the n parties:
    # MESSAGE 1: hashes of nonces (and maybe adaptors if they're used):
    for i in range(n):
        for j in range(n):
            if j == i:
                continue
            scs[i].receive_ms3a_msg_1(*scs[j].get_ms3a_msg_1(), j)
            # note: nothing to check here, just random commitments
    # MESSAGE 2: opening of commitments above.
    for i in range(n):
        for j in range(n):
            if j == i:
                continue
            if not scs[i].receive_ms3a_msg_2(*scs[j].get_ms3a_msg_2(), j):
                print("Message 2 received by index {} from "
                      "index {} was rejected".format(i, j))
                exit(1)
    # MESSAGE 3: partial signatures from all to all.
    # They can be verified (positive result implies continuation,
    # negative result is more difficult to interpret! (Best to just abort).
    for i in range(n):
        for j in range(n):
            if j == i:
                continue
            if not scs[i].receive_ms3a_msg_3(scs[j].get_ms3a_msg_3(), j):
                print("Message 3 received by index {} from "
                      "index {} ws rejected".format(i, j))
                exit(1)
    print(scs[0].full_signature)
    # Key path signing only requires one witness element: the signature,
    # inserted manually here.
    tx2.wit.vtxinwit[0] = btc.core.CMutableTxInWitness(
        btc.core.script.CScriptWitness([scs[0].full_signature]))
    print(hexlify(tx2.serialize()))
    print(jmbitcoin.human_readable_transaction(tx2))

if __name__ == "__main__":
    # set number of counterparties in the multisig
    n = int(sys.argv[1])
    # see `DETERMINISTIC_TEST` above:
    deterministic = True
    if len(sys.argv) > 2:
        if int(sys.argv[2]) == 0:
            deterministic = False
    # TODO: alternative to pass in pubkeys
    test_musig_with_n_keys(n, deterministic)
