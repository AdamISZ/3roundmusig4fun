# Experimenting with multiparty coin swaps using MuSig (the 3-round variant)

If you're not interested in the background and just want to do something, skip [here](#running).

## Background on the MuSig part of this codebase

If you want to play with this, for example if you're trying to understand the mechanics of how MuSig concretely works, or if, like me, you're interested in experimenting with signature adaptors (which are now fully possible on Bitcoin), then this repo might be of interest, especially if you're still in a learning stage.
Note that the underlying crypto operations are being done in an unsafe way in Python. This is not safe for real world use (at all).

### Before we begin: how does MuSig work at all?

Those who can, should read the papers:

* First, the [original-but-updated-to-3-round-MuSig-paper](https://eprint.iacr.org/2018/068.pdf). This is "3 round Musig" as per the title, and is what is implemented here (for a reason that may be clear later in this doc).
* Second, [MuSig2](https://eprint.iacr.org/2020/1261.pdf), a slightly more sophisticated idea, that supports "sort of 2 round and sort of 1 round" MuSig; this is likely to be more widely used at an industrial level, but is a little harder to code and a little harder to reason about.

Here's my best effort at plain English explanation:

The trivial solution to "5 people co-sign" is for them all to give their signature, individually. Old-school Bitcoin multisig did this. It's crappy in the specific sense that it uses up a ton of space, and exposes who exactly signed in a quorum.

It did have one advantage - policies like "4 of 7" are intrinsically supported in this model.

We could try to add signatures together to make a so-called "aggregated signature". This proves unfortunately not *directly* possible with ECDSA signatures, which Bitcoin always used before the activation of taproot and Schnorr. Why? It's just a detail of mathematics: when you add (1/3) and (1/2) the answer is not (1/(3+2)) or 1/5. And why does *that* matter? Because it screws up the structure. We want (signature1 + signature2) to *look* like a signature, but because of that "adding inverses is weird" thing, it doesn't fit. (Note: you can get round this with fancy cryptography, but I'm going for plain English here ...).

With Schnorr, you never add fractions like that, you just add numbers. So signature1 + signature2 *does* look like a signature. So that's half the story - it's possible, in Schnorr.

The second half of the story is: that isn't safe, at all, due to the business of counterparties talking to each other in a certain order. The one who gets the other guy's key choices first, is able to manipulate his own keys in a way that leads to cheating. The simple way to stop that is to force everyone to *commit* to their keys (and nonces, which are also keys) upfront, before they see the other guys' keys. **And that is 3-round MuSig**, basically. MuSig2 achieves the same effect, in a more sophisticated way, using algebra on keys such that you don't need to actually *send* that commitment - and that's all I'll say about it here. If you want more, read the aforementioned paper and the draft MuSig2 BIP.

<a name="andtaproot" />

### And in Bitcoin, and taproot?

The end result is that a "MuSig signature" published on the Bitcoin network is just the same as a non-MuSig signature. They're both Schnorr signatures, conforming to the standard defined in [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki). They look like: $(R, s)$ where each of $R$ and $s$ are 32 bytes. And this is always the same, whether MuSig is a aggregated signature for 2 counterparties, or for 999 counterparties. The latter is of course 100% impossible with pre-existing multisignature techniques.

The point is that MuSig itself **does not have to be specified in the Bitcoin protocol**. When nodes verify such a transaction, they have no idea that any such thing is happening, and nor does any "blockchain analysis" reveal it. They just see $(R, s)$. The privacy effect of this is not to be underestimated.

What about the multisig address? Taproot changed what addresses mean in a pretty significant way. Previously, we had: single key addresses, then "pay to (witness) script hash" addresses - in the latter, any non-single-key address would have some complex script that got hashed, and then the script "printed out" when you spent from it. Now, all addresses represent a key of the form $P + \mathbb{H}(S)G$ where $S$ is a script, and $P$ is a normal pubkey. Meaning that if you know the private key of $P$, $x$, then you could spend using the private key $x + \mathbb{H}(S)$ - this is called **key path spending**. Or you could just reveal the script $S$ and satisfy its conditions (example: 3 of 4 keys after a timelock) - this is called **script path spending**.

Using MuSig is using the former. So we set, here, the script to `""`, i.e. deliberately unsatisfiable empty script, so script path spending isn't possible, and we make $P$ be the aggregated public key, negotiated by the MuSig code. More on this below.

<a name="adaptors" />

### Adaptors and how they are used here

In the actual running of these scripts (instructions below), all participants will be sending to their counterparts, before receiving partial signatures, a *signature adaptor* that promises to reveal the discrete log of a point (or public key) `T`, deducible by subtraction, from the full partial signature of this participant. The preceding is probably nearly unintelligible if you haven't already studied signature adaptors. For a full-ish treatment of how *this* code is using adaptors, see my blog post [here](https://reyify.com/blog/multiparty-s6). For a more general description of what they are, see [this](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#adaptor-signatures).

( *As you can see, my 'campaign' to rename them signature adaptors, and not adaptor signatures, has been spectacularly unsuccessful. The latter name is dangerous because they are categorically not signatures; you do not need a private key to create one.*)

This is set up in such a way that each participant will use the *same* adaptor across multiple signing events, so that the revelation of the secret `t` value, from the broadcast of any one transaction, will allow the enforcement of all the other transactions. See 'running a test' below on how to do it. Or, if you just want to understand it, see the above mentioned blog post.

<a name="installing" />

## Installing dependencies

Like a lot of more casual pet projects, this is unfortunately not self-contained. It requires basically two dependencies, apart from Bitcoin itself which you can run on regtest or signet as is convenient to you.

### Joinmarket

The installation on Linux is supposed to be as simple as:

```
git clone https://github.com/Joinmarket-Org/joinmarket-clientserver
cd joinmarket-clientserver
./install.sh
source jmvenv/bin/activate
```

Latest release or master should both be fine; we are only actually using `jmbitcoin` here.

If it isn't that simple, you'll want to read that project's `README.md` for more, and then possibly the `docs/INSTALL.md`.

Note that this project uses Joinmarket's function of starting an onion service (as used for yieldgenerators), so you probably want to read [here](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/tor.md#configuring-tor-to-setup-an-onion-service).

If the install is complete and you have `(jmvenv)` on your CLI prompt, you only need to do one more thing before starting:

### python-bitcointx taproot support

Taproot support has been in the project for most of a year now, but new release is uncertain.

Luckily you can just install ( *inside the JM venv as per above* ) using pip easily:

```
pip install git+https://github.com/Simplexum/python-bitcointx.git@d5ff9b02b7fb983e61b30fe00373f1dad30628ca
```

<a name="running" />

## How to do a multiparty coinswap using this code

Steps:

1. Gather N people in a communication channel (this might be the hard part! except, it's only a test with play coins, so nothing to worry about!). Each one of them needs to have some coins in a wallet.

2. Choose `signet` (if you're working on your own, use `regtest`, but for a group, signet will work a lot better than testnet).

3. Install the dependencies. There are two elements to this, and they're specified in the [section above](#installing).

4. Decide on a numbering of the N people. E.g. Alice, Bob Carol can be 0, 1, 2. Alice here has a special role of 'coordinator', in only one sense: she has to enter the transaction funding details as explained below.

5. Run `python musigparticipant.py --help` to see the options (the only one you probably care about is `--network signet`) and the arguments. They are `myindex`, `number of counterparties` and `destination address`. Source the last one from your signet wallet. This is where coins will go *from* the musig address, back to you.

6. Run `python musigparticipant.py --bootstrap` and note down the `**.onion` address that it shows you. Send that to each other participant.

7. Once everyone has the full list (e.g. 3 onion addresses if 3 participants), then they must put them, in order, at the bottom of the `musigparticipant.py`, in the entry for `onions=[xx.onion,...]`, replacing the hardcoded examples.

8. Now each person can run `python musigparticipant.py myindex ncounterparties mydestinationaddress`. After some time all should be able to connect to all, and should share key exchange information that allows N musig addresses to get created. Each person's output will look like:

```
(jmvenv) a@b:$python musigparticipant.py 0 3 bcrt1qaexgf476anael7fg93efnqp6kx3dl0l4s8e6wv
Attempting to start onion service on port: 5321 ...
We are starting a hidden service at:  6xapwqugm5i63625hqif45joly33h7nf63c6ecwr6feshybnkwiiutqd.onion
We have connected to 1 participants.
We have connected to 2 participants.
Key exchange complete
Key exchange complete
You are index 0. You should fund the musig address for signing session 1, which is: bcrt1pm9lj8uefng650m6lf38e59mhlqj2a62uw8naxjncdxxjn7zd8jhsp3csg2
```

... and the script will just wait at this point.

9. Once output like that is seen, go ahead and fund the address mentioned. The N parties should agree an amount (the idea is that the amount is ~ the same, since all parties will also *receive* the same amount, minus fees, but for a simple demo the details are somewhat omitted.

9a. **NOTE THAT THERE IS NO TIMELOCKED BACKOUT TRANSACTION CREATED, BUT THIS WOULD BE ESSENTIAL IN A REAL PROTOCOL** (as otherwise, funding a multisig, of whatever type, could result in the coins being permanently locked up). This is a TODO for this project, though to be clear it is not terribly hard to do.

10. Once all N parties have submitted their funding transactions, they should share the txid:n of the output which funds the described multisig address. Specifically, counterparty at index `i` will, by following the above instructions, be funding the multisig address which, itself, will pay out to counterparty `(i+1) mod n`, i.e. the next "around the loop". They should all give this info to everyone for checking but specifically counterparty 0 (Alice, above) will need it to enter into a file.

11. Counterparty at index 0 (Alice for short) needs to create files `fundingfile0[i].txt` for i from 0 to N-1. In each one she must enter a single line of this format: 

```
cc2829751a75cdc002b25ef897cae4987d5a71919a00e116f36265ac8a4f2769,0,5000000
```

that is, txid, index(output index of the utxo), amount-in-satoshis. So as a concrete example, if Alice, Bob, Carol so 3 of 3, then `fundingfile00.txt` will contain a line with the funding info that was paid-in by Carol, `fundingfile01.txt` will contain a line with the funding info that was paid in by Alice, and `fundingfile02.txt` will contain a line with the funding info that was paid in by Bob. ("Each pays the next").

12. When Alice creates these files her own script will see it, read the funding info, then start the MuSig negotiation. All parties will see the information, and they will not do full signing until they have seen signature adaptors for *all* of the N transactions that have been created, to be signed.

13. Once all parties have received over the network, both the funding information, and the nonces and signature adaptors for all of the transactions, and if everything checks out, they will send partial signatures for all the transactions **knowing that at this point they are safe that, if one transaction is broadcast, all the others can be, by using the information in the signature adaptors**.

There is no '14' here but a really good test would involve, say, Alice broadcasting her transaction but not releasing her partial signatures on the other transactions. Each party should still be able to claim their funds. And similar scenarios. See the blog post for justification.


## Reading the code

More technical in the weeds stuff goes here, so a casual reader (or non-coder) can ignore it. This is WIP.

The module `ms3a.py` (short with MuSig 3-round with adaptors) is organized around an object `MS3A` which manages (a) the key setup and then (b) the 3 messages. Note that since we want to try using adaptors at some point, the first message is now:

* `H(R), H(T)` - where `H` means hash, by default SHA256 and `R`, `T` are elliptic curve points serialized in old-style compressed form, where `R` is the nonce and `T` is an adaptor point. As for now, this `T` is set to something random and unused in signing..
The second round message is purely the opening of the first:

* `R`, `T`

and the third round message is each party sending a partial signature `s` value, i.e. 32 bytes, which is calculated as:

* `s_i = k_i + schnorr_challenge_hash(R_agg || P_agg || sighashmessage) * H(L || P_i) * x_i mod secp256k1_group_N`

This obviously needs some unpacking. Read the extensive comments in the code, but a few notes: 1. the subscript `i` is obviously per participant in the N of N. The value `L` is just the concatenation of all the participants' pubkeys `P_i`, the `x_i` is our privkey corresponding to that, and `R_agg` is just the sum of the `R_i` values, specifically because we're using 3-round.

I did omit there the key setup, but it's probably fairly obvious if you understand the above equation: each "aggregated pubkey" is `H(L||P_i)P_i`.



