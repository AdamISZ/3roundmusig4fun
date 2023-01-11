# Experimenting with MuSig (the 3-round variant) in Bitcoin

If you want to play with this, for example if you're trying to understand the mechanics of how MuSig concretely works, or if, like me, you're interested in experimenting with signature adaptors (which are now fully possible on Bitcoin), then this repo might be of interest, especially if you're still in a learning stage.
If you want to do real world work though, there isn't much of interest here, mostly because the underlying crypto operations are being done in an unsafe way in Python.

Here is a 7.5 minute video of what running the code actually does: https://www.youtube.com/watch?v=YhH2zqkJK_w ; culminating in a spending event that looks like a normal p2tr (keypath) spend, like [this](https://mempool.space/signet/tx/5e21e25cfb7d447536c49950ce412b91f0a9a4ec44fd416a66a041eb6ccfa149).

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

### Adaptors

All participants will be sending to their counterparts, before receiving partial signatures, a *signature adaptor* that promises to reveal the discrete log of a point (or public key) `T`, deducible by subtraction, from the full partial signature of this participant. The preceding is probably nearly unintelligible if you haven't already studied signature adaptors. For a full-ish treatment of how *this* code is using adaptors, see my blog post [here](https://reyify.com/blog/multiparty-s6). For a more general description of what they are, see [this](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#adaptor-signatures).

( *As you can see, my 'campaign' to rename them signature adaptors, and not adaptor signatures, has been spectacularly unsuccessful. The latter name is dangerous because they are categorically not signatures; you do not need a private key to create one.*)

This is set up in such a way that each participant will use the *same* adaptor across multiple signing events, so that the revelation of the secret `t` value, from the broadcast of any one transaction, will allow the enforcement of all the other transactions. See 'running a test' below on how to do it. Or, if you just want to understand it, see the above mentioned blog post.

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

If it isn't, you'll want to read that project's `README.md` for more, and then possibly the `docs/INSTALL.md`.

### python-bitcointx taproot support

Taproot support has been in the project for most of a year now, but new release is uncertain.

Luckily you can just install ( *inside the JM venv as per above* ) using pip easily:

```
pip install git+https://github.com/Simplexum/python-bitcointx.git@d5ff9b02b7fb983e61b30fe00373f1dad30628ca
```

## Running a test

Steps:

* Choose `regtest` or `signet` and enter that string on this line (yeah should be config file, whatever):

https://github.com/AdamISZ/3roundmusig4fun/blob/a9c4989f1845e4166f04c896c1e5cb97f46e4afe/ms3a.py#L3

* Run `N` instances of `musigparticipant.py` (3 seems a good start), like this:

```
(jmvenv)$ python musigparticipant.py 0 3
```

replacing `0` with `1`, `2`, in different terminals. They will all connect to each other (they talk to each other on random ports), then negotiate an aggregated pubkey after a short delay. Once that happens, they'll all show you the same funding address for the multisig (it will be a taproot address like `tb1p..` or `bcrt1p..`).

* Fund the address and enter the funding details

To fund the address, use whatever wallet/code you choose. Then, in a file named `./fundingfile[i][j].txt`, (i, j explained in a moment) enter these fields:

```
cc2829751a75cdc002b25ef897cae4987d5a71919a00e116f36265ac8a4f2769,0,508000,tb1pha7uk8tt9c0g4fwrlwvzmzc0jsa46shhx8uf9yhsat4zcz4y3ejqph2076,500000,tb1q3xr7l9nylsdlyqf9rkw0rg3f0yx6slguhtwpzp
```

These are examples that I used on signet. The fields are: fundingtxid,funding-output-index,funding-output-amount,musig-address,amount-to-spend,destinationaddress.

i: for now, keep it at 0; the 0th (first) participant will be the one reading this file as a trigger. j: this index is for the signing context. We explain that here:

As per the design in the blog post above, we will have N transactions for N parties; each one will spend out of an N of N MuSig address, (let's set N=3 from here) each of those 3 addresses negotiated by the 3 parties. That means 3 executions of the MuSig protocol are done simultaneously, with each of the 3 parties generating 3 pubkeys (i.e. there are 9 pubkeys input to key exchange, in total). 3 spending-out transactions are being signed; 3 funding transactions must occur, paying *into* the 3 MuSig addresses. So, the index `j` deals with that: for this 3 party case, you'll want to create files fundingfile00.txt, fundingfile01.txt, fundingfile02.txt (doesn't matter what order they get created); each one will trigger the adaptor and signature exchange process for that individual signing context.

Each participant only releases partial signatures once they're sure that the adaptor point `T` for each participant is fixed across the 3 signing contexts; it's that property that ensures that, if one spending transaction is broadcast, the other two can also be broadcast.

Obviously this will be cleaned up a bit. The musigaddress is redundant (the code already knows it of course!), and it also only support a 1-in-1-out spend (but that seems fine just for testing).


## Reading the code

The module `ms3a.py` (short with MuSig 3-round with adaptors) is organized around an object `MS3A` which manages (a) the key setup and then (b) the 3 messages. Note that since we want to try using adaptors at some point, the first message is now:

* `H(R), H(T)` - where `H` means hash, by default SHA256 and `R`, `T` are elliptic curve points serialized in old-style compressed form, where `R` is the nonce and `T` is an adaptor point. As for now, this `T` is set to something random and unused in signing.

The second round message is purely the opening of the first:

* `R`, `T`

and the third round message is each party sending a partial signature `s` value, i.e. 32 bytes, which is calculated as:

* `s_i = k_i + schnorr_challenge_hash(R_agg || P_agg || sighashmessage) * H(L || P_i) * x_i mod secp256k1_group_N`

This obviously needs some unpacking. Read the extensive comments in the code, but a few notes: 1. the subscript `i` is obviously per participant in the N of N. The value `L` is just the concatenation of all the participants' pubkeys `P_i`, the `x_i` is our privkey corresponding to that, and `R_agg` is just the sum of the `R_i` values, specifically because we're using 3-round.

I did omit there the key setup, but it's probably fairly obvious if you understand the above equation: each "aggregated pubkey" is `H(L||P_i)P_i`.

### The network interaction

Obviously this is just for demonstration purposes, but we have N different instances of `musigparticipant.py`, each one serves on a random TCP port (but they all calculate each others' ports based on the chosen index). They speak a simple protocol with message types and text lines containing fields as defined [here](https://github.com/AdamISZ/3roundmusig4fun/blob/53e8b744314bc0842e6b373efee0a72dd47c9aab/musigparticipant.py#L20-L37). Each participant (the class representing them is [here](https://github.com/AdamISZ/3roundmusig4fun/blob/53e8b744314bc0842e6b373efee0a72dd47c9aab/musigparticipant.py#L70) is running multiple signing contexts (e.g. 3 signing contexts for N participants, each a different transaction spending out to a different party). Messages are multiplexed across the different signing contexts in parallel.

The index 0 participant acts as a coordinator and starts off the process, after a delay, sending key exchange messages for each signing context, which kicks off all the others. Once keys are exchanged they can all publish the addresses corresponding to $\sum \left(H(L,P_i) P_i\right) $. They then have to wait for the users to fund those addresses. (And this is done N times in parallel).

After the user funds the addresses he has to enter the funding details as per above. Then the `MS3AManager` objects encapsulated by the `MS3AParticipant` (N of them) can kick off sending messages 1, 2 and 3 as described above.

Footnote:
Since we are interested in investigating signature adaptors, especially multiple of them, it is a bit easier and safer to deal with a 3 round variant where **every user-generated point is committed to up-front** (i.e. it's somewhat in the spirit of 'don't roll your own crypto' to commit to everything at the start in those more whacky scenarios, so 3 round is a logical way to start for that.


