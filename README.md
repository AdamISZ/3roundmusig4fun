# Experimenting with MuSig (the 3-round variant) in Bitcoin

If you want to play with this, for example if you're trying to understand the mechanics of how MuSig concretely works, or if, like me, you're interested in experimenting with signature adaptors (which are now fully possible on Bitcoin), then this repo might be of interest, especially if you're still in a learning stage.
If you want to do real world work though, there isn't much of interest here, mostly because the underlying crypto operations are being done in an unsafe way in Python.

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

replacing `0` with `1`, `2`, in different terminals. They will all talk to each other after being kicked off with a non-empty line in a file `musigfile[i].txt` (yeah, I'll replace that with a delayed start shortly). They talk to each other on random ports. Once that happens, they'll all show you the same funding address for the multisig (it will be a taproot address like `tb1p..` or `bcrt1p..`).

* Fund the address and enter the funding details

To fund the address, use whatever wallet/code you choose. Then, in `fundingfile[i].txt`, enter these fields:

```
cc2829751a75cdc002b25ef897cae4987d5a71919a00e116f36265ac8a4f2769,0,508000,tb1pha7uk8tt9c0g4fwrlwvzmzc0jsa46shhx8uf9yhsat4zcz4y3ejqph2076,500000,tb1q3xr7l9nylsdlyqf9rkw0rg3f0yx6slguhtwpzp
```

These are examples that I used on signet. The fields are: fundingtxid,funding-output-index,funding-output-amount,musig-address,amount-to-spend,destinationaddress.

Obviously this will be cleaned up a bit. The musigaddress is redundant (the code already knows it of course!), and it also only support a 1-in-1-out spend (but that seems fine just for testing).

Example transaction spending a 3 of 3 MuSig on signet: https://mempool.space/signet/tx/5e21e25cfb7d447536c49950ce412b91f0a9a4ec44fd416a66a041eb6ccfa149

(Examples on chain don't show much, and that's kind of the point .. the spending utxo here is a simple p2tr keyspend; for these, the witness is just a single 64 byte Schnorr signature, as per the rules of BIP341.)

Footnote:
Since we are interested in investigating signature adaptors, especially multiple of them, it is a bit easier and safer to deal with a 3 round variant where **every user-generated point is committed to up-front** (i.e. it's somewhat in the spirit of 'don't roll your own crypto' to commit to everything at the start in those more whacky scenarios, so 3 round is a logical way to start for that.


