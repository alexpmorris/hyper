### hyper-sdk utilities including base58-style wif/pubkeys, sign/verify, and memo encryption/decryption

```
node node_serve.js
http://localhost:1337/hyper.html
```

in console:

<img src="https://github.com/alexpmorris/hyper/blob/main/hyper-utils.png">

Adding such functionality to hyper-sdk should make it much easier and safer for users to maintain their keys locally for a browser-based social app like CTZN, while requiring little or no state to be maintained server-side *(similar to how Steem, Hive, and WhaleShares function)*.

For browsers that support chrome/firefox extensions, <a href="https://chrome.google.com/webstore/detail/whalevault/hcoigoaekhfajcoingnngmfjdidhmdon?hl=en">WhaleVault</a> could be used to safely sign transactions, verify auth/logins, etc, so the websites that you authorize can safely and securely request a signature or encrypt/decrypt a memo without ever having direct access to any of your private keys *(similar to MetaMask for Ethereum or Scatter for EOS)*.

<img src="https://lh3.googleusercontent.com/C4XeuyHr5DcnToQT0770_Yu7DVm35yBAD22CuvQHS7JJQzw937s9yDMcFQ9fPasq4DzbdI09PONXZFCkwAiO8p_IYEs=w640-h400-e365-rj-sc0x00ffffff">

to use in the context of a hyperfeed *(feed_alt_crypto is defined in the html)*:

```
>feed = sdk.Hypercore("testkey342423", {crypto: feed_alt_crypto});
```

regarding the *possible* verification issue I described on the livestream... apparently, verification takes place on replication. It seems any bad actor can call append() on a feed. However, if the invalid feed is propagated to another node, it would reject the tampered feed in `_verifyAndWrite()`  -> `_verifyRootsAndWrite()`, thus throwing the exception `Remote signature could not be verified`.

```
>await feed.append('test123')
0

>await feed.append('test123')
1

>await feed.append('test123')
2

>k1 = sdk.utils.keyPair('','HYP')

>feed.key = sdk.utils.getKeyBytes(k1.publicKey)

>feed.publicKey = sdk.utils.fromKeyString(k1.publicKey, 'public')

>await feed.append('test123')
3  <-- no rejection on addition after key changed!

HOWEVER, manual verification of feed WILL now fail:

>await feed.verify(feed.length-1, feed._storage.signatures.toBuffer().slice(-64))
Uncaught Error: Signature verification failed
```

Lastly, here is a demo of signing a `feed.append()` using WhaleVault. 
For now, it still uses graphene's secp256k1-style keys for signing:

```
  wv_alt_crypto = {
    async sign (data, sk, cb) {
      if (sk == null) {
        if (!whalevault) return cb(new Error('WhaleVault required for signing!'));
        response = await whalevault.promiseRequestSignBuffer('demo', 'wls:guest123', sdk.utils.buffer.from(data).toString('utf8'), 'Posting', 'feedPost', 'raw');
        if (response.success) return cb(null, sdk.utils.buffer.from(response.result,'hex').slice(1)); else
          return cb(new Error(response.message));
      } else return cb(null, sdk.utils.sign(data, sk))
    },
    verify (sig, data, pk, cb) {
      return cb(null, sdk.utils.verify(sig, data, pk))
    }
  }
  k1 = sdk.utils.keyPair('','HYP');
  feed = sdk.Hypercore("testkey3424231232111", {crypto: wv_alt_crypto, key: sdk.utils.getKeyBytes(k1.publicKey,'public')})
  
  to append:
  >feed.writable=true; await feed.append('test');
  
  if transaction is confirmed from WhaleVault popup, to review:
  >sdk.utils.buffer.from(await feed.get(0)).toString()
  "test"
  
```
