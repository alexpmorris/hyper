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

`
feed = sdk.Hypercore("testkey342423", {crypto: feed_alt_crypto});
`
