# Namada FAQ

### Q: How do I join as a validator post-genesis?

**A:** Joining as a validator post genesis can be done following [these instructions](https://hackmd.io/@bengtlofgren/rkear5uOs)

### **Q: How do I use the Faucet?**
    
**A:** The faucet can be used to get a various list of tokens from the following command:

```bash!
namadac transfer \
    --token NAM \
    --amount 1000 \
    --source faucet \
    --target [your-established-account-alias] \
    --signer [your-established-account-alias]
```
### **Q: Where can I see the available tokens on the Faucet?**
    
**A:** The following list of tokens are available to withdraw from the faucet:
    
`NAM, DOT, ETH, BTC`

There are a few more, but we leave it to you as a challenge to find out which these are :thinking_face: 
HINT: `namadac balance`

### **Q: How do I use the Ethereum Bridge?**
    
**A:** The Ethereum Bridge is not yet implemented as of 0.12.0. Keep an eye on the [Changelog](https://github.com/anoma/namada/tree/main/.changelog) 👀 to see when it will be officially released.

### **Q: How can I make an IBC transfer?**
    
**A:** Same as Ethereum Bridge, so keep an eye on the [Changelog](https://github.com/anoma/namada/tree/main/.changelog)!

### **Q: What requirements do I need to be a User/Validator on Namada**

**A:**  See [hardware requirements](./install/hardware.md)

In order to build binaries from source, at least 16GB RAM will be required

### Q: Where can I find the binaries to run Namada if I do not want to build from source?

**A:** See [Installing Namada from binaries](./install/from-binary.md)
