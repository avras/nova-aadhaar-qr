# Age Proof from Aadhaar QR code

**TLDR:** [Anon Aadhaar](https://pse.dev/en/projects/anon-aadhaar) using [Nova](https://github.com/microsoft/Nova) instead of Groth16. This substitution reduces memory and download requirements.

## What is an Aadhaar QR code?
 An Aadhaar QR code is a QR code containing digitally signed data about an Aadhaar holder. It can be found on the back of an Aadhaar card. It can also be downloaded using the mAadhaar app (<a href="https://play.google.com/store/apps/details?id=in.gov.uidai.mAadhaarPlus" target="_blank">Google Play</a>, <a href="https://apps.apple.com/in/app/maadhaar/id1435469474" target="_blank">App Store</a>).  It contains the following information about the holder.
    
- Last 4 digits of Aadhaar number
- Name
- Date of birth
- Gender
- Address
- Last 4 digits of mobile number
- Photo (in JPEG format)
  
Additionally, it contains a timestamp indicating the date and time at which the QR code was created.

## Running the example
You will need an Aadhaar QR code image file to run the `proveage` example. Give the filename as the first argument and the current date in DD-MM-YYYY as the second argument.

```
cargo run -r --example proveage qr.jpeg 30-11-2024
    Finished `release` profile [optimized] target(s) in 0.07s
     Running `target/release/examples/proveage qr2.jpeg 30-11-2024`
Producing public parameters...
PublicParams::setup, took 1.914233506s 
Number of constraints per step (primary circuit): 103697
Number of constraints per step (secondary circuit): 10349
Number of variables per step (primary circuit): 103361
Number of variables per step (secondary circuit): 10331
Generating a RecursiveSNARK...
RecursiveSNARK::prove_step 0: true, took 488ns 
RecursiveSNARK::prove_step 1: true, took 225.987865ms 
RecursiveSNARK::prove_step 2: true, took 254.678452ms 
RecursiveSNARK::prove_step 3: true, took 262.673012ms 
RecursiveSNARK::prove_step 4: true, took 266.085199ms 
RecursiveSNARK::prove_step 5: true, took 271.970083ms 
RecursiveSNARK::prove_step 6: true, took 274.87408ms 
RecursiveSNARK::prove_step 7: true, took 280.217542ms 
RecursiveSNARK::prove_step 8: true, took 279.292071ms 
RecursiveSNARK::prove_step 9: true, took 285.611861ms 
RecursiveSNARK::prove_step 10: true, took 275.645804ms 
RecursiveSNARK::prove_step 11: true, took 298.4705ms 
RecursiveSNARK::prove_step 12: true, took 296.514819ms 
RecursiveSNARK::prove_step 13: true, took 287.150979ms 
RecursiveSNARK::prove_step 14: true, took 277.84232ms 
RecursiveSNARK::prove_step 15: true, took 289.620471ms 
RecursiveSNARK::prove_step 16: true, took 283.021459ms 
Total time taken by RecursiveSNARK::prove_steps: 4.409968786s
Verifying a RecursiveSNARK...
RecursiveSNARK::verify: true, took 213.311751ms
Generating a CompressedSNARK using Spartan with IPA-PC...
CompressedSNARK::prove: true, took 7.190590591s
Total proving time is 12.351944587s
CompressedSNARK::len 10852 bytes
Verifying a CompressedSNARK...
CompressedSNARK::verify: true, took 236.126807ms
=========================================================
Public parameters generation time: 1.914233506s 
Total proving time (excl pp generation): 12.351944587s
Total verification time: 236.126807ms
=========================================================
Nullifier = 0x3ee1abd50fd64c25d033406023341d7c0ac351eebf9a56f8fe0379de1a8288ff
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-
2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall b
e
dual licensed as above, without any additional terms or conditions.
