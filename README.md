# 78K0R Flash Leaker

Sequential dump tool for 78K0/78K0R Renesas chips. 

Based on the attack outlined by Claudio Bozzato, Riccardo Focardi, and Francesco Palmarini in their paper **"Shaping the Glitch: Optimizing Voltage Fault Injection Attacks"**.

Bozzato, C., Focardi, R. and Palmarini, F. (2019) “Shaping the Glitch: Optimizing Voltage Fault Injection Attacks”, IACR Transactions on Cryptographic Hardware and Embedded Systems, 2019(2), pp. 199-224. doi: 10.13154/tches.v2019.i2.199-224.

[Shaping The Glitch](https://tches.iacr.org/index.php/TCHES/article/view/7390/6562)

#

* Developed for the Teensy 4.0

* Drives the 78K0/78K0R flash programmer ROM with fault injection to work on 4 bytes minimum.

* Injects a fault to get checksum to operate on 4 bytes minimum.

* Injects a fault to leaks out individual bytes from targeted 4 byte sections, and then cracks their position.(no fault needed for 4 byte verify).
#

**This tool is very slow for full flash dumping, using it as a side channel tool to target areas of interest is a more appropriate use.**
