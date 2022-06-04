# qtestsign
[qtestsign] is a simple, open-source tool to sign ELF Qualcomm firmware images using test keys.
It implements the image format described in [Secure Boot and Image Authentication - Technical Overview v1.0](
https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v1-0.pdf).
**It is not meant to provide any security, only to pack the images into a format accepted by the Qualcomm
firmware loaders.**

**Note:** Most Qualcomm devices have a certain root CA "burned" into fuses and refuse to boot firmware
signed with other certificates. This tool works only for devices with disabled secure boot. Currently,
it does not even generate an actual signature because it does not seem to be verified at least on
MSM8916/APQ8016 devices with disabled secure boot.

## Usage
[qtestsign] requires Python 3.7+ and [cryptography] 3.1+, a Python module used to generate new CA certificates.
On many distributions this will likely be already installed by default (but perhaps outdated).
Alternatively you can install it with pip:

```
$ pip install -r requirements.txt
```

Then, just use `./qtestsign.py --help` to figure out how the tool works. You need to specify the firmware type
and the ELF image to sign, e.g. for [U-Boot]:

```
$ ./qtestsign.py aboot u-boot
```

And the tool will produce `u-boot-test-signed.mbn`, signed with automatically generated test certificates.
Note that this will also automatically strip the binary, so there is no need to do that manually first.

## Supported SoCs/firmwares
So far [qtestsign] is only tested to work for signing firmware for the MSM8916/APQ8016 SoC.
It can successfully sign aboot/hyp/tz/rpm/sbl1 (tested by re-signing official firmware).
It is likely that it works for many other SoCs that use the [v1.0 image format].

This tool was created to sign (open-source) firmware for the [DragonBoard 410c] (APQ8016) and other MSM8916 devices, e.g.:
- `aboot`: [LK (Little Kernel)] bootloader
- `aboot`: [U-Boot] bootloader
- `hyp`: [qhypstub], [tfalkstub]
- `tz`: [Trusted Firmware-ARM (TF-A)]

## License
[qtestsign] is licensed under the [GNU General Public License, version 2]. It is mostly based on the specification
of the [v1.0 image format], but some implementation details (e.g. the exact hash segment header format) are adapted
from [signlk]. Unlike [signlk] it can also successfully sign other firmware types, like `hyp`.

[qtestsign]: https://github.com/msm8916-mainline/qtestsign
[cryptography]: https://cryptography.io
[v1.0 image format]: https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v1-0.pdf
[DragonBoard 410c]: https://www.96boards.org/product/dragonboard410c/
[LK (Little Kernel)]: https://git.linaro.org/landing-teams/working/qualcomm/lk.git
[U-Boot]: https://u-boot.readthedocs.io/en/latest/board/qualcomm/dragonboard410c.html
[qhypstub]: https://github.com/msm8916-mainline/qhypstub
[tfalkstub]: https://github.com/msm8916-mainline/tfalkstub
[Trusted Firmware-ARM (TF-A)]: https://trustedfirmware-a.readthedocs.io/en/latest/plat/qti-msm8916.html
[GNU General Public License, version 2]: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
[signlk]: https://git.linaro.org/landing-teams/working/qualcomm/signlk.git
