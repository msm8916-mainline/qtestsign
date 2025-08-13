# qtestsign
[qtestsign] is a simple tool to "sign" ELF Qualcomm firmware images using a dummy certificate chain ("test keys").
It partially implements the image format described in Qualcomm's whitepaper _"Secure Boot and Image Authentication"_ (both
[v1.0](https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v1-0.pdf) and
[v2.0](https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v2-0.pdf))
by extending ELF images with a Qualcomm-specific "hash segment", consisting of:

  - A special MBN Header
  - Hashes for each ELF segment
  - A stub signature (actual signatures are not generated at the moment)
  - A dummy certificate chain

**NOTE:** Most Qualcomm devices have a certain root CA "burned" into fuses and refuse to boot firmware
signed with other certificates. [qtestsign] is not meant to work in such setups, it only packs the images
into a format accepted by Qualcomm devices without firmware secure boot. **Most Qualcomm devices
available in production have firmware secure boot permanently enabled (with no way to disable it).
They will fail to boot when flashing modified firmware!**

## Usage
[qtestsign] requires Python 3.7+ and [cryptography] 3.1+, a Python module used to generate the certificate chain.
On many distributions this will likely be already installed by default (but perhaps outdated).
Alternatively you can install it with pip:

```
$ pip install -r requirements.txt
```

Then, just use `./qtestsign.py --help` to figure out how the tool works. You need to specify the firmware type
and the ELF image to sign, e.g. for [U-Boot]:

```
$ ./qtestsign.py aboot u-boot.elf
```

And the tool will produce `u-boot-test-signed.mbn`, "signed" with a dummy certificate chain.
Note that this will also automatically strip the binary, so there is no need to do that manually.

## Supported chipsets
[qtestsign] should work for most Qualcomm chipsets, assuming the device has firmware secure boot disabled.
However, the format of the hash segment changes occasionally and different firmware versions may have
varying requirements for the signed images. On some platforms only the hashes are required, others also
require a valid certificate chain (but no valid signature). Some platforms even accept unsigned ELF images
and can therefore work without using [qtestsign].

The `-v`/`--version` option must be set correctly depending on the chipset:

- **`-v3` (default):** MSM8916, MSM8939, MSM8953
  - MSM8909, MDM9607 (they usually accept unsigned ELF images as well)
- **`-v5`:** MSM8998, SDM845
- **`-v6`:** SM8150, IPQ9574, IPQ5332
  - In case of problems, try using `-v5` instead. Sometimes both seem to be supported.
- **`-v7`:** IPQ5424

The list of chipsets is not complete, most other Qualcomm chipsets likely use one of the already supported
versions above or an older/newer version that is not supported yet by [qtestsign].

## Supported firmware
Qualcomm's own signing tool is proprietary and not publicly available. [qtestsign] was created to allow
building open-source firmware projects without access to Qualcomm's tool, e.g.:
- `aboot`: [U-Boot] bootloader (for DragonBoard 410c, QCA SoCs etc..)
- `aboot`: [Qualcomm's fork of LK (Little Kernel)], used as bootloader on older platforms
- `abl`: [Qualcomm's Android Bootloader for UEFI], used on newer platforms
- `hyp`: [qhypstub], [tfalkstub]
- `tz`: [Trusted Firmware-ARM (TF-A)]

[qtestsign] also accepts already signed firmware as input. In this case, the original hash segment/signature
is stripped and replaced with new hashes.

## Extra Tools
[qtestsign] also provides some extra tools for working with (Qualcomm-related) ELF images:

  - `merge.py`: Merge program headers and segments from multiple ELF files into a single ELF image.
    This can be used if multiple separate firmware images should be loaded at runtime, but only
    a limited amount of firmware partitions (`tz`, `hyp`, ...) are available.

    **Note:** The resulting image is not automatically signed, this must be done separately.

 - `patchxbl.py`: Replace the XBL core segment inside a XBL image (`xbl.elf`). This can be used
   to load U-Boot instead of edk2 on some platforms. See the following blog post for details:
   [Initial U-Boot release for Qualcomm platforms]

 - `region.py`: Show the reserved memory region required for an ELF image.

 - `strip.py`: Remove section header table and drop hash segment from the ELF image.

## License
[qtestsign] is licensed under the [GNU General Public License, version 2]. It is mostly based on the specification
from Qualcomm's whitepaper _"Secure Boot and Image Authentication"_ (both
[v1.0](https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v1-0.pdf) and
[v2.0](https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v2-0.pdf)).
Some implementation details (e.g. the exact MBN header format) are adapted from [signlk] and [coreboot]
(`util/qualcomm/mbn_tools.py`, `util/cbfstool/platform_fixups.c`) available under a `BSD-3-Clause` license.

For QCA chipsets, Qualcomm maintains a similar set of tools at https://git.codelinaro.org/clo/qsdk/oss/system/tools/meta
available under a `ISC` license.

[qtestsign]: https://github.com/msm8916-mainline/qtestsign
[cryptography]: https://cryptography.io
[v1.0 image format]: https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v1-0.pdf
[DragonBoard 410c]: https://www.96boards.org/product/dragonboard410c/
[Qualcomm's fork of LK (Little Kernel)]: https://git.codelinaro.org/clo/la/kernel/lk
[Qualcomm's Android Bootloader for UEFI]: https://git.codelinaro.org/clo/la/abl/tianocore/edk2
[U-Boot]: https://u-boot.readthedocs.io/en/latest/board/qualcomm/dragonboard410c.html
[qhypstub]: https://github.com/msm8916-mainline/qhypstub
[tfalkstub]: https://github.com/msm8916-mainline/tfalkstub
[Trusted Firmware-ARM (TF-A)]: https://trustedfirmware-a.readthedocs.io/en/latest/plat/qti-msm8916.html
[GNU General Public License, version 2]: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
[signlk]: https://git.linaro.org/landing-teams/working/qualcomm/signlk.git
[coreboot]: https://coreboot.org
[Initial U-Boot release for Qualcomm platforms]: https://www.linaro.org/blog/initial-u-boot-release-for-qualcomm-platforms/
